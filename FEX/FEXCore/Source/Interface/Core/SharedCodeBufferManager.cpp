// SPDX-License-Identifier: MIT
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/SharedCodeBufferManager.h"

#include <FEXCore/fextl/memory.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>

#ifdef FEX_IOS_HOST
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <mutex>
#endif

#ifndef _WIN32
#include <FEXCore/Utils/PrctlUtils.h>
#endif

namespace FEXCore::CPU {
static constexpr size_t INITIAL_CODE_SIZE = 1024 * 1024 * 16;
// iOS-Madeira ml437/ml1052: the JIT pool grants what it can afford and refuses the rest, and the
// constructor's halving ladder handles a refusal, so the ceiling stays FEX's own branch range.
// We don't want to move above 128MB atm because that means we will have to encode longer jumps
static constexpr size_t MAX_CODE_SIZE = 1024 * 1024 * 128;

#if defined(FEX_IOS_HOST) && defined(ARCHITECTURE_arm64ec)
/* madeira [code-buffer-big] rev=code-buffer-big-1, env MADEIRA_FEX_CODE_BUFFER_MB = <N> (MB, 129-1024;
 * unset, empty, not a number or 128 and below: MAX_CODE_SIZE as before).
 * idea: BOR1NG (Avery Felts, https://github.com/aaf2tbz), MetalSharp-Wine, Discord Nov 22; MIT
 *
 * The 128 MB cap above is not a correctness limit of the JIT. Everything that branches out of a block
 * copes with a target beyond B/BL range: ExitFunctionLink patches the callsite only when the offset
 * IsInt26 and otherwise links through the record's HostCode (ldr + br), the dispatcher and the shared
 * routines are loaded from CpuStateFrame::Pointers, and the *_OrRestart branches only reach labels in
 * the block being compiled (its jump thunks sit at its own end). So a larger buffer needs no new
 * branch encoding. On iOS the size it gets is decided by the JIT pool (ntdll virtual_ios.c): a carve
 * above 128 MB comes only from pool-low's region C, and only with this same variable set; anything
 * the pool cannot afford is refused and the ladder in the CodeBuffer constructor steps down to it.
 * ARM64EC only: WoW64 FEX cannot use region C (AllocatorHooks.h) and keeps MAX_CODE_SIZE. */
static size_t IosBigCodeSize() {
  static const size_t Size = [] {
    const char* E = getenv("MADEIRA_FEX_CODE_BUFFER_MB");
    if (!E || *E < '1' || *E > '9') {
      return size_t {0};
    }
    char* End = nullptr;
    unsigned long Mb = strtoul(E, &End, 10);
    if (!End || *End || Mb <= MAX_CODE_SIZE / (1024 * 1024)) {
      return size_t {0};
    }
    if (Mb > 1024) {
      Mb = 1024;
    }
    return static_cast<size_t>(Mb & ~15UL) * 1024 * 1024; /* whole 16 MB steps, as the pool hands out */
  }();
  return Size;
}
#else
static size_t IosBigCodeSize() {
  return 0;
}
#endif

/* MAX_CODE_SIZE, or MADEIRA_FEX_CODE_BUFFER_MB when it is set (see above). */
static size_t MaxCodeSize() {
  const size_t Big = IosBigCodeSize();
  return Big > MAX_CODE_SIZE ? Big : MAX_CODE_SIZE;
}

CodeBuffer::CodeBuffer(size_t Size, bool ShouldBeNamed)
  : AllocatedSize(Size) {
  Ptr = static_cast<uint8_t*>(FEXCore::Allocator::VirtualAlloc(Size, true));
#ifdef FEX_IOS_HOST
  /* iOS-Madeira ml364: exec allocations come from the finite JIT pool. Degrade before dying:
   * halve the request down to 1MB (freelist gaps often satisfy small carves), and if even that
   * fails force a fault at a recognizable address so the fault pipeline reports it. */
  while (!Ptr && Size > 0x100000) {
    /* code-buffer-big-1: a request above MAX_CODE_SIZE steps down by halves but never past
     * MAX_CODE_SIZE (a 384 MB ask tries 192, then 128), so the opt-in never ends with less than the
     * 128 MB it would have got without it. Below MAX_CODE_SIZE the ladder is the ml364 one. */
    Size = Size > MAX_CODE_SIZE ? std::max<size_t>(Size >> 1, MAX_CODE_SIZE) : Size >> 1;
    Ptr = static_cast<uint8_t*>(FEXCore::Allocator::VirtualAlloc(Size, true));
  }
  if (Ptr && Size != AllocatedSize) {
    LogMan::Msg::EFmt("[code-buffer] rev=ml364 exec alloc degraded 0x{:x} -> 0x{:x} (pool pressure)", AllocatedSize, Size);
    AllocatedSize = Size;
  }
  if (!Ptr) {
    LogMan::Msg::EFmt("[code-buffer] rev=ml364 EXEC ALLOC FAILED even at 0x{:x} - JIT pool exhausted; forcing honest fault at 0xdead", Size);
    *reinterpret_cast<volatile uint64_t*>(0xdeadULL) = Size;
  }
#endif
  LOGMAN_THROW_A_FMT(!!Ptr, "Couldn't allocate code buffer");

  // Protect the last page of the allocated buffer to trigger SIGSEGV on write access
  uintptr_t LastPageAddr = AlignDown(reinterpret_cast<uintptr_t>(Ptr) + Size - 1, FEXCore::Utils::FEX_PAGE_SIZE);
  if (!FEXCore::Allocator::VirtualProtect(reinterpret_cast<void*>(LastPageAddr), FEXCore::Utils::FEX_PAGE_SIZE,
                                          FEXCore::Allocator::ProtectOptions::None)) {
    LogMan::Msg::EFmt("Failed to mprotect last page of code buffer.");
  }

  if (ShouldBeNamed) {
    FEXCore::Allocator::VirtualName("FEXMemJIT", Ptr, Size);
  }

  // Huge-pages reduce the amount of iTLB misses dramatically when it works.
  FEXCore::Allocator::VirtualTHPControl(Ptr, Size, FEXCore::Allocator::THPControl::Enable);

  LookupCache = fextl::make_unique<GuestToHostMap>();

  CodeBufferEnd = Ptr + UsableSize();
  CodeBufferOffset = Ptr;
}

CodeBuffer::~CodeBuffer() {
  FEXCore::Allocator::VirtualFree(Ptr, AllocatedSize);
}

SharedCodeBufferManager::SharedCodeBufferManager() {
  FEX_CONFIG_OPT(GlobalJITNaming, GLOBALJITNAMING);
  FEX_CONFIG_OPT(LibraryJITNaming, LIBRARYJITNAMING);
  FEX_CONFIG_OPT(BlockJITNaming, BLOCKJITNAMING);

  // Only name the JIT buffers if perf JIT naming is disabled.
  // `perf top` prefers VMA names over the JIT symbols file for some reason.
  // Breaks memory tracking when naming is enabled, but it's a debug feature so it isn't expected to be enabled by default.
  NameJITBuffers = !(GlobalJITNaming || LibraryJITNaming || BlockJITNaming);
}

#ifdef FEX_IOS_HOST
/* ml460 (#75): process-wide generation counter; read by the deferred-sweep trigger (Core.cpp)
 * and the sweeper (CPUBackend.cpp) via IosCodeBufferGeneration. */
static std::atomic<uint64_t> IosCodeBufferGenCounter {0};
uint64_t IosCodeBufferGeneration() {
  return IosCodeBufferGenCounter.load(std::memory_order_acquire);
}
#endif

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::AllocateNew(size_t Size) {
#if defined(__linux__)
  // MDWE (Memory-Deny-Write-Execute) is a new Linux 6.3 feature.
  // It's equivalent to systemd's `MemoryDenyWriteExecute` but implemented entirely in the kernel.
  //
  // MDWE prevents applications from creating RWX memory mappings.
  // This prevents FEX from doing anything JIT related, as FEX uses RWX for JIT memory mappings.
  //
  // A potential workaround to make FEX work with MDWE is to call mprotect every time we need to write or modify code.
  // Alternatively, FEX could use a memory mirror where one half is mapped as RW and the other is RX.
  //
  // Once MDWE is enabled with the prctl, the feature is sealed and it can /NOT/ be turned off.
  //
  // Status of MDWE is queried through prctl using `PR_GET_MDWE`:
  // -1: The kernel doesn't support MDWE
  // 0: MDWE is supported but disabled
  // >0: MDWE is enabled, hence prohibiting RWX mappings
  int MDWE = ::prctl(PR_GET_MDWE, 0, 0, 0, 0);
  if (MDWE != -1 && MDWE != 0) {
    LogMan::Msg::EFmt("MDWE was set to 0x{:x} which means FEX can't allocate executable memory", MDWE);
  }
#endif

  auto Buffer = fextl::make_shared<CodeBuffer>(Size, NameJITBuffers);

  if (Size > MAX_CODE_SIZE) {
    static std::atomic<int> BigLogCount {0};
    if (BigLogCount.fetch_add(1, std::memory_order_relaxed) < 32) {
      LogMan::Msg::EFmt("[code-buffer-big] rev=code-buffer-big-1 max={}MB granted={}MB", MaxCodeSize() >> 20,
                        Buffer->TotalAllocationSize() >> 20);
    }
  }

#ifdef FEX_IOS_HOST
  /* ml460 (#75): generation bookkeeping. prev_use_count at swap time is the direct pinning
   * measurement: 1 (the manager) + one per thread still holding the outgoing generation. */
  {
    static std::atomic<int> GenLogCount {0};
    long PrevUseCount = 0;
    size_t PrevSize = 0;
    {
      std::scoped_lock lk {LatestMutex};
      if (Latest) {
        PrevUseCount = Latest.use_count();
        PrevSize = Latest->TotalAllocationSize();
      }
      Latest = Buffer;
    }
    const uint64_t Gen = IosCodeBufferGenCounter.fetch_add(1, std::memory_order_release) + 1;
    if (GenLogCount.fetch_add(1, std::memory_order_relaxed) < 64) {
      LogMan::Msg::EFmt("[gen] alloc#{} size=0x{:x} prev_size=0x{:x} prev_use_count={} rev=ml460", Gen, Size, PrevSize, PrevUseCount);
    }
  }
#else
  Latest = Buffer;
#endif

  OnCodeBufferAllocated(Buffer);

  return Buffer;
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::GetLatest() {
#ifdef FEX_IOS_HOST
  /* ml460: the sweeper reads Latest from another thread; reads and the AllocateNew assignment
   * go through LatestMutex. The first allocation happens outside the lock. */
  {
    std::scoped_lock lk {LatestMutex};
    if (Latest) {
      return Latest;
    }
  }
  AllocateNew(INITIAL_CODE_SIZE);
  std::scoped_lock lk {LatestMutex};
  return Latest;
#else
  if (!Latest) {
    AllocateNew(INITIAL_CODE_SIZE);
  }
  return Latest;
#endif
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartLargerCodeBuffer() {
  if (!Latest) {
    // Allocate initial CodeBuffer and return it
    return GetLatest();
  }

  auto NewCodeBufferSize = GetLatest()->TotalAllocationSize();
#ifdef FEX_IOS_HOST
  // ml1052: pool tail carves are fixed-size and never coalesce, so a doubling ladder strands
  // odd-sized carves. A process that fills its first buffer is hot: go straight to the maximum
  // (a refusal halves it down).
  NewCodeBufferSize = MaxCodeSize();
#else
  NewCodeBufferSize = std::min<size_t>(NewCodeBufferSize * 2, MaxCodeSize());
#endif
  return AllocateNew(NewCodeBufferSize);
}

fextl::shared_ptr<CodeBuffer> SharedCodeBufferManager::StartMaximalCodeBuffer() {
  return AllocateNew(MaxCodeSize());
}
} // namespace FEXCore::CPU
