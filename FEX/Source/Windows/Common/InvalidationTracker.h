// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/IntervalList.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <string_view>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::Context {
class Context;
}

namespace FEX::Windows {
/**
 * @brief Handles SMC and regular code invalidation
 */
class InvalidationTracker {
public:
#if !defined(ARCHITECTURE_arm64ec)
  // Guest window (WOW64 module on the iOS host): address namespaces.
  //
  // Every address this class stores, queries and hands to the OS (VirtualQuery,
  // NtQueryVirtualMemory, NtProtectVirtualMemory) is a HOST address: its callers - wow64.dll's
  // BTCpuNotify* callbacks, the exception path's fault address, the image-map notifications - all
  // speak host addresses, and the interval bookkeeping has to line up with what the OS reports.
  // FEXCore keys code invalidation, the lookup caches and executable-range queries on GUEST
  // addresses. So the conversion happens at the calls into FEXCore (InvalidateIntervalInternalLocked,
  // DetectMonoBackpatcherBlock) using GuestBase, and in the WOW64 module's SyscallHandler overrides.
  //
  // GuestBase is 0 when identity mapped, which makes all of this a no-op. The ARM64EC module does
  // not compile any of it.
  InvalidationTracker(FEXCore::Context::Context& CTX, const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads,
                      uint64_t GuestBase = 0);
#else
  InvalidationTracker(FEXCore::Context::Context& CTX, const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads);
#endif
  void HandleMemoryProtectionNotification(uint64_t Address, uint64_t Size, ULONG Prot);
  void HandleProcessExecuteFlagsChange(ULONG Flags);
  void HandleImageMap(std::string_view Name, uint64_t Address);
  struct InvalidateContainingSectionResult {
    uint64_t SectionStart;
    uint64_t SectionSize;
  };
  InvalidateContainingSectionResult InvalidateContainingSection(uint64_t Address, bool Free);
  // NoFilter (madeira [jit-inval]): FEX's own JIT asked for this removal (a block found its code
  // changed), so the "no code here" filter must not skip it.
  void InvalidateAlignedInterval(uint64_t Address, uint64_t Size, bool Free, bool NoFilter = false);
  void ReprotectRWXIntervals(uint64_t Address, uint64_t Size);
  // MADEIRA: if HotPage is given, it is set when the fault hit an already hot page (see EnableHotSMCPages),
  // which is unprotected again but not invalidated.
  bool HandleRWXAccessViolation(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC, uint64_t FaultAddress, bool* HotPage = nullptr);

  // MADEIRA: hot SMC pages. A page taking Threshold write faults within a second (data sharing a page
  // with code, e.g. a counter next to the function updating it) becomes hot: its code is invalidated once
  // more, after which it is never write-protected again, and FEXCore compiles blocks touching it with
  // per-instruction code validation (SyscallHandler::IsHotSMCCodePage). Off until enabled; 0 disables.
  void EnableHotSMCPages(uint32_t Threshold);
  bool IsHotSMCPage(uint64_t Address) const;

  // Unprotects any RWX intervals in the input interval and invalidates code
  // NOTE: CodeInvalidationMutex must be locked when calling this, and if true is returned, kept locked until the write ends.
  bool BeginUntrackedWriteLocked(uint64_t Address, uint64_t Size);

  FEXCore::HLE::ExecutableRangeInfo QueryExecutableRange(uint64_t Address);

  // MADEIRA section-views (ported from MetalSharp patches/fex/0025, AGPL-3.0, Avery Felts):
  // views of one data section share their pages, so a write through one view changes code
  // translated from another with no fault or protection change FEX sees. Wine reports every
  // data-section view with its section handle and offset; views of the same section are
  // grouped (NtCompareObjects), and code compiled from a view whose section has another view
  // mapped checks its bytes before each instruction (IsSharedSectionPage feeds the same
  // per-instruction validation as a hot SMC page). Code translated before the second view
  // appeared is dropped once. NoInvalidate: the caller holds CodeInvalidationMutex shared.
  void HandleDataSectionMap(HANDLE Section, uint64_t Address, uint64_t Size, uint64_t Offset, bool NoInvalidate);
  void HandleDataSectionUnmap(uint64_t Address);
  bool IsSharedSectionPage(uint64_t Address);

private:
#if !defined(ARCHITECTURE_arm64ec)
  // Lazy DEP-off promotion under a guest window: registers [Address's committed region] as
  // executable because DEP is off, called only from QueryExecutableRange, i.e. only when the guest
  // actually tries to execute there. Returns a zero-size interval when the address is not a
  // committed, readable, non-executable page inside the window (a genuine wild branch, which must
  // still fault). NOTE: IntervalsLock must be held exclusively.
  FEXCore::IntervalList<uint64_t>::Interval PromoteDEPRegionLocked(uint64_t Address);
  // The interval-list half of QueryExecutableRange. NOTE: IntervalsLock must be held.
  FEXCore::HLE::ExecutableRangeInfo QueryExecutableRangeLocked(uint64_t Address);
#endif

  void DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC);
  void DisableSMCDetection();
  void InvalidateIntervalInternal(uint64_t Address, uint64_t Size);
  // NOTE: This assumed CodeInvalidationMutex is locked by the caller
  void InvalidateIntervalInternalLocked(uint64_t Address, uint64_t Size);

  // NOTE: If ForWriteLocked is true then this assumes CodeInvalidationMutex is locked by the caller,
  // and any code in the range will be invalidated before protection as RWX, otherwise protects as RX if false.
  bool ProtectRWXIntervalsInternal(uint64_t Address, uint64_t Size, bool ForWriteLocked);

  // Returns the correct protection for trapping (removing write) or untrapping (restoring write) an RWX interval.
  // For DEP-promoted regions (originally non-exec), uses PAGE_READONLY/PAGE_READWRITE instead of PAGE_EXECUTE_READ/PAGE_EXECUTE_READWRITE.
  // NOTE: Must be called with IntervalsLock held.
  ULONG GetTrapProt(uint64_t Address) const;
  ULONG GetUntrapProt(uint64_t Address) const;

  FEXCore::IntervalList<uint64_t> XIntervals;
  FEXCore::IntervalList<uint64_t> RWXIntervals;
  // MADEIRA: a std::shared_mutex that remembers which thread holds it exclusively. Anything that
  // grows or shrinks FEX's own heap under the lock (a log line, an interval insert) comes back on
  // the same thread through the memory notifications (HandleMemoryProtectionNotification,
  // InvalidateAlignedInterval, InvalidateContainingSection); they check HeldByThisThread() and
  // return instead of waiting on a lock that is not recursive.
  class OwnedSharedMutex {
  public:
    void lock() {
      Mutex.lock();
      Owner.store(Self(), std::memory_order_relaxed);
    }
    bool try_lock() {
      if (!Mutex.try_lock()) {
        return false;
      }
      Owner.store(Self(), std::memory_order_relaxed);
      return true;
    }
    void unlock() {
      Owner.store(0, std::memory_order_relaxed);
      Mutex.unlock();
    }
    void lock_shared() {
      Mutex.lock_shared();
    }
    bool try_lock_shared() {
      return Mutex.try_lock_shared();
    }
    void unlock_shared() {
      Mutex.unlock_shared();
    }
    // Only the owning thread can find its own identity here, so relaxed accesses suffice.
    bool HeldByThisThread() const {
      return Owner.load(std::memory_order_relaxed) == Self();
    }
    // The calling thread's identity, as stored in Owner.
    static uint64_t Self();
  private:
    std::shared_mutex Mutex;
    std::atomic<uint64_t> Owner {0};
  };
  OwnedSharedMutex IntervalsLock;
  FEXCore::Context::Context& CTX;
  const std::unordered_map<DWORD, FEXCore::Core::InternalThreadState*>& Threads;
#if !defined(ARCHITECTURE_arm64ec)
  const uint64_t GuestBase {0}; // Host address of guest address 0, or 0 when identity mapped
#endif
  bool SMCDetectionDisabled {false};                    // Protected by IntervalsLock
  bool DEPDisabled {false};                             // Protected by IntervalsLock
  FEXCore::IntervalList<uint64_t> DEPPromotedIntervals; // Protected by IntervalsLock

  struct SectionView {
    uint64_t Base;
    uint64_t Size;
    HANDLE Section;
    uint64_t Group;
    bool Shared;
  };
  std::vector<SectionView> SectionViews;          // Protected by IntervalsLock
  uint64_t NextSectionGroup {1};                  // Protected by IntervalsLock
  std::atomic<uint32_t> SharedSectionViewCount {0}; // fast path for IsSharedSectionPage
  void RecountSharedSectionViewsLocked();

  bool MonoBackpatcherDetectionPending {false};
  uint64_t MonoBase {0};
  uint64_t MonoEnd {0};

  // MADEIRA: hot SMC pages. Fixed-size tables, so nothing allocates under HotPagesLock (an allocation
  // can come back through the memory notifications, which take IntervalsLock and then HotPagesLock).
  // Lock order: IntervalsLock, then HotPagesLock; CodeInvalidationMutex is never taken under it.
  // HotPages is read without the lock: a slot holds a page address or 0.
  // Returns true when this fault made the page hot. NOTE: HotPagesLock must not be held.
  bool CountSMCWriteFault(uint64_t Page);
  // Forgets hot pages in [Begin, End) when their memory is freed.
  void ForgetHotSMCPages(uint64_t Begin, uint64_t End);

  // MADEIRA: the thread currently inside InvalidateIntervalInternalLocked (OwnedSharedMutex::Self(), 0 when
  // none). Only a write owner of CodeInvalidationMutex gets there, so one slot is enough. FEXCore frees and
  // commits its own memory while it invalidates (lookup-cache pages, the call-ret stack, a released code
  // buffer); Wine reports that back as memory notifications on the same thread, which would invalidate again
  // under CodeBufferListLock (not recursive) and wait on themselves. Notifications raised from inside an
  // invalidation are FEX's own memory, never guest code, so they are skipped (see InsideOwnInvalidation).
  std::atomic<uint64_t> InvalidatingThread {0};
  // Logs how many notifications InsideOwnInvalidation skipped since the last report (outside any lock).
  static void ReportOwnInvalidationSkips();
  bool InsideOwnInvalidation() const {
    const auto Thread = InvalidatingThread.load(std::memory_order_relaxed);
    return Thread && Thread == OwnedSharedMutex::Self();
  }

  // MADEIRA: locks CodeInvalidationMutex exclusively unless this thread already write-owns it.
  // Returns whether it locked; the caller unlocks only then.
  bool LockCodeInvalidationUnlessHeld(const char* Path, uint64_t Address);
  static constexpr size_t HotFaultSlots = 64;
  static constexpr size_t MaxHotPages = 64;
  struct HotFaultSlot {
    uint64_t Page;
    uint64_t WindowStart; // CNTVCT_EL0 ticks
    uint32_t Count;
  };
  uint32_t HotPageThreshold {0}; // 0: hot pages disabled
  std::mutex HotPagesLock;
  HotFaultSlot HotFaults[HotFaultSlots] {}; // Protected by HotPagesLock
  std::atomic<uint64_t> HotPages[MaxHotPages] {};
  std::atomic<uint32_t> HotPagesUsed {0}; // Slots of HotPages in use (high-water mark)
};
} // namespace FEX::Windows
