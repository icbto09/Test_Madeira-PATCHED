/*
 * ARM64EC signal handling routines
 *
 * Copyright 1999, 2005, 2023 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef __arm64ec__

#include <stdlib.h>
#include <stdarg.h>
#include <setjmp.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/exception.h"
#include "wine/list.h"
#include "ntdll_misc.h"
#include "unixlib.h"
#include "unwind.h"
#include "wine/debug.h"
#include "ntsyscalls.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);
WINE_DECLARE_DEBUG_CHANNEL(relay);

struct xcontext
{
    ARM64EC_NT_CONTEXT c;
    CONTEXT_EX c_ex;
    char xs[sizeof(XSTATE) + 64];
};

C_ASSERT( sizeof(struct xcontext) == 0x670 );

/* xtajit64.dll functions */
static void     (WINAPI *pBTCpu64FlushInstructionCache)(const void*,SIZE_T);
static BOOLEAN  (WINAPI *pBTCpu64IsProcessorFeaturePresent)(UINT);
/* iOS-only xtajit64 export — see BTInterface.h. On non-iOS hosts the
 * export doesn't exist and the GET_PTR call below returns NULL; the
 * pointer-null check around the unix-call invocation skips it. No
 * #ifdef guard because PE-side builds don't have an iOS-specific
 * macro (target is arm64ec-windows in all cases). */
static void     (WINAPI *pBTCpu64IosAddAliasMapping)(unsigned long long, unsigned long long, unsigned long long);
static void     (WINAPI *pBTCpu64IosSetMonoBridge)(unsigned long long);  /* ml648 */
/* ml618: iOS-only. MUST be obtained via GET_PTR (arm64ec_redirect_ptr), never via a
 * raw base+RVA lookup — see the registration comment below. */
static unsigned int (WINAPI *pBTCpu64IosReleaseThreadHolds)(void*, unsigned long long*, unsigned int*, unsigned int*);
static void     (WINAPI *pBTCpu64NotifyMemoryDirty)(void*,SIZE_T);
static unsigned int (WINAPI *pBTCpu64IosDebugRegs)(unsigned int,ULONG64*);  /* madeira [dr-pass]; iOS-only */
static unsigned int (WINAPI *pBTCpu64IosGuestContext)(void*,ARM64_NT_CONTEXT*,unsigned int);  /* madeira [getctx-guest]; iOS-only */
static unsigned int (WINAPI *pBTCpu64IosRaisePfAf)(ULONG64,ULONG64);  /* madeira [pfaf-int3]; iOS-only */
static unsigned int (WINAPI *pBTCpu64IosCrashMailerData)(unsigned int,void*,unsigned int);  /* madeira [crashmailer-dump]; iOS-only */
static void     (WINAPI *pBTCpu64NotifyReadFile)(HANDLE,void*,SIZE_T,BOOL,NTSTATUS);
static void     (WINAPI *pBeginSimulation)(void);
static void     (WINAPI *pFlushInstructionCacheHeavy)(const void*,SIZE_T);
static NTSTATUS (WINAPI *pNotifyMapViewOfSection)(void*,void*,void*,SIZE_T,ULONG,ULONG);
static void     (WINAPI *pNotifyImageMap)(void*);
static void     (WINAPI *pNotifyMemoryAlloc)(void*,SIZE_T,ULONG,ULONG,BOOL,NTSTATUS);
static void     (WINAPI *pNotifyMemoryFree)(void*,SIZE_T,ULONG,BOOL,NTSTATUS);
static void     (WINAPI *pNotifyMemoryProtect)(void*,SIZE_T,ULONG,BOOL,NTSTATUS);
static void     (WINAPI *pNotifyUnmapViewOfSection)(void*,BOOL,NTSTATUS);
static NTSTATUS (WINAPI *pProcessInit)(void);
static void     (WINAPI *pProcessTerm)(HANDLE,BOOL,NTSTATUS);
static void     (WINAPI *pResetToConsistentState)(EXCEPTION_RECORD*,CONTEXT*,ARM64_NT_CONTEXT*);
static NTSTATUS (WINAPI *pThreadInit)(void);
static void     (WINAPI *pThreadTerm)(HANDLE,LONG);
static void     (WINAPI *pUpdateProcessorInformation)(SYSTEM_CPU_INFORMATION*);

/* store full xstate before the config is fully initialized */
static BOOLEAN emulated_processor_features[PROCESSOR_FEATURE_MAX] = { [PF_AVX_INSTRUCTIONS_AVAILABLE] = TRUE };

static BYTE KiUserExceptionDispatcher_orig[16]; /* to detect patching */
extern void KiUserExceptionDispatcher_thunk(void) asm("EXP+#KiUserExceptionDispatcher");

static inline CHPE_V2_CPU_AREA_INFO *get_arm64ec_cpu_area(void)
{
    return NtCurrentTeb()->ChpeV2CpuAreaInfo;
}

/* iOS-Madeira ml617: THE GUEST-STACK WINDOW FOR ONE UNWIND.
 *
 * ml616 fabricated 24,576 unwind frames and then terminated the process with
 * exit code 0xdaa1f848 — which is not a status at all, it is the low half of
 * 0x71daa1f848, a stack address from the very frame being walked. The real
 * exception (an execute AV at 0x7e8946a680, private RW heap) was destroyed and
 * replaced by garbage.
 *
 * Root cause is the third fallback below: it accepts ANY aligned, committed,
 * writable private page as a valid frame. Thread 020c's stack ended at
 * 0x71daa20000 and the walk happily accepted 0x71daa20008 and kept going.
 *
 * So bound the walk by the allocation the ORIGINAL guest RSP belongs to:
 *   - use AllocationBase and enumerate every contiguous region of that same
 *     allocation, because guard/committed regions carry different protections
 *     and a single RegionSize would cut the stack short;
 *   - the TEB stack is NOT usable for this — on this port Tib describes the
 *     NATIVE pthread stack, not the guest x64 stack (task #34).
 * Zeroed window = "not established", and the old permissive behaviour stands,
 * so no path that never sets a window can regress. */
struct ec_stack_window
{
    ULONG_PTR lo, hi;      /* validated guest-stack allocation */
    ULONG_PTR emu_lo, emu_hi; /* emulator stack: a legitimate transition target */
    ULONG_PTR last_frame;  /* monotonic baseline within the current segment */
    ULONG_PTR last_pc;
    ULONG     steps, budget;
    ULONG     repeats;
    BOOL      on_emu;      /* which segment the baseline refers to */
};
/* iOS-Madeira ml848: NOT a thread-local. THE FIX FOR THE UE5 THREAD-EXIT FATAL.
 *
 * ml617 declared this window as static TLS. An ntdll with static TLS is a
 * design error on this port: the loader assigns TLS slots only to modules it
 * maps through the normal path, never to ntdll itself, so ntdll's `_tls_index`
 * stayed at its zero initial value and `ThreadLocalStoragePointer[0]` -- THE
 * GAME EXECUTABLE'S OWN THREAD-LOCAL BLOCK -- was where this struct actually
 * lived. Every exception dispatch zeroed and then filled it on top of the
 * exe's thread-locals at +0x20..+0x60: `emu_hi` (the FEX emulator stack top)
 * landed on a UE5 thread-local whose destructor frees its first word, and the
 * engine allocator refused our stack top with "FMallocBinned2 Attempt to free
 * an unrecognized block" at every thread exit. Six probe rounds, a page write
 * watch and offline disassembly of the executable converged on the pool copy
 * of ec_stack_window_begin as the writer.
 *
 * The TEB has no contiguous 64 free bytes (Instrumentation[1,6,7,8,9,10] are
 * taken), and nothing may allocate in a fault path. What every EC thread does
 * own is the CHPE CPU-area page: thread_ios.c places the 0x58-byte area at the
 * base of a committed 0x40000 region with the x64 context inline at +0x50, and
 * FEX then replaces that region's stack with its own, leaving the bytes after
 * the context unused. The state lives there, aligned, never allocated, never
 * aliased. A thread with no CPU area (not an EC thread) gets a static fallback,
 * i.e. the pre-ml617 permissive behaviour. */
struct ec_thread_state
{
    struct ec_stack_window win;
    int root_used;          /* ml633: terminal root frame accepted once per walk */
    /* madeira [pfaf-keep]: x86 PF/AF of the context last passed to NtContinue / NtSetContextThread(self) */
    ULONG_PTR pfaf_rip, pfaf_rsp;
    ULONG pfaf_bits, pfaf_valid;
    /* madeira [df-ctx]: x86 DF of the context last passed to NtContinue / NtSetContextThread(self) */
    ULONG_PTR df_rip, df_rsp;
    ULONG df_bits, df_valid;
};
static struct ec_thread_state ec_state_fallback;
static inline struct ec_thread_state *ec_state( void )
{
    CHPE_V2_CPU_AREA_INFO *area = get_arm64ec_cpu_area();
    ULONG_PTR p;
    if (!area) return &ec_state_fallback;
    /* Wine 11.22: dispatch_emulation() writes a whole struct xcontext (context,
     * CONTEXT_EX and XSTATE, 0x670 bytes) at ContextAmd64, so the free bytes
     * start after that, not after the bare context. */
    p = (ULONG_PTR)area + FIELD_OFFSET( CHPE_V2_CPU_AREA_INFO, EmulatorDataInline ) + sizeof(struct xcontext);
    p = (p + 15) & ~(ULONG_PTR)15;
    return (struct ec_thread_state *)p;
}
#define ec_win          (ec_state()->win)
#define ml633_root_used (ec_state()->root_used)

static void ec_stack_window_begin( ULONG_PTR rsp )
{
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T got;
    ULONG_PTR base, probe, hi;
    CHPE_V2_CPU_AREA_INFO *area;

    memset( &ec_win, 0, sizeof(ec_win) );
    if (!rsp) return;
    if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)rsp, MemoryBasicInformation,
                              &mbi, sizeof(mbi), &got )) return;
    if (mbi.State != MEM_COMMIT) return;

    base = (ULONG_PTR)mbi.AllocationBase;
    if (!base) return;

    /* Walk forward while the region still belongs to the same allocation. */
    hi = base;
    for (probe = base; ; )
    {
        if (NtQueryVirtualMemory( NtCurrentProcess(), (void *)probe, MemoryBasicInformation,
                                  &mbi, sizeof(mbi), &got )) break;
        if ((ULONG_PTR)mbi.AllocationBase != base) break;
        hi = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        probe = hi;
        if (hi <= base) break;   /* paranoia: never loop on a zero-size region */
    }
    if (hi <= base) return;

    ec_win.lo = base;
    ec_win.hi = hi;
    area = get_arm64ec_cpu_area();
    if (area)
    {
        ec_win.emu_lo = area->EmulatorStackLimit;
        ec_win.emu_hi = area->EmulatorStackBase;
    }
    /* Budget proportional to the real range (one frame per 16 bytes is already
     * generous for AAPCS64), with an absolute ceiling so a huge stack cannot buy
     * an unbounded walk. Repeated (pc,frame) pairs are caught separately — a
     * non-advancing walk is corrupt no matter how much budget remains. */
    ec_win.budget = (ULONG)min( (hi - base) / 16, 65536 );
    if (ec_win.budget < 256) ec_win.budget = 256;
    ec_win.last_frame = 0;
    ec_win.on_emu = FALSE;
}

static inline BOOL is_valid_arm64ec_frame( ULONG_PTR frame )
{
    if (frame & (sizeof(void*) - 1)) return FALSE;

    /* ml617: once a window is established it is authoritative — the permissive
     * committed-RW fallback below is exactly what let the walk run away. */
    if (ec_win.hi)
    {
        if (frame >= ec_win.lo && frame < ec_win.hi) return TRUE;
        if (ec_win.emu_hi && frame >= ec_win.emu_lo && frame <= ec_win.emu_hi) return TRUE;
        return FALSE;
    }

    if (is_valid_frame( frame )) return TRUE;
    /* ml382: NULL-safe — this runs during exception dispatch, where a second
     * fault is far worse than a missed range check (see the enter/leave
     * _syscall_callback comment below for why the CPU area can be NULL here). */
    {
        CHPE_V2_CPU_AREA_INFO *area = get_arm64ec_cpu_area();
        if (area && frame >= area->EmulatorStackLimit &&
            frame <= area->EmulatorStackBase) return TRUE;
    }
    /* iOS-Madeira task#34: EC threads here run on THREE stacks — Tib holds
     * the NATIVE pthread stack, the CpuArea holds the emulator stack, and
     * the guest x64 frames live on the GUEST stack that neither range
     * covers (ml65: frame 0x7ecafb0008 vs Tib 0x153c88000-0x153d80000 →
     * "unable to dispatch exception" killed steamwebhelper; same failure
     * class as the old FEX-2607 bootstrapper fault). Windows proper has
     * Tib = the x64 stack, our port cannot (native code needs the pthread
     * stack there). Fallback: accept a frame that points into committed
     * writable private memory — i.e. SOME plausible stack. */
    {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T got;
        if (!NtQueryVirtualMemory( NtCurrentProcess(), (void *)frame, MemoryBasicInformation,
                                   &mbi, sizeof(mbi), &got ) &&
            mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)))
        {
            static LONG gsf_n;
            if (gsf_n < 20 && InterlockedIncrement( &gsf_n ) <= 20)
                ERR( "[guest-frame] accepting frame %I64x outside Tib/emulator stacks (committed RW region %p+%Ix)\n",
                     (ULONG64)frame, mbi.BaseAddress, mbi.RegionSize );
            return TRUE;
        }
    }
    return FALSE;
}

/* ml617: per-step unwind guard. Returns NULL to continue, else the reason.
 *
 * Monotonic progress is required WITHIN a segment only; a validated transition
 * between the guest stack and the emulator stack legitimately moves the frame
 * pointer anywhere, so the baseline is reset there — but only for a transition
 * we recognise, so a corrupt frame cannot escape the check by pretending to
 * switch stacks. */
static const char *ec_stack_window_step( ULONG_PTR frame, ULONG_PTR pc )
{
    BOOL on_emu;

    if (!ec_win.hi) return NULL;   /* no window established: legacy behaviour */

    if (++ec_win.steps > ec_win.budget) return "budget exceeded";

    if (frame == ec_win.last_frame && pc == ec_win.last_pc)
    {
        if (++ec_win.repeats >= 4) return "no progress (repeated pc/frame)";
        return NULL;
    }
    ec_win.repeats = 0;

    on_emu = (ec_win.emu_hi && frame >= ec_win.emu_lo && frame <= ec_win.emu_hi);
    if (on_emu != ec_win.on_emu)
    {
        /* Recognised stack transition: re-baseline, do not compare across it. */
        ec_win.on_emu = on_emu;
        ec_win.last_frame = frame;
        ec_win.last_pc = pc;
        return NULL;
    }
    /* iOS-Madeira ml627: `<=` WAS A FALSE POSITIVE. `<` IS THE CORRECT TEST.
     *
     * Unwinding walks UP the stack, so a frame pointer must never move BACKWARDS
     * -- but it may legitimately stay EQUAL across consecutive steps while
     * ControlPc changes (several unwind steps can resolve within one frame). The
     * genuinely-stuck case is already covered above by the identical
     * (frame, pc) repeat counter, so `<=` bought nothing and cost correctness.
     *
     * It fired on ULTRAKILL/Mono's thread-naming exception: Mono raises
     * EXCEPTION_WINE_NAME_THREAD (0x406D1388) from mono_native_thread_set_name and
     * expects to resume at `add rsp,0x48; ret`. This guard aborted that unwind at
     * steps=3 with the frame merely equal, flagged the stack invalid, and left the
     * handler/unwind state inconsistent -- after which 0x406D1388+8 was read as a
     * pointer, degrading into 0xC000000D, a 256-deep redelivery storm and a stack
     * overflow. The guard was mine (ml617) and it was the bug. */
    if (ec_win.last_frame && frame < ec_win.last_frame)
        return "frame moved backwards";

    if (ec_win.last_frame && frame == ec_win.last_frame)
    {
        /* Confirmation that this case is real and now allowed. Capped: this runs
         * per unwind step, and formatting in an exception path is what killed
         * ml620. One short line, bounded by construction. */
        static int ml627_same_frame;
        if (ml627_same_frame < 16)
            ERR( "[unwind-guard] ml627 same-frame step #%d frame=%p pc %p -> %p (ALLOWED, was a false stop)\n",
                 ++ml627_same_frame, (void *)frame, (void *)ec_win.last_pc, (void *)pc );
    }

    ec_win.last_frame = frame;
    ec_win.last_pc = pc;
    return NULL;
}

/* iOS-Madeira ml382: the CPU area can legitimately be NULL on this port.
 *
 * get_arm64ec_cpu_area() is NtCurrentTeb()->ChpeV2CpuAreaInfo, and
 * init_thread_stack deliberately does NOT set it for the native-aarch64
 * session — logged three times in the ml382 run:
 *   "iOS arm64ec: NOT setting cpu_area (owner machine=0xaa64 session is_arm64ec=0)"
 * But ARM64EC ntdll code still executes on those threads (every SYSCALL_API
 * wrapper here calls enter/leave_syscall_callback), so the unguarded
 * dereference is a NULL store.
 *
 * That is exactly what killed the SESSION process in ml380 AND ml382 — and
 * killing the session kills the whole app, which is why it capped both runs.
 * Decoded from our own ntdll at the faulting RVA 0x582e4:
 *     ldr  x8, [x18, #0x1788]     ; x8 = TEB->ChpeV2CpuAreaInfo  == 0
 *     strb wzr, [x8, #0x1]        ; InSyscallCallback = 0  -> FAULTS at 0x1
 * matching the log's `addr=0x1 insn=3900051f` and
 * `CPUArea(teb+0x1788)=0x0(ok=1)`.
 *
 * With no CPU area the thread is not running emulated code, so the
 * re-entrancy flag is vacuous: report "not already in a callback" and skip the
 * bookkeeping. Deliberately returning TRUE rather than FALSE — FALSE would
 * route callers to the raw syscall and skip pNotifyMemoryAlloc, and stale FEX
 * memory notifications are what caused the ml36 NOEXEC wall. Proceeding keeps
 * behaviour identical to every thread that does have a CPU area. */
/* Set when the emulator module gets DLL_PROCESS_DETACH at process exit: its
 * DllMain runs its C++ static destructors, so FEX's context is gone, and the
 * DLLs detached after it (ucrtbase, ntdll's heap) still free memory. A free
 * notified to FEX then called through the destroyed context's vtable (a
 * null read at +0xf0 in InvalidateAlignedInterval) when Rocket League quit.
 * From then on the hooks below make the plain syscalls. */
static BOOL emulator_detached;

void arm64ec_emulator_detach(void)
{
    emulator_detached = TRUE;
}

static inline BOOL enter_syscall_callback(void)
{
    CHPE_V2_CPU_AREA_INFO *area = get_arm64ec_cpu_area();

    if (emulator_detached) return FALSE;
    if (!area) return TRUE;
    if (area->InSyscallCallback) return FALSE;
    area->InSyscallCallback = 1;
    return TRUE;
}

static inline void leave_syscall_callback(void)
{
    CHPE_V2_CPU_AREA_INFO *cpu_area = get_arm64ec_cpu_area();
    CONTEXT ctx;

    if (!cpu_area) return;   /* iOS-Madeira: a thread with no CPU area yet */
    cpu_area->InSyscallCallback = 0;

    if (!cpu_area->InSimulation && cpu_area->SuspendDoorbell && *cpu_area->SuspendDoorbell)
    {
        RtlCaptureContext( &ctx );
        if (*cpu_area->SuspendDoorbell) NtContinue( &ctx, FALSE );
    }
}

/**********************************************************************
 *           create_cross_process_work_list
 */
static NTSTATUS create_cross_process_work_list( CHPEV2_PROCESS_INFO *info )
{
    SIZE_T map_size = 0x4000;
    LARGE_INTEGER size;
    NTSTATUS status;
    HANDLE section;
    CROSS_PROCESS_WORK_LIST *list = NULL;
    CROSS_PROCESS_WORK_ENTRY *end;
    UINT i;

    size.QuadPart = map_size;
    status = NtCreateSection( &section, SECTION_ALL_ACCESS, NULL, &size, PAGE_READWRITE, SEC_COMMIT, 0 );
    if (status) return status;
    status = NtMapViewOfSection( section, GetCurrentProcess(), (void **)&list, 0, 0, NULL,
                                 &map_size, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE );
    if (status)
    {
        NtClose( section );
        return status;
    }

    end = (CROSS_PROCESS_WORK_ENTRY *)((char *)list + map_size);
    for (i = 0; list->entries + i + 1 <= end; i++)
        RtlWow64PushCrossProcessWorkOntoFreeList( &list->free_list, &list->entries[i] );

    info->SectionHandle = section;
    info->CrossProcessWorkList = list;
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           send_cross_process_notification
 */
static BOOL send_cross_process_notification( HANDLE process, UINT id, const void *addr, SIZE_T size,
                                             int nb_args, ... )
{
    CROSS_PROCESS_WORK_LIST *list;
    CROSS_PROCESS_WORK_ENTRY *entry;
    void *unused;
    HANDLE section;
    va_list args;
    int i;

    RtlOpenCrossProcessEmulatorWorkConnection( process, &section, (void **)&list );
    if (!list) return FALSE;
    if ((entry = RtlWow64PopCrossProcessWorkFromFreeList( &list->free_list )))
    {
        entry->id = id;
        entry->addr = (ULONG_PTR)addr;
        entry->size = size;
        if (nb_args)
        {
            va_start( args, nb_args );
            for (i = 0; i < nb_args; i++) entry->args[i] = va_arg( args, int );
            va_end( args );
        }
        RtlWow64PushCrossProcessWorkOntoWorkList( &list->work_list, entry, &unused );
    }
    NtUnmapViewOfSection( GetCurrentProcess(), list );
    NtClose( section );
    return TRUE;
}


/* iOS: PE .text sections are non-executable at their unix VA; an executable
 * alias lives in the JIT pool. arm64ec_redirect_ptr resolves to unix .text
 * addresses, so on iOS every return path must be translated to the JIT alias.
 *
 * `p_ios_jit_translate_addr` holds the address of unix-side
 * ios_jit_translate_addr (a native ARM64 function), set by unix-side
 * load_ntdll_functions. NULL on non-iOS / pre-init.
 *
 * `xlate_ios_jit` is a naked PE-side thunk that does `br x16` to the unix
 * function — bypassing arm64x_check_call which would otherwise misroute a
 * non-EC target through x86 emulation. Same trick as __wine_unix_call_arm64ec.
 *
 * The pointer is exported via ntdll.spec so unix-side can install the address. */
void *p_ios_jit_translate_addr = NULL;

void *__attribute__((naked)) xlate_ios_jit( void *ptr )
{
    asm( ".seh_proc \"#xlate_ios_jit\"\n\t"
         ".seh_endprologue\n\t"
         "cbz x0, 1f\n\t"                                 /* NULL → return NULL */
         "adrp x16, p_ios_jit_translate_addr\n\t"
         "ldr x16, [x16, #:lo12:p_ios_jit_translate_addr]\n\t"
         "cbz x16, 1f\n\t"                                /* fn-ptr unset → identity */
         "br x16\n"                                       /* tail-call unix fn */
         "1: ret\n\t"
         ".seh_endproc" );
}

/* iOS: the reverse mapping (JIT-pool alias → original PE VA). Exception
 * contexts capture POOL VAs (that's where code physically executes), but
 * function tables / unwind info are registered for PE VAs — so unwinding a
 * pool pc finds no tables, the leaf-frame fallback cycles, and SEH handlers
 * are never found (one boot-time RPC raise spun 1.2e9 unwind steps on a
 * pegged core; with the no-progress guard it became an unhandled-exception
 * process death). virtual_unwind reverse-translates each step's pc through
 * this hook so the walk runs in PE space and handlers resolve. */
void *p_ios_jit_reverse_translate_addr = NULL;

void *__attribute__((naked)) xlate_ios_jit_rev( void *ptr )
{
    asm( ".seh_proc \"#xlate_ios_jit_rev\"\n\t"
         ".seh_endprologue\n\t"
         "cbz x0, 1f\n\t"                                 /* NULL → return NULL */
         "adrp x16, p_ios_jit_reverse_translate_addr\n\t"
         "ldr x16, [x16, #:lo12:p_ios_jit_reverse_translate_addr]\n\t"
         "cbz x16, 1f\n\t"                                /* fn-ptr unset → identity */
         "br x16\n"                                       /* tail-call unix fn */
         "1: ret\n\t"
         ".seh_endproc" );
}


void *arm64ec_redirect_ptr( HMODULE module, void *ptr, const IMAGE_ARM64EC_METADATA *metadata )
{
    const IMAGE_ARM64EC_REDIRECTION_ENTRY *map = get_rva( module, metadata->RedirectionMetadata );
    int min = 0, max = metadata->RedirectionMetadataCount - 1;
    ULONG_PTR rva = (ULONG_PTR)ptr - (ULONG_PTR)module;

    if (!ptr) return NULL;
    while (min <= max)
    {
        int pos = (min + max) / 2;
        if (map[pos].Source == rva)
        {
            /* iOS-Madeira 2026-07-10 (Steam S3 run 7): validate the Destination
             * RVA before trusting it. A corrupt entry once produced
             * module+0xC483974 (far past SizeOfImage); xlate_ios_jit then
             * matched that VA against ANOTHER process's module mapping and a
             * poison pool pointer landed in kernelbase's IAT — the
             * steamerrorreporter64 2000-fault storm. Out-of-image → treat as
             * no-entry and let the thunk-decode / runtime check_call resolve. */
            const IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );
            if (!nt || map[pos].Destination < nt->OptionalHeader.SizeOfImage)
                return xlate_ios_jit( get_rva( module, map[pos].Destination ) );
            break;
        }
        if (map[pos].Source < rva) min = pos + 1;
        else max = pos - 1;
    }

    /* No entry in the redirection table — but the export may still be a
     * .hexpthk x86_64 thunk in one of two forms:
     *   (a) Forwarder: `jmp qword ptr [rip+offset]` (ff 25 NN NN NN NN) —
     *       loads target from import slot. Used for cross-module forwards
     *       (e.g. kernel32!lstrcmpW → kernelbase!lstrcmpW).
     *   (b) Fast-forward: `mov rsp,rax; mov [rax+0x20],rbx; push rbp;
     *       pop rbp; jmp arm_code` (14 bytes: 48 8b c4 48 89 58 20 55 5d
     *       e9 NN NN NN NN) — the ARM64 target is at thunk+14+offset
     *       within the same module. arm64x_check_call recognizes this at
     *       runtime; we replicate the decode here so direct callers don't
     *       have to dispatch through it. */
    {
        const unsigned char *bytes = ptr;
        /* (b) fast-forward sequence */
        if (bytes[0] == 0x48 && bytes[1] == 0x8b && bytes[2] == 0xc4 &&
            bytes[3] == 0x48 && bytes[4] == 0x89 && bytes[5] == 0x58 &&
            bytes[6] == 0x20 && bytes[7] == 0x55 && bytes[8] == 0x5d &&
            bytes[9] == 0xe9)
        {
            LONG off = *(const LONG *)&bytes[10];
            void *target = (char *)ptr + 14 + off;
            return xlate_ios_jit( target );
        }
        /* Madeira [hotpatch-thunks]: step over the 8-byte hotpatch prologue
         * (48 8d a4 24 00 00 00 00) the loader puts before forwarder jumps when
         * env MADEIRA_ARM64X_HOTPATCH_THUNKS = 1. */
        if (bytes[0] == 0x48 && bytes[1] == 0x8d && bytes[2] == 0xa4 && bytes[3] == 0x24 &&
            !bytes[4] && !bytes[5] && !bytes[6] && !bytes[7] && bytes[8] == 0xff && bytes[9] == 0x25)
            bytes += 8;
        /* (a) simple forwarder thunk */
        if (bytes[0] == 0xff && bytes[1] == 0x25)
        {
            LONG off = *(const LONG *)&bytes[2];
            void **imp = (void **)(bytes + 6 + off);
            void *target = *imp;
            /* Only follow the forwarder if the IAT slot is actually bound to
             * a usable pointer. At import-binding time the target module's
             * IAT may still hold raw IBN RVAs (small 32-bit values) — chasing
             * those returns a low integer that gets stored as a "function
             * pointer" and crashes later when called. Require the value to
             * look like a real address (above the lowest module DllBase).
             * If it doesn't, fall through to `return ptr;` so the IAT entry
             * gets the thunk address, and runtime arm64x_check_call handles
             * the (now-bound) forwarder on first call. */
            if (target && target != ptr && (ULONG_PTR)target >= 0x10000000)
            {
                /* Find the module containing the target and redirect within
                 * it. If the target is also a thunk, this recurses. */
                LDR_DATA_TABLE_ENTRY *mod_entry;
                LIST_ENTRY *list = &RtlGetCurrentPeb()->LdrData->InLoadOrderModuleList;
                LIST_ENTRY *entry;
                for (entry = list->Flink; entry != list; entry = entry->Flink)
                {
                    mod_entry = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
                    if ((char *)target >= (char *)mod_entry->DllBase &&
                        (char *)target < (char *)mod_entry->DllBase + mod_entry->SizeOfImage)
                    {
                        const IMAGE_ARM64EC_METADATA *target_metadata =
                            arm64ec_get_module_metadata( mod_entry->DllBase );
                        /* Recursive call already applies xlate_ios_jit at its
                         * own return paths; passing through unchanged is correct. */
                        if (target_metadata)
                            return arm64ec_redirect_ptr( mod_entry->DllBase, target, target_metadata );
                        return xlate_ios_jit( target );
                    }
                }
                /* NOTE (2026-07-10): do NOT reject targets missing from the
                 * module list here — during early loader phases (hybrid
                 * metadata patching) legit targets live in modules not yet
                 * linked in, and returning `ptr` instead zeroed ucrtbase's
                 * dispatch_call_no_redirect slot (blr x16=0 at boot). */
                return xlate_ios_jit( target );
            }
        }
    }
    return xlate_ios_jit( ptr );
}

static void arm64x_check_call(void);

/*******************************************************************
 *         arm64ec_process_init
 */
/*******************************************************************
 *         arm64ec_process_init_dispatchers
 *
 * Phase 1 of arm64ec init: set up dispatcher pointers and FEX function
 * pointers. Must run BEFORE the PE-side DllMain dependency walk so that
 * exception dispatch (KiUserExceptionDispatcher uses
 * __os_arm64x_dispatch_call_no_redirect) and dispatch_emulation
 * (uses pBeginSimulation) work during DllMain.
 *
 * Note: pProcessInit is captured here but NOT called — that's deferred
 * to phase 2 (arm64ec_process_init_finish), which runs AFTER DllMains
 * because FEX's CRT init requires ucrtbase to be initialized.
 */
/* rtcs-diag (Battle.net / Overwatch 2 test builds): diagnostic only, no behaviour change.
 * In the Overwatch process pResetToConsistentState was NULL ("[rtcs] pre ... rtcs=0000000000000000"), so a
 * brk #0 from FEX's guest-SIGTRAP stub reached the guest handler with the host rip and sp. This logs what
 * the CPU module's ResetToConsistentState export looked like at init and whether the pointer is still the
 * same at the first exceptions. MADEIRA_RTCS_DIAG=0 turns it off (read once; any other value leaves it on). */
static void *rtcs_diag_raw, *rtcs_diag_init;
static LONG rtcs_diag_hits;

static BOOL rtcs_diag_enabled( void )
{
    static LONG mode;   /* 0 not yet, 1 off, 2 on */

    if (!mode)
    {
        UNICODE_STRING name, value;
        WCHAR buffer[2];

        RtlInitUnicodeString( &name, L"MADEIRA_RTCS_DIAG" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        mode = (!RtlQueryEnvironmentVariable_U( NULL, &name, &value ) &&
                value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
    }
    return mode == 2;
}

/* rtcs-diag2 (bnettest22): the bnettest21 log showed pointer, stored-at-init and export all reading 0 at
 * the exception although init had set them (same thread). So either this .data page was cleared after init,
 * or the exception runs in a DIFFERENT ntdll instance than the one init wrote. Log, at init and at the
 * exception: where the static lives, which code instance is running (this function's address), the
 * arm64x_check_call address init stashed in PEB.WerRegistrationData versus this instance's own, and an
 * FNV-1a hash of the 4 KB page holding the static. Same off switch: MADEIRA_RTCS_DIAG=0. */
/* returns the FNV-1a hash; *nz = non-zero bytes in the page (a page cleared after init shows only the few
 * bytes the diag's own counters wrote since, instead of hundreds) */
static unsigned int rtcs_diag_page_fnv( const void *p, unsigned int *nz )
{
    const unsigned char *b = (const unsigned char *)((ULONG_PTR)p & ~(ULONG_PTR)0xfff);
    unsigned int h = 2166136261u, i;

    *nz = 0;
    for (i = 0; i < 0x1000; i++) { h = (h ^ b[i]) * 16777619u; *nz += b[i] != 0; }
    return h;
}

static void rtcs_diag_where( const char *when )
{
    void *stashed = RtlGetCurrentPeb()->WerRegistrationData;
    void *mine = (void *)arm64x_check_call;
    unsigned int nz, fnv = rtcs_diag_page_fnv( &pResetToConsistentState, &nz );

    ERR( "[rtcs-where] %s: static=%p value=%p code=%p check_call peb=%p this-copy=%p (%s) page-fnv=%08x page-nonzero-bytes=%u rev=rtcs-diag2\n",
         when, (void *)&pResetToConsistentState, (void *)pResetToConsistentState, (void *)rtcs_diag_where,
         stashed, mine, stashed == mine ? "same ntdll instance as init" : "DIFFERENT ntdll instance from init",
         fnv, nz );
}

NTSTATUS arm64ec_process_init_dispatchers( HMODULE module )
{
    CHPEV2_PROCESS_INFO *info = (CHPEV2_PROCESS_INFO *)(RtlGetCurrentPeb() + 1);
    const IMAGE_ARM64EC_METADATA *metadata = arm64ec_get_module_metadata( module );

    /* Stash arm64x_check_call's address in PEB.WerRegistrationData (unused
     * on iOS) BEFORE pProcessInit runs, so ntdll-unix's SEGV handler can
     * dump arm64x_check_call's first instructions if FEX's ProcessInit
     * crashes inside arm64x_check_call. */
    RtlGetCurrentPeb()->WerRegistrationData = arm64x_check_call;

    __os_arm64x_dispatch_call_no_redirect = RtlFindExportedRoutineByName( module, "ExitToX64" );
    __os_arm64x_dispatch_fptr = RtlFindExportedRoutineByName( module, "DispatchJump" );
    __os_arm64x_dispatch_ret = RtlFindExportedRoutineByName( module, "RetToEntryThunk" );

    /* The dispatcher globals were 0 when EVERY ARM64EC module's
     * arm64ec_update_hybrid_metadata ran (because the globals only get set
     * here, AFTER xtajit64 finishes loading — but kernel32/ucrtbase/kernelbase
     * are loaded BEFORE xtajit64 finishes). So every loaded ARM64EC module's
     * hybrid pointer slots currently hold 0. Without this re-patch,
     * kernel32's exit thunks would `blr x16` with x16=0 → branch to NULL.
     *
     * Walk loaded modules and re-patch their hybrid metadata. SKIP ntdll
     * itself: re-running arm64ec_update_hybrid_metadata on ntdll's .data
     * triggers the iOS NtProtect IAT-sync path (in our virtual_ios.c) which
     * over-aggressively rewrites one pointer in ntdll's .data to a JIT-pool
     * address, breaking ntdll's own internals immediately after. ntdll's
     * slots happen to already be functional (the EC dispatcher slots that
     * matter for ntdll are written elsewhere during ntdll's special
     * loader-init path, not via arm64ec_update_hybrid_metadata). */
    {
        LIST_ENTRY *list = &RtlGetCurrentPeb()->LdrData->InLoadOrderModuleList;
        LIST_ENTRY *entry;
        void *self_module = (void *)NtCurrentTeb()->Peb->ImageBaseAddress;  /* unused but harmless */
        (void)self_module;
        void *ntdll_base = (void *)RtlGetCurrentPeb();
        (void)ntdll_base;
        for (entry = list->Flink; entry != list; entry = entry->Flink)
        {
            LDR_DATA_TABLE_ENTRY *mod_entry =
                CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
            const IMAGE_ARM64EC_METADATA *mod_metadata =
                arm64ec_get_module_metadata( mod_entry->DllBase );
            if (!mod_metadata) continue;
            /* Skip ntdll — re-patch breaks it via iOS NtProtect-sync side
             * effects, and ntdll doesn't need it anyway. Match by base name. */
            if (mod_entry->BaseDllName.Buffer &&
                !wcscmp( mod_entry->BaseDllName.Buffer, L"ntdll.dll" ))
            {
                ERR( "arm64ec_process_init_dispatchers: SKIP ntdll re-patch\n" );
                continue;
            }
            ERR( "arm64ec_process_init_dispatchers: re-patching %s metadata\n",
                 debugstr_w(mod_entry->BaseDllName.Buffer) );
            arm64ec_update_hybrid_metadata( mod_entry->DllBase,
                                            RtlImageNtHeader( mod_entry->DllBase ),
                                            (IMAGE_ARM64EC_METADATA *)mod_metadata );
        }
    }

    /* ml755: print xtajit64's VA band selector log, which nothing else can.
     *
     * ios_fex_band_select() runs during rpmalloc init, before the ARM64EC TEB
     * exists, so it cannot call any logging API -- it appends to a static byte
     * buffer instead. ml751 flushed that buffer from FEX's own Module.cpp after
     * the [build-id] line, which works only when FEX gets far enough to print
     * it. When the selector finds NO BAND, FEX dies long before that on a null
     * allocation result, and every [va-profile] line is lost precisely in the
     * failure that needs explaining.
     *
     * Here is early, it demonstrably runs in those failed launches, it has
     * working logging, and it holds the correct module handle for THIS
     * pseudo-process -- pseudo-processes carry separate libarm64ecfex mappings
     * inside one Mach task, so a native-side symbol lookup could read the wrong
     * copy. Read it as exported DATA; never call a PE export from native code.
     * A stale flush is harmless: FEX's own later flush is bounded by the same
     * length and simply reprints. */
    {
        const int *len = RtlFindExportedRoutineByName( module, "ios_va_log_len" );
        const char *log = RtlFindExportedRoutineByName( module, "ios_va_log" );
        if (len && log && *len > 0)
            ERR( "[va-profile] ml755 selector log (%d bytes, early flush):\n%.*s\n",
                 *len, *len, log );
        else
            ERR( "[va-profile] ml755 selector log EMPTY at dispatcher init "
                 "(len=%p log=%p) -- band selection has not run yet\n", len, log );
    }

    /* ml797: hand the arena to the emulator's band selector as PLAIN DATA.
     *
     * The selector cannot fetch it for itself. It runs during rpmalloc init,
     * before the ARM64EC TEB exists and before ucrtbase's DllMain, so getenv()
     * recurses forever in _lock(17) and GetEnvironmentVariableA faults reading
     * the TEB -- ml793 and its attempted fix each killed every launch, x64 cube
     * included. Writing its globals from here costs the selector no call at all.
     *
     * This is the right site for it, for the same reason the log above is read
     * here: it runs BEFORE the selector (the else-branch above says so), and it
     * holds the module handle for THIS pseudo-process, which carries its own
     * libarm64ecfex mapping inside the shared Mach task.
     *
     * Validation belongs here too, not in the selector -- this side can name the
     * reason in the log. A published-but-invalid arena zeroes the band, which
     * the selector reports as "no band" rather than silently selecting one and
     * recreating the overlap the arena exists to prevent. */
    {
        /* ml800: ask the UNIX side, never an ntdll global.
         *
         * ml799 read `extern ULONG_PTR ios_fex_arena_base` here and got zero on
         * every run, while the unix side had demonstrably published the right
         * value moments earlier. ntdll's image is copied into the JIT pool
         * BEFORE that publication -- the [jit-pool] line precedes it in the log
         * -- so the linked read resolved inside a stale duplicate of ntdll's
         * .data. FEX then selected its own band while an 8GB arena sat held,
         * which is precisely the ml757 configuration, and rendering stopped.
         *
         * ios_teb_tsd_offset avoids this only because its reader goes through
         * GetProcAddress on the live module. The unix side has one copy per
         * Mach task and cannot be duplicated, so it is the authoritative source. */
        struct ios_get_fex_arena_params arena_params = { 0, 0 };
        ULONG_PTR ios_fex_arena_base = 0, ios_fex_arena_end = 0;
        ULONG_PTR *band_base = RtlFindExportedRoutineByName( module, "ios_fex_band_base" );
        ULONG_PTR *band_end  = RtlFindExportedRoutineByName( module, "ios_fex_band_end" );

        if (!WINE_UNIX_CALL( unix_ios_get_fex_arena, &arena_params ))
        {
            ios_fex_arena_base = (ULONG_PTR)arena_params.base;
            ios_fex_arena_end  = (ULONG_PTR)arena_params.end;
        }
        else
            ERR( "[fex-arena] ml800 unix_ios_get_fex_arena FAILED -- cannot learn the arena; "
                 "the emulator will select its own band\n" );

        if (!band_base || !band_end)
            ERR( "[fex-arena] ml797 emulator exports ios_fex_band_base/end NOT FOUND "
                 "(base=%p end=%p) -- arena cannot be handed over\n", band_base, band_end );
        else if (!ios_fex_arena_base && !ios_fex_arena_end)
            ERR( "[fex-arena] ml797 no arena published this run -- emulator selects its own "
                 "band, as before\n" );
        else
        {
            const char *why = NULL;
            ULONG_PTR b = ios_fex_arena_base, e = ios_fex_arena_end;

            if (!b || !e)                     why = "zero base or end";
            else if (e <= b)                  why = "end is not above base";
            else if (b & 0xffff)              why = "base is not 64K aligned";
            else if (e & 0xffff)              why = "end is not 64K aligned";
            else if (e - b < 0x40000000ull)   why = "range is under the 1GB minimum";

            if (why)
            {
                *band_base = 0;
                *band_end  = 0;
                ERR( "[fex-arena] ml797 PUBLISHED ARENA REJECTED [%p,%p): %s -- band zeroed; the "
                     "emulator will report no band rather than select one\n",
                     (void *)b, (void *)e, why );
            }
            else
            {
                *band_base = b;
                *band_end  = e - 1;   /* the selector's end is INCLUSIVE */
                ERR( "[fex-arena] ml797 ARENA HANDED OVER base=%p end=%p (inclusive) -- the "
                     "selector must not run\n", (void *)*band_base, (void *)*band_end );
            }
        }
    }

#define GET_PTR(name) p ## name = arm64ec_redirect_ptr( module, \
                                      RtlFindExportedRoutineByName( module, #name ), metadata )
    GET_PTR( BTCpu64FlushInstructionCache );
    GET_PTR( BTCpu64IosAddAliasMapping );  /* iOS-only; NULL on non-iOS hosts. */
    GET_PTR( BTCpu64IosCrashMailerData );  /* madeira [crashmailer-dump]; iOS-only, NULL elsewhere. */
    GET_PTR( BTCpu64IosDebugRegs );  /* madeira [dr-pass]; iOS-only, NULL elsewhere. */
    GET_PTR( BTCpu64IosGuestContext );  /* madeira [getctx-guest]; iOS-only, NULL elsewhere. */
    GET_PTR( BTCpu64IosRaisePfAf );  /* madeira [pfaf-int3]; iOS-only, NULL elsewhere. */
    GET_PTR( BTCpu64IosReleaseThreadHolds );  /* iOS-only; ml618 leaked-hold release. */
    GET_PTR( BTCpu64IosSetMonoBridge );  /* iOS-only; ml648 Mono backpatcher bridge. */
    GET_PTR( BTCpu64IsProcessorFeaturePresent );
    GET_PTR( BTCpu64NotifyMemoryDirty );
    GET_PTR( BTCpu64NotifyReadFile );
    GET_PTR( BeginSimulation );
    GET_PTR( FlushInstructionCacheHeavy );
    GET_PTR( NotifyImageMap );  /* iOS-only loader-safe fallback; NULL on other hosts. */
    GET_PTR( NotifyMapViewOfSection );
    GET_PTR( NotifyMemoryAlloc );
    GET_PTR( NotifyMemoryFree );
    GET_PTR( NotifyMemoryProtect );
    GET_PTR( NotifyUnmapViewOfSection );
    GET_PTR( ProcessInit );
    GET_PTR( ProcessTerm );
    GET_PTR( ResetToConsistentState );
    GET_PTR( ThreadInit );
    GET_PTR( ThreadTerm );
    GET_PTR( UpdateProcessorInformation );
#undef GET_PTR

    if (rtcs_diag_enabled())
    {
        const unsigned char *b = rtcs_diag_raw = RtlFindExportedRoutineByName( module, "ResetToConsistentState" );

        rtcs_diag_init = (void *)pResetToConsistentState;
        ERR( "[rtcs-ptr] init: module=%p redirect-entries=%u ResetToConsistentState export=%p pointer=%p "
             "bytes=%02x%02x%02x%02x%02x%02x%02x%02x | ProcessInit=%p ThreadInit=%p BeginSimulation=%p "
             "NotifyMemoryAlloc=%p rev=rtcs-diag\n",
             module, (unsigned int)metadata->RedirectionMetadataCount, rtcs_diag_raw, (void *)pResetToConsistentState,
             b ? b[0] : 0, b ? b[1] : 0, b ? b[2] : 0, b ? b[3] : 0, b ? b[4] : 0, b ? b[5] : 0, b ? b[6] : 0, b ? b[7] : 0,
             (void *)pProcessInit, (void *)pThreadInit, (void *)pBeginSimulation, (void *)pNotifyMemoryAlloc );
        rtcs_diag_where( "init" );
    }

    RtlGetCurrentPeb()->ChpeV2ProcessInfo = info;
    info->NativeMachineType = IMAGE_FILE_MACHINE_ARM64;
    info->EmulatedMachineType = IMAGE_FILE_MACHINE_AMD64;
    memcpy( KiUserExceptionDispatcher_orig, KiUserExceptionDispatcher_thunk, sizeof(KiUserExceptionDispatcher_orig) );

    /* iOS-only: push the iOS JIT-pool alias table to xtajit64 so FEX can
     * recognize alias addresses as executable. Without this, x86 sub-ranges
     * inside any copied ARM64EC DLL (sechost, msvcrt, msvcp140, etc.) hit
     * NoExecOp during translation and trap when executed.
     *
     * No #ifdef guard — on non-iOS hosts, pBTCpu64IosAddAliasMapping is NULL
     * (export doesn't exist) and we skip silently. The unix-side handler
     * also returns success with zero mappings on non-iOS. */
    if (pBTCpu64IosAddAliasMapping)
    {
        struct ios_push_jit_aliases_params params = { (void *)pBTCpu64IosAddAliasMapping };
        NTSTATUS push_status = WINE_UNIX_CALL( unix_ios_push_jit_aliases, &params );
        if (push_status)
            ERR( "arm64ec_process_init_dispatchers: unix_ios_push_jit_aliases failed: %lx\n", push_status );
    }
    /* No else — on non-iOS hosts pBTCpu64IosAddAliasMapping is naturally NULL,
     * which is silent + correct: the bridge has nothing to do off-iOS. */

    /* iOS-Madeira ml648: HAND FEX THE MONO-BACKPATCHER BRIDGE.
     *
     * Two hops, both in safe directions. PE -> unix via WINE_UNIX_CALL gets the
     * shared struct's address; PE -> PE via the arm64ec_redirect_ptr'd export
     * hands it to FEX. Nothing here calls an ARM64EC export from native Mach-O
     * code, which is what crashed every ml613 launch.
     *
     * FEX publishes its struct offsets on receipt but leaves mono_base at 0, so
     * the native Mach handler stays inert until InvalidationTracker recognises
     * the Mono module. Off iOS the export is absent, the pointer is NULL, and
     * this is silently skipped. */
    if (pBTCpu64IosSetMonoBridge)
    {
        ULONG64 bridge = 0;
        NTSTATUS st = WINE_UNIX_CALL( unix_ios_mono_bridge_ptr, &bridge );
        if (!st && bridge)
            pBTCpu64IosSetMonoBridge( bridge );
        else
            ERR( "ml648: mono bridge unavailable (status %lx, ptr %s)\n",
                 st, bridge ? "set" : "NULL" );
    }

    /* iOS-Madeira ml618: REGISTER THE LEAKED-HOLD RELEASE CALLBACK.
     *
     * ml611/ml616/ml617 all froze the whole app the same way: a thread dies in
     * abnormal exit still owning one CodeInvalidationMutex reader, a writer
     * queues behind it, write-priority blocks every later reader, and JIT
     * compilation stops process-wide (ml617: callret-gen 312 -> 0 at the exact
     * line the hold leaked).
     *
     * 🔑 PROVENANCE IS THE WHOLE FIX. ml613 resolved this same export with
     * ios_pe_find_export() — plain module_base + export_rva — which yields the
     * raw x64 ENTRY THUNK. Native ARM64 then executed `48 8b c4 48...` and every
     * launch died. GET_PTR above goes through arm64ec_redirect_ptr(), which
     * resolves the EC redirection entry and xlate_ios_jit()s it into an
     * executable ARM64 alias in the JIT pool. That pointer IS natively callable
     * — which is why pBTCpu64IosAddAliasMapping has always worked when called
     * from unix code, including long after the original unix call returned.
     *
     * ⛔ NEVER register a pointer obtained any other way.
     *
     * The self-test below is the cheap insurance: invoke with a NULL TEB, which
     * the callback answers with REL_SELFTEST and nothing else. If we ever bind a
     * raw thunk again, this faults here at init instead of on a dying thread. */
    if (pBTCpu64IosReleaseThreadHolds)
    {
        unsigned int probe = pBTCpu64IosReleaseThreadHolds( NULL, NULL, NULL, NULL );
        if (probe != 0x10u)
        {
            ERR( "[hold-release] ml618 SELF-TEST FAILED (got %#x, want 0x10) — NOT registering; "
                 "the bound pointer is not the redirected ARM64 alias\n", probe );
        }
        else
        {
            struct ios_register_hold_release_params params;
            NTSTATUS reg_status;
            params.size     = sizeof(params);
            params.version  = 1;
            params.peb      = RtlGetCurrentPeb();
            params.callback = (void *)pBTCpu64IosReleaseThreadHolds;
            reg_status = WINE_UNIX_CALL( unix_ios_register_hold_release, &params );
            ERR( "[hold-release] ml618 self-test OK; registered cb=%p peb=%p -> %lx\n",
                 (void *)pBTCpu64IosReleaseThreadHolds, params.peb, reg_status );
        }
    }

    return STATUS_SUCCESS;
}


/*******************************************************************
 *         arm64ec_process_init
 *
 * Phase 2 of arm64ec init: invoke FEX's pProcessInit and pThreadInit,
 * then set the call-checker slots. Must run AFTER all module DllMains
 * so that ucrtbase's CRT (lock_table etc.) is initialized when FEX's
 * CRT static constructors fire.
 */
NTSTATUS arm64ec_process_init( HMODULE module )
{
    NTSTATUS status = STATUS_SUCCESS;
    CHPEV2_PROCESS_INFO *info = RtlGetCurrentPeb()->ChpeV2ProcessInfo;
    (void)module;

    enter_syscall_callback();
    if (pProcessInit) status = pProcessInit();
    ERR( "arm64ec_process_init: pProcessInit -> %lx (info=%p)\n", status, info );
    if (!status)
    {
        for (unsigned int i = 0; i < PROCESSOR_FEATURE_MAX; i++)
            emulated_processor_features[i] = pBTCpu64IsProcessorFeaturePresent( i );

        status = create_cross_process_work_list( info );
        ERR( "arm64ec_process_init: create_cross_process_work_list -> %lx\n", status );
    }
    if (!status && pThreadInit)
    {
        status = pThreadInit();
        ERR( "arm64ec_process_init: pThreadInit -> %lx\n", status );
    }
    leave_syscall_callback();
    __os_arm64x_check_call = arm64x_check_call;
    __os_arm64x_check_icall = arm64x_check_call;
    __os_arm64x_check_icall_cfg = arm64x_check_call;
    return status;
}


/*******************************************************************
 *         arm64ec_thread_init
 */
NTSTATUS arm64ec_thread_init(void)
{
    NTSTATUS status = STATUS_SUCCESS;

    enter_syscall_callback();
    if (pThreadInit) status = pThreadInit();
    leave_syscall_callback();
    return status;
}


/**********************************************************************
 *           arm64ec_get_module_metadata
 */
IMAGE_ARM64EC_METADATA *arm64ec_get_module_metadata( HMODULE module )
{
    IMAGE_LOAD_CONFIG_DIRECTORY *cfg;
    ULONG size;

    if (!(cfg = RtlImageDirectoryEntryToData( module, TRUE,
                                              IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &size )))
        return NULL;

    size = min( size, cfg->Size );
    if (size <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer )) return NULL;
    return (IMAGE_ARM64EC_METADATA *)cfg->CHPEMetadataPointer;
}


static void update_hybrid_pointer( void *module, const IMAGE_SECTION_HEADER *sec, UINT rva, void *ptr )
{
    if (!rva) return;

    if (rva < sec->VirtualAddress || rva >= sec->VirtualAddress + sec->Misc.VirtualSize)
        ERR( "rva %x outside of section %s (%lx-%lx)\n", rva,
             sec->Name, sec->VirtualAddress, sec->VirtualAddress + sec->Misc.VirtualSize );
    else
        *(void **)get_rva( module, rva ) = ptr;
}

/*******************************************************************
 *         arm64ec_update_hybrid_metadata
 */
void arm64ec_update_hybrid_metadata( void *module, IMAGE_NT_HEADERS *nt,
                                     const IMAGE_ARM64EC_METADATA *metadata )
{
    DWORD i, protect_old;
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION( nt );

    /* assume that all pointers are in the same section */
    ERR( "arm64ec_update_hybrid_metadata: module=%p dispatch_call_rva=%lx check_call=%p\n",
         module, (unsigned long)metadata->__os_arm64x_dispatch_call, arm64x_check_call );

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if ((sec->VirtualAddress <= metadata->__os_arm64x_dispatch_call) &&
            (sec->VirtualAddress + sec->Misc.VirtualSize > metadata->__os_arm64x_dispatch_call))
        {
            void *base = get_rva( module, sec->VirtualAddress );
            SIZE_T size = sec->Misc.VirtualSize;

            NtProtectVirtualMemory( NtCurrentProcess(), &base, &size, PAGE_READWRITE, &protect_old );

#define SET_FUNC(func,val) update_hybrid_pointer( module, sec, metadata->func, val )
            SET_FUNC( __os_arm64x_dispatch_call, arm64x_check_call );
            SET_FUNC( __os_arm64x_dispatch_call_no_redirect, __os_arm64x_dispatch_call_no_redirect );
            SET_FUNC( __os_arm64x_dispatch_fptr, __os_arm64x_dispatch_fptr );
            SET_FUNC( __os_arm64x_dispatch_icall, arm64x_check_call );
            SET_FUNC( __os_arm64x_dispatch_icall_cfg, arm64x_check_call );
            SET_FUNC( __os_arm64x_dispatch_ret, __os_arm64x_dispatch_ret );
            SET_FUNC( __os_arm64x_helper3, __os_arm64x_helper3 );
            SET_FUNC( __os_arm64x_helper4, __os_arm64x_helper4 );
            SET_FUNC( __os_arm64x_helper5, __os_arm64x_helper5 );
            SET_FUNC( __os_arm64x_helper6, __os_arm64x_helper6 );
            SET_FUNC( __os_arm64x_helper7, __os_arm64x_helper7 );
            SET_FUNC( __os_arm64x_helper8, __os_arm64x_helper8 );
            SET_FUNC( GetX64InformationFunctionPointer, __os_arm64x_get_x64_information );
            SET_FUNC( SetX64InformationFunctionPointer, __os_arm64x_set_x64_information );
#undef SET_FUNC

            NtProtectVirtualMemory( NtCurrentProcess(), &base, &size, protect_old, &protect_old );
            return;
        }
    }
    ERR( "module %p no section found for %lx\n", module, metadata->__os_arm64x_dispatch_call );
}


/*******************************************************************
 *         syscalls
 */
enum syscall_ids
{
#define SYSCALL_ENTRY(id,name,args) __id_##name = id,
ALL_SYSCALLS
#undef SYSCALL_ENTRY
    __nb_syscalls
};

#define DEFINE_SYSCALL_(ret,name,args) \
    ret __attribute__((naked, hybrid_patchable)) name args { __ASM_SYSCALL_FUNC( __id_##name, name ); }

#define DEFINE_SYSCALL(name,args) DEFINE_SYSCALL_(NTSTATUS,name,args)

#define DEFINE_WRAPPED_SYSCALL(name,args) \
    static NTSTATUS __attribute__((naked)) syscall_##name args { __ASM_SYSCALL_FUNC( __id_##name, syscall_##name ); }

#define SYSCALL_API __attribute__((hybrid_patchable))

DEFINE_SYSCALL(NtAcceptConnectPort, (HANDLE *handle, ULONG id, LPC_MESSAGE *msg, BOOLEAN accept, LPC_SECTION_WRITE *write, LPC_SECTION_READ *read))
DEFINE_SYSCALL(NtAccessCheck, (PSECURITY_DESCRIPTOR descr, HANDLE token, ACCESS_MASK access, GENERIC_MAPPING *mapping, PRIVILEGE_SET *privs, ULONG *retlen, ULONG *access_granted, NTSTATUS *access_status))
DEFINE_SYSCALL(NtAccessCheckAndAuditAlarm, (UNICODE_STRING *subsystem, HANDLE handle, UNICODE_STRING *typename, UNICODE_STRING *objectname, PSECURITY_DESCRIPTOR descr, ACCESS_MASK access, GENERIC_MAPPING *mapping, BOOLEAN creation, ACCESS_MASK *access_granted, NTSTATUS *access_status, BOOLEAN *onclose))
DEFINE_SYSCALL(NtAccessCheckByTypeAndAuditAlarm, (UNICODE_STRING *subsystem, HANDLE handle, UNICODE_STRING *typename, UNICODE_STRING *objectname, PSECURITY_DESCRIPTOR descr, PSID sid, ACCESS_MASK access, AUDIT_EVENT_TYPE audit_type, ULONG flags, OBJECT_TYPE_LIST *obj_list, ULONG list_len, GENERIC_MAPPING *mapping, BOOLEAN creation, ACCESS_MASK *access_granted, NTSTATUS *access_status, BOOLEAN *onclose))
DEFINE_SYSCALL(NtAddAtom, (const WCHAR *name, ULONG length, RTL_ATOM *atom))
DEFINE_SYSCALL(NtAdjustGroupsToken, (HANDLE token, BOOLEAN reset, TOKEN_GROUPS *groups, ULONG length, TOKEN_GROUPS *prev, ULONG *retlen))
DEFINE_SYSCALL(NtAdjustPrivilegesToken, (HANDLE token, BOOLEAN disable, TOKEN_PRIVILEGES *privs, DWORD length, TOKEN_PRIVILEGES *prev, DWORD *retlen))
DEFINE_SYSCALL(NtAlertMultipleThreadByThreadId, (HANDLE *tids, ULONG count, void *unk1, void *unk2))
DEFINE_SYSCALL(NtAlertResumeThread, (HANDLE handle, ULONG *count))
DEFINE_SYSCALL(NtAlertThread, (HANDLE handle))
DEFINE_SYSCALL(NtAlertThreadByThreadId, (HANDLE tid))
DEFINE_SYSCALL(NtAllocateLocallyUniqueId, (LUID *luid))
DEFINE_SYSCALL(NtAllocateReserveObject, (HANDLE *handle, const OBJECT_ATTRIBUTES *attr, MEMORY_RESERVE_OBJECT_TYPE type))
DEFINE_SYSCALL(NtAllocateUuids, (ULARGE_INTEGER *time, ULONG *delta, ULONG *sequence, UCHAR *seed))
DEFINE_WRAPPED_SYSCALL(NtAllocateVirtualMemory, (HANDLE process, PVOID *ret, ULONG_PTR zero_bits, SIZE_T *size_ptr, ULONG type, ULONG protect))
DEFINE_WRAPPED_SYSCALL(NtAllocateVirtualMemoryEx, (HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type, ULONG protect, MEM_EXTENDED_PARAMETER *parameters, ULONG count))
DEFINE_SYSCALL(NtAlpcAcceptConnectPort, (HANDLE *communication_port, HANDLE connection_port, DWORD flags, OBJECT_ATTRIBUTES *obj_attr, ALPC_PORT_ATTRIBUTES *port_attr, void *port_context, ALPC_PORT_MESSAGE *send_msg, ALPC_MESSAGE_ATTRIBUTES *send_msg_attr, BOOLEAN accept))
DEFINE_SYSCALL(NtAlpcConnectPort, (HANDLE *port_handle, UNICODE_STRING *port_name, OBJECT_ATTRIBUTES *obj_attr, ALPC_PORT_ATTRIBUTES *port_attr, DWORD flags, PSID required_server_sid, ALPC_PORT_MESSAGE *connect_msg, SIZE_T *connect_msg_size, ALPC_MESSAGE_ATTRIBUTES *send_msg_attr, ALPC_MESSAGE_ATTRIBUTES *recv_msg_attr, LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtAlpcCreatePort, (HANDLE *port_handle, OBJECT_ATTRIBUTES *obj_attr, ALPC_PORT_ATTRIBUTES *port_attr))
DEFINE_SYSCALL(NtAlpcDisconnectPort, (HANDLE port_handle, ULONG flags))
DEFINE_SYSCALL(NtAlpcImpersonateClientOfPort, (HANDLE port_handle, ALPC_PORT_MESSAGE *msg, void *reserved ))
DEFINE_SYSCALL(NtAlpcSendWaitReceivePort, (HANDLE port_handle, DWORD flags, ALPC_PORT_MESSAGE *send_msg, ALPC_MESSAGE_ATTRIBUTES *send_msg_attr, ALPC_PORT_MESSAGE *recv_msg, SIZE_T *recv_buffer_size, ALPC_MESSAGE_ATTRIBUTES *recv_msg_attr, LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtApphelpCacheControl, (ULONG class, void *context))
DEFINE_SYSCALL(NtAreMappedFilesTheSame, (PVOID addr1, PVOID addr2))
DEFINE_SYSCALL(NtAssignProcessToJobObject, (HANDLE job, HANDLE process))
DEFINE_SYSCALL(NtCallbackReturn, (void *ret_ptr, ULONG ret_len, NTSTATUS status))
DEFINE_SYSCALL(NtCancelIoFile, (HANDLE handle, IO_STATUS_BLOCK *io_status))
DEFINE_SYSCALL(NtCancelIoFileEx, (HANDLE handle, IO_STATUS_BLOCK *io, IO_STATUS_BLOCK *io_status))
DEFINE_SYSCALL(NtCancelSynchronousIoFile, (HANDLE handle, IO_STATUS_BLOCK *io, IO_STATUS_BLOCK *io_status))
DEFINE_SYSCALL(NtCancelTimer, (HANDLE handle, BOOLEAN *state))
DEFINE_SYSCALL(NtClearEvent, (HANDLE handle))
DEFINE_WRAPPED_SYSCALL(NtClose, (HANDLE handle))
DEFINE_SYSCALL(NtCloseObjectAuditAlarm, (UNICODE_STRING *subsystem, HANDLE handle, BOOLEAN onclose))
DEFINE_SYSCALL(NtCommitTransaction, (HANDLE transaction, BOOLEAN wait))
DEFINE_SYSCALL(NtCompareObjects, (HANDLE first, HANDLE second))
DEFINE_SYSCALL(NtCompareTokens, (HANDLE first, HANDLE second, BOOLEAN *equal))
DEFINE_SYSCALL(NtCompleteConnectPort, (HANDLE handle))
DEFINE_SYSCALL(NtConnectPort, (HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos, LPC_SECTION_WRITE *write, LPC_SECTION_READ *read, ULONG *max_len, void *info, ULONG *info_len))
DEFINE_WRAPPED_SYSCALL(NtContinue, (ARM64_NT_CONTEXT *context, BOOLEAN alertable))
DEFINE_WRAPPED_SYSCALL(NtContinueEx, (ARM64_NT_CONTEXT *context, KCONTINUE_ARGUMENT *args))
DEFINE_SYSCALL(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter, (ULONG flag, ULONGLONG *from, ULONGLONG *to, ULONGLONG *error))
DEFINE_SYSCALL(NtCreateDebugObject, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, ULONG flags))
DEFINE_SYSCALL(NtCreateDirectoryObject, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr))
DEFINE_WRAPPED_SYSCALL(NtCreateEvent, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, EVENT_TYPE type, BOOLEAN state))
DEFINE_WRAPPED_SYSCALL(NtCreateFile, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, IO_STATUS_BLOCK *io, LARGE_INTEGER *alloc_size, ULONG attributes, ULONG sharing, ULONG disposition, ULONG options, void *ea_buffer, ULONG ea_length))
DEFINE_SYSCALL(NtCreateIoCompletion, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, ULONG threads))
DEFINE_SYSCALL(NtCreateJobObject, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtCreateKey, (HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, ULONG index, const UNICODE_STRING *class, ULONG options, ULONG *dispos))
DEFINE_SYSCALL(NtCreateKeyTransacted, (HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, ULONG index, const UNICODE_STRING *class, ULONG options, HANDLE transacted, ULONG *dispos))
DEFINE_SYSCALL(NtCreateKeyedEvent, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, ULONG flags))
DEFINE_SYSCALL(NtCreateLowBoxToken, (HANDLE *token_handle, HANDLE token, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, SID *sid, ULONG count, SID_AND_ATTRIBUTES *capabilities, ULONG handle_count, HANDLE *handle))
DEFINE_SYSCALL(NtCreateMailslotFile, (HANDLE *handle, ULONG access, OBJECT_ATTRIBUTES *attr, IO_STATUS_BLOCK *io, ULONG options, ULONG quota, ULONG msg_size, LARGE_INTEGER *timeout))
DEFINE_WRAPPED_SYSCALL(NtCreateMutant, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, BOOLEAN owned))
DEFINE_SYSCALL(NtCreateNamedPipeFile, (HANDLE *handle, ULONG access, OBJECT_ATTRIBUTES *attr, IO_STATUS_BLOCK *io, ULONG sharing, ULONG dispo, ULONG options, ULONG pipe_type, ULONG read_mode, ULONG completion_mode, ULONG max_inst, ULONG inbound_quota, ULONG outbound_quota, LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtCreatePagingFile, (UNICODE_STRING *name, LARGE_INTEGER *min_size, LARGE_INTEGER *max_size, LARGE_INTEGER *actual_size))
DEFINE_SYSCALL(NtCreatePort, (HANDLE *handle, OBJECT_ATTRIBUTES *attr, ULONG info_len, ULONG data_len, ULONG *reserved))
DEFINE_SYSCALL(NtCreateProcessEx, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, HANDLE parent, ULONG flags, HANDLE section, HANDLE debug, HANDLE token, ULONG reserved))
DEFINE_WRAPPED_SYSCALL(NtCreateSection, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, const LARGE_INTEGER *size, ULONG protect, ULONG sec_flags, HANDLE file))
DEFINE_SYSCALL(NtCreateSectionEx, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, const LARGE_INTEGER *size, ULONG protect, ULONG sec_flags, HANDLE file, MEM_EXTENDED_PARAMETER *parameters, ULONG count))
DEFINE_SYSCALL(NtCreateSemaphore, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, LONG initial, LONG max))
DEFINE_SYSCALL(NtCreateSymbolicLinkObject, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, UNICODE_STRING *target))
DEFINE_SYSCALL(NtCreateThread, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, HANDLE process, CLIENT_ID *id, CONTEXT *ctx, INITIAL_TEB *teb, BOOLEAN suspended))
DEFINE_SYSCALL(NtCreateThreadEx, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, HANDLE process, PRTL_THREAD_START_ROUTINE start, void *param, ULONG flags, ULONG_PTR zero_bits, SIZE_T stack_commit, SIZE_T stack_reserve, PS_ATTRIBUTE_LIST *attr_list))
DEFINE_SYSCALL(NtCreateTimer, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, TIMER_TYPE type))
DEFINE_SYSCALL(NtCreateToken, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, TOKEN_TYPE type, LUID *token_id, LARGE_INTEGER *expire, TOKEN_USER *user, TOKEN_GROUPS *groups, TOKEN_PRIVILEGES *privs, TOKEN_OWNER *owner, TOKEN_PRIMARY_GROUP *group, TOKEN_DEFAULT_DACL *dacl, TOKEN_SOURCE *source))
DEFINE_SYSCALL(NtCreateTransaction, (HANDLE *handle, ACCESS_MASK mask, OBJECT_ATTRIBUTES *obj_attr, GUID *guid, HANDLE tm, ULONG options, ULONG isol_level, ULONG isol_flags, PLARGE_INTEGER timeout, UNICODE_STRING *description))
DEFINE_WRAPPED_SYSCALL(NtCreateUserProcess, (HANDLE *process_handle_ptr, HANDLE *thread_handle_ptr, ACCESS_MASK process_access, ACCESS_MASK thread_access, OBJECT_ATTRIBUTES *process_attr, OBJECT_ATTRIBUTES *thread_attr, ULONG process_flags, ULONG thread_flags, RTL_USER_PROCESS_PARAMETERS *params, PS_CREATE_INFO *info, PS_ATTRIBUTE_LIST *ps_attr))
DEFINE_SYSCALL(NtDebugActiveProcess, (HANDLE process, HANDLE debug))
DEFINE_SYSCALL(NtDebugContinue, (HANDLE handle, CLIENT_ID *client, NTSTATUS status))
DEFINE_WRAPPED_SYSCALL(NtDelayExecution, (BOOLEAN alertable, const LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtDeleteAtom, (RTL_ATOM atom))
DEFINE_SYSCALL(NtDeleteFile, (OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtDeleteKey, (HANDLE key))
DEFINE_SYSCALL(NtDeleteValueKey, (HANDLE key, const UNICODE_STRING *name))
DEFINE_WRAPPED_SYSCALL(NtDeviceIoControlFile, (HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context, IO_STATUS_BLOCK *io, ULONG code, void *in_buffer, ULONG in_size, void *out_buffer, ULONG out_size))
DEFINE_SYSCALL(NtDisplayString, (UNICODE_STRING *string))
DEFINE_SYSCALL(NtDuplicateObject, (HANDLE source_process, HANDLE source, HANDLE dest_process, HANDLE *dest, ACCESS_MASK access, ULONG attributes, ULONG options))
DEFINE_SYSCALL(NtDuplicateToken, (HANDLE token, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, BOOLEAN effective_only, TOKEN_TYPE type, HANDLE *handle))
DEFINE_SYSCALL(NtEnumerateKey, (HANDLE handle, ULONG index, KEY_INFORMATION_CLASS info_class, void *info, DWORD length, DWORD *result_len))
DEFINE_SYSCALL(NtEnumerateValueKey, (HANDLE handle, ULONG index, KEY_VALUE_INFORMATION_CLASS info_class, void *info, DWORD length, DWORD *result_len))
DEFINE_SYSCALL(NtFilterToken, (HANDLE token, ULONG flags, TOKEN_GROUPS *disable_sids, TOKEN_PRIVILEGES *privileges, TOKEN_GROUPS *restrict_sids, HANDLE *new_token))
DEFINE_SYSCALL(NtFindAtom, (const WCHAR *name, ULONG length, RTL_ATOM *atom))
DEFINE_SYSCALL(NtFlushBuffersFile, (HANDLE handle, IO_STATUS_BLOCK *io))
DEFINE_SYSCALL(NtFlushBuffersFileEx, (HANDLE handle, ULONG flags, void *params, ULONG size, IO_STATUS_BLOCK *io))
DEFINE_WRAPPED_SYSCALL(NtFlushInstructionCache, (HANDLE handle, const void *addr, SIZE_T size))
DEFINE_SYSCALL(NtFlushKey, (HANDLE key))
DEFINE_SYSCALL(NtFlushProcessWriteBuffers, (void))
DEFINE_SYSCALL(NtFlushVirtualMemory, (HANDLE process, LPCVOID *addr_ptr, SIZE_T *size_ptr, IO_STATUS_BLOCK *io))
DEFINE_WRAPPED_SYSCALL(NtFreeVirtualMemory, (HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type))
DEFINE_SYSCALL(NtFsControlFile, (HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context, IO_STATUS_BLOCK *io, ULONG code, void *in_buffer, ULONG in_size, void *out_buffer, ULONG out_size))
DEFINE_WRAPPED_SYSCALL(NtGetContextThread, (HANDLE handle, ARM64_NT_CONTEXT *context))
DEFINE_SYSCALL_(ULONG, NtGetCurrentProcessorNumber, (void))
DEFINE_SYSCALL(NtGetNextProcess, (HANDLE process, ACCESS_MASK access, ULONG attributes, ULONG flags, HANDLE *handle))
DEFINE_SYSCALL(NtGetNextThread, (HANDLE process, HANDLE thread, ACCESS_MASK access, ULONG attributes, ULONG flags, HANDLE *handle))
DEFINE_SYSCALL(NtGetNlsSectionPtr, (ULONG type, ULONG id, void *unknown, void **ptr, SIZE_T *size))
DEFINE_SYSCALL(NtGetWriteWatch, (HANDLE process, ULONG flags, PVOID base, SIZE_T size, PVOID *addresses, ULONG_PTR *count, ULONG *granularity))
DEFINE_SYSCALL(NtImpersonateAnonymousToken, (HANDLE thread))
DEFINE_SYSCALL(NtImpersonateClientOfPort, (HANDLE handle, LPC_MESSAGE *request))
DEFINE_SYSCALL(NtInitializeNlsFiles, (void **ptr, LCID *lcid, LARGE_INTEGER *size))
DEFINE_SYSCALL(NtInitiatePowerAction, (POWER_ACTION action, SYSTEM_POWER_STATE state, ULONG flags, BOOLEAN async))
DEFINE_SYSCALL(NtIsProcessInJob, (HANDLE process, HANDLE job))
DEFINE_SYSCALL(NtListenPort, (HANDLE handle, LPC_MESSAGE *msg))
DEFINE_SYSCALL(NtLoadDriver, (const UNICODE_STRING *name))
DEFINE_SYSCALL(NtLoadKey, (const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file))
DEFINE_SYSCALL(NtLoadKey2, (const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file, ULONG flags))
DEFINE_SYSCALL(NtLoadKeyEx, (const OBJECT_ATTRIBUTES *attr, OBJECT_ATTRIBUTES *file, ULONG flags, HANDLE trustkey, HANDLE event, ACCESS_MASK access, HANDLE *roothandle, IO_STATUS_BLOCK *iostatus))
DEFINE_SYSCALL(NtLockFile, (HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void* apc_user, IO_STATUS_BLOCK *io_status, LARGE_INTEGER *offset, LARGE_INTEGER *count, ULONG *key, BOOLEAN dont_wait, BOOLEAN exclusive))
DEFINE_SYSCALL(NtLockVirtualMemory, (HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown))
DEFINE_SYSCALL(NtMakePermanentObject, (HANDLE handle))
DEFINE_SYSCALL(NtMakeTemporaryObject, (HANDLE handle))
DEFINE_SYSCALL(NtMapUserPhysicalPagesScatter, (void **addr, SIZE_T count, ULONG_PTR *pages))
DEFINE_WRAPPED_SYSCALL(NtMapViewOfSection, (HANDLE handle, HANDLE process, PVOID *addr_ptr, ULONG_PTR zero_bits, SIZE_T commit_size, const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr, SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect))
DEFINE_WRAPPED_SYSCALL(NtMapViewOfSectionEx, (HANDLE handle, HANDLE process, PVOID *addr_ptr, const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr, ULONG alloc_type, ULONG protect, MEM_EXTENDED_PARAMETER *parameters, ULONG count))
DEFINE_SYSCALL(NtNotifyChangeDirectoryFile, (HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context, IO_STATUS_BLOCK *iosb, void *buffer, ULONG buffer_size, ULONG filter, BOOLEAN subtree))
DEFINE_SYSCALL(NtNotifyChangeKey, (HANDLE key, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context, IO_STATUS_BLOCK *io, ULONG filter, BOOLEAN subtree, void *buffer, ULONG length, BOOLEAN async))
DEFINE_SYSCALL(NtNotifyChangeMultipleKeys, (HANDLE key, ULONG count, OBJECT_ATTRIBUTES *attr, HANDLE event, PIO_APC_ROUTINE apc, void *apc_context, IO_STATUS_BLOCK *io, ULONG filter, BOOLEAN subtree, void *buffer, ULONG length, BOOLEAN async))
DEFINE_SYSCALL(NtOpenDirectoryObject, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_WRAPPED_SYSCALL(NtOpenEvent, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtOpenFile, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, IO_STATUS_BLOCK *io, ULONG sharing, ULONG options))
DEFINE_SYSCALL(NtOpenIoCompletion, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtOpenJobObject, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtOpenKey, (HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtOpenKeyEx, (HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, ULONG options))
DEFINE_SYSCALL(NtOpenKeyTransacted, (HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, HANDLE transaction))
DEFINE_SYSCALL(NtOpenKeyTransactedEx, (HANDLE *key, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, ULONG options, HANDLE transaction))
DEFINE_SYSCALL(NtOpenKeyedEvent, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_WRAPPED_SYSCALL(NtOpenMutant, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtOpenPrivateNamespace, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, const OBJECT_BOUNDARY_DESCRIPTOR *boundary_descriptor))
DEFINE_SYSCALL(NtOpenProcess, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, const CLIENT_ID *id))
DEFINE_SYSCALL(NtOpenProcessToken, (HANDLE process, DWORD access, HANDLE *handle))
DEFINE_SYSCALL(NtOpenProcessTokenEx, (HANDLE process, DWORD access, DWORD attributes, HANDLE *handle))
DEFINE_WRAPPED_SYSCALL(NtOpenSection, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtOpenSemaphore, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtOpenSymbolicLinkObject, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtOpenThread, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, const CLIENT_ID *id))
DEFINE_SYSCALL(NtOpenThreadToken, (HANDLE thread, DWORD access, BOOLEAN self, HANDLE *handle))
DEFINE_SYSCALL(NtOpenThreadTokenEx, (HANDLE thread, DWORD access, BOOLEAN self, DWORD attributes, HANDLE *handle))
DEFINE_SYSCALL(NtOpenTimer, (HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtPowerInformation, (POWER_INFORMATION_LEVEL level, void *input, ULONG in_size, void *output, ULONG out_size))
DEFINE_SYSCALL(NtPrivilegeCheck, (HANDLE token, PRIVILEGE_SET *privs, BOOLEAN *res))
DEFINE_WRAPPED_SYSCALL(NtProtectVirtualMemory, (HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG new_prot, ULONG *old_prot))
DEFINE_SYSCALL(NtPulseEvent, (HANDLE handle, LONG *prev_state))
DEFINE_SYSCALL(NtQueryAttributesFile, (const OBJECT_ATTRIBUTES *attr, FILE_BASIC_INFORMATION *info))
DEFINE_SYSCALL(NtQueryDefaultLocale, (BOOLEAN user, LCID *lcid))
DEFINE_SYSCALL(NtQueryDefaultUILanguage, (LANGID *lang))
DEFINE_SYSCALL(NtQueryDirectoryFile, (HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc_routine, void *apc_context, IO_STATUS_BLOCK *io, void *buffer, ULONG length, FILE_INFORMATION_CLASS info_class, BOOLEAN single_entry, UNICODE_STRING *mask, BOOLEAN restart_scan))
DEFINE_SYSCALL(NtQueryDirectoryObject, (HANDLE handle, DIRECTORY_BASIC_INFORMATION *buffer, ULONG size, BOOLEAN single_entry, BOOLEAN restart, ULONG *context, ULONG *ret_size))
DEFINE_SYSCALL(NtQueryEaFile, (HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length, BOOLEAN single_entry, void *list, ULONG list_len, ULONG *index, BOOLEAN restart))
DEFINE_SYSCALL(NtQueryEvent, (HANDLE handle, EVENT_INFORMATION_CLASS class, void *info, ULONG len, ULONG *ret_len))
DEFINE_SYSCALL(NtQueryFullAttributesFile, (const OBJECT_ATTRIBUTES *attr, FILE_NETWORK_OPEN_INFORMATION *info))
DEFINE_SYSCALL(NtQueryInformationAtom, (RTL_ATOM atom, ATOM_INFORMATION_CLASS class, void *ptr, ULONG size, ULONG *retsize))
DEFINE_SYSCALL(NtQueryInformationFile, (HANDLE handle, IO_STATUS_BLOCK *io, void *ptr, ULONG len, FILE_INFORMATION_CLASS class))
DEFINE_SYSCALL(NtQueryInformationJobObject, (HANDLE handle, JOBOBJECTINFOCLASS class, void *info, ULONG len, ULONG *ret_len))
DEFINE_WRAPPED_SYSCALL(NtQueryInformationProcess, (HANDLE handle, PROCESSINFOCLASS class, void *info, ULONG size, ULONG *ret_len))
DEFINE_WRAPPED_SYSCALL(NtQueryInformationThread, (HANDLE handle, THREADINFOCLASS class, void *data, ULONG length, ULONG *ret_len))
DEFINE_SYSCALL(NtQueryInformationToken, (HANDLE token, TOKEN_INFORMATION_CLASS class, void *info, ULONG length, ULONG *retlen))
DEFINE_SYSCALL(NtQueryInstallUILanguage, (LANGID *lang))
DEFINE_SYSCALL(NtQueryIoCompletion, (HANDLE handle, IO_COMPLETION_INFORMATION_CLASS class, void *buffer, ULONG len, ULONG *ret_len))
DEFINE_SYSCALL(NtQueryKey, (HANDLE handle, KEY_INFORMATION_CLASS info_class, void *info, DWORD length, DWORD *result_len))
DEFINE_SYSCALL(NtQueryLicenseValue, (const UNICODE_STRING *name, ULONG *type, void *data, ULONG length, ULONG *retlen))
DEFINE_SYSCALL(NtQueryMultipleValueKey, (HANDLE key, KEY_MULTIPLE_VALUE_INFORMATION *info, ULONG count, void *buffer, ULONG length, ULONG *retlen))
DEFINE_SYSCALL(NtQueryMutant, (HANDLE handle, MUTANT_INFORMATION_CLASS class, void *info, ULONG len, ULONG *ret_len))
DEFINE_WRAPPED_SYSCALL(NtQueryObject, (HANDLE handle, OBJECT_INFORMATION_CLASS info_class, void *ptr, ULONG len, ULONG *used_len))
DEFINE_SYSCALL(NtQueryPerformanceCounter, (LARGE_INTEGER *counter, LARGE_INTEGER *frequency))
DEFINE_SYSCALL(NtQuerySection, (HANDLE handle, SECTION_INFORMATION_CLASS class, void *ptr, SIZE_T size, SIZE_T *ret_size))
DEFINE_SYSCALL(NtQuerySecurityObject, (HANDLE handle, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR descr, ULONG length, ULONG *retlen))
DEFINE_SYSCALL(NtQuerySemaphore, (HANDLE handle, SEMAPHORE_INFORMATION_CLASS class, void *info, ULONG len, ULONG *ret_len))
DEFINE_SYSCALL(NtQuerySymbolicLinkObject, (HANDLE handle, UNICODE_STRING *target, ULONG *length))
DEFINE_SYSCALL(NtQuerySystemEnvironmentValue, (UNICODE_STRING *name, WCHAR *buffer, ULONG length, ULONG *retlen))
DEFINE_SYSCALL(NtQuerySystemEnvironmentValueEx, (UNICODE_STRING *name, GUID *vendor, void *buffer, ULONG *retlen, ULONG *attrib))
DEFINE_WRAPPED_SYSCALL(NtQuerySystemInformation, (SYSTEM_INFORMATION_CLASS class, void *info, ULONG size, ULONG *ret_size))
DEFINE_WRAPPED_SYSCALL(NtQuerySystemInformationEx, (SYSTEM_INFORMATION_CLASS class, void *query, ULONG query_len, void *info, ULONG size, ULONG *ret_size))
DEFINE_SYSCALL(NtQuerySystemTime, (LARGE_INTEGER *time))
DEFINE_SYSCALL(NtQueryTimer, (HANDLE handle, TIMER_INFORMATION_CLASS class, void *info, ULONG len, ULONG *ret_len))
DEFINE_SYSCALL(NtQueryTimerResolution, (ULONG *min_res, ULONG *max_res, ULONG *current_res))
DEFINE_SYSCALL(NtQueryValueKey, (HANDLE handle, const UNICODE_STRING *name, KEY_VALUE_INFORMATION_CLASS info_class, void *info, DWORD length, DWORD *result_len))
DEFINE_WRAPPED_SYSCALL(NtQueryVirtualMemory, (HANDLE process, LPCVOID addr, MEMORY_INFORMATION_CLASS info_class, PVOID buffer, SIZE_T len, SIZE_T *res_len))
DEFINE_SYSCALL(NtQueryVolumeInformationFile, (HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length, FS_INFORMATION_CLASS info_class))
DEFINE_SYSCALL(NtQueueApcThread, (HANDLE handle, PNTAPCFUNC func, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3))
DEFINE_SYSCALL(NtQueueApcThreadEx, (HANDLE handle, HANDLE reserve_handle, PNTAPCFUNC func, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3))
DEFINE_SYSCALL(NtQueueApcThreadEx2, (HANDLE handle, HANDLE reserve_handle, ULONG flags, PNTAPCFUNC func, ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3))
DEFINE_WRAPPED_SYSCALL(NtRaiseException, (EXCEPTION_RECORD *rec, ARM64_NT_CONTEXT *context, BOOL first_chance))
DEFINE_SYSCALL(NtRaiseHardError, (NTSTATUS status, ULONG count, ULONG params_mask, void **params, HARDERROR_RESPONSE_OPTION option, HARDERROR_RESPONSE *response))
DEFINE_WRAPPED_SYSCALL(NtReadFile, (HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user, IO_STATUS_BLOCK *io, void *buffer, ULONG length, LARGE_INTEGER *offset, ULONG *key))
DEFINE_SYSCALL(NtReadFileScatter, (HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user, IO_STATUS_BLOCK *io, FILE_SEGMENT_ELEMENT *segments, ULONG length, LARGE_INTEGER *offset, ULONG *key))
DEFINE_SYSCALL(NtReadRequestData, (HANDLE handle, LPC_MESSAGE *request, ULONG id, void *buffer, ULONG len, ULONG *retlen))
DEFINE_SYSCALL(NtReadVirtualMemory, (HANDLE process, const void *addr, void *buffer, SIZE_T size, SIZE_T *bytes_read))
DEFINE_SYSCALL(NtRegisterThreadTerminatePort, (HANDLE handle))
DEFINE_SYSCALL(NtReleaseKeyedEvent, (HANDLE handle, const void *key, BOOLEAN alertable, const LARGE_INTEGER *timeout))
DEFINE_WRAPPED_SYSCALL(NtReleaseMutant, (HANDLE handle, LONG *prev_count))
DEFINE_SYSCALL(NtReleaseSemaphore, (HANDLE handle, LONG count, ULONG *previous))
DEFINE_SYSCALL(NtRemoveIoCompletion, (HANDLE handle, ULONG_PTR *key, ULONG_PTR *value, IO_STATUS_BLOCK *io, LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtRemoveIoCompletionEx, (HANDLE handle, FILE_IO_COMPLETION_INFORMATION *info, ULONG count, ULONG *written, LARGE_INTEGER *timeout, BOOLEAN alertable))
DEFINE_SYSCALL(NtRemoveProcessDebug, (HANDLE process, HANDLE debug))
DEFINE_SYSCALL(NtRenameKey, (HANDLE key, UNICODE_STRING *name))
DEFINE_SYSCALL(NtReplaceKey, (OBJECT_ATTRIBUTES *attr, HANDLE key, OBJECT_ATTRIBUTES *replace))
DEFINE_SYSCALL(NtReplyPort, (HANDLE handle, LPC_MESSAGE *reply))
DEFINE_SYSCALL(NtReplyWaitReceivePort, (HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg))
DEFINE_SYSCALL(NtReplyWaitReceivePortEx, (HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg, LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtRequestWaitReplyPort, (HANDLE handle, LPC_MESSAGE *msg_in, LPC_MESSAGE *msg_out))
DEFINE_SYSCALL(NtResetEvent, (HANDLE handle, LONG *prev_state))
DEFINE_SYSCALL(NtResetWriteWatch, (HANDLE process, PVOID base, SIZE_T size))
DEFINE_SYSCALL(NtRestoreKey, (HANDLE key, HANDLE file, ULONG flags))
DEFINE_SYSCALL(NtResumeProcess, (HANDLE handle))
DEFINE_SYSCALL(NtResumeThread, (HANDLE handle, ULONG *count))
DEFINE_SYSCALL(NtRollbackTransaction, (HANDLE transaction, BOOLEAN wait))
DEFINE_SYSCALL(NtSaveKey, (HANDLE key, HANDLE file))
DEFINE_SYSCALL(NtSecureConnectPort, (HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos, LPC_SECTION_WRITE *write, PSID sid, LPC_SECTION_READ *read, ULONG *max_len, void *info, ULONG *info_len))
DEFINE_WRAPPED_SYSCALL(NtSetContextThread, (HANDLE handle, const ARM64_NT_CONTEXT *context))
DEFINE_SYSCALL(NtSetDebugFilterState, (ULONG component_id, ULONG level, BOOLEAN state))
DEFINE_SYSCALL(NtSetDefaultLocale, (BOOLEAN user, LCID lcid))
DEFINE_SYSCALL(NtSetDefaultUILanguage, (LANGID lang))
DEFINE_SYSCALL(NtSetEaFile, (HANDLE handle, IO_STATUS_BLOCK *io, void *buffer, ULONG length))
DEFINE_WRAPPED_SYSCALL(NtSetEvent, (HANDLE handle, LONG *prev_state))
DEFINE_SYSCALL(NtSetEventBoostPriority, (HANDLE handle))
DEFINE_SYSCALL(NtSetInformationDebugObject, (HANDLE handle, DEBUGOBJECTINFOCLASS class, void *info, ULONG len, ULONG *ret_len))
DEFINE_SYSCALL(NtSetInformationFile, (HANDLE handle, IO_STATUS_BLOCK *io, void *ptr, ULONG len, FILE_INFORMATION_CLASS class))
DEFINE_SYSCALL(NtSetInformationJobObject, (HANDLE handle, JOBOBJECTINFOCLASS class, void *info, ULONG len))
DEFINE_SYSCALL(NtSetInformationKey, (HANDLE key, int class, void *info, ULONG length))
DEFINE_SYSCALL(NtSetInformationObject, (HANDLE handle, OBJECT_INFORMATION_CLASS info_class, void *ptr, ULONG len))
DEFINE_WRAPPED_SYSCALL(NtSetInformationProcess, (HANDLE handle, PROCESSINFOCLASS class, void *info, ULONG size))
DEFINE_WRAPPED_SYSCALL(NtSetInformationThread, (HANDLE handle, THREADINFOCLASS class, const void *data, ULONG length))
DEFINE_SYSCALL(NtSetInformationToken, (HANDLE token, TOKEN_INFORMATION_CLASS class, void *info, ULONG length))
DEFINE_SYSCALL(NtSetInformationVirtualMemory, (HANDLE process, VIRTUAL_MEMORY_INFORMATION_CLASS info_class, ULONG_PTR count, PMEMORY_RANGE_ENTRY addresses, PVOID ptr, ULONG size))
DEFINE_SYSCALL(NtSetIntervalProfile, (ULONG interval, KPROFILE_SOURCE source))
DEFINE_SYSCALL(NtSetIoCompletion, (HANDLE handle, ULONG_PTR key, ULONG_PTR value, NTSTATUS status, SIZE_T count))
DEFINE_SYSCALL(NtSetIoCompletionEx, (HANDLE completion_handle, HANDLE completion_reserve_handle, ULONG_PTR key, ULONG_PTR value, NTSTATUS status, SIZE_T count))
DEFINE_SYSCALL(NtSetLdtEntries, (ULONG sel1, ULONG entry1_low, ULONG entry1_high, ULONG sel2, ULONG entry2_low, ULONG entry2_high))
DEFINE_SYSCALL(NtSetSecurityObject, (HANDLE handle, SECURITY_INFORMATION info, PSECURITY_DESCRIPTOR descr))
DEFINE_SYSCALL(NtSetSystemInformation, (SYSTEM_INFORMATION_CLASS class, void *info, ULONG length))
DEFINE_SYSCALL(NtSetSystemTime, (const LARGE_INTEGER *new, LARGE_INTEGER *old))
DEFINE_SYSCALL(NtSetThreadExecutionState, (EXECUTION_STATE new_state, EXECUTION_STATE *old_state))
DEFINE_SYSCALL(NtSetTimer, (HANDLE handle, const LARGE_INTEGER *when, PTIMER_APC_ROUTINE callback, void *arg, BOOLEAN resume, ULONG period, BOOLEAN *state))
DEFINE_SYSCALL(NtSetTimerResolution, (ULONG res, BOOLEAN set, ULONG *current_res))
DEFINE_SYSCALL(NtSetValueKey, (HANDLE key, const UNICODE_STRING *name, ULONG index, ULONG type, const void *data, ULONG count))
DEFINE_SYSCALL(NtSetVolumeInformationFile, (HANDLE handle, IO_STATUS_BLOCK *io, void *info, ULONG length, FS_INFORMATION_CLASS class))
DEFINE_SYSCALL(NtShutdownSystem, (SHUTDOWN_ACTION action))
DEFINE_SYSCALL(NtSignalAndWaitForSingleObject, (HANDLE signal, HANDLE wait, BOOLEAN alertable, const LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtSuspendProcess, (HANDLE handle))
DEFINE_SYSCALL(NtSuspendThread, (HANDLE handle, ULONG *count))
DEFINE_SYSCALL(NtSystemDebugControl, (SYSDBG_COMMAND command, void *in_buff, ULONG in_len, void *out_buff, ULONG out_len, ULONG *retlen))
DEFINE_SYSCALL(NtTerminateJobObject, (HANDLE handle, NTSTATUS status))
DEFINE_WRAPPED_SYSCALL(NtTerminateProcess, (HANDLE handle, LONG exit_code))
DEFINE_WRAPPED_SYSCALL(NtTerminateThread, (HANDLE handle, LONG exit_code))
DEFINE_SYSCALL(NtTestAlert, (void))
DEFINE_SYSCALL(NtTraceControl, (ULONG code, void *inbuf, ULONG inbuf_len, void *outbuf, ULONG outbuf_len, ULONG *size))
DEFINE_SYSCALL(NtTraceEvent, (HANDLE handle, ULONG flags, ULONG size, void *data))
DEFINE_SYSCALL(NtUnloadDriver, (const UNICODE_STRING *name))
DEFINE_SYSCALL(NtUnloadKey, (OBJECT_ATTRIBUTES *attr))
DEFINE_SYSCALL(NtUnlockFile, (HANDLE handle, IO_STATUS_BLOCK *io_status, LARGE_INTEGER *offset, LARGE_INTEGER *count, ULONG *key))
DEFINE_SYSCALL(NtUnlockVirtualMemory, (HANDLE process, PVOID *addr, SIZE_T *size, ULONG unknown))
DEFINE_WRAPPED_SYSCALL(NtUnmapViewOfSection, (HANDLE process, PVOID addr))
DEFINE_WRAPPED_SYSCALL(NtUnmapViewOfSectionEx, (HANDLE process, PVOID addr, ULONG flags))
DEFINE_WRAPPED_SYSCALL(NtWaitForAlertByThreadId, (const void *address, const LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtWaitForDebugEvent, (HANDLE handle, BOOLEAN alertable, LARGE_INTEGER *timeout, DBGUI_WAIT_STATE_CHANGE *state))
DEFINE_SYSCALL(NtWaitForKeyedEvent, (HANDLE handle, const void *key, BOOLEAN alertable, const LARGE_INTEGER *timeout))
DEFINE_WRAPPED_SYSCALL(NtWaitForMultipleObjects, (DWORD count, const HANDLE *handles, WAIT_TYPE type, BOOLEAN alertable, const LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtWaitForMultipleObjects32, (ULONG count, LONG *handles, WAIT_TYPE type, BOOLEAN alertable, const LARGE_INTEGER *timeout))
DEFINE_WRAPPED_SYSCALL(NtWaitForSingleObject, (HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout))
DEFINE_SYSCALL(NtWorkerFactoryWorkerReady, (HANDLE handle))
DEFINE_SYSCALL(NtWriteFile, (HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user, IO_STATUS_BLOCK *io, const void *buffer, ULONG length, LARGE_INTEGER *offset, ULONG *key))
DEFINE_SYSCALL(NtWriteFileGather, (HANDLE file, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user, IO_STATUS_BLOCK *io, FILE_SEGMENT_ELEMENT *segments, ULONG length, LARGE_INTEGER *offset, ULONG *key))
DEFINE_SYSCALL(NtWriteRequestData, (HANDLE handle, LPC_MESSAGE *request, ULONG id, void *buffer, ULONG len, ULONG *retlen))
DEFINE_SYSCALL(NtWriteVirtualMemory, (HANDLE process, void *addr, const void *buffer, SIZE_T size, SIZE_T *bytes_written))
DEFINE_WRAPPED_SYSCALL(NtYieldExecution, (void))

/* madeira [crashmailer-dump]: defined after [exc-ring] */
enum { IOS_CMD_QIP = 1, IOS_CMD_QSI, IOS_CMD_QSIX, IOS_CMD_QIT, IOS_CMD_SIT, IOS_CMD_QO, IOS_CMD_CLOSE, IOS_CMD_SIP };
static void ios_cmd_q_hook( ULONG fn, HANDLE handle, ULONG cls, NTSTATUS status, const void *data, ULONG len,
                            const ULONG *retlen );
static void ios_cmd_getctx( HANDLE handle, const CONTEXT *context, ULONG want, NTSTATUS status );
void ios_cmd_continue(void);

NTSTATUS SYSCALL_API NtAllocateVirtualMemory( HANDLE process, PVOID *ret, ULONG_PTR zero_bits,
                                              SIZE_T *size_ptr, ULONG type, ULONG protect )
{
    BOOL is_current = RtlIsCurrentProcess( process );
    NTSTATUS status;

    if (!enter_syscall_callback())
        return syscall_NtAllocateVirtualMemory( process, ret, zero_bits, size_ptr, type, protect );

    if (!*ret && (type & MEM_COMMIT)) type |= MEM_RESERVE;

    if (!is_current) send_cross_process_notification( process, CrossProcessPreVirtualAlloc,
                                                      *ret, *size_ptr, 3, type, protect, 0 );
    else if (pNotifyMemoryAlloc) pNotifyMemoryAlloc( *ret, *size_ptr, type, protect, FALSE, 0 );

    status = syscall_NtAllocateVirtualMemory( process, ret, zero_bits, size_ptr, type, protect );

    if (!is_current) send_cross_process_notification( process, CrossProcessPostVirtualAlloc,
                                                      *ret, *size_ptr, 3, type, protect, status );
    else if (pNotifyMemoryAlloc) pNotifyMemoryAlloc( *ret, *size_ptr, type, protect, TRUE, status );

    /* ml387 probe: each new guest thread costs 2x128MB of un-named
     * reserve-only VA ([guest-reserve] census) and the guest band hit 38MB
     * free. Name the owner: ret= is the PE caller for wine/FEX-PE callers or
     * the FEX syscall stub for guest x86 callers; ZERO hits while the unix
     * census still grows means the reserves are FEX host-side (unixlib). */
    if (is_current && !status && (type & MEM_RESERVE) && !(type & MEM_COMMIT) && *size_ptr >= 0x4000000)
    {
        static ULONG big_n;
        if (big_n < 24)
        {
            big_n++;
            ERR( "[big-reserve] addr=%p size=%Ix type=%lx prot=%lx ret=%p\n",
                 *ret, *size_ptr, type, protect, __builtin_return_address(0) );
        }
    }

    leave_syscall_callback();
    return status;
}

NTSTATUS SYSCALL_API NtAllocateVirtualMemoryEx( HANDLE process, PVOID *ret, SIZE_T *size_ptr, ULONG type,
                                                ULONG protect, MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    BOOL is_current = RtlIsCurrentProcess( process );
    NTSTATUS status;

    if (!enter_syscall_callback())
        return syscall_NtAllocateVirtualMemoryEx( process, ret, size_ptr, type, protect, parameters, count );

    if (!*ret && (type & MEM_COMMIT)) type |= MEM_RESERVE;

    if (!is_current) send_cross_process_notification( process, CrossProcessPreVirtualAlloc,
                                                      *ret, *size_ptr, 3, type, protect, 0 );
    else if (pNotifyMemoryAlloc) pNotifyMemoryAlloc( *ret, *size_ptr, type, protect, FALSE, 0 );

    status = syscall_NtAllocateVirtualMemoryEx( process, ret, size_ptr, type, protect, parameters, count );

    if (!is_current) send_cross_process_notification( process, CrossProcessPostVirtualAlloc,
                                                      *ret, *size_ptr, 3, type, protect, status );
    else if (pNotifyMemoryAlloc) pNotifyMemoryAlloc( *ret, *size_ptr, type, protect, TRUE, status );

    leave_syscall_callback();
    return status;
}

/* madeira-bcd [subpage-sweep] (env MADEIRA_SUBPAGE_SWEEP = 0 turns it off).
 *
 * iOS pages are 16 KB; Windows pages are 4 KB. Wine gives a host page the union of its four
 * 4 KB protections (virtual_ios.c get_host_page_vprot: "Return the union of the page protection
 * bytes of all the pages making up the host page"). Overwatch 2's loader keeps its .text
 * PAGE_NOACCESS per 4 KB page and decrypts a page when touching it faults. Once one 4 KB page of a
 * host page is unlocked, its locked neighbours become readable while still ENCRYPTED, so a read
 * never faults and the game uses garbage. 0.2.75 log e59342d7: a switch at Overwatch.exe
 * 141C5AFBB read its jump table at 141C5B49C (page 141C5B000, bytes still encrypted, same host
 * page as the decrypted 141C5A000) and jumped to Rcx=00000001533C7640 -> c0000005, 20 s in.
 *
 * Idea from NutsEmu's notes 0203/0205 (study only, our own code). Only while a thread is
 * dispatching a REAL access violation on a PAGE_NOACCESS image page ("armed"): when that thread
 * unlocks a 4 KB page of the image and other 4 KB pages of the same host page are still
 * PAGE_NOACCESS in the same image, remember them; when the thread resumes from that dispatch
 * (NtContinue, not alertable) at a pc in the same image, hand it a read access violation for each
 * one still locked, so the game's handler unlocks (decrypts) them as it would on Windows when they
 * are first touched. At most 8 raises per armed chain. Also logs re-locks that leave a host page
 * mixed (evidence for a later step). */
#define IOS_SP_HOST 0x4000   /* iOS host page size; the guest page is 4 KB */
#define IOS_SP_SLOTS 64
#define IOS_SP_CHAIN_MAX 8

static struct ios_sp_slot
{
    LONG tid;              /* owner thread, 0 = free; only the owner writes the other fields */
    LONG n;                /* queued pages */
    LONG armed;            /* dispatching an AV on a locked page of alloc_base */
    LONG chain;            /* raises since the last real AV */
    ULONG_PTR alloc_base;  /* image the pages belong to */
    ULONG_PTR armed_sp;    /* v3: tick count when armed (name kept) */
    ULONG_PTR last_page, last_rip;   /* the last synthetic AV, so its own dispatch is not "real" */
    ULONG_PTR page[6];     /* the other 4 KB pages of at most two host pages */
} ios_sp_slots[IOS_SP_SLOTS];
static LONG ios_sp_mode;   /* 0 = unread, 1 = off, 2 = on */
static LONG ios_sp_noted, ios_sp_raised, ios_sp_relocks, ios_sp_capped;

static BOOL ios_sp_on(void)
{
    if (!ios_sp_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        RtlInitUnicodeString( &var, L"MADEIRA_SUBPAGE_SWEEP" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_sp_mode = (!RtlQueryEnvironmentVariable_U( NULL, &var, &value ) &&
                       value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[subpage-sweep] %s (env.MADEIRA_SUBPAGE_SWEEP = 0 turns it off) rev=subpage-sweep-3\n",
             ios_sp_mode == 2 ? "on" : "off" );
    }
    return ios_sp_mode == 2;
}

static struct ios_sp_slot *ios_sp_slot_get( BOOL create )
{
    LONG tid = (LONG)HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
    unsigned i;

    for (i = 0; i < IOS_SP_SLOTS; i++) if (ios_sp_slots[i].tid == tid) return &ios_sp_slots[i];
    if (!create) return NULL;
    for (i = 0; i < IOS_SP_SLOTS; i++)
        if (!InterlockedCompareExchange( &ios_sp_slots[i].tid, tid, 0 ))
        {
            struct ios_sp_slot *slot = &ios_sp_slots[i];
            slot->n = slot->armed = slot->chain = 0;
            slot->alloc_base = slot->last_page = slot->last_rip = slot->armed_sp = 0;
            return slot;
        }
    {
        static LONG full;
        if (InterlockedIncrement( &full ) <= 4) ERR( "[subpage-sweep] thread table full, no sweep\n" );
    }
    return NULL;
}

static void ios_sp_slot_free( struct ios_sp_slot *slot )
{
    slot->n = slot->armed = slot->chain = 0;
    InterlockedExchange( &slot->tid, 0 );   /* claims only CAS 0 -> tid, so this is the owner's last write */
}

/* v3: the main exe's range from its PE header (no loader lock); 0.2.76 log af6b8f01 showed no
 * queue at all, so the image test no longer depends on MEMORY_BASIC_INFORMATION.Type */
static BOOL ios_sp_in_main_image( ULONG_PTR addr, ULONG_PTR *base_out )
{
    static ULONG_PTR lo, hi;
    if (!hi)
    {
        ULONG_PTR base = (ULONG_PTR)NtCurrentTeb()->Peb->ImageBaseAddress;
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS64 nt;
        SIZE_T got;
        if (!base ||
            NtReadVirtualMemory( GetCurrentProcess(), (void *)base, &dos, sizeof(dos), &got ) || got != sizeof(dos) ||
            dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000 ||
            NtReadVirtualMemory( GetCurrentProcess(), (void *)(base + dos.e_lfanew), &nt, sizeof(nt), &got ) ||
            got != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE) return FALSE;
        lo = base;
        __sync_synchronize();   /* publish lo before hi: readers test hi first */
        hi = base + nt.OptionalHeader.SizeOfImage;
    }
    if (base_out) *base_out = lo;
    return addr >= lo && addr < hi;
}

static BOOL ios_sp_query( ULONG_PTR addr, MEMORY_BASIC_INFORMATION *mbi )
{
    SIZE_T len = 0;
    return !NtQueryVirtualMemory( GetCurrentProcess(), (void *)addr, MemoryBasicInformation,
                                  mbi, sizeof(*mbi), &len ) && len >= sizeof(*mbi);
}

static BOOL ios_sp_locked_image_page( ULONG_PTR page, ULONG_PTR alloc_base, ULONG_PTR *base_out )
{
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR base;
    if (!ios_sp_in_main_image( page, &base )) return FALSE;
    if (!ios_sp_query( page, &mbi ) || mbi.State != MEM_COMMIT || mbi.Protect != PAGE_NOACCESS) return FALSE;
    if (base_out) *base_out = base;
    return !alloc_base || base == alloc_base;
}

/* armed only while this code runs inside that dispatch, i.e. below the faulting stack pointer;
 * a resume that skipped NtContinue (own register restore, thread death) leaves a stale arm,
 * which this drops the next time it is looked at */
static BOOL ios_sp_still_armed( struct ios_sp_slot *slot, const void *here )
{
    /* v3: the x64 stack and this code's stack differ under FEX here (0.2.76: guest Rsp
     * 0x707923FFA8, native sp 0x70ebd70000), so an sp test is meaningless; an arm lasts 500 ms */
    if (!slot->armed) return FALSE;
    if (NtGetTickCount() - (ULONG)slot->armed_sp < 500) return TRUE;
    {
        static LONG stale;
        LONG k = InterlockedIncrement( &stale );
        if (k <= 8 || !(k % 256))
            ERR( "[subpage-sweep] stale arm dropped (armed %lu ms ago, %ld queued)\n",
                 NtGetTickCount() - (ULONG)slot->armed_sp, slot->n );
    }
    ios_sp_slot_free( slot );
    return FALSE;
}

/* called from prepare_exception_arm64ec for every access violation */
static void ios_sp_note_av( const EXCEPTION_RECORD *rec, ULONG_PTR sp )
{
    struct ios_sp_slot *slot;
    ULONG_PTR addr, base = 0;

    if (ios_sp_mode == 1 || rec->NumberParameters < 2) return;
    addr = rec->ExceptionInformation[1];
    if (ios_sp_in_main_image( addr, NULL ))
    {
        static LONG seen;
        MEMORY_BASIC_INFORMATION mbi;
        if (seen < 16 && InterlockedIncrement( &seen ) <= 16 && ios_sp_on() && ios_sp_query( addr & ~(ULONG_PTR)0xfff, &mbi ))
            ERR( "[subpage-sweep] av %lu of %p in main image: state %lx type %lx protect %lx base %p\n",
                 (unsigned long)rec->ExceptionInformation[0], (void *)addr, mbi.State, mbi.Type, mbi.Protect,
                 mbi.AllocationBase );
    }
    if (!ios_sp_locked_image_page( addr & ~(ULONG_PTR)0xfff, 0, &base )) return;   /* not a locked image page */
    if (!ios_sp_on() || !(slot = ios_sp_slot_get( TRUE ))) return;
    if (slot->alloc_base != base) slot->n = 0;
    slot->alloc_base = base;
    slot->armed = 1;
    slot->armed_sp = NtGetTickCount();
    (void)sp;
    if (!(addr - (addr & 0xfff) == slot->last_page && (ULONG_PTR)rec->ExceptionAddress == slot->last_rip))
        slot->chain = 0;   /* a real fault starts a new chain; our own raise continues it */
}

/* called after a successful protect in the current process; addr/size are the rounded results */
static void ios_sp_note_protect( ULONG_PTR addr, SIZE_T size, ULONG new_prot, ULONG old )
{
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR host, q, alloc_base;
    struct ios_sp_slot *slot;
    BOOL unlock, relock;

    if (!size || size >= IOS_SP_HOST || ios_sp_mode == 1) return;
    if (ios_sp_in_main_image( addr, NULL ))
    {
        static LONG seen;
        struct ios_sp_slot *s0;
        if (seen < 48 && InterlockedIncrement( &seen ) <= 48 && ios_sp_on() && ((s0 = ios_sp_slot_get( FALSE )) || 1))
            ERR( "[subpage-sweep] protect %p+0x%lx old %lx new %lx armed %d\n", (void *)addr,
                 (unsigned long)size, old, new_prot, s0 ? (int)s0->armed : -1 );
    }
    unlock = old == PAGE_NOACCESS && (new_prot & 0xff) != PAGE_NOACCESS;
    relock = old != PAGE_NOACCESS && (new_prot & 0xff) == PAGE_NOACCESS;
    if (!unlock && !relock) return;
    slot = ios_sp_slot_get( FALSE );
    if (unlock && (!slot || !ios_sp_still_armed( slot, &mbi ))) return;   /* only inside a real locked-page AV's dispatch */
    if (!ios_sp_on()) return;
    if (!ios_sp_in_main_image( addr, &alloc_base )) return;

    for (host = addr & ~(ULONG_PTR)(IOS_SP_HOST - 1); host < addr + size; host += IOS_SP_HOST)
    {
        if (relock)
        {
            /* evidence only: a re-lock next to a page that stays open leaves the host page readable */
            for (q = host; q < host + IOS_SP_HOST; q += 0x1000)
            {
                if (q >= addr && q < addr + size) continue;
                if (ios_sp_in_main_image( q, NULL ) && ios_sp_query( q, &mbi ) && mbi.State == MEM_COMMIT &&
                    mbi.Protect != PAGE_NOACCESS)
                {
                    LONG k = InterlockedIncrement( &ios_sp_relocks );
                    if (k <= 16 || !(k % 256))
                        ERR( "[subpage-sweep] relock #%ld %p+0x%lx next to open %p (prot %lx): host page %p stays readable\n",
                             k, (void *)addr, (unsigned long)size, (void *)q, mbi.Protect, (void *)host );
                    break;
                }
            }
            continue;
        }
        if (slot->alloc_base != alloc_base) continue;   /* armed for another image */
        for (q = host; q < host + IOS_SP_HOST; q += 0x1000)
        {
            LONG i;
            BOOL have = FALSE;
            if (q >= addr && q < addr + size) continue;
            if (!ios_sp_locked_image_page( q, alloc_base, NULL )) continue;
            for (i = 0; i < slot->n; i++) if (slot->page[i] == q) have = TRUE;
            if (have || slot->n >= (LONG)ARRAY_SIZE(slot->page)) continue;
            slot->page[slot->n++] = q;
            {
                LONG k = InterlockedIncrement( &ios_sp_noted );
                if (k <= 32 || !(k % 256))
                    ERR( "[subpage-sweep] #%ld unlock of %p (was NOACCESS, now %lx) leaves %p locked in host page %p: queued\n",
                         k, (void *)addr, new_prot, (void *)q, (void *)host );
            }
        }
    }
}

/* called from NtContinue/NtContinueEx: raise a read AV for the next still-locked queued page */
static void ios_sp_continue( CONTEXT *context, BOOL alertable )
{
    struct ios_sp_slot *slot;
    MEMORY_BASIC_INFORMATION mbi;

    if (ios_sp_mode != 2 || !(slot = ios_sp_slot_get( FALSE ))) return;
    if (alertable || !ios_sp_still_armed( slot, &mbi )) return;   /* APC resume etc.: not the end of a locked-page dispatch */
    if (slot->n && ios_sp_in_main_image( context->Rip, NULL ))
    {
        while (slot->n)
        {
            ULONG_PTR page = slot->page[--slot->n];
            EXCEPTION_RECORD rec;
            LONG k;

            if (!ios_sp_locked_image_page( page, slot->alloc_base, NULL )) continue;   /* unlocked meanwhile */
            if (slot->chain >= IOS_SP_CHAIN_MAX)
            {
                k = InterlockedIncrement( &ios_sp_capped );
                if (k <= 8 || !(k % 256))
                    ERR( "[subpage-sweep] chain cap %d hit at %p (page %p still locked): stopping this chain\n",
                         IOS_SP_CHAIN_MAX, (void *)context->Rip, (void *)page );
                break;
            }
            memset( &rec, 0, sizeof(rec) );
            rec.ExceptionCode = STATUS_ACCESS_VIOLATION;
            rec.ExceptionAddress = (void *)context->Rip;
            rec.NumberParameters = 2;
            rec.ExceptionInformation[0] = EXCEPTION_READ_FAULT;
            rec.ExceptionInformation[1] = page;
            slot->chain++;
            slot->last_page = page;
            slot->last_rip = context->Rip;
            k = InterlockedIncrement( &ios_sp_raised );
            if (k <= 32 || !(k % 256))
                ERR( "[subpage-sweep] raise #%ld AV READ of %p at Rip=%p (%ld left, chain %ld)\n",
                     k, (void *)page, (void *)context->Rip, slot->n, slot->chain );
            NtRaiseException( &rec, context, TRUE );   /* does not return when dispatch starts */
            return;
        }
    }
    if (slot->n)
    {
        static LONG dropped;
        LONG k = InterlockedIncrement( &dropped );
        if (k <= 8 || !(k % 256))
            ERR( "[subpage-sweep] resume at %p outside the image: %ld queued page(s) dropped\n",
                 (void *)context->Rip, slot->n );
    }
    ios_sp_slot_free( slot );   /* chain over: nothing queued, nothing left to raise */
}

/* madeira [pfaf-keep] (env MADEIRA_EC_PFAF_KEEP = 0 turns it off, here and in xtajit64). rev=pfaf-keep-2.
 *
 * An ARM64EC context has room for NZCV (+SS) of the x86 EFLAGS only, so PF and AF were lost both
 * ways: the guest's exception handler always saw PF=AF=0, and the code it resumed (same RIP or the
 * new RIP it chose) ran with whatever PF/AF the handler code computed last (xtajit64
 * SyncThreadContext takes them from the live JIT state). Overwatch 2's protector steps obfuscated
 * code through int3 exceptions, its handler picking the next RIP each time (0.2.79 log 80f5a778:
 * "[set-ctx] ml946 ... req pc=0x70eaa91e92" after "Exception: Code: 80000003 Address: 70EAA91E93"),
 * and decrypts pages on fault. Online: GameNative/proton-wine PR #47 and GameNative/FEX patch 0001
 * (Dmage22, MIT/LGPL): Blizzard's loader resumes a decrypt fault on a `jp`; they carry PF/AF in
 * CPSR bits 26/27 both ways. Here: out to the guest the same way (xtajit64 sets the bits, unwind.h
 * cpsr_to_eflags maps them); back WITHOUT CPSR bits, because on this port the unix syscall frame
 * masks the cpsr with cpsr_user_mask (bit 27 lost) and writes it to the host PSTATE. Instead the
 * x64 context's PF/AF are stashed per thread here and put into ContextAmd64 by dispatch_emulation
 * when the resume RIP/RSP match, with reserved EFLAGS bit 15 set to tell xtajit64 they are real. */
static LONG ios_pfaf_mode, ios_pfaf_logged;   /* 0 not read, 1 off, 2 on */

static BOOL ios_pfaf_enabled(void)
{
    if (!ios_pfaf_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        RtlInitUnicodeString( &var, L"MADEIRA_EC_PFAF_KEEP" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_pfaf_mode = (!RtlQueryEnvironmentVariable_U( NULL, &var, &value ) &&
                         value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[pfaf-keep] rev=pfaf-keep-2 %s\n", ios_pfaf_mode == 2 ? "on" : "off (MADEIRA_EC_PFAF_KEEP=0)" );
    }
    return ios_pfaf_mode == 2;
}

/* madeira [pfaf-int3] (env MADEIRA_EC_PFAF_INT3 = 0 turns it off; needs [pfaf-keep] on). rev=pfaf-int3-2. Ours.
 * pfaf-keep-2's known gap: an int3 / ud / single-step trap reaches the guest through FEX's RaiseException and the unix
 * NtRaiseException syscall, whose frame keeps CPSR bit 26 (PF) but masks bit 27 (AF). The guest's handler then saw
 * AF=0, and since NtContinue stashes the handler's flags for the resume, the code also resumed with AF=0. Real x64
 * Windows gives the handler the true AF. xtajit64 keeps the PF/AF of its last raise with the guest RIP/RSP; this puts
 * them into the handler's context when the context is that raise's (same RIP and RSP). Nothing else changes. */
static LONG ios_pfaf_int3_mode, ios_pfaf_int3_logged;   /* 0 not read, 1 off, 2 on */

static void ios_pfaf_int3( CONTEXT *context )
{
    ULONG r;

    if (!pBTCpu64IosRaisePfAf) return;
    /* ios_pfaf_enabled() reads the environment through the PEB lock: only once loader_init() has set it up */
    if (ios_pfaf_mode ? ios_pfaf_mode != 2 : (!NtCurrentTeb()->Peb->FastPebLock || !ios_pfaf_enabled()))
    {
        pBTCpu64IosRaisePfAf( 0, 0 );   /* use up a saved value anyway (review-2 SHOULD 1); FEX keeps none when off */
        return;
    }
    if (!ios_pfaf_int3_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        RtlInitUnicodeString( &var, L"MADEIRA_EC_PFAF_INT3" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_pfaf_int3_mode = (!RtlQueryEnvironmentVariable_U( NULL, &var, &value ) &&
                              value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[pfaf-int3] rev=pfaf-int3-2 %s\n", ios_pfaf_int3_mode == 2 ? "on" : "off (MADEIRA_EC_PFAF_INT3=0)" );
    }
    if (ios_pfaf_int3_mode != 2) return;
    if (!(r = pBTCpu64IosRaisePfAf( context->Rip, context->Rsp ))) return;
    if ((context->EFlags & 0x14) != (r & 0x14))
    {
        LONG n = InterlockedIncrement( &ios_pfaf_int3_logged );
        if (n <= 16 || !(n % 5000))
            ERR( "[pfaf-int3] handler context rip=%p PF/AF %lx -> %lx n=%ld\n", (void *)context->Rip,
                 context->EFlags & 0x14, r & 0x14, n );
    }
    context->EFlags = (context->EFlags & ~0x14) | (r & 0x14);
}

static void ios_pfaf_stash( const CONTEXT *context )
{
    struct ec_thread_state *st;

    if ((context->ContextFlags & CONTEXT_AMD64_CONTROL) != CONTEXT_AMD64_CONTROL || !ios_pfaf_enabled()) return;
    st = ec_state();
    if (st == &ec_state_fallback) return;   /* not an EC thread */
    /* an alertable resume can run an APC first, whose own NtContinue carries the same rip/rsp but
     * PF/AF lost in the ARM round trip: keep the first, real values */
    if (st->pfaf_valid && st->pfaf_rip == context->Rip && st->pfaf_rsp == context->Rsp) return;
    st->pfaf_rip = context->Rip;
    st->pfaf_rsp = context->Rsp;
    st->pfaf_bits = context->EFlags & 0x14;
    st->pfaf_valid = 1;
}

/* dispatch_emulation: the thread resumes x64 code from this context */
static void ios_pfaf_apply( CONTEXT *context )
{
    struct ec_thread_state *st;

    if (ios_pfaf_mode != 2) return;
    st = ec_state();
    if (st == &ec_state_fallback || !st->pfaf_valid) return;
    st->pfaf_valid = 0;
    if (st->pfaf_rip != context->Rip || st->pfaf_rsp != context->Rsp) return;
    context->EFlags = (context->EFlags & ~0x14) | st->pfaf_bits | 0x8000;   /* bit 15: PF/AF valid */
    if (st->pfaf_bits)
    {
        LONG n = InterlockedIncrement( &ios_pfaf_logged );
        if (n <= 16 || !(n % 5000))
            ERR( "[pfaf-keep] resume rip=%p with PF/AF=%lx n=%ld\n", (void *)context->Rip, st->pfaf_bits, n );
    }
}

/* madeira [df-ctx] Credit: BOR1NG (Avery Felts, https://github.com/aaf2tbz), MetalSharp-Wine FEX patch 0004 / Wine patch 0017
 * (MIT/LGPL). env MADEIRA_EC_DF_CTX = 0 turns it off, here and in xtajit64. rev=df-ctx-1.
 *
 * The [pfaf-keep] design, for the direction flag. Out to the guest's exception handler: xtajit64 writes DF
 * through at STD/CLD/POPF (so a fault later in the block sees it) and sets CPSR bit 16; unwind.h cpsr_to_eflags
 * maps it. Back: not through CPSR (cpsr_user_mask drops bit 16 in the unix frame), so the x64 context's DF is
 * stashed per thread here and put into ContextAmd64 by dispatch_emulation when the resume RIP/RSP match, with
 * reserved EFLAGS bit 3 set to tell xtajit64 it is real (bit 15 is [pfaf-keep]'s). Without it xtajit64 resumes
 * with the DF of the live JIT state, i.e. of the handler code, whatever the handler put in the context. xtajit64
 * trusts the mark only after an exception it delivered with bit 16 (not for traps raised through the unix syscall
 * path, which masks bit 16 so the handler saw DF=0). */
static LONG ios_df_mode, ios_df_logged;   /* 0 not read, 1 off, 2 on */

static BOOL ios_df_enabled(void)
{
    if (!ios_df_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        PEB *peb = NtCurrentTeb()->Peb;
        /* as in ios_xstate_revert(): before loader_init() FastPebLock is NULL, so read the block itself */
        WCHAR *env = peb->FastPebLock ? NULL : peb->ProcessParameters->Environment;
        RtlInitUnicodeString( &var, L"MADEIRA_EC_DF_CTX" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_df_mode = (!RtlQueryEnvironmentVariable_U( env, &var, &value ) &&
                       value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[df-ctx] rev=df-ctx-1 %s\n", ios_df_mode == 2 ? "on" : "off (MADEIRA_EC_DF_CTX=0)" );
    }
    return ios_df_mode == 2;
}

static void ios_df_stash( const CONTEXT *context )
{
    struct ec_thread_state *st;

    if ((context->ContextFlags & CONTEXT_AMD64_CONTROL) != CONTEXT_AMD64_CONTROL || !ios_df_enabled()) return;
    st = ec_state();
    if (st == &ec_state_fallback) return;   /* not an EC thread */
    /* as [pfaf-keep]: an APC run first by an alertable resume continues with the same rip/rsp, keep the first */
    if (st->df_valid && st->df_rip == context->Rip && st->df_rsp == context->Rsp) return;
    st->df_rip = context->Rip;
    st->df_rsp = context->Rsp;
    st->df_bits = context->EFlags & 0x400;
    st->df_valid = 1;
}

/* dispatch_emulation: the thread resumes x64 code from this context */
static void ios_df_apply( CONTEXT *context )
{
    struct ec_thread_state *st;

    if (ios_df_mode != 2) return;
    st = ec_state();
    if (st == &ec_state_fallback || !st->df_valid) return;
    st->df_valid = 0;
    if (st->df_rip != context->Rip || st->df_rsp != context->Rsp) return;
    context->EFlags = (context->EFlags & ~0x400) | st->df_bits | 0x8;   /* bit 3: DF valid */
    if (st->df_bits)
    {
        LONG n = InterlockedIncrement( &ios_df_logged );
        if (n <= 16 || !(n % 5000))
            ERR( "[df-ctx] resume rip=%p with DF=1 n=%ld\n", (void *)context->Rip, n );
    }
}

/* madeira [dr-pass] (env MADEIRA_EC_DEBUG_REGS = 0 turns it off). rev=dr-pass-1.
 *
 * x64 debug registers (Dr0-Dr3, Dr6, Dr7) for emulated code. context_x64_to_arm() has nowhere to
 * put them, so until now a SetThreadContext / NtContinue with CONTEXT_DEBUG_REGISTERS silently
 * dropped them and a GetThreadContext or an exception context returned whatever was in memory.
 * FEX keeps them in its per-thread state and already turns instruction breakpoints into
 * EXCEPTION_SINGLE_STEP; this hands them over (xtajit64 BTCpu64IosDebugRegs). Current thread
 * only; another thread's debug registers are logged, not applied.
 * Online: FEX #6099 ("needs Debug Register support" for the Overwatch loader on ARM64EC),
 * MetalSharp-Wine 4614051 (passes them on NtContinue / NtSetContextThread / NtGetContextThread).
 * Our own code. */
static LONG ios_dr_mode, ios_dr_logged;   /* mode: 0 not read, 1 off, 2 on */

static BOOL ios_dr_enabled(void)
{
    if (!ios_dr_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        RtlInitUnicodeString( &var, L"MADEIRA_EC_DEBUG_REGS" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_dr_mode = (!RtlQueryEnvironmentVariable_U( NULL, &var, &value ) &&
                       value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[dr-pass] rev=dr-pass-1 %s, xtajit64 export %s\n", ios_dr_mode == 2 ? "on" : "off (MADEIRA_EC_DEBUG_REGS=0)",
             pBTCpu64IosDebugRegs ? "found" : "missing" );
    }
    return ios_dr_mode == 2 && pBTCpu64IosDebugRegs;
}

static BOOL ios_dr_log_ok(void)
{
    LONG n = InterlockedIncrement( &ios_dr_logged );
    return n <= 32 || !(n % 1000);
}

static BOOL ios_dr_is_self( HANDLE handle )
{
    THREAD_BASIC_INFORMATION tbi;

    if (handle == GetCurrentThread()) return TRUE;
    if (NtQueryInformationThread( handle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL )) return FALSE;
    return tbi.ClientId.UniqueThread == NtCurrentTeb()->ClientId.UniqueThread;
}

/* the x64 context's debug registers -> FEX, for the current thread */
static void ios_dr_apply( const CONTEXT *context, const char *why )
{
    ULONG64 regs[6], old[6];

    if ((context->ContextFlags & CONTEXT_AMD64_DEBUG_REGISTERS) != CONTEXT_AMD64_DEBUG_REGISTERS) return;
    if (!ios_dr_enabled()) return;
    regs[0] = context->Dr0; regs[1] = context->Dr1; regs[2] = context->Dr2; regs[3] = context->Dr3;
    regs[4] = context->Dr6; regs[5] = context->Dr7;
    if (!pBTCpu64IosDebugRegs( 0, old )) return;
    if (!memcmp( regs, old, sizeof(regs) )) return;
    pBTCpu64IosDebugRegs( 1, regs );
    if (ios_dr_log_ok())
        ERR( "[dr-pass] %s tid=%04lx rip=%p dr0=%p dr1=%p dr2=%p dr3=%p dr6=%p dr7=%p (was dr7=%p) eflags=%08lx\n",
             why, HandleToULong( NtCurrentTeb()->ClientId.UniqueThread ), (void *)context->Rip,
             (void *)regs[0], (void *)regs[1], (void *)regs[2], (void *)regs[3], (void *)regs[4], (void *)regs[5],
             (void *)old[5], (ULONG)context->EFlags );
}

/* x86 RF (resume flag) is not emulated: resuming ON an enabled instruction breakpoint with RF set
 * would fire it again. Logged so a loop shows up in the log. */
static void ios_dr_check_rf( const CONTEXT *context )
{
    ULONG64 regs[6];
    int i;

    if (!(context->EFlags & 0x10000) || !ios_dr_enabled() || !pBTCpu64IosDebugRegs( 0, regs ) || !(regs[5] & 0xff)) return;
    for (i = 0; i < 4; i++)
        if (((regs[5] >> (2 * i)) & 3) && !((regs[5] >> (16 + 4 * i)) & 3) && regs[i] == context->Rip && ios_dr_log_ok())
            ERR( "[dr-pass] RF resume on breakpoint %d at %p: RF is not emulated, it will fire again\n", i, (void *)context->Rip );
}

/* FEX -> the x64 context, for the current thread */
static void ios_dr_fill( CONTEXT *context )
{
    ULONG64 regs[6];

    if (!ios_dr_enabled() || !pBTCpu64IosDebugRegs( 0, regs )) return;
    context->Dr0 = regs[0]; context->Dr1 = regs[1]; context->Dr2 = regs[2]; context->Dr3 = regs[3];
    context->Dr6 = regs[4]; context->Dr7 = regs[5];
    context->ContextFlags |= CONTEXT_AMD64_DEBUG_REGISTERS;
}

/* madeira [xstate-revert] (env MADEIRA_EC_XSTATE_REVERT = 0 turns it off).
 *
 * Credit: BOR1NG (Avery Felts, https://github.com/aaf2tbz), MetalSharp-Wine
 * 5af8c40642 "ntdll: Revert the ARM64EC XSTATE context series from Wine 11.22"
 * (https://github.com/metalsharp/MetalSharp-Wine/pull/64): the 17 upstream Wine
 * 11.22 commits that carry AVX state through ARM64EC contexts "make Overwatch's
 * loader stop on an int3 under FEX". His change reverts them in the source. Ours
 * is our own runtime version of the same thing, written from upstream Wine
 * (LGPL-2.1) and no MetalSharp code: while the switch is on, every x64 context
 * this file builds or reads behaves as in Wine 11.21 -
 *   - exception, APC, emulation and thread-start contexts carry no CONTEXT_XSTATE
 *     (flags come from the ARM context, as 11.21's context_arm_to_x64() did);
 *   - NtGetContextThread ignores a CONTEXT_XSTATE request (11.21 had no XSTATE);
 *   - NtContinue(Ex) / NtSetContextThread / NtRaiseException ignore the XSTATE
 *     area of the context they are given (11.21 never read it).
 * The frame layouts (struct xcontext, the 0x670 KiUserExceptionDispatcher frame)
 * stay; [ki-legacy-frame] already hands a hooked x64 dispatcher the 0x4d0 frame.
 * The unix side (init_shared_data_cpuinfo) reads the same variable. */
static LONG ios_xsr_mode;   /* 0 not read, 1 off, 2 on */

static BOOL ios_xstate_revert(void)
{
    if (!ios_xsr_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        PEB *peb = NtCurrentTeb()->Peb;
        /* The first call comes from LdrInitializeThunk, before loader_init() has set
         * FastPebLock: RtlQueryEnvironmentVariable_U( NULL, ... ) would take that NULL lock.
         * Passing the environment block itself takes no lock; the process has one thread
         * then, so reading it unlocked is safe (and the mode is cached from then on). */
        WCHAR *env = peb->FastPebLock ? NULL : peb->ProcessParameters->Environment;
        RtlInitUnicodeString( &var, L"MADEIRA_EC_XSTATE_REVERT" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_xsr_mode = (!RtlQueryEnvironmentVariable_U( env, &var, &value ) &&
                        value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[xstate-revert] rev=xstate-revert-2 %s\n", ios_xsr_mode == 2 ? "on" : "off (MADEIRA_EC_XSTATE_REVERT=0)" );
        if (ios_xsr_mode == 2 && (user_shared_data->XState.EnabledFeatures & XSTATE_MASK_AVX))
            ERR( "[xstate-revert] AVX is advertised (MADEIRA_FEX_AVX=1) but contexts carry no YMM state: "
                 "use MADEIRA_EC_XSTATE_REVERT=0 for a game that needs AVX across exceptions\n" );
    }
    return ios_xsr_mode == 2;
}

/* madeira [ctx-x64-fields] (env MADEIRA_EC_CTX_X64_FIELDS = 0 turns it off). rev=ctx-x64-fields-1.
 *
 * Credit: BOR1NG (Avery Felts, https://github.com/aaf2tbz), MetalSharp-Wine d100ac4215 "ntdll: Give an
 * x64 exception context its segment registers and x87 control word, and recognise hot-patchable
 * export prologues" (LGPL-2.1,
 * https://github.com/metalsharp/MetalSharp-Wine). An exception context built from an ARM64 context
 * said nothing of segments (no CONTEXT_SEGMENTS, though the selectors are filled in) and had an x87
 * control word of 0, where x64 Windows hands a handler CONTEXT_SEGMENTS and 0x27f. His commit: protection
 * code compares the context its exception handler gets with what x64 Windows gives it. (Our own 0.2.88
 * log: Overwatch's loader takes ~537 int3 traps through its own handler before its check.) Ours applies
 * it to exception contexts only, after init_xcontext(). */
static LONG ios_cxf_mode;   /* 0 not read, 1 off, 2 on */

static void ios_ctx_x64_fields( CONTEXT *context )
{
    if (!ios_cxf_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        PEB *peb = NtCurrentTeb()->Peb;
        /* as in ios_xstate_revert(): before loader_init() FastPebLock is NULL, so read the block itself */
        WCHAR *env = peb->FastPebLock ? NULL : peb->ProcessParameters->Environment;
        RtlInitUnicodeString( &var, L"MADEIRA_EC_CTX_X64_FIELDS" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_cxf_mode = (!RtlQueryEnvironmentVariable_U( env, &var, &value ) &&
                        value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[ctx-x64-fields] rev=ctx-x64-fields-1 %s\n", ios_cxf_mode == 2 ? "on" : "off (MADEIRA_EC_CTX_X64_FIELDS=0)" );
    }
    if (ios_cxf_mode != 2) return;
    if ((context->ContextFlags & CONTEXT_AMD64_CONTROL) == CONTEXT_AMD64_CONTROL)
        context->ContextFlags |= CONTEXT_AMD64_SEGMENTS;
    if (!context->FltSave.ControlWord) context->FltSave.ControlWord = 0x27f;
}

/* [xstate-revert]: context_x64_to_arm() without reading the caller's XSTATE area. */
static NTSTATUS ios_x64_to_arm( ARM64_NT_CONTEXT *arm_ctx, const CONTEXT *context )
{
    ARM64EC_NT_CONTEXT copy;

    if (!ios_xstate_revert() || (context->ContextFlags & CONTEXT_AMD64_XSTATE) != CONTEXT_AMD64_XSTATE)
        return context_x64_to_arm( arm_ctx, (const ARM64EC_NT_CONTEXT *)context );
    memcpy( &copy, context, sizeof(copy) );
    copy.ContextFlags &= ~(CONTEXT_AMD64_XSTATE & ~CONTEXT_AMD64);
    return context_x64_to_arm( arm_ctx, &copy );
}

NTSTATUS SYSCALL_API NtContinue( CONTEXT *context, BOOLEAN alertable )
{
    ARM64_NT_CONTEXT arm_ctx;
    NTSTATUS status;

    ios_cmd_continue();                      /* madeira [crashmailer-dump]: a handler that continues is done */
    ios_sp_continue( context, alertable );   /* madeira-bcd [subpage-sweep] */
    ios_dr_apply( context, "continue" );     /* madeira [dr-pass] */
    ios_pfaf_stash( context );               /* madeira [pfaf-keep] */
    ios_df_stash( context );                 /* madeira [df-ctx] */
    ios_dr_check_rf( context );

    if ((status = ios_x64_to_arm( &arm_ctx, context ))) return status;   /* madeira [xstate-revert] */
    return syscall_NtContinue( &arm_ctx, alertable );
}

NTSTATUS SYSCALL_API NtContinueEx( CONTEXT *context, KCONTINUE_ARGUMENT *args )
{
    ARM64_NT_CONTEXT arm_ctx;
    NTSTATUS status;

    ios_cmd_continue();   /* madeira [crashmailer-dump] */
    /* [subpage-sweep]; a value <= 0xff is the legacy BOOLEAN alertable form */
    ios_sp_continue( context, (ULONG_PTR)args <= 0xff ? (ULONG_PTR)args != 0
                                                      : (args->ContinueFlags & 1 /* KCONTINUE_FLAG_TEST_ALERT */) != 0 );
    ios_dr_apply( context, "continue-ex" );  /* madeira [dr-pass] */
    ios_pfaf_stash( context );               /* madeira [pfaf-keep] */
    ios_df_stash( context );                 /* madeira [df-ctx] */
    ios_dr_check_rf( context );

    if ((status = ios_x64_to_arm( &arm_ctx, context ))) return status;   /* madeira [xstate-revert] */
    return syscall_NtContinueEx( &arm_ctx, args );
}

NTSTATUS SYSCALL_API NtFlushInstructionCache( HANDLE process, const void *addr, SIZE_T size )
{
    NTSTATUS status = syscall_NtFlushInstructionCache( process, addr, size );

    if (!status && enter_syscall_callback())
    {
        if (!RtlIsCurrentProcess( process ))
            send_cross_process_notification( process, CrossProcessFlushCache, addr, size, 0 );
        else if (pBTCpu64FlushInstructionCache)
            pBTCpu64FlushInstructionCache( addr, size );
        leave_syscall_callback();
    }
    return status;
}

NTSTATUS SYSCALL_API NtDeviceIoControlFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc,
                                            void *apc_context, IO_STATUS_BLOCK *io, ULONG code,
                                            void *in_buffer, ULONG in_size, void *out_buffer,
                                            ULONG out_size )
{
    /* ml388 (task #66): three runs died writing the IO_STATUS_BLOCK from the
     * unix side of THIS syscall — NULL (ml385: server_ioctl_file `stp` through
     * x9=0), pool-band garbage (ml386), and misaligned 0x7200000103 (ml388:
     * set_async_direct_result <- sock_send, a BUS not a SEGV, which is what
     * gives the family away: the pointer is not merely unmapped, it is
     * MALFORMED). wine writes into it unconditionally (set_sync_iosb), so a
     * malformed one is an unrecoverable native fault mid-pseudo-process.
     *
     * Reject cheaply — this is the hot socket path (every AFD send/recv), so
     * NO SEH probe and no NtQueryVirtualMemory here: an IO_STATUS_BLOCK is
     * pointer-aligned by contract, and both observed bad values fail that in
     * one AND. Returning a status keeps the pseudo-process alive and the
     * [iosb-guard] line names the caller so the corruption source can be
     * chased offline. */
    if (!io || ((ULONG_PTR)io & (sizeof(void *) - 1)) || (ULONG_PTR)io >= 0x8000000000ull)
    {
        static ULONG bogus_n;
        if (bogus_n < 16)
        {
            bogus_n++;
            ERR( "[iosb-guard] #%lu MALFORMED iosb %p (handle=%p code=%lx in=%p/%lu out=%p/%lu "
                 "ret=%p) — failing the call instead of faulting unix-side\n",
                 bogus_n, io, handle, code, in_buffer, in_size, out_buffer, out_size,
                 __builtin_return_address(0) );
        }
        return STATUS_ACCESS_VIOLATION;
    }
    return syscall_NtDeviceIoControlFile( handle, event, apc, apc_context, io, code,
                                          in_buffer, in_size, out_buffer, out_size );
}

/* ml392 (task #60): SteamChrome named-object sniffer.  Section sharing is
 * fixed ([sec-test] MATCH) yet the webhelper-init hello still never reaches
 * CSteamUISharedJSController.  The handshake objects are known by name
 * (SteamChrome_MasterStream_spid%u / _Event_spid%u / _mutex / ClientStream);
 * log every create/open touching them, with result status, so the next run
 * maps the topology: who created what, whose open failed, where the chain
 * stops.  Substring match over a non-terminated UNICODE_STRING. */
static BOOL ios_name_is_steamchrome( const OBJECT_ATTRIBUTES *attr )
{
    const WCHAR *p;
    static const WCHAR key[] = {'S','t','e','a','m','C','h','r','o','m','e'};
    ULONG i, n;

    if (!attr || !attr->ObjectName || !attr->ObjectName->Buffer) return FALSE;
    p = attr->ObjectName->Buffer;
    n = attr->ObjectName->Length / sizeof(WCHAR);
    if (n < ARRAY_SIZE(key)) return FALSE;
    for (i = 0; i + ARRAY_SIZE(key) <= n; i++)
        if (!memcmp( p + i, key, sizeof(key) )) return TRUE;
    return FALSE;
}

/* ml394: data-plane tracking.  Creates/opens all succeed and steam retries
 * its client-connect 4x — the break is now in the signal/wait/read ping-pong.
 * Track SteamChrome handles at create/open, then log Set/Wait/Release/Close
 * ops on them (rate-limited).  Table is per-process (EC ntdll data is a
 * per-pseudo-process copy); races with the probe are tolerable. */
#define IOS_CHROME_HANDLES 64
static struct { HANDLE h; void *view; char tag[40]; } ios_chrome_handles[IOS_CHROME_HANDLES];
static LONG ios_chrome_handle_count;

static void ios_chrome_track( HANDLE h, const OBJECT_ATTRIBUTES *attr )
{
    int i, j, n;
    const WCHAR *p;
    LONG idx;

    if (!h) return;
    p = attr->ObjectName->Buffer;
    n = attr->ObjectName->Length / sizeof(WCHAR);
    for (i = 0; i < ios_chrome_handle_count && i < IOS_CHROME_HANDLES; i++)
        if (ios_chrome_handles[i].h == h) break;
    if (i >= IOS_CHROME_HANDLES) return;
    if (i == ios_chrome_handle_count)
    {
        idx = InterlockedIncrement( &ios_chrome_handle_count ) - 1;
        if (idx >= IOS_CHROME_HANDLES) return;
        i = idx;
    }
    /* keep the tail of the name (the distinctive part), narrowed */
    j = n > 38 ? n - 38 : 0;
    for (n = 0; j + n < (int)(attr->ObjectName->Length / sizeof(WCHAR)) && n < 38; n++)
        ios_chrome_handles[i].tag[n] = (char)p[j + n];
    ios_chrome_handles[i].tag[n] = 0;
    ios_chrome_handles[i].h = h;
}

static const char *ios_chrome_lookup( HANDLE h )
{
    int i;
    if (!ios_chrome_handle_count) return NULL;
    for (i = 0; i < ios_chrome_handle_count && i < IOS_CHROME_HANDLES; i++)
        if (ios_chrome_handles[i].h == h) return ios_chrome_handles[i].tag;
    return NULL;
}

/* ml398 (task #60, last hop): pump wakes on MasterStream_Event but never
 * replies and never re-waits.  Leading hypothesis: steam's hello write into
 * the master _mem never becomes visible through webhelper's view (the one
 * sharing direction [sec-test] never exercised).  Record where each tracked
 * SteamChrome section gets mapped, then hex-dump the first 64 bytes of every
 * "_mem" view at the three decisive moments: steam SetEvent(_written)
 * [what steam wrote], pump Wait1(Stream_Event)==0 [what webhelper sees],
 * steam Wait1(_written)==0x102 [is the hello still there at timeout].
 * Reads go through NtReadVirtualMemory so a stale view can't fault the
 * observed thread. */
static void ios_chrome_set_view( HANDLE h, void *base )
{
    int i;
    for (i = 0; i < ios_chrome_handle_count && i < IOS_CHROME_HANDLES; i++)
        if (ios_chrome_handles[i].h == h)
        {
            ios_chrome_handles[i].view = base;
            ERR( "[chrome-ipc] MapView %s base=%p\n", ios_chrome_handles[i].tag, base );
            return;
        }
}

static void ios_chrome_clear_view( void *base )
{
    int i;
    if (!base || !ios_chrome_handle_count) return;
    for (i = 0; i < ios_chrome_handle_count && i < IOS_CHROME_HANDLES; i++)
        if (ios_chrome_handles[i].view == base)
        {
            ERR( "[chrome-ipc] Unmap %s base=%p\n", ios_chrome_handles[i].tag, base );
            ios_chrome_handles[i].view = NULL;
        }
}

static const char *ios_strstr( const char *s, const char *sub )
{
    int i, j;
    for (i = 0; s[i]; i++)
    {
        for (j = 0; sub[j] && s[i + j] == sub[j]; j++) ;
        if (!sub[j]) return s + i;
    }
    return NULL;
}

static void ios_chrome_dump_views( const char *when )
{
    int i;
    static LONG dumps;
    if (dumps >= 64) return;
    for (i = 0; i < ios_chrome_handle_count && i < IOS_CHROME_HANDLES; i++)
    {
        ULONGLONG buf[8] = { 0 };
        SIZE_T got = 0;
        NTSTATUS st;
        if (!ios_chrome_handles[i].h || !ios_chrome_handles[i].view) continue;
        if (!ios_strstr( ios_chrome_handles[i].tag, "_mem" )) continue;
        if (InterlockedIncrement( &dumps ) > 64) return;
        st = NtReadVirtualMemory( GetCurrentProcess(), ios_chrome_handles[i].view, buf, sizeof(buf), &got );
        ERR( "[chrome-mem] %s %s @%p st=%lx: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx\n",
             when, ios_chrome_handles[i].tag, ios_chrome_handles[i].view, (ULONG)st,
             buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7] );
    }
}

#define SNIFF_STEAMCHROME(op, attr, status, handle_ptr) \
    do { if (ios_name_is_steamchrome( attr )) { \
        ERR( "[chrome-ipc] %s %s -> status=%lx handle=%p\n", op, \
             debugstr_us( (attr)->ObjectName ), (ULONG)(status), \
             (handle_ptr) ? *(handle_ptr) : NULL ); \
        if (!(status & 0x80000000) && (handle_ptr)) ios_chrome_track( *(handle_ptr), attr ); \
    } } while (0)

NTSTATUS SYSCALL_API NtCreateEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                    EVENT_TYPE type, BOOLEAN state )
{
    NTSTATUS status = syscall_NtCreateEvent( handle, access, attr, type, state );
    SNIFF_STEAMCHROME( "CreateEvent", attr, status, handle );
    /* ml399: the server thread stalled BEFORE its first park (last line =
     * this very CreateEvent), so the pump-wake beacon never armed.  Stamp the
     * CREATOR of the master event (status 0 = created, not opened-existing)
     * so [pump-sample] covers it from birth. */
    if (status == 0 && handle)
    {
        const char *tag = ios_chrome_lookup( *handle );
        if (tag && ios_strstr( tag, "Stream_Event" ))
        {
            NtCurrentTeb()->Instrumentation[10] = (void *)(ULONG_PTR)0x504d5550; /* 'PUMP' */
            ERR( "[pump-op] beacon armed on creator of %s\n", tag );
        }
    }
    return status;
}

NTSTATUS SYSCALL_API NtOpenEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS status = syscall_NtOpenEvent( handle, access, attr );
    SNIFF_STEAMCHROME( "OpenEvent", attr, status, handle );
    return status;
}

NTSTATUS SYSCALL_API NtCreateMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                     BOOLEAN owned )
{
    NTSTATUS status = syscall_NtCreateMutant( handle, access, attr, owned );
    SNIFF_STEAMCHROME( "CreateMutant", attr, status, handle );
    return status;
}

NTSTATUS SYSCALL_API NtOpenMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS status = syscall_NtOpenMutant( handle, access, attr );
    SNIFF_STEAMCHROME( "OpenMutant", attr, status, handle );
    return status;
}

NTSTATUS SYSCALL_API NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                      const LARGE_INTEGER *size, ULONG protect, ULONG sec_flags,
                                      HANDLE file )
{
    NTSTATUS status = syscall_NtCreateSection( handle, access, attr, size, protect, sec_flags, file );
    SNIFF_STEAMCHROME( "CreateSection", attr, status, handle );
    return status;
}

NTSTATUS SYSCALL_API NtOpenSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    NTSTATUS status = syscall_NtOpenSection( handle, access, attr );
    SNIFF_STEAMCHROME( "OpenSection", attr, status, handle );
    return status;
}

NTSTATUS SYSCALL_API NtSetEvent( HANDLE handle, LONG *prev_state )
{
    NTSTATUS status = syscall_NtSetEvent( handle, prev_state );
    const char *tag = ios_chrome_lookup( handle );
    static LONG n;
    if (tag && n < 200) { InterlockedIncrement( &n );
        ERR( "[chrome-ipc] SetEvent %s -> %lx\n", tag, (ULONG)status ); }
    if (tag && ios_strstr( tag, "_written" )) ios_chrome_dump_views( "set-written" );
    return status;
}

NTSTATUS SYSCALL_API NtReleaseMutant( HANDLE handle, LONG *prev_count )
{
    NTSTATUS status = syscall_NtReleaseMutant( handle, prev_count );
    const char *tag = ios_chrome_lookup( handle );
    static LONG n;
    if (tag && n < 200) { InterlockedIncrement( &n );
        ERR( "[chrome-ipc] ReleaseMutant %s -> %lx\n", tag, (ULONG)status ); }
    return status;
}

NTSTATUS SYSCALL_API NtWaitForSingleObject( HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    const char *tag = ios_chrome_lookup( handle );
    NTSTATUS status;
    static LONG n;
    if (tag && n < 200) { InterlockedIncrement( &n );
        ERR( "[chrome-ipc] Wait1 %s timeout=%s...\n", tag,
             timeout ? wine_dbgstr_longlong( timeout->QuadPart ) : "INF" ); }
    status = syscall_NtWaitForSingleObject( handle, alertable, timeout );
    if (tag && n < 200) { InterlockedIncrement( &n );
        ERR( "[chrome-ipc] Wait1 %s -> %lx\n", tag, (ULONG)status ); }
    if (tag && status == STATUS_SUCCESS && ios_strstr( tag, "Stream_Event" ))
    {
        ios_chrome_dump_views( "pump-wake" );
        /* ml398: beacon for the unix-side [pump-sample] Mach sampler — the
         * pump goes silent after this wake; mark its TEB so the census thread
         * can sample pc/run-state and settle spin vs blocked vs dead. */
        NtCurrentTeb()->Instrumentation[10] = (void *)(ULONG_PTR)0x504d5550; /* 'PUMP' */
    }
    if (tag && status == STATUS_TIMEOUT && ios_strstr( tag, "_written" ))
        ios_chrome_dump_views( "timeout" );
    return status;
}

NTSTATUS SYSCALL_API NtWaitForMultipleObjects( DWORD count, const HANDLE *handles, WAIT_TYPE type,
                                               BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    NTSTATUS status;
    DWORD i;
    int tracked = -1;
    static LONG n;
    if (ios_chrome_handle_count && handles)
        for (i = 0; i < count && i < 64; i++)
            if (ios_chrome_lookup( handles[i] )) { tracked = i; break; }
    if (tracked >= 0 && n < 200) { InterlockedIncrement( &n );
        ERR( "[chrome-ipc] WaitN count=%lu [%d]=%s timeout=%s...\n", (ULONG)count, tracked,
             ios_chrome_lookup( handles[tracked] ),
             timeout ? wine_dbgstr_longlong( timeout->QuadPart ) : "INF" ); }
    status = syscall_NtWaitForMultipleObjects( count, handles, type, alertable, timeout );
    if (tracked >= 0 && n < 200) { InterlockedIncrement( &n );
        ERR( "[chrome-ipc] WaitN [%d]=%s -> %lx\n", tracked,
             ios_chrome_lookup( handles[tracked] ), (ULONG)status ); }
    return status;
}

/* ml398: once the pump beacon is set, log the wait-family syscalls our
 * handle-tag sniffing can't see (critical sections block in
 * NtWaitForAlertByThreadId; sleeps and yields have no handle at all).  If the
 * silent pump lands in one of these, the log names the blocker. */
#define IOS_PUMP_MARKED() (NtCurrentTeb()->Instrumentation[10] == (void *)(ULONG_PTR)0x504d5550)

NTSTATUS SYSCALL_API NtWaitForAlertByThreadId( const void *address, const LARGE_INTEGER *timeout )
{
    NTSTATUS status;
    static LONG n;
    BOOL marked = IOS_PUMP_MARKED();
    if (marked && n < 40) { InterlockedIncrement( &n );
        ERR( "[pump-op] WaitForAlertByThreadId addr=%p timeout=%s...\n", address,
             timeout ? wine_dbgstr_longlong( timeout->QuadPart ) : "INF" ); }
    status = syscall_NtWaitForAlertByThreadId( address, timeout );
    if (marked && n < 40) { InterlockedIncrement( &n );
        ERR( "[pump-op] WaitForAlertByThreadId -> %lx\n", (ULONG)status ); }
    return status;
}

NTSTATUS SYSCALL_API NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    static LONG n;
    if (IOS_PUMP_MARKED() && n < 40) { InterlockedIncrement( &n );
        ERR( "[pump-op] DelayExecution timeout=%s\n",
             timeout ? wine_dbgstr_longlong( timeout->QuadPart ) : "INF" ); }
    return syscall_NtDelayExecution( alertable, timeout );
}

NTSTATUS SYSCALL_API NtYieldExecution(void)
{
    static LONG n;
    if (IOS_PUMP_MARKED() && n < 40) { InterlockedIncrement( &n );
        ERR( "[pump-op] YieldExecution\n" ); }
    return syscall_NtYieldExecution();
}

NTSTATUS SYSCALL_API NtClose( HANDLE handle )
{
    if (ios_chrome_handle_count)
    {
        int i;
        for (i = 0; i < ios_chrome_handle_count && i < IOS_CHROME_HANDLES; i++)
            if (ios_chrome_handles[i].h == handle)
            {
                ERR( "[chrome-ipc] Close %s\n", ios_chrome_handles[i].tag );
                ios_chrome_handles[i].h = NULL;
                ios_chrome_handles[i].view = NULL;
                break;
            }
    }
    {
        NTSTATUS status = syscall_NtClose( handle );
        if (status) ios_cmd_q_hook( IOS_CMD_CLOSE, handle, 0, status, NULL, 0, NULL );   /* madeira [crashmailer-dump] */
        return status;
    }
}

NTSTATUS SYSCALL_API NtFreeVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr, ULONG type )
{
    BOOL is_current = RtlIsCurrentProcess( process );
    NTSTATUS status;

    if (!enter_syscall_callback())
        return syscall_NtFreeVirtualMemory( process, addr_ptr, size_ptr, type );

    if (!is_current) send_cross_process_notification( process, CrossProcessPreVirtualFree,
                                                      *addr_ptr, *size_ptr, 2, type, 0 );
    else if (pNotifyMemoryFree) pNotifyMemoryFree( *addr_ptr, *size_ptr, type, FALSE, 0 );

    status = syscall_NtFreeVirtualMemory( process, addr_ptr, size_ptr, type );

    if (!is_current) send_cross_process_notification( process, CrossProcessPostVirtualFree,
                                                      *addr_ptr, *size_ptr, 2, type, status );
    else if (pNotifyMemoryFree) pNotifyMemoryFree( *addr_ptr, *size_ptr, type, TRUE, status );

    /* ml386 probe (task #57): same-region free livelock — CEF calls
     * NtFreeVirtualMemory on ONE 64KB range thousands of times while making no
     * progress (ml364: 5,901x; ml386: 1,787+ and climbing). Discriminate the
     * two possible drivers in one run: (a) our free silently fails (region
     * still committed/reserved after SUCCESS → the caller's retry is sane), or
     * (b) the free works and the caller loops for its own reasons (→ map the
     * host return address to a guest RIP offline via the JIT dump). */
    if (is_current)
    {
        static void *loop_addr;
        static ULONG loop_type, loop_n, loop_prints;
        if (*addr_ptr == loop_addr && type == loop_type)
        {
            loop_n++;
            if (loop_prints < 16 && (loop_n == 8 || (loop_n & 0x3ff) == 0))
            {
                MEMORY_BASIC_INFORMATION mbi = { 0 };
                SIZE_T got = 0;
                NtQueryVirtualMemory( NtCurrentProcess(), *addr_ptr, MemoryBasicInformation,
                                      &mbi, sizeof(mbi), &got );
                loop_prints++;
                ERR( "[free-loop] addr=%p size=%Ix type=%lx status=%lx repeats=%lu ret=%p | "
                     "after: state=%lx protect=%lx region=%p+%Ix\n",
                     *addr_ptr, *size_ptr, type, status, loop_n, __builtin_return_address(0),
                     mbi.State, mbi.Protect, mbi.BaseAddress, mbi.RegionSize );
            }
        }
        else
        {
            loop_addr = *addr_ptr;
            loop_type = type;
            loop_n = 1;
        }
    }

    leave_syscall_callback();
    return status;
}

/* madeira [getctx-guest] (env MADEIRA_GETCTX_GUEST = 0 turns it off; on by default). rev=getctx-guest-2. Ours.
 *
 * NtGetContextThread on another thread of this process that is suspended inside FEX's translated code
 * used to hand back the native ARM64 registers converted with the ARM64EC mapping: Rip a JIT code-buffer
 * address, Rsp the host sp, and the flags without PF/AF. Real x64 Windows hands back the guest state.
 * When the native pc is not EC code, the target is in this process, is not the caller, and is suspended
 * (ThreadSuspendCount > 0, so its JIT block cannot change under us), xtajit64's BTCpu64IosGuestContext
 * rebuilds the guest registers from that same native context. Anywhere else (EC code, a syscall, the
 * dispatcher) the export returns 0 and the old answer stands. The native context is always fetched with
 * CONTROL|INTEGER|FLOATING_POINT in that case, because the guest RIP, RSP and PF/AF need all of them; only
 * the parts the caller asked for are converted. */
static LONG ios_gcg_mode;   /* 0 not read, 1 off, 2 on */

static BOOL ios_getctx_guest_on(void)
{
    if (!ios_gcg_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        PEB *peb = NtCurrentTeb()->Peb;
        WCHAR *env = peb->FastPebLock ? NULL : peb->ProcessParameters->Environment;   /* as ios_xstate_revert */
        RtlInitUnicodeString( &var, L"MADEIRA_GETCTX_GUEST" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_gcg_mode = (!RtlQueryEnvironmentVariable_U( env, &var, &value ) &&
                        value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[getctx-guest] rev=getctx-guest-2 %s, export %s\n",
             ios_gcg_mode == 2 ? "on" : "off (MADEIRA_GETCTX_GUEST=0)",
             pBTCpu64IosGuestContext ? "found" : "missing" );
    }
    return ios_gcg_mode == 2 && pBTCpu64IosGuestContext;
}

/* returns TRUE when arm_ctx now holds the guest view. No server call: the target's TEB is the snapshot's x18
 * (ARM64EC keeps the TEB there, also in FEX's JIT); xtajit64 checks it and reads the target only through
 * checked reads, and never writes it. The rebuild works on a copy, so a refusal leaves arm_ctx untouched. */
static BOOL ios_getctx_guest( ARM64_NT_CONTEXT *arm_ctx )
{
    static LONG log_n;
    ARM64_NT_CONTEXT copy;

    if (RtlIsEcCode( arm_ctx->Pc ) || !arm_ctx->X18 || arm_ctx->X18 == (ULONG_PTR)NtCurrentTeb()) return FALSE;
    copy = *arm_ctx;
    if (!pBTCpu64IosGuestContext( (void *)(ULONG_PTR)arm_ctx->X18, &copy, 1 )) return FALSE;
    if (InterlockedIncrement( &log_n ) <= 32)
        ERR( "[getctx-guest] rev=getctx-guest-2 teb %p: native pc %I64x sp %I64x -> guest rip %I64x rsp %I64x\n",
             (void *)(ULONG_PTR)arm_ctx->X18, arm_ctx->Pc, arm_ctx->Sp, copy.Pc, copy.Sp );
    *arm_ctx = copy;
    return TRUE;
}

NTSTATUS SYSCALL_API NtGetContextThread( HANDLE handle, CONTEXT *context )
{
    /* madeira [xstate-revert]: as in Wine 11.21, a CONTEXT_XSTATE request is not served
     * (the XSTATE bit is dropped from the request and from the result). */
    const ULONG cmd_want = context->ContextFlags;   /* madeira [crashmailer-dump] */
    const ULONG xsr_want = ios_xstate_revert() ? (context->ContextFlags & ~(CONTEXT_AMD64_XSTATE & ~CONTEXT_AMD64))
                                               : context->ContextFlags;
    ARM64_NT_CONTEXT arm_ctx = { .ContextFlags = ctx_flags_x64_to_arm( xsr_want ) };
    const ULONG arm_want = arm_ctx.ContextFlags;   /* madeira [getctx-guest] */
    BOOL gcg;
    ULONG64 native_pc = 0;   /* madeira [getctx-guest] */
    NTSTATUS status;

    if ((xsr_want & CONTEXT_AMD64_XSTATE) == CONTEXT_AMD64_XSTATE)
    {
        CONTEXT_EX *context_ex = (CONTEXT_EX *)(context + 1);
        XSTATE *xstate = (XSTATE *)((char *)context_ex + context_ex->XState.Offset);

        if (context_ex->XState.Length < sizeof(XSAVE_AREA_HEADER) || context_ex->XState.Length > sizeof(*xstate))
            return STATUS_INVALID_PARAMETER;

        xstate->Mask &= XSTATE_MASK_AVX & RtlGetEnabledExtendedFeatures( XSTATE_MASK_AVX );
        xstate->CompactionMask = 0;
        if ((xstate->Mask & XSTATE_MASK_AVX) && context_ex->XState.Length < sizeof(*xstate))
            return STATUS_BUFFER_OVERFLOW;
    }

    gcg = handle != GetCurrentThread() && ios_getctx_guest_on();   /* madeira [getctx-guest] */
    /* the rebuild needs CONTROL (pc, NZCV) and INTEGER (the GPRs, x9/x24, x18); not FLOATING_POINT: xmm0-15
     * are already at v0-v15, so a caller that asks for them gets them, and MADEIRA_CTX_FP=0 does not matter */
    if (gcg) arm_ctx.ContextFlags |= CONTEXT_ARM64_CONTROL | CONTEXT_ARM64_INTEGER;
    status = syscall_NtGetContextThread( handle, &arm_ctx );
    native_pc = arm_ctx.Pc;   /* for the ml715 line below */
    if (!status)
    {
        ULONG want = context->ContextFlags;   /* madeira [dr-pass] */
        if (gcg)   /* madeira [getctx-guest] */
        {
            const ULONG need = CONTEXT_ARM64_CONTROL | CONTEXT_ARM64_INTEGER;
            /* only the bits this wrapper added and the caller did not ask for are taken away again; the rest of
             * the answer (CONTEXT_EXCEPTION_REPORTING, SERVICE_ACTIVE, EXCEPTION_ACTIVE ...) stays */
            const ULONG added = need & ~arm_want & ~CONTEXT_ARM64;
            /* YMM upper halves: this Wine has no FEX YMM context flag, and with [xstate-revert] (default) no
             * XSTATE is returned, so v16-v31 (JIT temporaries) never reach the caller as YMM-high */
            if ((arm_ctx.ContextFlags & need) == need) ios_getctx_guest( &arm_ctx );
            arm_ctx.ContextFlags &= ~added;
        }
        context_arm_to_x64( (ARM64EC_NT_CONTEXT *)context, &arm_ctx,
                            ctx_flags_arm_to_x64( arm_ctx.ContextFlags ) | (xsr_want & CONTEXT_AMD64_XSTATE));
        if ((want & CONTEXT_AMD64_DEBUG_REGISTERS) == CONTEXT_AMD64_DEBUG_REGISTERS && ios_dr_enabled())
        {
            if (ios_dr_is_self( handle )) ios_dr_fill( context );
            else if (ios_dr_log_ok())
                ERR( "[dr-pass] get of another thread's debug registers (handle %p) not filled\n", handle );
        }
    }

    /* ml715: WHAT THE CALLER ACTUALLY RECEIVES.
     *
     * This wrapper unconditionally asks for the NATIVE ARM context and converts it, and
     * context_arm_to_x64() maps Pc directly into Rip. That is right only while the target
     * is executing genuine ARM64EC code. If it is parked in FEX JIT, the dispatcher, or
     * plain Mach-O (libsystem_kernel __ulock_wait2), the "x64 RIP" handed back is not an
     * x64 address at all and the integer registers are ARM ABI values reinterpreted --
     * even though the server captured a perfectly good saved AMD64 context at the same
     * instant (see [srv-getctx]).
     *
     * RtlIsEcCode(native_pc) is logged because it is the likely selector for the fix:
     * EC code -> convert the native context; JIT/dispatcher/Mach-O -> return the saved
     * AMD64 context; neither available -> fail rather than manufacture one. InSimulation
     * alone is NOT sufficient, since a translated thread inside a Wine/Mach syscall can
     * have it clear while its correct Windows context is still the saved AMD64 one.
     *
     * Correlate with [srv-getctx] on native_pc (and tid), not on ordering. Capped. */
    {
        static LONG ec_getctx_n;
        LONG n = InterlockedIncrement( &ec_getctx_n );
        if (n <= 48)
        {
            ARM64EC_NT_CONTEXT *ec = (ARM64EC_NT_CONTEXT *)context;
            ERR( "[ec-getctx] ml715 #%d handle=%p status=%08x native_pc=%p is_ec=%d -> "
                 "returned rip=%p rsp=%p flags=%08x\n",
                 (int)n, handle, (unsigned int)status, (void *)(ULONG_PTR)native_pc,
                 status ? -1 : (RtlIsEcCode( native_pc ) ? 1 : 0),
                 status ? NULL : (void *)ec->Pc, status ? NULL : (void *)ec->Sp,
                 status ? 0 : (unsigned int)ec->ContextFlags );
        }
    }
    ios_cmd_getctx( handle, context, cmd_want, status );   /* madeira [crashmailer-dump] */
    return status;
}

/* iOS-Madeira ml188: SELF-TARGETING FILTER.
 *
 * A global cap is the wrong design when the event of interest is LATE: the ml187/ml188
 * probes burned their whole budget on early loader traffic (unexec #400 at log line 3048)
 * and went blind 2100 lines BEFORE libcef was even mapped (line 5176), so "0 events
 * touching libcef" was a blind spot, not a result.
 *
 * Instead: remember the range of any BIG image as it is mapped (libcef is 0xD3CA000; no
 * Wine DLL comes close), then log protect/unmap events ONLY when they fall inside one.
 * That is immune to ordering and keeps the log small. */
#define IOS_BIGIMG_MAX 4
static struct { ULONG_PTR base, size; } ios_bigimg[IOS_BIGIMG_MAX];
static unsigned ios_bigimg_n;

static void ios_note_big_image( void *addr, SIZE_T size )
{
    if (size < 0x1000000 || ios_bigimg_n >= IOS_BIGIMG_MAX) return;
    ios_bigimg[ios_bigimg_n].base = (ULONG_PTR)addr;
    ios_bigimg[ios_bigimg_n].size = size;
    ios_bigimg_n++;
    ERR( "[bigimg] tracking %p +%p for protect/unmap events\n", addr, (void *)size );
}

static int ios_in_big_image( ULONG_PTR a )
{
    unsigned i;
    for (i = 0; i < ios_bigimg_n; i++)
        if (a >= ios_bigimg[i].base && a < ios_bigimg[i].base + ios_bigimg[i].size) return 1;
    return 0;
}

/* iOS-Madeira ml187: unmap ALSO removes executable intervals
 * (InvalidationTracker::InvalidateContainingSection -> XIntervals.Remove), and this port
 * purges stale image mappings (#33). If libcef's view is unmapped and not re-notified, its
 * .text leaves XIntervals and every later decode there is NOEXEC. Log unmaps in the guest
 * PE band so they can be correlated against libcef's base. */
static void ios_log_unmap( void *addr )
{
    static int unmap_n;
    if (ios_in_big_image( (ULONG_PTR)addr ) && unmap_n < 200)
    {
        unmap_n++;
        ERR( "[unmap] #%d addr=%p\n", unmap_n, addr );
    }
}

/* MADEIRA_MAP_EXEC_VIEW, read once: 0 not yet, 1 off (value "0"), 2 on (default). */
static BOOL ios_map_exec_view_enabled( void )
{
    static LONG mode;

    if (!mode)
    {
        UNICODE_STRING name, value;
        WCHAR buffer[2];

        RtlInitUnicodeString( &name, L"MADEIRA_MAP_EXEC_VIEW" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        mode = (!RtlQueryEnvironmentVariable_U( NULL, &name, &value ) &&
                value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
    }
    return mode == 2;
}

/* Madeira ec-raw-image-metadata (Black Ops III, 0.2.79 run).
 *
 * An ARM64EC (or ARM64X) image's code reaches the emulator only through the
 * __os_arm64x_* pointer slots named in its CHPE metadata: every exit thunk,
 * indirect call and entry-thunk return loads one of them. Only the loader fills
 * them (update_load_config -> arm64ec_update_hybrid_metadata). An application that
 * maps an image section itself, without the loader, gets a view whose slots are all
 * 0, so its first outgoing call or return jumps to address 0. Black Ops III's
 * protector does exactly that with gdi32.dll (Wine bug 48171): the 0.2.79 run logs
 * "[map-notify] SKIP (no ArbitraryUserPointer) addr=0000000071ED590000" and then
 * "Unhandled exception code c0000005 flags 0 addr 0x0" in gdi32.dll+0x706a0.
 * On x64 Windows gdi32 is plain x64 with nothing to fill, so such a copy works.
 *
 * Fill the slots for views that were mapped without the loader, with the same
 * values the loader writes (they are process-wide, not per module). Loader views
 * carry an ArbitraryUserPointer and are left to update_load_config.
 * The idea was found in DroidDeck-Proton PR #34 (BSD-3-Clause repo), which copies
 * the slots from the loaded instance in unix virtual.c; this is our own code and
 * fills them directly instead. Off: env MADEIRA_EC_RAW_IMAGE_METADATA=0. */
static BOOL ios_ec_raw_image_metadata_enabled( void )
{
    static LONG mode;  /* 0 not read yet, 1 off, 2 on (default) */

    if (!mode)
    {
        UNICODE_STRING name, value;
        WCHAR buffer[2];

        RtlInitUnicodeString( &name, L"MADEIRA_EC_RAW_IMAGE_METADATA" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        mode = (!RtlQueryEnvironmentVariable_U( NULL, &name, &value ) &&
                value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
    }
    return mode == 2;
}

static void ios_fill_raw_image_metadata( HANDLE handle, void *addr, SIZE_T size )
{
    static LONG fill_n, skip_n;  /* separate caps, so skips cannot hide the fill line */
    SECTION_IMAGE_INFORMATION info;
    IMAGE_NT_HEADERS *nt;
    IMAGE_LOAD_CONFIG_DIRECTORY *cfg;
    ULONG cfg_size;
    ULONG_PTR rva;
    LONG n;

    if (!ios_ec_raw_image_metadata_enabled()) return;
    if (NtQuerySection( handle, SectionImageInformation, &info, sizeof(info), NULL )) return;
    if (!(nt = RtlImageNtHeader( addr ))) return;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return;
    if (nt->OptionalHeader.SizeOfImage > size) goto skip;  /* partial view */
    if (!(cfg = RtlImageDirectoryEntryToData( addr, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &cfg_size )))
        goto skip;
    cfg_size = min( cfg_size, cfg->Size );
    if (cfg_size <= offsetof( IMAGE_LOAD_CONFIG_DIRECTORY, CHPEMetadataPointer )) goto skip;
    if (!cfg->CHPEMetadataPointer) goto skip;  /* plain x64 image: nothing to fill */
    /* The unix side relocates a view to image_info->map_addr and stores that base in
     * OptionalHeader.ImageBase (upstream: the first view's base; iOS virtual_ios.c forces
     * it to this view's own address). Either way the pointer and ImageBase move together,
     * so the pointer is turned back into an RVA and used against THIS view. */
    rva = cfg->CHPEMetadataPointer - nt->OptionalHeader.ImageBase;
    if (rva >= nt->OptionalHeader.SizeOfImage ||
        rva + sizeof(IMAGE_ARM64EC_METADATA) > nt->OptionalHeader.SizeOfImage) goto skip;

    n = InterlockedIncrement( &fill_n );
    if (n <= 16)
        ERR( "[ec-raw-meta] #%d fill hybrid pointers in raw view %p (size %p, metadata rva %lx)"
             " (MADEIRA_EC_RAW_IMAGE_METADATA=0 turns this off)\n",
             (int)n, addr, (void *)size, (unsigned long)rva );
    arm64ec_update_hybrid_metadata( addr, nt, (const IMAGE_ARM64EC_METADATA *)((char *)addr + rva) );
    return;

skip:
    n = InterlockedIncrement( &skip_n );
    if (n <= 16) ERR( "[ec-raw-meta] #%d no fill for x64 image view %p (size %p)\n", (int)n, addr, (void *)size );
}

/* Madeira section-views (Overwatch 2, 0.2.82 run). Ported from MetalSharp-Wine
 * patches/wine/0132 (Avery Felts, AGPL-3.0; idea also in GameNative's FEX patch 0001/0003
 * and proton-wine #47). Overwatch_loader.dll re-maps itself as a pagefile-backed section:
 * an RW alias at 70D0DC0000 and RX views at its base, and our log shows neither reaches
 * the emulator ("[map-notify] SKIP (no ArbitraryUserPointer) addr=00000070D0DC0000
 * size=0000000002440000"). A write through the RW alias changes code FEX translated from
 * the RX view without any fault FEX can see, so the stale translation keeps running.
 * Hand every view of a DATA section (not an image) to the emulator with its section handle
 * and offset; xtajit64 groups views of one section and checks their code per instruction.
 * Image sections and every existing path below are unchanged. MADEIRA_EC_SECTION_VIEWS=0
 * turns it off. */
static BOOL ios_section_views_enabled( void )
{
    static LONG mode; /* 0 not read, 1 off, 2 on */

    if (!mode)
    {
        static const WCHAR nameW[] = {'M','A','D','E','I','R','A','_','E','C','_','S','E','C','T','I','O','N','_','V','I','E','W','S',0};
        WCHAR buffer[8];
        UNICODE_STRING name, value;

        RtlInitUnicodeString( &name, nameW );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        mode = (!RtlQueryEnvironmentVariable_U( NULL, &name, &value ) &&
                value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[section-views] rev=section-views-1 %s\n", mode == 2 ? "on" : "off (MADEIRA_EC_SECTION_VIEWS=0)" );
    }
    return mode == 2;
}

static void ios_notify_data_section_view( HANDLE handle, void *addr, SIZE_T size, ULONG alloc,
                                          ULONG protect, const LARGE_INTEGER *offset )
{
    SECTION_IMAGE_INFORMATION info;
    NTSTATUS status;
    static LONG logged;

    if (!pNotifyMapViewOfSection || !handle || !addr || !size) return;
    if (!ios_section_views_enabled()) return;
    /* only a section the server says is not an image; any other failure (e.g. no SECTION_QUERY
     * access on an image handle) keeps the old behaviour */
    status = NtQuerySection( handle, SectionImageInformation, &info, sizeof(info), NULL );
    if (status != STATUS_SECTION_NOT_IMAGE)
    {
        static LONG odd;
        if (status && InterlockedIncrement( &odd ) <= 8)
            ERR( "[section-views] view addr=%p size=%p not sent: NtQuerySection status %x\n", addr, (void *)size, (int)status );
        return;
    }
    if (InterlockedIncrement( &logged ) <= 32)
        ERR( "[section-views] data view addr=%p size=%p offset=%s prot=%x\n", addr, (void *)size,
             wine_dbgstr_longlong( offset ? offset->QuadPart : 0 ), protect );
    /* xtajit64 always answers STATUS_SUCCESS for a data view; never unmap on its answer. */
    pNotifyMapViewOfSection( handle, addr, (void *)(ULONG_PTR)(offset ? offset->QuadPart : 0), size, alloc, protect );
}

static void notify_map_view_of_section( HANDLE handle, void *addr, SIZE_T size, ULONG alloc,
                                        ULONG protect, NTSTATUS *ret_status )
{
    SECTION_IMAGE_INFORMATION info;
    NTSTATUS status;

    /* iOS-Madeira ml184 PROBE. FEX only treats a guest range as executable if
     * InvalidationTracker::XIntervals covers it, and that is populated ONLY from
     * HandleImageMap(), which runs off this notification. A skipped notify means every
     * later decode in that image returns NOEXEC -> NoExecOp -> FAULT_SIGSEGV -> the
     * GuestSignal_SIGSEGV trampoline -> dead thread. libcef.dll+0x1900733 and +0x3b508f0
     * still hit that trampoline after relaxing FEX's own ThreadState guard, so log which
     * of these three gates is dropping it. */
    {
        static int notify_probe;
        if (notify_probe < 40)
        {
            notify_probe++;
            ERR( "[map-notify] addr=%p size=%p alloc=%x prot=%x pfn=%d aup=%p\n",
                 addr, (void *)size, alloc, protect, !!pNotifyMapViewOfSection,
                 NtCurrentTeb()->Tib.ArbitraryUserPointer );
        }
    }
    if (!pNotifyMapViewOfSection) return;
    if (!NtCurrentTeb()->Tib.ArbitraryUserPointer)
    {
        static int skip_aup;
        /* map-exec-view: a view mapped with no ArbitraryUserPointer is not a loader image map,
         * so it is not handed to NotifyMapViewOfSection. If its protection asks for execute,
         * though (StarCraft's ClientSdk.dll: the image section mapped as plain data, protected
         * RWX, unmapped, then mapped again in pieces with the .text as PAGE_EXECUTE_READ), FEX
         * never learns the range is code: the unmap removed it from XIntervals and nothing adds
         * it back, so the first decode there is NOEXEC and the process dies with c0000005.
         * Tell FEX the way an [exec-req] NtProtectVirtualMemory does: the post-protect
         * notification for the same address, size and protection. Views with an
         * ArbitraryUserPointer and views without execute are left alone. */
        if ((protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            && pNotifyMemoryProtect && ios_map_exec_view_enabled())
        {
            static LONG exec_view_n;
            LONG n = InterlockedIncrement( &exec_view_n );
            if (n <= 16)
                ERR( "[map-exec-view] #%d base=%p size=%p prot=%x\n", (int)n, addr, (void *)size, protect );
            pNotifyMemoryProtect( addr, size, protect, TRUE, STATUS_SUCCESS );
        }
        if (skip_aup < 20)
        { skip_aup++; ERR( "[map-notify] SKIP (no ArbitraryUserPointer) addr=%p size=%p\n", addr, (void *)size ); }
        ios_fill_raw_image_metadata( handle, addr, size );
        return;
    }
    if (NtQuerySection( handle, SectionImageInformation, &info, sizeof(info), NULL ))
    {
        static int skip_qs;
        if (skip_qs < 20)
        { skip_qs++; ERR( "[map-notify] SKIP (not an image section) addr=%p size=%p\n", addr, (void *)size ); }
        return;
    }
    ios_note_big_image( addr, size );
    status = pNotifyMapViewOfSection( NULL, addr, NULL, size, alloc, protect );
    if (NT_SUCCESS(status)) return;
    NtUnmapViewOfSection( GetCurrentProcess(), addr );
    *ret_status = status;
}

/* iOS-Madeira ml709: WHICH GATE DROPS THE IMAGE NOTIFICATION?
 *
 * FEX only treats a guest range as executable if InvalidationTracker::XIntervals
 * covers it, and that is populated ONLY from HandleImageMap(), which runs off
 * notify_map_view_of_section(). In the GTA V run the child pseudo-process
 * registered just two images -- the main exe and ntdll, both of which FEX's own
 * ProcessInit inserts directly -- and every native x64 dependency was absent, so
 * the first one whose code was executed (d3dx9_43) decoded as NOEXEC, raised
 * NoExecOp, and took the GuestSignal_SIGSEGV trampoline that deliberately reads
 * address 0. That synthetic fault is what surfaced as c0000005; it is NOT a bad
 * pointer in the guest.
 *
 * The existing [map-notify] probe sits INSIDE the helper, which is only entered
 * after three outer gates, so its silence was ambiguous between four causes:
 *   (a) this wrapper is never called (images mapped by unix code directly),
 *   (b) the map failed,
 *   (c) RtlIsCurrentProcess() is false for a pseudo-process,
 *   (d) enter_syscall_callback() refused -- InSyscallCallback already set, which
 *       once stuck stays stuck and silently drops every later notification.
 * Log outside every gate so one run separates them. Zero [map-gate] lines
 * alongside the [jit-pool] image lines means (a) and nothing else. */

/* iOS-Madeira ml709: REGISTER IMAGES AT THE LOADER BOUNDARY, NOT THE SYSCALL BOUNDARY.
 *
 * FEX only treats a guest range as executable if InvalidationTracker::XIntervals covers
 * it, and that is populated from HandleImageMap(), which until now ran ONLY off
 * NtMapViewOfSection's notification. In a child pseudo-process that notification never
 * arrived: the GTA V run registered just two images -- the main exe and ntdll, both
 * inserted directly by FEX's own ProcessInit -- while every native x64 dependency was
 * absent, so the first one whose code was executed (d3dx9_43) decoded as NOEXEC, raised
 * NoExecOp, and took the GuestSignal_SIGSEGV trampoline that deliberately reads address
 * zero. The resulting c0000005 looked exactly like a bad pointer in the guest and is not
 * one. The direct-launch case registers 14 images and works, which is the control.
 *
 * The syscall notification stays (applications may map executable images without ever
 * loading them as modules), but it is no longer the only path. This one fires from the
 * loader's semantic "module is mapped, relocated and imported, no DllMain has run yet"
 * boundary, which is in safe PE/ARM64EC context, is keyed to the correct pseudo-process
 * by construction, and does not depend on any of the four syscall-path gates.
 *
 * Symmetry matters as much as the map: if registration bypasses the broken gate but
 * removal still depends on it, FEX keeps stale executable intervals across a DLL unload
 * and a later address reuse inherits them. So the unload boundary is wired too.
 *
 * Duplicate registration is harmless -- HandleImageMap re-inserts the same intervals --
 * so the direct-launch path can and does notify twice for the same image. */
void arm64ec_notify_image_map( void *base )
{
    static unsigned int n_map;
    static LONG guard;  /* MADEIRA_IMAGE_MAP_GUARD, read once: 0 not yet, 1 off, 2 on */
    BOOL entered = FALSE;

    /* ml710: must be the intervals-only entry point, NEVER NotifyMapViewOfSection.
     * The latter also drives ImageTracker, which takes FEX's CodeInvalidationMutex
     * EXCLUSIVELY; we are called from the loader on a thread that may already hold it
     * SHARED from executing translated code, and there is no read-to-write upgrade. That
     * combination froze Marvel Cosmic Invasion on cryptbase.dll for 88s with wine's
     * loader lock held. If pNotifyImageMap is absent, do nothing: the syscall path is
     * still authoritative, and a wedge is far worse than a missed registration. */
    if (!base || !pNotifyImageMap) return;
    n_map++;
    if (n_map <= 64)
        ERR( "[ldr-image] ml710 MAP #%u base=%p peb=%p\n", n_map, base, RtlGetCurrentPeb() );

    /* The emulator's image-map handler inserts the image's executable sections
     * while it holds its own interval lock, and the insert can allocate. When the
     * emulator's allocator has to commit a page, the commit goes through
     * NtAllocateVirtualMemory above, which, with InSyscallCallback clear as it is
     * here, notifies the same emulator of the allocation. That notification takes
     * the same interval lock, so the thread waits on itself for good with the
     * loader lock held. Every syscall-boundary notification sets InSyscallCallback
     * for exactly this reason: memory calls made by the notified emulator are not
     * notified again. MADEIRA_IMAGE_MAP_GUARD=1 makes this loader-boundary
     * notification do the same; off by default. If the flag is already set,
     * nested notifications are already suppressed and it is left alone.
     *
     * Device log: a 64-bit process parked for good right after the MAP line of
     * one of the imports of a DLL it was loading, its only thread in a wait for
     * an alert, with one commit of an emulator-heap page between the two and no
     * section insert logged for that image. */
    if (!guard)
    {
        UNICODE_STRING name, value;
        WCHAR buffer[2];

        RtlInitUnicodeString( &name, L"MADEIRA_IMAGE_MAP_GUARD" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        guard = (!RtlQueryEnvironmentVariable_U( NULL, &name, &value ) &&
                 value.Length == sizeof(WCHAR) && buffer[0] == '1') ? 2 : 1;
        if (guard == 2) ERR( "[ldr-image] image-map guard on (MADEIRA_IMAGE_MAP_GUARD=1)\n" );
    }
    if (guard == 2) entered = enter_syscall_callback();
    pNotifyImageMap( base );
    if (entered) leave_syscall_callback();
}

/* ml709b: UNUSED, deliberately. The loader must not call this -- see the long comment
 * at the removed call site in loader.c free_modref(). Kept only so the reasoning has a
 * home next to its map counterpart; wiring it up again re-freezes the process. */
void arm64ec_notify_image_unmap( void *base )
{
    static unsigned int n_unmap;

    if (!base || !pNotifyUnmapViewOfSection) return;
    n_unmap++;
    if (n_unmap <= 64)
        ERR( "[ldr-image] ml709 UNMAP #%u base=%p peb=%p\n", n_unmap, base, RtlGetCurrentPeb() );
    pNotifyUnmapViewOfSection( base, FALSE, 0 );
    pNotifyUnmapViewOfSection( base, TRUE, STATUS_SUCCESS );
}

static void ios_map_gate_probe( const char *who, HANDLE handle, HANDLE process, NTSTATUS status,
                                void *base, SIZE_T size, int is_cur, void *area,
                                int insc_before, int entered )
{
    static int n;
    if (n >= 48) return;
    n++;
    ERR( "[map-gate] ml709 %s handle=%p process=%p status=%x ok=%d cur=%d area=%p "
         "insc_before=%d entered=%d base=%p size=%p\n",
         who, handle, process, (unsigned int)status, NT_SUCCESS(status) ? 1 : 0, is_cur,
         area, insc_before, entered, base, (void *)size );
}

NTSTATUS SYSCALL_API NtMapViewOfSection( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                         ULONG_PTR zero_bits, SIZE_T commit_size,
                                         const LARGE_INTEGER *offset, SIZE_T *size_ptr,
                                         SECTION_INHERIT inherit, ULONG alloc_type, ULONG protect )
{
    NTSTATUS status = syscall_NtMapViewOfSection( handle, process, addr_ptr, zero_bits, commit_size,
                                                  offset, size_ptr, inherit, alloc_type, protect );

    if (NT_SUCCESS(status) && RtlIsCurrentProcess( process ) && ios_chrome_lookup( handle ))
        ios_chrome_set_view( handle, *addr_ptr );
    {
        CHPE_V2_CPU_AREA_INFO *area = get_arm64ec_cpu_area();
        int is_cur = RtlIsCurrentProcess( process ) ? 1 : 0;
        int insc_before = area ? !!area->InSyscallCallback : 0;
        int entered = 0;

        if (NT_SUCCESS(status) && is_cur) entered = enter_syscall_callback() ? 1 : 0;
        ios_map_gate_probe( "NtMapViewOfSection", handle, process, status,
                            NT_SUCCESS(status) ? *addr_ptr : NULL,
                            NT_SUCCESS(status) ? *size_ptr : 0,
                            is_cur, area, insc_before, entered );
        if (entered)
        {
            ios_notify_data_section_view( handle, *addr_ptr, *size_ptr, alloc_type, protect, offset );
            notify_map_view_of_section( handle, *addr_ptr, *size_ptr, alloc_type, protect, &status );
            leave_syscall_callback();
        }
    }
    return status;
}

NTSTATUS SYSCALL_API NtMapViewOfSectionEx( HANDLE handle, HANDLE process, PVOID *addr_ptr,
                                           const LARGE_INTEGER *offset, SIZE_T *size_ptr, ULONG alloc_type,
                                           ULONG protect, MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    NTSTATUS status = syscall_NtMapViewOfSectionEx( handle, process, addr_ptr, offset, size_ptr,
                                                    alloc_type, protect, parameters, count );

    if (NT_SUCCESS(status) && RtlIsCurrentProcess( process ) && ios_chrome_lookup( handle ))
        ios_chrome_set_view( handle, *addr_ptr );
    {
        CHPE_V2_CPU_AREA_INFO *area = get_arm64ec_cpu_area();
        int is_cur = RtlIsCurrentProcess( process ) ? 1 : 0;
        int insc_before = area ? !!area->InSyscallCallback : 0;
        int entered = 0;

        if (NT_SUCCESS(status) && is_cur) entered = enter_syscall_callback() ? 1 : 0;
        ios_map_gate_probe( "NtMapViewOfSectionEx", handle, process, status,
                            NT_SUCCESS(status) ? *addr_ptr : NULL,
                            NT_SUCCESS(status) ? *size_ptr : 0,
                            is_cur, area, insc_before, entered );
        if (entered)
        {
            ios_notify_data_section_view( handle, *addr_ptr, *size_ptr, alloc_type, protect, offset );
            notify_map_view_of_section( handle, *addr_ptr, *size_ptr, alloc_type, protect, &status );
            leave_syscall_callback();
        }
    }
    return status;
}

/* iOS-Madeira ml206: shared guard for ALL THREE NotifyMemoryProtect paths.
 *
 * A protect spanning >= 1GB is never a code-permission change; it is an allocator managing
 * a reservation. FEX, however, treats any protect without EXEC as "this range is no longer
 * executable" and REMOVES it from InvalidationTracker::XIntervals
 * (InvalidationTracker.cpp:69-71), so forwarding one 16GB PartitionAlloc protect
 *   [iOS-xrem] via=protect 0x7000000000-0x7400000000
 * wipes the executable interval of EVERY module inside the range. Modules keep their own
 * real mappings and protections, so suppressing the notification cannot lose a genuine
 * executability transition — whereas forwarding it loses all of them at once. */
static BOOL ios_bulk_protect_suppressed( const char *via, void *addr, SIZE_T size, ULONG prot )
{
    static int suppressed;

    if (size < (1ull << 30)) return FALSE;
    if (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        return FALSE;

    if (suppressed < 20)
    {
        suppressed++;
        ERR( "[protect-wall] SUPPRESSED via=%s %p+%p prot=%x (>=1GB non-exec would nuke all "
             "module exec intervals in range)\n", via, addr, (void *)size, prot );
    }
    return TRUE;
}

NTSTATUS SYSCALL_API NtProtectVirtualMemory( HANDLE process, PVOID *addr_ptr, SIZE_T *size_ptr,
                                             ULONG new_prot, ULONG *old_prot )
{
    BOOL is_current = RtlIsCurrentProcess( process );
    NTSTATUS status;

    if (!enter_syscall_callback())
        return syscall_NtProtectVirtualMemory( process, addr_ptr, size_ptr, new_prot, old_prot );

    if (!is_current) send_cross_process_notification( process, CrossProcessPreVirtualProtect,
                                                      *addr_ptr, *size_ptr, 2, new_prot, 0 );
    else if (pNotifyMemoryProtect)
    {
        /* iOS-Madeira ml203 ROOT-CAUSE FIX. FEX treats a protect notification without EXEC
         * as "this range is no longer executable" and REMOVES it from
         * InvalidationTracker::XIntervals (InvalidationTracker.cpp:69-71). A single
         * PartitionAlloc protect over its own 16GB soft pool
         *   [iOS-xrem] via=protect 0x7000000000-0x7400000000
         * therefore wiped the executable intervals of EVERY module in the furniture window
         * — libcef included (mapped at 0x73858d0000) — after which the decoder reported
         * NOEXEC at libcef code addresses, raised FAULT_SIGSEGV, branched to the
         * GuestSignal_SIGSEGV trampoline, and killed webhelper threads. That is the whole
         * chain we have been chasing, and it is a consequence of our lazy-reservation
         * geometry: soft-pool slot 0 aliases the region where PE modules are mapped.
         *
         * A protect spanning >= 1GB is never a code-permission change; it is an allocator
         * managing a reservation. Modules inside it keep their own real mappings and their
         * own protections, so suppressing the notification cannot lose a genuine
         * executability transition — whereas forwarding it loses ALL of them. */
        if (!ios_bulk_protect_suppressed( "cur-pre", *addr_ptr, *size_ptr, new_prot ))
            pNotifyMemoryProtect( *addr_ptr, *size_ptr, new_prot, FALSE, 0 );
    }

    /* iOS-Madeira ml186 PROBE. libcef IS registered at map time ([map-notify] addr=...
     * size=0xD3CA000 pfn=1), so its .text reaches InvalidationTracker::XIntervals — yet
     * the decoder still reports NOEXEC at libcef+0x1900733 / +0x3b508f0. The only thing
     * that REMOVES an XInterval is HandleMemoryProtectionNotification being told a
     * protection without EXEC (InvalidationTracker.cpp:69-71). We forward the REQUESTED
     * prot here, which is correct emulation — so log every non-exec protect landing in the
     * guest PE band, whoever the caller is (Chromium, Wine's loader, or our own JIT-pool
     * machinery touching the PE mapping). Correlate the address against the [jit-pool]
     * image lines to see if it covers libcef .text. */
    if (is_current && ios_in_big_image( (ULONG_PTR)*addr_ptr )
        && !(new_prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
    {
        static int unexec_n;
        if (unexec_n < 200)
        {
            unexec_n++;
            ERR( "[unexec] #%d addr=%p size=%p new_prot=%x\n",
                 unexec_n, *addr_ptr, (void *)*size_ptr, new_prot );
        }
    }

    /* ml283: log every protect that REQUESTS execute, anywhere, with its result.
     *
     * The [unexec] probe above cannot answer this: it filters to ios_in_big_image() AND to
     * protections WITHOUT execute. I nonetheless used its output to claim "the guest never
     * requests an execute protection", and retracted the V8-JIT theory on that basis. The
     * claim was unfounded -- that probe is structurally incapable of showing an exec
     * request, and doubly so outside a big PE image.
     *
     * What we actually know (ml273/ml283): libcef.dll+0x59ef805 calls a pointer landing at
     * 0x7e600f0080, inside a 6.7MB MEM_PRIVATE PAGE_READWRITE region based at
     * 0x7E60000000, and the target is COMMITTED but NOT EXECUTABLE. A private multi-MB
     * region entered at a 64KB-slot offset is V8 code-space shape. So the question is
     * precisely: does anything ask for EXECUTE on it, and does the request SUCCEED?
     * No address filter, no protection filter, and the status is printed -- so silence
     * here means "never requested", not "filtered out". */
    {
        static int execreq_n;
        const ULONG exec_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        if ((new_prot & exec_mask) && execreq_n < 64)
        {
            void *req_addr = *addr_ptr;
            SIZE_T req_size = *size_ptr;
            NTSTATUS st = syscall_NtProtectVirtualMemory( process, addr_ptr, size_ptr, new_prot, old_prot );

            execreq_n++;
            ERR( "[exec-req] #%d addr=%p size=%p new_prot=%lx -> status=%08x%s%s\n",
                 execreq_n, req_addr, (void *)req_size, new_prot, (unsigned)st,
                 st ? "  <== FAILED" : "",
                 is_current ? "" : "  (cross-process)" );

            if (is_current && !st && old_prot)   /* madeira-bcd [subpage-sweep] */
                ios_sp_note_protect( (ULONG_PTR)*addr_ptr, *size_ptr, new_prot, *old_prot );
            if (!is_current) send_cross_process_notification( process, CrossProcessPostVirtualProtect,
                                                             *addr_ptr, *size_ptr, 2, new_prot, st );
            else if (pNotifyMemoryProtect
                     && !ios_bulk_protect_suppressed( "cur-post", *addr_ptr, *size_ptr, new_prot ))
                pNotifyMemoryProtect( *addr_ptr, *size_ptr, new_prot, TRUE, st );
            /* ml1259: this early return skipped the leave, so the thread kept
             * InSyscallCallback set and its next notifications to FEX (protect,
             * flush, alloc) were dropped until something else cleared it. */
            leave_syscall_callback();
            return st;
        }
    }

    status = syscall_NtProtectVirtualMemory( process, addr_ptr, size_ptr, new_prot, old_prot );
    if (is_current && !status && old_prot)   /* madeira-bcd [subpage-sweep] */
        ios_sp_note_protect( (ULONG_PTR)*addr_ptr, *size_ptr, new_prot, *old_prot );

    if (!is_current) send_cross_process_notification( process, CrossProcessPostVirtualProtect,
                                                      *addr_ptr, *size_ptr, 2, new_prot, status );
    else if (pNotifyMemoryProtect
             && !ios_bulk_protect_suppressed( "cur-post", *addr_ptr, *size_ptr, new_prot ))
        pNotifyMemoryProtect( *addr_ptr, *size_ptr, new_prot, TRUE, status );

    leave_syscall_callback();
    return status;
}

/* madeira [cpu-x64-identity] (rev=cpu-identity-2; env MADEIRA_CPU_X64_IDENTITY = 0 or the master
 * MADEIRA_CPU_IDENTITY = 0 turns it off). The x64 process is described as on an x64 PC where Windows on ARM
 * already does so for an emulated x64 process: GetSystemInfo (SystemCpuInformation, FEX's
 * UpdateProcessorInformation: AMD64 and the CPUID signature, as before), GetNativeSystemInfo
 * (RtlGetNativeSystemInformation: the same, where it said ARM64 before; Windows on ARM answers AMD64 here too)
 * and SystemEmulationProcessorInformation (the x86 view: INTEL with the same level and revision, where it said
 * ARM). Read once, like ios_xstate_revert. */
static LONG ios_x64id_mode;   /* 0 unread, 1 off, 2 on */

static BOOL ios_env_is_zero( WCHAR *env, const WCHAR *name )
{
    UNICODE_STRING var, value;
    WCHAR buffer[2];

    RtlInitUnicodeString( &var, name );
    value.Buffer = buffer;
    value.Length = 0;
    value.MaximumLength = sizeof(buffer);
    return !RtlQueryEnvironmentVariable_U( env, &var, &value ) && value.Length == sizeof(WCHAR) && buffer[0] == '0';
}

static BOOL ios_x64_identity(void)
{
    if (!ios_x64id_mode)
    {
        PEB *peb = NtCurrentTeb()->Peb;
        WCHAR *env = peb->FastPebLock ? NULL : peb->ProcessParameters->Environment;   /* see ios_xstate_revert */
        ios_x64id_mode = (ios_env_is_zero( env, L"MADEIRA_CPU_IDENTITY" ) ||
                          ios_env_is_zero( env, L"MADEIRA_CPU_X64_IDENTITY" )) ? 1 : 2;
        ERR( "[cpu-x64-identity] rev=cpu-identity-2 %s\n", ios_x64id_mode == 2 ? "on: GetNativeSystemInfo and the "
             "emulation processor information follow FEX's CPUID" : "off (MADEIRA_CPU_X64_IDENTITY=0 or MADEIRA_CPU_IDENTITY=0)" );
    }
    return ios_x64id_mode == 2;
}

NTSTATUS SYSCALL_API NtQuerySystemInformation( SYSTEM_INFORMATION_CLASS class, void *info, ULONG size, ULONG *ret_size )
{
    NTSTATUS status = syscall_NtQuerySystemInformation( class, info, size, ret_size );

    if (!status && class == SystemCpuInformation && pUpdateProcessorInformation) pUpdateProcessorInformation( info );
    if (!status && class == SystemEmulationProcessorInformation && pUpdateProcessorInformation &&
        size >= sizeof(SYSTEM_CPU_INFORMATION) && ios_x64_identity())
    {
        SYSTEM_CPU_INFORMATION *cpu = info;
        pUpdateProcessorInformation( info );   /* madeira [cpu-x64-identity] */
        cpu->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
    }
    ios_cmd_q_hook( IOS_CMD_QSI, NULL, class, status, info, size, ret_size );   /* madeira [crashmailer-dump] */
    return status;
}

NTSTATUS SYSCALL_API NtRaiseException( EXCEPTION_RECORD *rec, CONTEXT *context, BOOL first_chance )
{
    ARM64_NT_CONTEXT arm_ctx;
    NTSTATUS status;

    if ((status = ios_x64_to_arm( &arm_ctx, context ))) return status;   /* madeira [xstate-revert] */
    /* madeira [pfaf-keep]: carry PF/AF to the handler of a raise from x64 context (e.g. [subpage-sweep]'s
     * read AVs); bit 26 survives the unix frame's cpsr_user_mask, bit 27 (AF) does not. */
    if (ios_pfaf_enabled() && (context->ContextFlags & CONTEXT_AMD64_CONTROL) == CONTEXT_AMD64_CONTROL)
    {
        if (context->EFlags & 0x04) arm_ctx.Cpsr |= 0x04000000;
        if (context->EFlags & 0x10) arm_ctx.Cpsr |= 0x08000000;
    }
    /* madeira [df-ctx]: and DF in bit 16. [subpage-sweep] re-raises from inside NtContinue, after the
     * FEX-delivered fault whose IosDfDelivered is still set, so xtajit64 will trust the DF of the context
     * this handler continues with: without the bit the handler saw DF=0 and a std; rep movs resumed forwards. */
    if ((context->ContextFlags & CONTEXT_AMD64_CONTROL) == CONTEXT_AMD64_CONTROL && (context->EFlags & 0x400) &&
        ios_df_enabled())
        arm_ctx.Cpsr |= 0x00010000;
    return syscall_NtRaiseException( rec, &arm_ctx, first_chance );
}

NTSTATUS SYSCALL_API NtReadFile( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                 IO_STATUS_BLOCK *io, void *buffer, ULONG length,
                                 LARGE_INTEGER *offset, ULONG *key )
{
    NTSTATUS status;

    if (pBTCpu64NotifyReadFile && enter_syscall_callback())
    {
        pBTCpu64NotifyReadFile( handle, buffer, length, FALSE, 0 );
        leave_syscall_callback();
    }
    status = syscall_NtReadFile( handle, event, apc, apc_user, io, buffer, length, offset, key );
    if (pBTCpu64NotifyReadFile && enter_syscall_callback())
    {
        pBTCpu64NotifyReadFile( handle, buffer, length, TRUE, status );
        leave_syscall_callback();
    }
    return status;
}

NTSTATUS SYSCALL_API NtSetContextThread( HANDLE handle, const CONTEXT *context )
{
    ARM64_NT_CONTEXT arm_ctx;
    NTSTATUS status;

    if ((status = ios_x64_to_arm( &arm_ctx, context ))) return status;   /* madeira [xstate-revert] */
    /* madeira [dr-pass] */
    if ((context->ContextFlags & CONTEXT_AMD64_DEBUG_REGISTERS) == CONTEXT_AMD64_DEBUG_REGISTERS && ios_dr_enabled())
    {
        if (ios_dr_is_self( handle )) ios_dr_apply( context, "set-self" );
        else if ((context->Dr7 & 0xff) && ios_dr_log_ok())
            ERR( "[dr-pass] set of another thread's debug registers (handle %p dr0=%p dr7=%p) not applied\n",
                 handle, (void *)context->Dr0, (void *)context->Dr7 );
    }
    if (ios_pfaf_enabled() && (context->ContextFlags & CONTEXT_AMD64_CONTROL) == CONTEXT_AMD64_CONTROL &&
        ios_dr_is_self( handle ))
        ios_pfaf_stash( context );   /* madeira [pfaf-keep] */
    if ((context->ContextFlags & CONTEXT_AMD64_CONTROL) == CONTEXT_AMD64_CONTROL && ios_df_enabled() &&
        ios_dr_is_self( handle ))
        ios_df_stash( context );     /* madeira [df-ctx] */
    return syscall_NtSetContextThread( handle, &arm_ctx );
}

/* madeira-bcd [exc-ring] (env MADEIRA_EXC_RING = 0 turns it off). Log only.
 *
 * 0.2.77 log 87c31d6e: with [subpage-sweep] working, Overwatch 2 no longer jumps wild; it starts
 * its own crash reporter ("CrashMailer_64.exe" "Overwatch") at 20 s and exits with status 0. What
 * made it give up is not in the log: the game's KiUserExceptionDispatcher hook handles most
 * exceptions itself, so call_seh_handlers' [exc] lines see few of them, and thousands of
 * page-decrypt faults bury the rest. This keeps the last 128 exceptions of the process as seen in
 * prepare_exception_arm64ec (before any hook), skipping page-decrypt faults (an access violation on
 * a PAGE_NOACCESS page of the main exe: only counted) and folding repeats of the same
 * code+address+thread among the last 8 entries into a count. The ring is printed once, when the process terminates. */
#define IOS_XR_N 512   /* v2: 128 held only the last 0.3 s in 0.2.79 log 80f5a778 */
static struct ios_xr_ent
{
    ULONG code, tid, tick, reps;
    ULONG_PTR addr, p0, p1, sp;
    ULONG_PTR handler;   /* [crashmailer-dump]: the handler that took it (or the last that ran) */
    LONG hret;
    USHORT hkind, nh;
} ios_xr[IOS_XR_N];
static LONG ios_xr_mode, ios_xr_next, ios_xr_decrypt, ios_xr_printed;   /* next is used as unsigned */

/* returns the ring index of the entry (or of the one it was folded into), -1 when not recorded */
static LONG ios_xr_record( const EXCEPTION_RECORD *rec, ULONG_PTR sp )
{
    struct ios_xr_ent *e;
    ULONG tid, i, n;

    if (ios_xr_mode == 1) return -1;
    if (!ios_xr_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        RtlInitUnicodeString( &var, L"MADEIRA_EXC_RING" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_xr_mode = (!RtlQueryEnvironmentVariable_U( NULL, &var, &value ) &&
                       value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        if (ios_xr_mode == 1) return -1;
    }
    if (rec->ExceptionCode == STATUS_EMULATION_SYSCALL) return -1;
    if (rec->ExceptionCode == STATUS_ACCESS_VIOLATION && rec->NumberParameters >= 2 &&
        ios_sp_locked_image_page( rec->ExceptionInformation[1] & ~(ULONG_PTR)0xfff, 0, NULL ))
    {
        InterlockedIncrement( &ios_xr_decrypt );
        return -1;
    }
    tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
    n = (ULONG)ios_xr_next;
    for (i = 1; i <= 8 && i <= n; i++)
    {
        e = &ios_xr[(n - i) % IOS_XR_N];
        BOOL same_addr = e->addr == (ULONG_PTR)rec->ExceptionAddress;
        /* v2: the game's int3 / ud bursts walk through a page one address at a time; fold them by page */
        if ((rec->ExceptionCode == STATUS_BREAKPOINT || rec->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) &&
            (e->addr >> 12) == ((ULONG_PTR)rec->ExceptionAddress >> 12)) same_addr = TRUE;
        if (e->code == rec->ExceptionCode && same_addr && e->tid == tid)
        {
            InterlockedIncrement( (LONG *)&e->reps );
            e->tick = NtGetTickCount();
            e->hkind &= 0xff;   /* [crashmailer-dump]: let this repeat's handler be noted */
            return (LONG)((n - i) % IOS_XR_N);
        }
    }
    n = (ULONG)InterlockedIncrement( &ios_xr_next ) - 1;
    e = &ios_xr[n % IOS_XR_N];
    e->code = rec->ExceptionCode;
    e->addr = (ULONG_PTR)rec->ExceptionAddress;
    e->p0 = rec->NumberParameters >= 1 ? rec->ExceptionInformation[0] : 0;
    e->p1 = rec->NumberParameters >= 2 ? rec->ExceptionInformation[1] : 0;
    e->sp = sp;
    e->tid = tid;
    e->tick = NtGetTickCount();
    e->reps = 0;
    e->handler = 0;
    e->hret = 0;
    e->hkind = e->nh = 0;
    return (LONG)(n % IOS_XR_N);
}

static void ios_xr_dump( const char *why, LONG exit_code )
{
    ULONG n = (ULONG)ios_xr_next, first, i;
    ULONG now = NtGetTickCount();

    if (ios_xr_mode != 2 || InterlockedExchange( &ios_xr_printed, 1 )) return;
    first = n > IOS_XR_N ? n - IOS_XR_N : 0;
    ERR( "[exc-ring] %s exit_code=%08lx: last %lu of %lu exceptions (+%ld page-decrypt faults not listed), oldest first rev=exc-ring-2\n",
         why, (ULONG)exit_code, n - first, n, ios_xr_decrypt );
    for (i = first; i < n; i++)
    {
        const struct ios_xr_ent *e = &ios_xr[i % IOS_XR_N];
        ERR( "[exc-ring] #%lu -%lums tid=%04lx code=%08lx addr=%p p0=%p p1=%p sp=%p x%lu\n",
             i, now - e->tick, e->tid, e->code, (void *)e->addr, (void *)e->p0, (void *)e->p1,
             (void *)e->sp, e->reps + 1 );
    }
}


/* madeira [crashmailer-dump] (env MADEIRA_EC_CRASHMAILER_DUMP = 0 turns it off). rev=crashmailer-dump-1. LOG ONLY.
 *
 * Overwatch 2 raises int 0x2c (STATUS_ASSERTION_FAILURE) at Overwatch_loader.dll+0x441960, handles it, runs ~7 s
 * more and then its main thread starts "...\ErrorReporting\x64\CrashMailer_64.exe" "Overwatch". Why it decided to
 * is not in the log. When NtCreateUserProcess is called for an image whose name contains "CrashMailer"
 * (case-insensitive), this prints, once per process and before the process is created:
 *   1. the calling thread's x64 state: unwound from here through the EC frames to the x64 caller (exact for rip,
 *      rsp, the nonvolatile GPRs and xmm6-15), plus FEX's stored state for the thread (BTCpu64IosCrashMailerData);
 *   2. a scan of up to 2048 stack slots from that rsp to the stack base: every value inside an executable section of
 *      a loaded image (at most 24), with module+rva and the code from ret-512 to ret+64;
 *   3. +-64 bytes around every register value and around the first 8 callers' frames (slot and saved rbp);
 *   4. the last 64 [exc-ring] exceptions with the VEH/SEH/KiUserExceptionDispatcher-hook handler that took each one
 *      and its return value, the x64 contexts of the last 12, and FEX's ring of delivered contexts;
 *   5. the calling thread's last 4096 translated blocks (the ml1205 block ring; FEX turns it on for Overwatch.exe);
 *   6. rings of the last 256 information queries (NtQueryInformationProcess/Thread, NtQuerySystemInformation(Ex),
 *      NtSetInformationThread/Process, NtQueryObject, failed NtClose), the last 64 NtQueryVirtualMemory calls with
 *      per-class counts, the last answer to each debugger-related query, the debugger fields of the PEB, the
 *      process heap and KUSER_SHARED_DATA, unwinds made by exception handlers and NtGetContextThread calls on
 *      other threads;
 *   7. the CrashMailer command line, the last NtCreateFile calls, the process's open file handles and the files
 *      under the game folder (and TEMP) changed in the last 60 s.
 * The rings only record (no logging, no locks, no allocation); everything is printed by the dump. The dump reads
 * memory only through NtQueryVirtualMemory-checked NtReadVirtualMemory, calls the syscalls through private stubs
 * (a game hook on an ntdll export is not run, and the rings do not record the dump's own queries), takes no loader
 * lock and allocates nothing. About 2000 lines. The FEX side reads the same variable. */
#define IOS_CMD "[crashmailer-dump] "

#define DEFINE_IOS_CMD_SYSCALL(name,args) \
    static NTSTATUS __attribute__((naked)) ioscmd_##name args { __ASM_SYSCALL_FUNC( __id_##name, ioscmd_##name ); }
DEFINE_IOS_CMD_SYSCALL(NtReadVirtualMemory, (HANDLE process, const void *addr, void *buffer, SIZE_T size, SIZE_T *bytes_read))
DEFINE_IOS_CMD_SYSCALL(NtOpenFile, (HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, IO_STATUS_BLOCK *io, ULONG sharing, ULONG options))
DEFINE_IOS_CMD_SYSCALL(NtQueryDirectoryFile, (HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc_routine, void *apc_context, IO_STATUS_BLOCK *io, void *buffer, ULONG length, FILE_INFORMATION_CLASS info_class, BOOLEAN single_entry, UNICODE_STRING *mask, BOOLEAN restart_scan))
DEFINE_IOS_CMD_SYSCALL(NtQuerySystemTime, (LARGE_INTEGER *time))
#undef DEFINE_IOS_CMD_SYSCALL

static LONG ios_cmd_mode;      /* 0 not read yet, 1 off, 2 on */
static LONG ios_cmd_dumping;   /* the dump runs: the rings stop recording */
static LONG ios_cmd_done;
static void ios_xp_read_switch( WCHAR *env );   /* [crashmailer-exit-probe] */
static void ios_xp_exit_event( const char *why );
static void ios_xp_exit_hint( LONG *latch, const char *why );
static LONG ios_xp_sppi_done;
static void ios_xp_av_check( const EXCEPTION_RECORD *rec, const CONTEXT *c );
static BOOL ios_xp_ring_last( ULONG_PTR ring, ULONG64 idx, ULONG64 *out, ULONG want );

/* Read once, from LdrInitializeThunk of the first thread (before loader_init(), one thread, no lock: the
 * ios_xstate_revert() pattern). The rings only look at the cached mode, so they never take the PEB lock. */
static void ios_cmd_read_switch(void)
{
    UNICODE_STRING var, value;
    WCHAR buffer[2];
    PEB *peb = NtCurrentTeb()->Peb;
    WCHAR *env;

    if (ios_cmd_mode) return;
    if (!peb->FastPebLock && !peb->ProcessParameters) return;
    env = peb->FastPebLock ? NULL : peb->ProcessParameters->Environment;
    RtlInitUnicodeString( &var, L"MADEIRA_EC_CRASHMAILER_DUMP" );
    value.Buffer = buffer;
    value.Length = 0;
    value.MaximumLength = sizeof(buffer);
    ios_cmd_mode = (!RtlQueryEnvironmentVariable_U( env, &var, &value ) &&
                    value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
    ios_xp_read_switch( env );   /* [crashmailer-exit-probe] */
}

static inline BOOL ios_cmd_rec(void)
{
    return ios_cmd_mode == 2 && !ios_cmd_dumping;
}

static inline ULONG ios_cmd_tid(void)
{
    return HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
}

/* per-thread state, hashed by thread id (a collision only mislabels a log line) */
static struct ios_cmd_thr
{
    LONG tid;
    LONG depth;      /* VEH/SEH handlers being run on this thread */
    LONG internal;   /* ntdll's own dispatch/unwind code is running (its unwinds are not the game's) */
    ULONG exc_tick;  /* last exception delivered to this thread */
} ios_cmd_thr[256];

static struct ios_cmd_thr *ios_cmd_thr_get( BOOL claim )
{
    ULONG tid = ios_cmd_tid();
    struct ios_cmd_thr *t = &ios_cmd_thr[(tid >> 2) & 255];

    if ((ULONG)t->tid == tid) return t;
    if (!claim) return NULL;
    t->depth = t->internal = 0;
    t->exc_tick = 0;
    t->tid = tid;
    return t;
}

LONG ios_cmd_internal_enter(void)
{
    struct ios_cmd_thr *t;
    LONG old;

    if (ios_cmd_mode != 2 || !(t = ios_cmd_thr_get( TRUE ))) return 0;
    old = t->internal;
    t->internal = 1;
    return old;
}

void ios_cmd_internal_leave( LONG old )
{
    struct ios_cmd_thr *t;

    if (ios_cmd_mode == 2 && (t = ios_cmd_thr_get( FALSE ))) t->internal = old;
}

/* ---- 4. handlers, x64 contexts ---- */

/* kind: 1 VEH, 2 SEH, 3 TEB-list handler, 4 hooked KiUserExceptionDispatcher */
#define IOS_CMD_NORET 0x7fffffff   /* the handler was entered and has not returned (yet) */

/* Before (phase 0) and after (phase 1) a guest-visible handler call; phase 2 only notes a handler (the hooked
 * KiUserExceptionDispatcher, which runs outside ntdll's dispatch). Phase 0 returns the internal flag to restore. */
LONG ios_cmd_handler( const EXCEPTION_RECORD *rec, ULONG kind, const void *handler, LONG ret, int phase )
{
    struct ios_cmd_thr *t;
    LONG saved = 0;
    ULONG tid, n, i;

    if (ios_cmd_mode != 2) return 0;
    if ((t = ios_cmd_thr_get( TRUE )))
    {
        if (!phase)
        {
            saved = t->internal;
            t->internal = 0;
            t->depth++;
        }
        else if (phase == 1 && t->depth > 0) t->depth--;   /* the caller restores internal (ios_cmd_internal_leave) */
    }
    if (!rec || ios_xr_mode != 2 || ios_cmd_dumping) return saved;
    tid = ios_cmd_tid();
    n = (ULONG)ios_xr_next;
    /* the handler belongs to this thread's newest ring entry with this code (the address may have been rewritten
     * by ResetToConsistentState since it was recorded) */
    for (i = 1; i <= 16 && i <= n; i++)
    {
        struct ios_xr_ent *e = &ios_xr[(n - i) % IOS_XR_N];

        if (e->tid != tid || e->code != rec->ExceptionCode) continue;
        if (phase != 1) e->nh++;
        /* keep the handler that took it: VEH -1 (continue execution), SEH 0 (continue execution) or one that
         * never returned (it unwound or continued itself); otherwise the last one that ran */
        if (!(e->hkind & 0x100))
        {
            e->hkind = (USHORT)kind;
            e->handler = (ULONG_PTR)handler;
            e->hret = phase == 1 ? ret : IOS_CMD_NORET;
            if (phase && ((kind == 1 && ret == EXCEPTION_CONTINUE_EXECUTION) ||
                          ((kind == 2 || kind == 3) && ret == ExceptionContinueExecution)))
                e->hkind |= 0x100;
        }
        break;
    }
    return saved;
}

#define IOS_CMD_XCTX_N 16
static struct ios_cmd_xctx
{
    LONG xr;   /* [exc-ring] index + 1, 0 while written */
    ULONG tid, code, ctxflags, eflags, mxcsr;
    USHORT fcw, pad;
    ULONG_PTR addr;
    ULONG64 gpr[16], rip, dr[6];
    M128A xmm[16];
} ios_cmd_xctx[IOS_CMD_XCTX_N];
static LONG ios_cmd_xctx_next;

static void ios_cmd_exc_ctx( LONG xr, const EXCEPTION_RECORD *rec, const CONTEXT *c )
{
    struct ios_cmd_xctx *x;
    struct ios_cmd_thr *t;
    LONG n;

    if (!ios_cmd_rec()) return;
    if ((t = ios_cmd_thr_get( TRUE ))) t->exc_tick = NtGetTickCount();
    if (xr < 0) return;
    n = InterlockedIncrement( &ios_cmd_xctx_next ) - 1;
    x = &ios_cmd_xctx[(ULONG)n % IOS_CMD_XCTX_N];
    x->xr = 0;
    x->tid = ios_cmd_tid();
    x->code = rec->ExceptionCode;
    x->addr = (ULONG_PTR)rec->ExceptionAddress;
    x->ctxflags = c->ContextFlags;
    x->eflags = c->EFlags;
    x->mxcsr = c->MxCsr;
    x->fcw = c->FltSave.ControlWord;
    memcpy( x->gpr, &c->Rax, sizeof(x->gpr) );   /* Rax..R15 are contiguous in CONTEXT */
    x->rip = c->Rip;
    x->dr[0] = c->Dr0; x->dr[1] = c->Dr1; x->dr[2] = c->Dr2; x->dr[3] = c->Dr3;
    x->dr[4] = c->Dr6; x->dr[5] = c->Dr7;
    memcpy( x->xmm, &c->Xmm0, sizeof(x->xmm) );
    x->xr = xr + 1;
    ios_xp_av_check( rec, c );   /* [crashmailer-exit-probe] */
}

/* ---- 6. information queries ---- */

static const char * const ios_cmd_qname[] = { "?", "QueryInformationProcess", "QuerySystemInformation",
    "QuerySystemInformationEx", "QueryInformationThread", "SetInformationThread", "QueryObject", "Close(bad)",
    "SetInformationProcess" };

#define IOS_CMD_Q_N 256
static struct ios_cmd_q
{
    ULONG seq, tick, tid, fn, cls, status, len, retlen;
    ULONG_PTR handle;
    UCHAR data[32];
} ios_cmd_q[IOS_CMD_Q_N];
static LONG ios_cmd_q_next;

/* the last answer to each debugger-related query */
static const struct { ULONG fn, cls; const char *name; } ios_cmd_dbgq[] =
{
    { IOS_CMD_QIP, 7, "ProcessDebugPort" },
    { IOS_CMD_QIP, 0x1e, "ProcessDebugObjectHandle" },
    { IOS_CMD_QIP, 0x1f, "ProcessDebugFlags" },
    { IOS_CMD_QSI, 0x23, "SystemKernelDebuggerInformation" },
    { IOS_CMD_QSI, 0x95, "SystemKernelDebuggerInformationEx" },
    { IOS_CMD_QIT, 0x11, "ThreadHideFromDebugger(query)" },
    { IOS_CMD_SIT, 0x11, "ThreadHideFromDebugger(set)" },
    { IOS_CMD_SIP, 0x1f, "ProcessDebugFlags(set)" },
};
static struct { LONG count; ULONG status, tid, len, tick; UCHAR data[16]; } ios_cmd_dbga[ARRAY_SIZE(ios_cmd_dbgq)];

/* data: for a query the result (copied only on success or buffer overflow, when the kernel side wrote it), for a
 * set the input (copied only on success: a failed set may never have read it, and the caller's pointer can be bad).
 * The copy never crosses the page of data[0], which the kernel side has just accessed. */
static void ios_cmd_q_record( ULONG fn, HANDLE handle, ULONG cls, NTSTATUS status, const void *data,
                              ULONG len, const ULONG *retlen_ptr )
{
    struct ios_cmd_q *q;
    ULONG n, copy = 0, retlen = 0, i;
    BOOL wrote = !status || status == STATUS_BUFFER_OVERFLOW;
    BOOL is_set = fn == IOS_CMD_SIT || fn == IOS_CMD_SIP;

    if (wrote && retlen_ptr) retlen = *retlen_ptr;
    if (data && (is_set ? !status : wrote))
    {
        copy = len;
        if (!is_set && retlen_ptr && retlen < copy) copy = retlen;
        if (copy > sizeof(q->data)) copy = sizeof(q->data);
        if (copy > 0x1000 - ((ULONG_PTR)data & 0xfff)) copy = 0x1000 - ((ULONG_PTR)data & 0xfff);
    }
    n = (ULONG)InterlockedIncrement( &ios_cmd_q_next );
    q = &ios_cmd_q[(n - 1) % IOS_CMD_Q_N];
    q->seq = 0;
    q->tick = NtGetTickCount();
    q->tid = ios_cmd_tid();
    q->fn = fn;
    q->cls = cls;
    q->status = status;
    q->len = len;
    q->retlen = retlen_ptr ? retlen : ~0u;
    q->handle = (ULONG_PTR)handle;
    memset( q->data, 0, sizeof(q->data) );
    if (copy) memcpy( q->data, data, copy );
    q->seq = n;

    for (i = 0; i < ARRAY_SIZE(ios_cmd_dbgq); i++)
    {
        if (ios_cmd_dbgq[i].fn != fn || ios_cmd_dbgq[i].cls != cls) continue;
        InterlockedIncrement( &ios_cmd_dbga[i].count );
        ios_cmd_dbga[i].status = status;
        ios_cmd_dbga[i].tid = q->tid;
        ios_cmd_dbga[i].len = len;
        ios_cmd_dbga[i].tick = q->tick;
        memset( ios_cmd_dbga[i].data, 0, sizeof(ios_cmd_dbga[i].data) );
        if (copy) memcpy( ios_cmd_dbga[i].data, data, min( copy, sizeof(ios_cmd_dbga[i].data) ) );
        break;
    }
}

static void ios_cmd_q_hook( ULONG fn, HANDLE handle, ULONG cls, NTSTATUS status, const void *data, ULONG len,
                            const ULONG *retlen )
{
    if (ios_cmd_rec()) ios_cmd_q_record( fn, handle, cls, status, data, len, retlen );
    if (fn == IOS_CMD_QSI && cls == 8 /* SystemProcessorPerformanceInformation */)   /* [crashmailer-exit-probe] */
        ios_xp_exit_hint( &ios_xp_sppi_done, "SystemProcessorPerformanceInformation query" );
}

#define IOS_CMD_VM_N 64
static LONG ios_cmd_vm_count[16];
static struct ios_cmd_vm
{
    ULONG seq, tick, tid, cls, status, state, protect, type;
    ULONG_PTR addr, base, size;
    HANDLE process;
} ios_cmd_vm[IOS_CMD_VM_N];
static LONG ios_cmd_vm_next;

static void ios_cmd_vm_record( HANDLE process, const void *addr, ULONG cls, NTSTATUS status, const void *buffer )
{
    struct ios_cmd_vm *v;
    ULONG n;

    InterlockedIncrement( &ios_cmd_vm_count[cls < 15 ? cls : 15] );
    n = (ULONG)InterlockedIncrement( &ios_cmd_vm_next );
    v = &ios_cmd_vm[(n - 1) % IOS_CMD_VM_N];
    v->seq = 0;
    v->tick = NtGetTickCount();
    v->tid = ios_cmd_tid();
    v->cls = cls;
    v->status = status;
    v->addr = (ULONG_PTR)addr;
    v->process = process;
    v->base = v->size = 0;
    v->state = v->protect = v->type = 0;
    if (!status && cls == MemoryBasicInformation && buffer)
    {
        const MEMORY_BASIC_INFORMATION *mbi = buffer;
        v->base = (ULONG_PTR)mbi->BaseAddress;
        v->size = mbi->RegionSize;
        v->state = mbi->State;
        v->protect = mbi->Protect;
        v->type = mbi->Type;
    }
    v->seq = n;
}

/* NtGetContextThread on another thread */
#define IOS_CMD_GC_N 16
static struct ios_cmd_gc
{
    ULONG seq, tick, tid, target, suspend, want, status, ctxflags, eflags;
    ULONG_PTR handle;
    ULONG64 gpr[16], rip, dr[6];
} ios_cmd_gc[IOS_CMD_GC_N];
static LONG ios_cmd_gc_next;

/* unwinds made by the game outside ntdll's own dispatch: inside a VEH/SEH handler, or within 100 ms of an
 * exception on that thread (a hooked KiUserExceptionDispatcher runs outside both) */
#define IOS_CMD_UNW_N 16
static struct ios_cmd_unw
{
    ULONG seq, tick, tid, kind, depth, since_exc, status, match, checked;
    ULONG_PTR base, pc, target, frame;
    ULONG64 pre[10], post[10];   /* rip rsp rbx rbp rsi rdi r12 r13 r14 r15 */
    M128A x6[2], x7[2];          /* pre, post */
} ios_cmd_unw[IOS_CMD_UNW_N];
static LONG ios_cmd_unw_next, ios_cmd_unw_total;

static void ios_cmd_nonvol( const CONTEXT *c, ULONG64 *r )
{
    r[0] = c->Rip; r[1] = c->Rsp; r[2] = c->Rbx; r[3] = c->Rbp; r[4] = c->Rsi;
    r[5] = c->Rdi; r[6] = c->R12; r[7] = c->R13; r[8] = c->R14; r[9] = c->R15;
}

/* kind 1 RtlVirtualUnwind(2), 2 RtlUnwindEx. Returns a token for ios_cmd_unwind_post(), or -1 (not recorded). */
int ios_cmd_unwind_pre( ULONG kind, ULONG_PTR base, ULONG_PTR pc, const CONTEXT *context )
{
    struct ios_cmd_thr *t;
    struct ios_cmd_unw *u;
    ULONG now, since, n;

    if (!ios_cmd_rec() || !(t = ios_cmd_thr_get( FALSE )) || t->internal) return -1;
    now = NtGetTickCount();
    since = t->exc_tick ? now - t->exc_tick : ~0u;
    if (t->depth <= 0 && since > 100) return -1;
    InterlockedIncrement( &ios_cmd_unw_total );
    n = (ULONG)InterlockedIncrement( &ios_cmd_unw_next );
    u = &ios_cmd_unw[(n - 1) % IOS_CMD_UNW_N];
    u->seq = 0;
    u->tick = now;
    u->tid = ios_cmd_tid();
    u->kind = kind;
    u->depth = t->depth;
    u->since_exc = since;
    u->base = base;
    u->pc = pc;
    u->target = u->frame = 0;
    u->status = 0;
    u->match = u->checked = 0;
    ios_cmd_nonvol( context, u->pre );
    memcpy( &u->x6[0], &context->Xmm6, sizeof(M128A) );
    memcpy( &u->x7[0], &context->Xmm7, sizeof(M128A) );
    memset( u->post, 0, sizeof(u->post) );
    u->seq = n;
    return (int)((n - 1) % IOS_CMD_UNW_N);
}

/* ptrs (may be NULL): where the unwinder took each register from. A restored register "matches" when its new value
 * equals the memory it was restored from. The unwinder has just read those slots, so they are read directly (no
 * syscalls on this path). */
void ios_cmd_unwind_post( int tok, const CONTEXT *context, NTSTATUS status, const KNONVOLATILE_CONTEXT_POINTERS *ptrs,
                          ULONG_PTR target, ULONG_PTR frame )
{
    static const int gpr_idx[8] = { 3, 5, 6, 7, 12, 13, 14, 15 };   /* rbx rbp rsi rdi r12-r15 in IntegerContext */
    struct ios_cmd_unw *u;
    int i;

    if (tok < 0 || tok >= IOS_CMD_UNW_N) return;
    u = &ios_cmd_unw[tok];
    u->status = status;
    u->target = target;
    u->frame = frame;
    ios_cmd_nonvol( context, u->post );
    memcpy( &u->x6[1], &context->Xmm6, sizeof(M128A) );
    memcpy( &u->x7[1], &context->Xmm7, sizeof(M128A) );
    if (!ptrs || status) return;
    for (i = 0; i < 8; i++)
    {
        if (!ptrs->IntegerContext[gpr_idx[i]]) continue;
        u->checked |= 1u << i;
        if (*ptrs->IntegerContext[gpr_idx[i]] == u->post[i + 2]) u->match |= 1u << i;
    }
    for (i = 6; i <= 7; i++)
    {
        const M128A *now = i == 6 ? &context->Xmm6 : &context->Xmm7;
        if (!ptrs->FloatingContext[i]) continue;
        u->checked |= 1u << (i + 2);
        if (!memcmp( ptrs->FloatingContext[i], now, sizeof(*now) )) u->match |= 1u << (i + 2);
    }
}

void ios_cmd_continue(void)
{
    struct ios_cmd_thr *t;

    if (ios_cmd_mode == 2 && (t = ios_cmd_thr_get( FALSE ))) t->depth = t->internal = 0;
}

/* ---- 7. NtCreateFile ---- */
#define IOS_CMD_F_N 64
#define IOS_CMD_FW_N 32
struct ios_cmd_file
{
    ULONG seq, tick, tid, access, dispo, options, status;
    ULONG_PTR root, handle;
    USHORT len;
    WCHAR name[118];
};
static struct ios_cmd_file ios_cmd_f[IOS_CMD_F_N], ios_cmd_fw[IOS_CMD_FW_N];
static LONG ios_cmd_f_next, ios_cmd_fw_next;

static void ios_cmd_file_record( const HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr, ULONG dispo,
                                 ULONG options, NTSTATUS status )
{
    BOOL name_ok = !status || status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND ||
                   status == STATUS_ACCESS_DENIED || status == STATUS_SHARING_VIOLATION ||
                   status == STATUS_OBJECT_NAME_COLLISION || status == STATUS_FILE_IS_A_DIRECTORY ||
                   status == STATUS_NOT_A_DIRECTORY;
    BOOL write = (access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL | DELETE)) ||
                 dispo == FILE_CREATE || dispo == FILE_SUPERSEDE || dispo == FILE_OVERWRITE || dispo == FILE_OVERWRITE_IF;
    int pass;

    for (pass = 0; pass < (write ? 2 : 1); pass++)
    {
        struct ios_cmd_file *f;
        ULONG n;

        if (!pass)
        {
            n = (ULONG)InterlockedIncrement( &ios_cmd_f_next );
            f = &ios_cmd_f[(n - 1) % IOS_CMD_F_N];
        }
        else
        {
            n = (ULONG)InterlockedIncrement( &ios_cmd_fw_next );
            f = &ios_cmd_fw[(n - 1) % IOS_CMD_FW_N];
        }
        f->seq = 0;
        f->tick = NtGetTickCount();
        f->tid = ios_cmd_tid();
        f->access = access;
        f->dispo = dispo;
        f->options = options;
        f->status = status;
        f->root = attr && name_ok ? (ULONG_PTR)attr->RootDirectory : 0;
        f->handle = !status && handle ? (ULONG_PTR)*handle : 0;
        f->len = 0;
        if (name_ok && attr && attr->ObjectName && attr->ObjectName->Buffer)
        {
            USHORT len = attr->ObjectName->Length / sizeof(WCHAR);
            /* keep the end of a long path: the file name is the interesting part */
            const WCHAR *src = attr->ObjectName->Buffer;
            if (len > ARRAY_SIZE(f->name)) { src += len - ARRAY_SIZE(f->name); len = ARRAY_SIZE(f->name); }
            memcpy( f->name, src, len * sizeof(WCHAR) );
            f->len = len;
        }
        f->seq = n;
    }
}

/* ---- the dump ---- */

static const char ios_cmd_hexd[] = "0123456789abcdef";

/* TRUE when [addr, addr+len) is committed, readable and not a guard page (reading one would clear its guard bit). */
static BOOL ios_cmd_readable( ULONG_PTR addr, SIZE_T len, ULONG *bad )
{
    ULONG_PTR page, end = addr + len;

    if (bad) *bad = 0;
    if (addr < 0x10000 || end < addr || end > 0x800000000000ULL)
    {
        if (bad) *bad = 0xfffffffd;
        return FALSE;
    }
    for (page = addr & ~(ULONG_PTR)0xfff; page < end;)
    {
        MEMORY_BASIC_INFORMATION mbi;
        ULONG_PTR next;

        if (syscall_NtQueryVirtualMemory( NtCurrentProcess(), (void *)page, MemoryBasicInformation,
                                          &mbi, sizeof(mbi), NULL ))
        {
            if (bad) *bad = 0xffffffff;
            return FALSE;
        }
        if (mbi.State != MEM_COMMIT || !mbi.Protect || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
        {
            if (bad) *bad = mbi.State != MEM_COMMIT ? 0xfffffffe : mbi.Protect;
            return FALSE;
        }
        next = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (next <= page) return FALSE;
        page = next;
    }
    return TRUE;
}

static SIZE_T ios_cmd_read( ULONG_PTR addr, void *buf, SIZE_T len )
{
    SIZE_T got = 0;

    if (!len || !ios_cmd_readable( addr, len, NULL )) return 0;
    if (ioscmd_NtReadVirtualMemory( NtCurrentProcess(), (void *)addr, buf, len, &got )) return 0;
    return got;
}

static void ios_cmd_hex( char *out, const UCHAR *b, SIZE_T len, SIZE_T got )
{
    SIZE_T i, o = 0;

    for (i = 0; i < len; i++)
    {
        if (i < got)
        {
            out[o++] = ios_cmd_hexd[b[i] >> 4];
            out[o++] = ios_cmd_hexd[b[i] & 15];
        }
        else
        {
            out[o++] = '?';
            out[o++] = '?';
        }
        out[o++] = (i % 8 == 7) ? '|' : ' ';
    }
    out[o] = 0;
}

/* one line: up to 64 bytes at addr */
static void ios_cmd_hexline( const char *what, ULONG_PTR addr, SIZE_T len )
{
    UCHAR b[64];
    char out[64 * 3 + 1];
    SIZE_T got;
    ULONG bad;

    if (len > sizeof(b)) len = sizeof(b);
    if (!ios_cmd_readable( addr, len, &bad ))
    {
        ERR( IOS_CMD "  %s %p: not read (state/protect %08lx)\n", what, (void *)addr, bad );
        return;
    }
    got = ios_cmd_read( addr, b, len );
    ios_cmd_hex( out, b, len, got );
    ERR( IOS_CMD "  %s %p: %s\n", what, (void *)addr, out );
}

/* loaded images seen by the dump: base, size, name and executable sections */
static struct ios_cmd_mod
{
    ULONG_PTR base, size;
    ULONG nsec;
    ULONG sec[16][2];   /* rva, size of the executable sections */
    char name[48];
} ios_cmd_mods[64];
static unsigned int ios_cmd_nmods;

static struct ios_cmd_mod *ios_cmd_module( ULONG_PTR addr )
{
    static struct { UNICODE_STRING str; WCHAR buf[300]; } fn;
    MEMORY_BASIC_INFORMATION mbi;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    struct ios_cmd_mod *m;
    ULONG_PTR base, sec_addr;
    unsigned int i, j, nsec;
    SIZE_T got = 0;

    if (addr < 0x10000 || addr >= 0x800000000000ULL) return NULL;
    if (syscall_NtQueryVirtualMemory( NtCurrentProcess(), (void *)addr, MemoryBasicInformation, &mbi, sizeof(mbi), NULL ) ||
        mbi.Type != MEM_IMAGE || !mbi.AllocationBase)
        return NULL;
    base = (ULONG_PTR)mbi.AllocationBase;
    for (i = 0; i < ios_cmd_nmods; i++)
        if (ios_cmd_mods[i].base == base) return addr - base < ios_cmd_mods[i].size ? &ios_cmd_mods[i] : NULL;
    if (ios_cmd_nmods >= ARRAY_SIZE(ios_cmd_mods)) return NULL;
    if (ios_cmd_read( base, &dos, sizeof(dos) ) != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew <= 0 || dos.e_lfanew > 0x10000 ||
        ios_cmd_read( base + dos.e_lfanew, &nt, sizeof(nt) ) != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    m = &ios_cmd_mods[ios_cmd_nmods];
    memset( m, 0, sizeof(*m) );
    m->base = base;
    m->size = nt.OptionalHeader.SizeOfImage;
    nsec = nt.FileHeader.NumberOfSections;
    sec_addr = base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    for (i = 0; i < nsec && i < 96 && m->nsec < ARRAY_SIZE(m->sec); i++)
    {
        IMAGE_SECTION_HEADER sec;
        if (ios_cmd_read( sec_addr + i * sizeof(sec), &sec, sizeof(sec) ) != sizeof(sec)) break;
        if (!(sec.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))) continue;
        m->sec[m->nsec][0] = sec.VirtualAddress;
        m->sec[m->nsec][1] = max( sec.Misc.VirtualSize, sec.SizeOfRawData );
        m->nsec++;
    }
    strcpy( m->name, "?" );
    if (!syscall_NtQueryVirtualMemory( NtCurrentProcess(), (void *)base, MemoryMappedFilenameInformation,
                                       &fn, sizeof(fn) - sizeof(WCHAR), &got ) &&
        fn.str.Buffer && fn.str.Length)
    {
        unsigned int len = fn.str.Length / sizeof(WCHAR), start = 0;
        for (j = 0; j < len; j++) if (fn.str.Buffer[j] == '\\') start = j + 1;
        for (j = 0; start + j < len && j < sizeof(m->name) - 1; j++)
        {
            WCHAR ch = fn.str.Buffer[start + j];
            m->name[j] = ch >= 0x20 && ch < 0x7f ? (char)ch : '?';
        }
        m->name[j] = 0;
    }
    ios_cmd_nmods++;
    return addr - base < m->size ? m : NULL;
}

static BOOL ios_cmd_in_exec( const struct ios_cmd_mod *m, ULONG_PTR addr )
{
    ULONG rva = (ULONG)(addr - m->base), i;

    for (i = 0; i < m->nsec; i++)
        if (rva >= m->sec[i][0] && rva - m->sec[i][0] < m->sec[i][1]) return TRUE;
    return FALSE;
}

/* "module+0xrva" for addr (a JIT-pool alias is shown by its PE address), or "-" */
static const char *ios_cmd_where( ULONG_PTR addr, char *buf, SIZE_T size )
{
    ULONG_PTR pe = (ULONG_PTR)xlate_ios_jit_rev( (void *)addr );
    struct ios_cmd_mod *m = ios_cmd_module( pe );

    if (!m) return "-";
    if (size < sizeof(((struct ios_cmd_mod *)0)->name) + 32) return "-";
    sprintf( buf, "%s+0x%lx%s%s", m->name, (ULONG)(pe - m->base), ios_cmd_in_exec( m, pe ) ? "" : "(data)",
              pe != addr ? "(pool)" : "" );
    return buf;
}

static BOOL ios_cmd_is_x64_code( ULONG_PTR addr )
{
    ULONG_PTR pe = (ULONG_PTR)xlate_ios_jit_rev( (void *)addr );
    return !RtlIsEcCode( pe ) && !RtlIsEcCode( addr );
}

/* 1. unwind from here through the EC frames to the first x64 frame: the caller's context at its call. Returns
 * the number of EC frames unwound, or -1. */
static int __attribute__((noinline)) ios_cmd_x64_context( CONTEXT *ctx )
{
    TEB *teb = NtCurrentTeb();
    ULONG_PTR lo = (ULONG_PTR)teb->DeallocationStack, hi = (ULONG_PTR)teb->Tib.StackBase;
    int i;

    RtlCaptureContext( ctx );
    for (i = 0; i < 64; i++)
    {
        ULONG_PTR pc = ctx->Rip, sp = ctx->Rsp, lpc, base = 0, frame = 0;
        RUNTIME_FUNCTION *func;
        PEXCEPTION_ROUTINE handler;
        void *data;

        if (!pc || sp < lo || sp >= hi) return -1;
        if (ios_cmd_is_x64_code( pc )) return i;
        lpc = (ULONG_PTR)xlate_ios_jit_rev( (void *)pc ) - 4;   /* a return address: look up the call */
        func = RtlLookupFunctionEntry( lpc, &base, NULL );
        if (RtlVirtualUnwind2( UNW_FLAG_NHANDLER, base, lpc, func, ctx, NULL, &data, &frame,
                               NULL, NULL, NULL, &handler, 0 ))
            return -1;
        if (ctx->Rsp < sp || (ctx->Rsp == sp && ctx->Rip == pc)) return -1;
    }
    return -1;
}

struct ios_cmd_fex_thread   /* mirrors IosCmFexThread in FEX's ARM64EC Module.cpp */
{
    ULONG64 version, rip, gregs[16], eflags, fcw, ftw, mxcsr, dr[6], xmm[16][2], ring_seq, block_ring;
};
struct ios_cmd_fex_exc      /* mirrors IosCmFexExc */
{
    ULONG64 seq;
    UINT tid, code, eflags, live_tf;
    ULONG64 x[31], sp, pc;
    UINT cpsr, fpcr, fpsr, ctxflags;
    ULONG64 v[32][2];
};
C_ASSERT( sizeof(struct ios_cmd_fex_thread) == 8 * 62 );
C_ASSERT( sizeof(struct ios_cmd_fex_exc) == 816 );

static void ios_cmd_regs( const char *what, const ULONG64 *g )   /* g: rax rcx rdx rbx rsp rbp rsi rdi r8-r15 */
{
    ERR( IOS_CMD "%s rax=%I64x rcx=%I64x rdx=%I64x rbx=%I64x rsp=%I64x rbp=%I64x rsi=%I64x rdi=%I64x\n",
         what, g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7] );
    ERR( IOS_CMD "%s r8=%I64x r9=%I64x r10=%I64x r11=%I64x r12=%I64x r13=%I64x r14=%I64x r15=%I64x\n",
         what, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15] );
}

static void ios_cmd_xmm( const char *what, const ULONG64 (*x)[2], int first, int count )
{
    int i;
    for (i = first; i < first + count; i += 4)
        ERR( IOS_CMD "%s xmm%d=%016I64x%016I64x xmm%d=%016I64x%016I64x xmm%d=%016I64x%016I64x xmm%d=%016I64x%016I64x\n",
             what, i, x[i][1], x[i][0], i + 1, x[i + 1][1], x[i + 1][0], i + 2, x[i + 2][1], x[i + 2][0],
             i + 3, x[i + 3][1], x[i + 3][0] );
}

static const char *ios_cmd_hkind( ULONG kind )
{
    switch (kind & 0xff)
    {
    case 1: return "VEH";
    case 2: return "SEH";
    case 3: return "TEB-SEH";
    case 4: return "KiUserExceptionDispatcher-hook";
    default: return "none-seen";
    }
}

/* the target of a hooked KiUserExceptionDispatcher thunk: jmp rel32, jmp [rip+x], mov rax/r11,imm64 + jmp */
static ULONG_PTR ios_cmd_hook_target( const UCHAR *p )
{
    ULONG_PTR t = 0;
    UCHAR b[16];

    if (ios_cmd_read( (ULONG_PTR)p, b, sizeof(b) ) != sizeof(b)) return 0;
    if (b[0] == 0xe9) return (ULONG_PTR)p + 5 + *(const INT *)(b + 1);
    if (b[0] == 0xff && b[1] == 0x25)
    {
        ios_cmd_read( (ULONG_PTR)p + 6 + *(const INT *)(b + 2), &t, sizeof(t) );
        return t;
    }
    if (b[0] == 0x48 && b[1] == 0xb8) return *(const ULONG_PTR *)(b + 2);
    if (b[0] == 0x49 && b[1] == 0xbb) return *(const ULONG_PTR *)(b + 2);
    return 0;
}

/* prepare_exception_arm64ec hands the exception to a hooked KiUserExceptionDispatcher thunk */
static void ios_cmd_note_ki( const EXCEPTION_RECORD *rec, const void *thunk )
{
    static UCHAR last[16];
    static ULONG_PTR target;

    if (!ios_cmd_rec()) return;
    if (memcmp( last, thunk, sizeof(last) ))   /* decode again only when the hook changed */
    {
        memcpy( last, thunk, sizeof(last) );
        target = ios_cmd_hook_target( (const UCHAR *)thunk );
    }
    ios_cmd_handler( rec, 4, (const void *)target, 0, 2 );
}

static BOOL ios_cmd_wcsistr( const WCHAR *s, SIZE_T len, const char *needle )
{
    SIZE_T n = strlen( needle ), i, j;

    for (i = 0; i + n <= len; i++)
    {
        for (j = 0; j < n; j++)
        {
            WCHAR c = s[i + j];
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (c != (WCHAR)needle[j]) break;
        }
        if (j == n) return TRUE;
    }
    return FALSE;
}

/* a string of process parameters (offsets when the block is not normalized), copied with checked reads */
static USHORT ios_cmd_pstr( const RTL_USER_PROCESS_PARAMETERS *p, const UNICODE_STRING *s, WCHAR *out, USHORT max )
{
    ULONG_PTR addr;
    USHORT len;

    if (!s->Buffer || !s->Length) return 0;
    addr = (p->Flags & PROCESS_PARAMS_FLAG_NORMALIZED) ? (ULONG_PTR)s->Buffer : (ULONG_PTR)p + (ULONG_PTR)s->Buffer;
    len = min( s->Length / sizeof(WCHAR), max );
    return ios_cmd_read( addr, out, len * sizeof(WCHAR) ) == len * sizeof(WCHAR) ? len : 0;
}

static void ios_cmd_wline( const char *what, const WCHAR *s, SIZE_T len )
{
    SIZE_T i;

    if (!len) ERR( IOS_CMD "%s (none)\n", what );
    for (i = 0; i < len; i += 160)
        ERR( IOS_CMD "%s%s %s\n", what, i ? " (cont.)" : "", debugstr_wn( s + i, min( 160, len - i ) ) );
}

static union { SYSTEM_HANDLE_INFORMATION_EX info; UCHAR buf[256 * 1024]; } ios_cmd_handles;
static struct ios_cmd_fex_exc ios_cmd_fexr[64];
static ULONG64 ios_cmd_blk[4096];
static ULONG_PTR ios_cmd_dirbuf[4][8192 / sizeof(ULONG_PTR)];

/* 7. files changed in the last 60 s under a folder (depth <= max_depth) */
static void ios_cmd_scan_dir( HANDLE root, const WCHAR *name, USHORT name_chars, WCHAR *rel, USHORT rel_len,
                              int depth, int max_depth, LONGLONG since, LONGLONG now, int *scanned, int *shown )
{
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING us;
    IO_STATUS_BLOCK io;
    HANDLE dir;
    struct { USHORT off, len; } subs[24];
    WCHAR subnames[24][64];
    int nsub = 0, k;
    BOOLEAN restart = TRUE;
    void *buf = ios_cmd_dirbuf[depth];

    us.Buffer = (WCHAR *)name;
    us.Length = us.MaximumLength = name_chars * sizeof(WCHAR);
    InitializeObjectAttributes( &attr, &us, OBJ_CASE_INSENSITIVE, root, NULL );
    if (ioscmd_NtOpenFile( &dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &io,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT ))
        return;
    while (*scanned < 6000 &&
           !ioscmd_NtQueryDirectoryFile( dir, NULL, NULL, NULL, &io, buf, sizeof(ios_cmd_dirbuf[0]),
                                         FileDirectoryInformation, FALSE, NULL, restart ))
    {
        FILE_DIRECTORY_INFORMATION *fi = buf;
        restart = FALSE;
        for (;;)
        {
            USHORT n = fi->FileNameLength / sizeof(WCHAR);
            const WCHAR *fname = fi->FileName;
            BOOL dot = (n == 1 && fname[0] == '.') || (n == 2 && fname[0] == '.' && fname[1] == '.');

            if (!dot)
            {
                (*scanned)++;
                if (fi->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    if (!(fi->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && depth < max_depth &&
                        nsub < ARRAY_SIZE(subs) && n <= ARRAY_SIZE(subnames[0]))
                    {
                        memcpy( subnames[nsub], fname, n * sizeof(WCHAR) );
                        subs[nsub].len = n;
                        nsub++;
                    }
                }
                else if ((fi->LastWriteTime.QuadPart >= since || fi->CreationTime.QuadPart >= since) && *shown < 48)
                {
                    LONGLONG t = max( fi->LastWriteTime.QuadPart, fi->CreationTime.QuadPart );
                    (*shown)++;
                    ERR( IOS_CMD "recent -%I64ds size=%I64d attr=%lx %s\\%s\n", (now - t) / 10000000,
                         fi->EndOfFile.QuadPart, fi->FileAttributes, debugstr_wn( rel, rel_len ),
                         debugstr_wn( fname, n ) );
                }
            }
            if (!fi->NextEntryOffset) break;
            fi = (FILE_DIRECTORY_INFORMATION *)((char *)fi + fi->NextEntryOffset);
        }
    }
    for (k = 0; k < nsub; k++)
    {
        USHORT len = rel_len;
        if (len + 1 + subs[k].len > 259) continue;
        rel[len++] = '\\';
        memcpy( rel + len, subnames[k], subs[k].len * sizeof(WCHAR) );
        len += subs[k].len;
        ios_cmd_scan_dir( dir, subnames[k], subs[k].len, rel, len, depth + 1, max_depth, since, now, scanned, shown );
    }
    syscall_NtClose( dir );
}

static void ios_cmd_scan_root( const char *what, const WCHAR *dos_dir, USHORT dir_chars, int max_depth,
                               LONGLONG since, LONGLONG now )
{
    WCHAR nt[300], rel[260];
    int scanned = 0, shown = 0;

    if (!dir_chars || dir_chars > 290) return;
    memcpy( nt, L"\\??\\", 4 * sizeof(WCHAR) );
    memcpy( nt + 4, dos_dir, dir_chars * sizeof(WCHAR) );
    ERR( IOS_CMD "recent files under %s %s (changed or created in the last 60 s, depth %d):\n", what,
         debugstr_wn( dos_dir, dir_chars ), max_depth );
    rel[0] = '.';
    ios_cmd_scan_dir( NULL, nt, dir_chars + 4, rel, 1, 0, max_depth, since, now, &scanned, &shown );
    ERR( IOS_CMD "recent: %d entries scanned, %d shown\n", scanned, shown );
}

/* madeira [crashmailer-exit-probe] (env MADEIRA_EC_EXIT_PROBE = 0 turns it off; also off with
 * MADEIRA_EC_CRASHMAILER_DUMP = 0). rev=crashmailer-exit-probe-2. LOG ONLY. Ours.
 *
 * Overwatch 2 decides to quit (or crashes) without saying why, and the crashmailer dump only runs when it
 * starts CrashMailer. This prints, at most once each:
 *   - on NtTerminateProcess of this process (which ExitProcess and the CRT's exit end in), the
 *     main thread's last 65536 translated blocks (FEX makes the ml1205 ring that big for Overwatch.exe while
 *     this probe is on), folded: a repeated cycle of up to 16 blocks is one "*kxr" token; the first
 *     LdrLoadDll of winbrand.dll and the first SystemProcessorPerformanceInformation query only log one line
 *     (rev 2: they come long before an exit in many processes and used to take the snapshot);
 *   - on the first recorded access violation at each target (env MADEIRA_EC_EXIT_PROBE_AV, a ';' list of
 *     "module+hexrva", up to 4; default "Overwatch_loader.dll+1d8b143;Overwatch_loader.dll+f03a09", the two
 *     AVs of the 0.2.94/0.2.95 crash), the faulting thread's x64 registers as its handlers get them, 64 bytes
 *     around every register value, 32 stack slots with module+rva, and the same block snapshot for that thread;
 *   - every software exception raised through RtlRaiseException (RaiseException, C++ throw 0xE06D7363 with
 *     the thrown type's name), the first 64 and then every 256th; for the first NONCONTINUABLE one also the
 *     caller's registers, the code addresses on its stack, this thread's last information queries and the
 *     block snapshots of this thread and of the main thread.
 * The snapshot and the AV dump read memory only through the dump's checked reads. The 512 KB snapshot buffer is
 * allocated once at startup, only when the probe is on. */
static LONG ios_xp_mode;   /* 0 not read, 1 off, 2 on; set with ios_cmd_mode */
static TEB *ios_xp_main_teb;
static LONG ios_xp_exit_done, ios_xp_busy, ios_xp_raise_n, ios_xp_nc_done, ios_xp_brand_done;
/* the snapshot buffer: allocated only when the probe is on (no .bss when it is off) */
#define IOS_XP_SNAP_N 65536
static ULONG64 *ios_xp_snap;
static struct { WCHAR mod[48]; ULONG rva; LONG done; } ios_xp_av[4];
static unsigned int ios_xp_nav;

/* [ptr-origin-1] heap ring: every RtlAllocateHeap/RtlFreeHeap of this process (all heaps, all threads), newest
 * 16384. Only allocated when the probe is on. LOG ONLY. */
#define IOS_PO_N 16384
LONG ios_po_mode;
static LONG ios_po_next;
static struct ios_po_ent { ULONG seq, tid, tick, op; ULONG_PTR heap, size, ptr, caller; } *ios_po_ring;

void ios_po_heap( ULONG op, void *heap, SIZE_T size, void *ptr, void *caller )
{
    struct ios_po_ent *e;
    LONG n;

    if (ios_po_mode != 2 || !ios_po_ring || ios_cmd_dumping || !ptr) return;
    n = InterlockedIncrement( &ios_po_next );
    e = &ios_po_ring[(n - 1) & (IOS_PO_N - 1)];
    e->seq = 0;   /* a reader skips an entry that is being rewritten */
    e->tid = ios_cmd_tid();
    e->tick = NtGetTickCount();
    e->op = op;
    e->heap = (ULONG_PTR)heap;
    e->size = size;
    e->ptr = (ULONG_PTR)ptr;
    e->caller = (ULONG_PTR)caller;
    e->seq = n;
}

static void ios_xp_parse_av( const WCHAR *s, USHORT len )
{
    USHORT i = 0;

    while (i < len && ios_xp_nav < ARRAY_SIZE(ios_xp_av))
    {
        unsigned int n = 0;
        ULONG rva = 0;
        BOOL ok = FALSE;

        while (i < len && s[i] != '+' && s[i] != ';')
        {
            if (n < ARRAY_SIZE(ios_xp_av[0].mod) - 1) ios_xp_av[ios_xp_nav].mod[n++] = s[i];
            i++;
        }
        ios_xp_av[ios_xp_nav].mod[n] = 0;
        if (i < len && s[i] == '+')
        {
            for (i++; i < len && s[i] != ';'; i++)
            {
                WCHAR c = s[i];
                if (c == 'x' || c == 'X') continue;
                if (c >= '0' && c <= '9') rva = rva * 16 + (c - '0');
                else if ((c | 0x20) >= 'a' && (c | 0x20) <= 'f') rva = rva * 16 + ((c | 0x20) - 'a' + 10);
                else continue;
                ok = TRUE;
            }
        }
        if (i < len && s[i] == ';') i++;
        if (ok && n)
        {
            ios_xp_av[ios_xp_nav].rva = rva;
            ios_xp_nav++;
        }
    }
}

/* first thread, from ios_cmd_read_switch (same lock-free environment read) */
static void ios_xp_read_switch( WCHAR *env )
{
    static const WCHAR dflt[] = L"Overwatch_loader.dll+1d8b143;Overwatch_loader.dll+f03a09";
    UNICODE_STRING var, value;
    WCHAR buffer[256];
    unsigned int i;

    ios_xp_main_teb = NtCurrentTeb();
    if (ios_cmd_mode != 2) { ios_xp_mode = 1; return; }
    RtlInitUnicodeString( &var, L"MADEIRA_EC_EXIT_PROBE" );
    value.Buffer = buffer;
    value.Length = 0;
    value.MaximumLength = 2 * sizeof(WCHAR);
    ios_xp_mode = (!RtlQueryEnvironmentVariable_U( env, &var, &value ) &&
                   value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
    if (ios_xp_mode != 2) return;
    RtlInitUnicodeString( &var, L"MADEIRA_EC_PTR_ORIGIN" );
    value.Length = 0;
    value.MaximumLength = 2 * sizeof(WCHAR);
    if (!(!RtlQueryEnvironmentVariable_U( env, &var, &value ) && value.Length == sizeof(WCHAR) && buffer[0] == '0'))
    {
        void *pm = NULL;
        SIZE_T psize = IOS_PO_N * sizeof(*ios_po_ring);
        if (!NtAllocateVirtualMemory( NtCurrentProcess(), &pm, 0, &psize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ))
        {
            ios_po_ring = pm;
            ios_po_mode = 2;
            ERR( "[ptr-origin] rev=ptr-origin-1 on (MADEIRA_EC_PTR_ORIGIN=0 turns it off): heap ring %u entries\n", IOS_PO_N );
        }
    }
    if (ios_po_mode != 2) ios_po_mode = 1;
    {
        void *mem = NULL;
        SIZE_T size = IOS_XP_SNAP_N * sizeof(ULONG64);
        if (NtAllocateVirtualMemory( NtCurrentProcess(), &mem, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ))
        {
            ERR( "[crashmailer-exit-probe] no memory for the snapshot buffer, probe off\n" );
            ios_xp_mode = 1;
            return;
        }
        ios_xp_snap = mem;
    }
    RtlInitUnicodeString( &var, L"MADEIRA_EC_EXIT_PROBE_AV" );
    value.Length = 0;
    value.MaximumLength = sizeof(buffer);
    if (!RtlQueryEnvironmentVariable_U( env, &var, &value )) ios_xp_parse_av( buffer, value.Length / sizeof(WCHAR) );
    else ios_xp_parse_av( dflt, ARRAY_SIZE(dflt) - 1 );
    ERR( "[crashmailer-exit-probe] rev=crashmailer-exit-probe-2 on (MADEIRA_EC_EXIT_PROBE=0 turns it off), %u AV target(s)\n",
         ios_xp_nav );
    for (i = 0; i < ios_xp_nav; i++)
        ERR( "[crashmailer-exit-probe] AV target %u: %s+0x%lx\n", i, debugstr_w( ios_xp_av[i].mod ), ios_xp_av[i].rva );
}

/* The last `want` entries of a ml1205 block ring, oldest first, into out[0..want). The ring's size is ring[-1]
 * (an older FEX without it: 4096). Unused slots read as 0. */
static BOOL ios_xp_ring_last( ULONG_PTR ring, ULONG64 idx, ULONG64 *out, ULONG want )
{
    ULONG64 n = 0;
    ULONG first, a;

    if (ios_cmd_read( ring - 8, &n, 8 ) != 8 || n < 4096 || n > 65536 || (n & (n - 1))) n = 4096;
    memset( out, 0, want * sizeof(*out) );
    if (want > n)
    {
        out += want - (ULONG)n;
        want = (ULONG)n;
    }
    idx &= n - 1;
    first = (ULONG)((idx + n - want) & (n - 1));   /* oldest wanted slot */
    a = (ULONG)min( (ULONG64)want, n - first );
    if (ios_cmd_read( ring + 8 + first * 8, out, a * 8 ) != a * 8) return FALSE;
    if (a < want && ios_cmd_read( ring + 8, out + a, (want - a) * 8 ) != (want - a) * 8) return FALSE;
    return TRUE;
}

/* the block snapshot of the thread whose TEB is teb */
static void ios_xp_blocks( const char *why, TEB *teb )
{
    static struct { ULONG_PTR base, size; char name[48]; } mods[32];
    unsigned int nmods = 0, cur = ~0u;
    ULONG_PTR ring = 0;
    ULONG64 idx = 0;
    ULONG n = IOS_XP_SNAP_N, cnt, i, lines = 0;
    char line[300], w[96];
    int o = 0, tokens = 0;

    if (!ios_xp_snap || !teb || ios_cmd_read( (ULONG_PTR)teb + 0x1710, &ring, sizeof(ring) ) != sizeof(ring) || !ring ||
        ios_cmd_read( ring, &idx, 8 ) != 8 || !ios_xp_ring_last( ring, idx, ios_xp_snap, n ))
    {
        ERR( "[crashmailer-exit-probe] blocks (%s): no block ring on thread %04lx\n", why,
             teb ? HandleToULong( teb->ClientId.UniqueThread ) : 0 );
        return;
    }
    for (cnt = 0; cnt < n && !ios_xp_snap[cnt]; cnt++) ;   /* cnt = the first used slot */
    ERR( "[crashmailer-exit-probe] blocks (%s): thread %04lx, last %lu of %lu block entries, oldest first; m<i>+rva "
         "(modules listed after), else the address; /len = x86 bytes in the translation; *kxr = the previous k "
         "entries repeated r more times\n", why, HandleToULong( teb->ClientId.UniqueThread ), n - cnt, n );
    for (i = cnt; i < n && lines < 8192; )
    {
        ULONG64 ent = ios_xp_snap[i], rip = (ULONG_PTR)xlate_ios_jit_rev( (void *)(ULONG_PTR)(ent & 0xffffffffffffULL) );
        ULONG k, best_k = 0, best_r = 0;

        /* fold a cycle: entries i.. repeat the k before them */
        for (k = 1; k <= 16 && i >= cnt + k; k++)
        {
            ULONG r = 0;
            while (i + (r + 1) * k <= n && !memcmp( &ios_xp_snap[i + r * k], &ios_xp_snap[i - k], k * 8 )) r++;
            if (r && r * k > best_r * best_k) { best_k = k; best_r = r; }
        }
        if (best_r && best_r * best_k >= 2)
        {
            o += sprintf( line + o, " *%lux%lu", best_k, best_r );
            i += best_r * best_k;
        }
        else
        {
            if (cur == ~0u || rip - mods[cur].base >= mods[cur].size)
            {
                struct ios_cmd_mod *m = ios_cmd_module( (ULONG_PTR)rip );   /* rip is already the PE address */
                unsigned int j;
                cur = ~0u;
                if (m)
                {
                    for (j = 0; j < nmods; j++) if (mods[j].base == m->base) break;
                    if (j == nmods && nmods < ARRAY_SIZE(mods))
                    {
                        mods[nmods].base = m->base;
                        mods[nmods].size = m->size;
                        strcpy( mods[nmods].name, m->name );
                        nmods++;
                    }
                    if (j < nmods) cur = j;
                }
            }
            if (cur != ~0u) o += sprintf( line + o, " m%u+%I64x/%x", cur, rip - mods[cur].base, (UINT)(ent >> 48) );
            else o += sprintf( line + o, " %I64x/%x", rip, (UINT)(ent >> 48) );
            i++;
        }
        if (++tokens == 10 || i >= n)
        {
            ERR( "[crashmailer-exit-probe] b%lu:%s\n", lines, line );
            lines++;
            o = tokens = 0;
        }
    }
    if (lines >= 8192) ERR( "[crashmailer-exit-probe] blocks: cut at 8192 lines\n" );
    for (i = 0; i < nmods; i++)
        ERR( "[crashmailer-exit-probe] m%lu = %s base %p size %Ix\n", i, mods[i].name, (void *)mods[i].base, mods[i].size );
    for (i = n > 32 ? n - 32 : 0; i < n; i++)
        if (ios_xp_snap[i])
            ERR( "[crashmailer-exit-probe] blk -%lu %s\n", n - i,
                 ios_cmd_where( (ULONG_PTR)(ios_xp_snap[i] & 0xffffffffffffULL), w, sizeof(w) ) );
}

static BOOL ios_xp_enter(void)
{
    if (ios_xp_mode != 2 || ios_cmd_dumping) return FALSE;
    if (InterlockedCompareExchange( &ios_xp_busy, 1, 0 )) return FALSE;   /* one printer at a time */
    ios_cmd_dumping = 1;   /* the rings do not record the probe's own reads */
    return TRUE;
}

static void ios_xp_leave(void)
{
    ios_cmd_dumping = 0;
    InterlockedExchange( &ios_xp_busy, 0 );
}

/* An exit-path hint (an SystemProcessorPerformanceInformation query, the winbrand.dll load): one line each, the
 * first time only, and no snapshot. Overlays, CPU monitors and branding code cause these long before an exit. */
static void ios_xp_exit_hint( LONG *latch, const char *why )
{
    if (ios_xp_mode != 2 || *latch || InterlockedExchange( latch, 1 )) return;
    ERR( "[crashmailer-exit-probe] exit-path hint (log only): %s, on thread %04lx\n", why, ios_cmd_tid() );
}

/* The real exit (NtTerminateProcess): the main thread's block snapshot, once. A busy printer does not use up
 * the latch. */
static void ios_xp_exit_event( const char *why )
{
    if (ios_xp_mode != 2 || ios_xp_exit_done) return;
    if (!ios_xp_enter()) return;
    if (!InterlockedExchange( &ios_xp_exit_done, 1 ))
    {
        ERR( "[crashmailer-exit-probe] exit: %s, on thread %04lx (main thread %04lx)\n", why,
             ios_cmd_tid(), ios_xp_main_teb ? HandleToULong( ios_xp_main_teb->ClientId.UniqueThread ) : 0 );
        ios_xp_blocks( why, ios_xp_main_teb );
    }
    ios_xp_leave();
}

void ios_xp_dll_event( const UNICODE_STRING *name )   /* loader.c LdrLoadDll */
{
    if (ios_xp_mode == 2 && !ios_xp_brand_done && name && name->Buffer &&
        ios_cmd_wcsistr( name->Buffer, name->Length / sizeof(WCHAR), "winbrand" ))
        ios_xp_exit_hint( &ios_xp_brand_done, "LdrLoadDll winbrand.dll" );
}

/* a recorded exception with the context its handlers get (from ios_cmd_exc_ctx) */
/* [ptr-origin-1] The AV target's address `a` (the read at loader+0xF03A09): which module/view it is relative to, what
 * the system says it is, which heap blocks cover it, where else the value is stored, and the newest heap calls. */
static void ios_po_report( const char *tag, ULONG64 a, const ULONG64 *g, ULONG_PTR sp )
{
    MEMORY_BASIC_INFORMATION mbi;
    LIST_ENTRY *head, *l;
    struct ios_po_ent snap;
    char w[96];
    LONG next = ios_po_next, i, hits = 0;
    unsigned int k;
    ULONG_PTR ldr_base = 0, ldr_size = 0;

    if (ios_po_mode != 2) return;
    ERR( "[ptr-origin] %s: target address %I64x\n", tag, a );
    if (!NtQueryVirtualMemory( NtCurrentProcess(), (void *)(ULONG_PTR)a, MemoryBasicInformation, &mbi, sizeof(mbi), NULL ))
        ERR( "[ptr-origin] %s: region base %p alloc base %p size %#Ix state %08lx protect %08lx type %08lx\n", tag,
             mbi.BaseAddress, mbi.AllocationBase, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type );
    else
        ERR( "[ptr-origin] %s: NtQueryVirtualMemory failed (unmapped)\n", tag );
    head = &NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList;
    for (l = head->Flink; l != head; l = l->Flink)
    {
        LDR_DATA_TABLE_ENTRY *m = CONTAINING_RECORD( l, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
        LONG64 d = (LONG64)a - (LONG64)(ULONG_PTR)m->DllBase;
        if (!m->BaseDllName.Buffer) continue;
        if (!wcsnicmp( m->BaseDllName.Buffer, L"Overwatch_loader.dll", 20 ))
        {
            ldr_base = (ULONG_PTR)m->DllBase;
            ldr_size = m->SizeOfImage;
        }
        if (d > -0x40000000LL && d < 0x40000000LL)
            ERR( "[ptr-origin] %s: address = %s%s%#I64x (module %s base %p size %#lx)\n", tag, "base", d < 0 ? "-" : "+",
                 d < 0 ? -d : d, debugstr_w( m->BaseDllName.Buffer ), m->DllBase, m->SizeOfImage );
    }
    /* heap blocks whose range holds the address (newest 8), newest first */
    for (i = next; i > 0 && i > next - IOS_PO_N && hits < 8; i--)
    {
        struct ios_po_ent *e = &ios_po_ring[(i - 1) & (IOS_PO_N - 1)];
        snap = *e;
        if (snap.seq != (ULONG)i) continue;
        if (a < snap.ptr || (snap.op == 0 && a >= snap.ptr + max( snap.size, 1 )) || (snap.op == 1 && a != snap.ptr)) continue;
        ERR( "[ptr-origin] %s: heap %s #%lu tid=%04lx -%lums heap=%p ptr=%p size=%#Ix caller=%s\n", tag,
             snap.op ? "FREE" : "ALLOC", snap.seq, snap.tid, NtGetTickCount() - snap.tick, (void *)snap.heap,
             (void *)snap.ptr, snap.size, ios_cmd_where( snap.caller, w, sizeof(w) ) );
        hits++;
    }
    if (!hits) ERR( "[ptr-origin] %s: no heap ring entry covers the address (ring holds the last %ld calls)\n", tag,
                    min( next, (LONG)IOS_PO_N ) );
    /* the newest 24 heap calls */
    for (i = max( next - 24, 0 ); i < next; i++)
    {
        snap = ios_po_ring[i & (IOS_PO_N - 1)];
        if (snap.seq != (ULONG)(i + 1)) continue;
        ERR( "[ptr-origin] %s: recent heap %s #%lu tid=%04lx -%lums ptr=%p size=%#Ix caller=%s\n", tag,
             snap.op ? "FREE" : "ALLOC", snap.seq, snap.tid, NtGetTickCount() - snap.tick, (void *)snap.ptr, snap.size,
             ios_cmd_where( snap.caller, w, sizeof(w) ) );
    }
    /* where else is the value (or a value within 0x1000 of it) stored: registers, 4 KB of stack, the loader's image */
    for (k = 0; k < 16; k++)
        if (g[k] + 0x1000 >= a && g[k] <= a + 0x1000)
            ERR( "[ptr-origin] %s: register #%u holds %I64x (%I64d from the address)\n", tag, k, g[k], (LONG64)(g[k] - a) );
    for (k = 0; k < 512; k++)
    {
        ULONG64 v;
        if (ios_cmd_read( sp + k * 8, &v, 8 ) != 8) break;
        if (v + 0x1000 >= a && v <= a + 0x1000)
            ERR( "[ptr-origin] %s: stack [rsp+%#x] holds %I64x (%I64d from the address)\n", tag, k * 8, v, (LONG64)(v - a) );
    }
    if (ldr_base && ldr_size)
    {
        static ULONG64 page[512];   /* the dump holds ios_xp_busy, so one buffer is enough */
        ULONG_PTR off;
        unsigned int found = 0;
        for (off = 0; off < ldr_size && found < 16; off += sizeof(page))
        {
            SIZE_T got = ios_cmd_read( ldr_base + off, page, sizeof(page) );
            for (k = 0; k < got / 8 && found < 16; k++)
                if (page[k] + 0x1000 >= a && page[k] <= a + 0x1000)
                {
                    ERR( "[ptr-origin] %s: loader image rva %#lx holds %I64x (%I64d from the address)\n", tag,
                         off + k * 8, page[k], (LONG64)(page[k] - a) );
                    found++;
                }
        }
        if (!found) ERR( "[ptr-origin] %s: the value is not stored anywhere in the loader image\n", tag );
    }
}

static void ios_xp_av_check( const EXCEPTION_RECORD *rec, const CONTEXT *c )
{
    LDR_DATA_TABLE_ENTRY *mod;
    ULONG_PTR addr = (ULONG_PTR)rec->ExceptionAddress, sp = c->Rsp;
    ULONG64 g[16];
    char w[96];
    unsigned int i, t;

    if (ios_xp_mode != 2 || !ios_xp_nav || rec->ExceptionCode != STATUS_ACCESS_VIOLATION) return;
    if (LdrFindEntryForAddress( (void *)addr, &mod ) || !mod->BaseDllName.Buffer) return;
    for (t = 0; t < ios_xp_nav; t++)
    {
        if (ios_xp_av[t].done || addr - (ULONG_PTR)mod->DllBase != ios_xp_av[t].rva) continue;
        if (wcsnicmp( mod->BaseDllName.Buffer, ios_xp_av[t].mod, mod->BaseDllName.Length / sizeof(WCHAR) ) ||
            ios_xp_av[t].mod[mod->BaseDllName.Length / sizeof(WCHAR)])
            continue;
        if (!ios_xp_enter()) return;   /* busy: the target stays armed for its next AV */
        if (InterlockedExchange( &ios_xp_av[t].done, 1 ))
        {
            ios_xp_leave();
            return;
        }
        ERR( "[crashmailer-exit-probe] AV at target %u %s+0x%lx (rip %p) on thread %04lx: %s %p, the context its "
             "handlers get:\n", t, debugstr_w( ios_xp_av[t].mod ), ios_xp_av[t].rva, (void *)addr, ios_cmd_tid(),
             rec->NumberParameters >= 1 && rec->ExceptionInformation[0] ? "write" : "read",
             rec->NumberParameters >= 2 ? (void *)rec->ExceptionInformation[1] : NULL );
        memcpy( g, &c->Rax, sizeof(g) );   /* Rax..R15 in CONTEXT order: rax rcx rdx rbx rsp rbp rsi rdi r8-r15 */
        ios_cmd_regs( "probe-av", g );
        ERR( IOS_CMD "probe-av eflags=%08lx mxcsr=%08lx\n", c->EFlags, c->MxCsr );
        ios_cmd_xmm( "probe-av", (const ULONG64 (*)[2])&c->Xmm0, 0, 16 );
        for (i = 0; i < 16; i++)
        {
            char what[128];
            static const char * const names[16] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
            if (g[i] < 0x10000 || g[i] >= 0x800000000000ULL) continue;
            snprintf( what, sizeof(what), "[%s-32] %s", names[i], ios_cmd_where( (ULONG_PTR)g[i], w, sizeof(w) ) );
            ios_cmd_hexline( what, (ULONG_PTR)g[i] - 32, 64 );
        }
        for (i = 0; i < 32; i++)
        {
            ULONG64 v = 0;
            if (ios_cmd_read( sp + i * 8, &v, 8 ) != 8) break;
            ERR( IOS_CMD "probe-av [rsp+%#x]=%I64x %s\n", i * 8, v, ios_cmd_where( (ULONG_PTR)v, w, sizeof(w) ) );
        }
        if (rec->NumberParameters >= 2) ios_po_report( t ? "target-1" : "target-0", rec->ExceptionInformation[1], g, sp );   /* [ptr-origin-1] */
        ios_xp_blocks( "AV target", NtCurrentTeb() );
        ios_xp_leave();
        return;
    }
}

/* The first noncontinuable raise (0.2.95 tso log: Overwatch_loader+0x1c1643b raises 0xC00000E5 noncontinuable
 * through kernelbase RaiseException): who raised it, what this thread asked the system just before, and the
 * blocks of this thread and of the main thread. */
static void ios_xp_noncontinuable( const EXCEPTION_RECORD *rec, const CONTEXT *c )
{
    const ULONG tid = ios_cmd_tid(), now = NtGetTickCount();
    ULONG64 g[16];
    char w[96];
    ULONG n, first, i, shown = 0;

    ERR( "[crashmailer-exit-probe] noncontinuable raise %08lx on thread %04lx; the caller's context (unwound from "
         "RtlRaiseException) and the code addresses on its stack:\n", rec->ExceptionCode, tid );
    memcpy( g, &c->Rax, sizeof(g) );
    ios_cmd_regs( "probe-nc", g );
    ERR( IOS_CMD "probe-nc rip=%p %s eflags=%08lx\n", (void *)c->Rip, ios_cmd_where( c->Rip, w, sizeof(w) ), c->EFlags );
    for (i = 0; i < 512 && shown < 24; i++)
    {
        ULONG64 v = 0;
        struct ios_cmd_mod *m;
        if (ios_cmd_read( c->Rsp + i * 8, &v, 8 ) != 8) break;
        if (!(m = ios_cmd_module( (ULONG_PTR)xlate_ios_jit_rev( (void *)(ULONG_PTR)v ) )) ||
            !ios_cmd_in_exec( m, (ULONG_PTR)xlate_ios_jit_rev( (void *)(ULONG_PTR)v ) ))
            continue;
        ERR( IOS_CMD "probe-nc [rsp+%#lx]=%I64x %s\n", i * 8, v, ios_cmd_where( (ULONG_PTR)v, w, sizeof(w) ) );
        ios_cmd_hexline( "code ret-64", (ULONG_PTR)v - 64, 64 );
        shown++;
    }
    /* the information queries this thread made last (the crashmailer-dump ring; other syscalls are not recorded) */
    n = (ULONG)ios_cmd_q_next;
    first = n > IOS_CMD_Q_N ? n - IOS_CMD_Q_N : 0;
    ERR( IOS_CMD "probe-nc this thread's last information queries, oldest first (of the last %lu of all threads):\n",
         n - first );
    for (i = first; i < n; i++)
    {
        const struct ios_cmd_q *q = &ios_cmd_q[i % IOS_CMD_Q_N];
        char hex[32 * 3 + 1];
        if (q->seq != i + 1 || q->tid != tid) continue;
        ios_cmd_hex( hex, q->data, sizeof(q->data), sizeof(q->data) );
        ERR( IOS_CMD "probe-nc q #%lu -%lums %s h=%p class=%lx status=%08lx len=%lu retlen=%ld data=%s\n", i,
             now - q->tick, ios_cmd_qname[q->fn < ARRAY_SIZE(ios_cmd_qname) ? q->fn : 0], (void *)q->handle, q->cls,
             q->status, q->len, (long)q->retlen, hex );
    }
    /* [ptr-origin-1] the raising thread made no queries in 0.2.96 (its list printed empty): the newest 16 of any thread */
    ERR( IOS_CMD "probe-nc newest information queries of ANY thread:\n" );
    for (i = n > 16 ? n - 16 : 0; i < n; i++)
    {
        const struct ios_cmd_q *q = &ios_cmd_q[i % IOS_CMD_Q_N];
        if (q->seq != i + 1) continue;
        ERR( IOS_CMD "probe-nc any #%lu tid=%04lx -%lums %s class=%lx status=%08lx len=%lu\n", i, q->tid, now - q->tick,
             ios_cmd_qname[q->fn < ARRAY_SIZE(ios_cmd_qname) ? q->fn : 0], q->cls, q->status, q->len );
    }
    ios_xp_blocks( "noncontinuable raise, raising thread", NtCurrentTeb() );
    if (ios_xp_main_teb && ios_xp_main_teb != NtCurrentTeb())
        ios_xp_blocks( "noncontinuable raise, main thread", ios_xp_main_teb );
}

/* RtlRaiseException, before dispatch (called from its asm) */
void WINAPI ios_xp_raise( const EXCEPTION_RECORD *rec, const CONTEXT *c )
{
    LONG n;
    char w[96], type[80] = "";

    if (ios_xp_mode != 2 || ios_cmd_dumping || !rec) return;
    n = InterlockedIncrement( &ios_xp_raise_n );
    if (n > 64 && n % 256) return;
    if (!ios_xp_enter()) return;
    if (rec->ExceptionCode == 0xe06d7363 && rec->NumberParameters >= 4)
    {
        /* x64 C++ throw: [2] = ThrowInfo (image-relative fields), [3] = image base. ThrowInfo+0xc ->
         * CatchableTypeArray, +4 the first CatchableType, its +4 the TypeDescriptor, whose name is at +0x10. */
        ULONG_PTR base = rec->ExceptionInformation[3], ti = rec->ExceptionInformation[2];
        int rva_cta = 0, rva_ct = 0, rva_td = 0;
        SIZE_T got;
        if (ti && base && ios_cmd_read( ti + 0xc, &rva_cta, 4 ) == 4 && rva_cta &&
            ios_cmd_read( base + rva_cta + 4, &rva_ct, 4 ) == 4 && rva_ct &&
            ios_cmd_read( base + rva_ct + 4, &rva_td, 4 ) == 4 && rva_td &&
            (got = ios_cmd_read( base + rva_td + 0x10, type, sizeof(type) - 1 )))
        {
            type[got] = 0;
            for (got = 0; type[got]; got++) if (type[got] < 0x20 || type[got] >= 0x7f) type[got] = '?';
        }
    }
    ERR( "[crashmailer-exit-probe] raise #%ld tid=%04lx code=%08lx flags=%lx at %p %s nparams=%lu p0=%p p1=%p%s%s\n",
         n, ios_cmd_tid(), rec->ExceptionCode, rec->ExceptionFlags, rec->ExceptionAddress,
         ios_cmd_where( (ULONG_PTR)rec->ExceptionAddress, w, sizeof(w) ), rec->NumberParameters,
         rec->NumberParameters >= 1 ? (void *)rec->ExceptionInformation[0] : NULL,
         rec->NumberParameters >= 2 ? (void *)rec->ExceptionInformation[1] : NULL,
         type[0] ? " c++ type " : "", type );
    if ((rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) && c && !InterlockedExchange( &ios_xp_nc_done, 1 ))
        ios_xp_noncontinuable( rec, c );
    ios_xp_leave();
}

static void ios_cmd_dump( const RTL_USER_PROCESS_PARAMETERS *params, const WCHAR *image, USHORT image_len,
                          ULONG process_flags, ULONG thread_flags )
{
    static WCHAR cmdline[2048], cwd[300];
    static const char * const gpr_names[16] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
    struct ios_cmd_fex_thread fex;
    TEB *teb = NtCurrentTeb();
    PEB *peb = teb->Peb;
    ULONG_PTR stack_lo = (ULONG_PTR)teb->DeallocationStack, stack_hi = (ULONG_PTR)teb->Tib.StackBase;
    ULONG_PTR caller_slot[24], caller_val[24], rsp;
    ULONG now = NtGetTickCount(), n, first, i;
    ULONG64 g[16];
    CONTEXT ctx;
    char w1[96], w2[96];
    int frames, ncallers = 0, k;
    BOOL have_fex;
    LARGE_INTEGER sys_now;
    USHORT len;

    ERR( IOS_CMD "rev=crashmailer-dump-1 NtCreateUserProcess for %s (tid %04lx, pid %04lx, tick %lu); "
         "MADEIRA_EC_CRASHMAILER_DUMP=0 turns this off\n", debugstr_wn( image, image_len ), ios_cmd_tid(),
         HandleToULong( teb->ClientId.UniqueProcess ), now );
    len = ios_cmd_pstr( params, &params->CommandLine, cmdline, ARRAY_SIZE(cmdline) );
    ios_cmd_wline( "child command line", cmdline, len );
    len = ios_cmd_pstr( params, &params->CurrentDirectory.DosPath, cwd, ARRAY_SIZE(cwd) );
    ios_cmd_wline( "child current dir", cwd, len );
    ERR( IOS_CMD "child process_flags=%lx thread_flags=%lx params->Flags=%lx\n", process_flags, thread_flags, params->Flags );

    /* 1. x64 state */
    memset( &ctx, 0, sizeof(ctx) );
    frames = ios_cmd_x64_context( &ctx );
    if (frames < 0)
    {
        /* no unwind: the first stack value that is x64 code in an image is the caller's return address */
        ULONG_PTR sp = ctx.Rsp && ctx.Rsp >= stack_lo && ctx.Rsp < stack_hi ? ctx.Rsp : (ULONG_PTR)&ctx;
        ULONG_PTR v = 0;
        ERR( IOS_CMD "x64 state: unwinding through the EC frames FAILED; scanning from sp=%p for the x64 return address "
             "(only rip/rsp below are meaningful)\n", (void *)sp );
        memset( &ctx, 0, sizeof(ctx) );
        for (sp &= ~(ULONG_PTR)7; sp + 8 <= stack_hi && sp < (ULONG_PTR)&ctx + 0x40000; sp += 8)
        {
            struct ios_cmd_mod *m;
            if (ios_cmd_read( sp, &v, 8 ) != 8) break;
            if ((m = ios_cmd_module( v )) && ios_cmd_in_exec( m, v ) && ios_cmd_is_x64_code( v ))
            {
                ctx.Rip = v;
                ctx.Rsp = sp + 8;
                break;
            }
        }
    }
    else ERR( IOS_CMD "x64 state of the caller, unwound through %d EC frames: rip, rsp, rbx, rbp, rsi, rdi, r12-r15 and "
              "xmm6-15 are exact; rax, rcx, rdx, r8-r11, xmm0-5 and eflags are what the EC code left (volatile)\n", frames );
    ERR( IOS_CMD "x64 rip=%I64x (%s) rsp=%I64x eflags=%08lx mxcsr=%08lx\n", ctx.Rip,
         ios_cmd_where( ctx.Rip, w1, sizeof(w1) ), ctx.Rsp, ctx.EFlags, ctx.MxCsr );
    memcpy( g, &ctx.Rax, sizeof(g) );
    ios_cmd_regs( "x64", g );
    ios_cmd_xmm( "x64", (const ULONG64 (*)[2])&ctx.Xmm0, 0, 16 );
    have_fex = pBTCpu64IosCrashMailerData && pBTCpu64IosCrashMailerData( 0, &fex, sizeof(fex) ) && fex.version == 1;
    if (have_fex)
    {
        ERR( IOS_CMD "fex state of this thread at its last JIT exit: rip=%I64x (%s) eflags=%08I64x fcw=%04I64x ftw=%02I64x "
             "mxcsr=%08I64x dr0=%I64x dr1=%I64x dr2=%I64x dr3=%I64x dr6=%I64x dr7=%I64x\n", fex.rip,
             ios_cmd_where( fex.rip, w1, sizeof(w1) ), fex.eflags, fex.fcw, fex.ftw, fex.mxcsr,
             fex.dr[0], fex.dr[1], fex.dr[2], fex.dr[3], fex.dr[4], fex.dr[5] );
        {
            /* FEX order is rax rcx rdx rbx rsp rbp rsi rdi r8-r15 as well */
            ios_cmd_regs( "fex", fex.gregs );
            ios_cmd_xmm( "fex", (const ULONG64 (*)[2])fex.xmm, 0, 16 );
        }
    }
    else ERR( IOS_CMD "fex state: not available (%s)\n", pBTCpu64IosCrashMailerData ? "no emulator state" : "export missing" );

    /* 2. stack walk from the x64 rsp */
    rsp = ctx.Rsp;
    if (rsp < stack_lo || rsp >= stack_hi)
        ERR( IOS_CMD "stack: x64 rsp %p is outside this thread's stack [%p,%p): no stack walk\n",
             (void *)rsp, (void *)stack_lo, (void *)stack_hi );
    else
    {
        ULONG_PTR slots = min( 2048, (stack_hi - rsp) / 8 ), chunk[64], s;
        ERR( IOS_CMD "stack: %Iu slots from rsp=%p to the stack base %p; values in an executable section of an image "
             "(at most 24):\n", slots, (void *)rsp, (void *)stack_hi );
        for (s = 0; s < slots && ncallers < 24; s += 64)
        {
            ULONG_PTR cnt = min( 64, slots - s ), j;
            if (ios_cmd_read( rsp + s * 8, chunk, cnt * 8 ) != cnt * 8)
            {
                ERR( IOS_CMD "stack: slot rsp+%Ix not readable, walk ends\n", s * 8 );
                break;
            }
            for (j = 0; j < cnt && ncallers < 24; j++)
            {
                ULONG_PTR v = chunk[j], pe = (ULONG_PTR)xlate_ios_jit_rev( (void *)chunk[j] ), c;
                struct ios_cmd_mod *m;
                if (pe < 0x10000 || (pe >= stack_lo && pe < stack_hi)) continue;
                if (!(m = ios_cmd_module( pe )) || !ios_cmd_in_exec( m, pe )) continue;
                caller_slot[ncallers] = rsp + (s + j) * 8;
                caller_val[ncallers] = v;
                ERR( IOS_CMD "caller #%d slot rsp+%Ix = %p -> %s+0x%lx%s%s\n", ncallers, (s + j) * 8, (void *)v,
                     m->name, (ULONG)(pe - m->base), pe != v ? " (pool alias)" : "",
                     RtlIsEcCode( pe ) ? " [EC]" : " [x64]" );
                for (c = 0; c < 9; c++)
                {
                    char what[24];
                    int off = (int)(c * 64) - 512;
                    sprintf( what, "  code ret%c%d", off < 0 ? '-' : '+', off < 0 ? -off : off );
                    ios_cmd_hexline( what, pe - 512 + c * 64, 64 );
                }
                ncallers++;
            }
        }
        ERR( IOS_CMD "stack: %d callers\n", ncallers );
    }

    /* 3. memory around the registers and the first 8 callers' frames */
    for (k = 0; k < 16; k++)
    {
        char what[32];
        if (g[k] < 0x10000 || g[k] >= 0x800000000000ULL) continue;
        sprintf( what, "mem %s-64", gpr_names[k] );
        ios_cmd_hexline( what, g[k] - 64, 64 );
        sprintf( what, "mem %s", gpr_names[k] );
        ios_cmd_hexline( what, g[k], 64 );
    }
    for (k = 0; k < ncallers && k < 8; k++)
    {
        char what[40];
        ULONG_PTR saved_rbp = 0;
        sprintf( what, "frame #%d slot-64", k );
        ios_cmd_hexline( what, caller_slot[k] - 64, 64 );
        sprintf( what, "frame #%d slot", k );
        ios_cmd_hexline( what, caller_slot[k], 64 );
        if (ios_cmd_read( caller_slot[k] - 8, &saved_rbp, 8 ) == 8 && saved_rbp >= stack_lo && saved_rbp + 64 <= stack_hi)
        {
            sprintf( what, "frame #%d [slot-8]=rbp-64", k );
            ios_cmd_hexline( what, saved_rbp - 64, 64 );
            sprintf( what, "frame #%d [slot-8]=rbp", k );
            ios_cmd_hexline( what, saved_rbp, 64 );
        }
    }

    /* 4. exceptions */
    n = (ULONG)ios_xr_next;
    first = n > 64 ? n - 64 : 0;
    ERR( IOS_CMD "exceptions: last %lu of %lu in [exc-ring] (+%ld page-decrypt faults not listed), oldest first%s\n",
         n - first, n, ios_xr_decrypt, ios_xr_mode == 2 ? "" : " (MADEIRA_EXC_RING=0: none recorded)" );
    for (i = first; i < n; i++)
    {
        const struct ios_xr_ent *e = &ios_xr[i % IOS_XR_N];
        ERR( IOS_CMD "exc #%lu -%lums tid=%04lx code=%08lx addr=%p (%s) p0=%p p1=%p sp=%p x%lu handlers=%u took=%s %p (%s) "
             "ret=%ld\n", i, now - e->tick, e->tid, e->code, (void *)e->addr, ios_cmd_where( e->addr, w1, sizeof(w1) ),
             (void *)e->p0, (void *)e->p1, (void *)e->sp, e->reps + 1, e->nh, ios_cmd_hkind( e->hkind ),
             (void *)e->handler, e->handler ? ios_cmd_where( e->handler, w2, sizeof(w2) ) : "-", (long)e->hret );
    }
    n = (ULONG)ios_cmd_xctx_next;
    first = n > 12 ? n - 12 : 0;
    ERR( IOS_CMD "exception contexts (x64, as handed to the handlers): last %lu, oldest first\n", n - first );
    for (i = first; i < n; i++)
    {
        const struct ios_cmd_xctx *x = &ios_cmd_xctx[i % IOS_CMD_XCTX_N];
        if (!x->xr) continue;
        ERR( IOS_CMD "ctx exc #%ld tid=%04lx code=%08lx ExceptionAddress=%p rip=%I64x (%s) delta=%I64d eflags=%08lx RF=%lu "
             "TF=%lu ContextFlags=%08lx mxcsr=%08lx fcw=%04x\n", x->xr - 1, x->tid, x->code, (void *)x->addr, x->rip,
             ios_cmd_where( x->rip, w1, sizeof(w1) ), (LONGLONG)(x->rip - x->addr), x->eflags, (x->eflags >> 16) & 1,
             (x->eflags >> 8) & 1, x->ctxflags, x->mxcsr, x->fcw );
        ios_cmd_regs( "ctx", x->gpr );
        ERR( IOS_CMD "ctx dr0=%I64x dr1=%I64x dr2=%I64x dr3=%I64x dr6=%I64x dr7=%I64x\n",
             x->dr[0], x->dr[1], x->dr[2], x->dr[3], x->dr[4], x->dr[5] );
        ios_cmd_xmm( "ctx", (const ULONG64 (*)[2])x->xmm, 0, 16 );
    }
    if (pBTCpu64IosCrashMailerData)
    {
        UINT cnt = pBTCpu64IosCrashMailerData( 1, ios_cmd_fexr, sizeof(ios_cmd_fexr) );
        ERR( IOS_CMD "fex delivered-context ring (assert-dump-2, all threads, JIT-raised only): %u entries, newest first, "
             "contexts for the newest 12\n", cnt );
        for (i = 0; i < cnt; i++)
        {
            const struct ios_cmd_fex_exc *e = &ios_cmd_fexr[i];
            /* ARM64EC: rax=x8 rcx=x0 rdx=x1 rbx=x27 rsp=sp rbp=fp rsi=x25 rdi=x26 r8-r11=x2-x5 r12-r15=x19-x22 */
            ULONG64 r[16] = { e->x[8], e->x[0], e->x[1], e->x[27], e->sp, e->x[29], e->x[25], e->x[26],
                              e->x[2], e->x[3], e->x[4], e->x[5], e->x[19], e->x[20], e->x[21], e->x[22] };
            ERR( IOS_CMD "fexexc seq=%I64u tid=%04x code=%08x rip=%I64x (%s) sp=%I64x x86eflags=%08x liveTF=%u cpsr=%08x "
                 "fpcr=%08x fpsr=%08x flags=%08x\n", e->seq, e->tid, e->code, e->pc, ios_cmd_where( e->pc, w1, sizeof(w1) ),
                 e->sp, e->eflags, e->live_tf, e->cpsr, e->fpcr, e->fpsr, e->ctxflags );
            if (i >= 12) continue;
            ios_cmd_regs( "fexexc", r );
            ios_cmd_xmm( "fexexc", (const ULONG64 (*)[2])e->v, 0, 16 );
        }
    }

    /* 5. the calling thread's last 4096 translated blocks (FEX ml1205 ring, pointer at TEB+0x1710) */
    {
        ULONG_PTR ring = 0;
        ULONG64 idx = 0;
        ios_cmd_read( (ULONG_PTR)teb + 0x1710, &ring, sizeof(ring) );
        if (!ring || ios_cmd_read( ring, &idx, 8 ) != 8 || !ios_xp_ring_last( ring, idx, ios_cmd_blk, 4096 ))
            ERR( IOS_CMD "blocks: no block ring on this thread (FEX turns it on for Overwatch.exe; MADEIRA_BLOCK_RING=1 "
                 "elsewhere)\n" );
        else
        {
            ULONG cnt = 4096, start, j;
            idx = 0;   /* [crashmailer-exit-probe]: ios_xp_ring_last put them oldest first */
            while (cnt && !ios_cmd_blk[(idx + 4096 - cnt) & 4095]) cnt--;
            start = (ULONG)(idx + 4096 - cnt) & 4095;
            ERR( IOS_CMD "blocks: last %lu translated blocks entered by this thread, oldest first, as rip/length; the "
                 "newest 48 with module+rva first\n", cnt );
            for (j = cnt > 48 ? cnt - 48 : 0; j < cnt; j++)
            {
                ULONG64 ent = ios_cmd_blk[(start + j) & 4095];
                ERR( IOS_CMD "blk -%lu %I64x/%x %s\n", cnt - j, ent & 0xffffffffffffULL, (UINT)(ent >> 48),
                     ios_cmd_where( (ULONG_PTR)(ent & 0xffffffffffffULL), w1, sizeof(w1) ) );
            }
            for (j = 0; j < cnt; j += 8)
            {
                char line[8 * 22 + 1];
                int o = 0, b;
                for (b = 0; b < 8 && j + b < cnt; b++)
                {
                    ULONG64 ent = ios_cmd_blk[(start + j + b) & 4095];
                    o += sprintf( line + o, " %I64x/%x", ent & 0xffffffffffffULL, (UINT)(ent >> 48) );
                }
                ERR( IOS_CMD "blks -%lu:%s\n", cnt - j, line );
            }
        }
    }

    /* 6. queries */
    n = (ULONG)ios_cmd_q_next;
    first = n > IOS_CMD_Q_N ? n - IOS_CMD_Q_N : 0;
    ERR( IOS_CMD "queries: last %lu of %lu information queries, oldest first (data = first 32 bytes of the result, or "
         "of the input for a set)\n", n - first, n );
    for (i = first; i < n; i++)
    {
        const struct ios_cmd_q *q = &ios_cmd_q[i % IOS_CMD_Q_N];
        char hex[32 * 3 + 1];
        if (q->seq != i + 1) continue;
        ios_cmd_hex( hex, q->data, sizeof(q->data), sizeof(q->data) );
        ERR( IOS_CMD "q #%lu -%lums tid=%04lx %s h=%p class=%lx status=%08lx len=%lu retlen=%ld data=%s\n", i, now - q->tick,
             q->tid, ios_cmd_qname[q->fn < ARRAY_SIZE(ios_cmd_qname) ? q->fn : 0], (void *)q->handle, q->cls,
             q->status, q->len, (long)q->retlen, hex );
    }
    ERR( IOS_CMD "vm: NtQueryVirtualMemory calls by class: 0=%ld 1=%ld 2=%ld 3=%ld 4=%ld 5=%ld 6=%ld 7=%ld 8=%ld 9=%ld "
         "10=%ld 11=%ld 12=%ld 13=%ld 14=%ld 15+=%ld\n", ios_cmd_vm_count[0], ios_cmd_vm_count[1], ios_cmd_vm_count[2],
         ios_cmd_vm_count[3], ios_cmd_vm_count[4], ios_cmd_vm_count[5], ios_cmd_vm_count[6], ios_cmd_vm_count[7],
         ios_cmd_vm_count[8], ios_cmd_vm_count[9], ios_cmd_vm_count[10], ios_cmd_vm_count[11], ios_cmd_vm_count[12],
         ios_cmd_vm_count[13], ios_cmd_vm_count[14], ios_cmd_vm_count[15] );
    n = (ULONG)ios_cmd_vm_next;
    first = n > IOS_CMD_VM_N ? n - IOS_CMD_VM_N : 0;
    for (i = first; i < n; i++)
    {
        const struct ios_cmd_vm *v = &ios_cmd_vm[i % IOS_CMD_VM_N];
        if (v->seq != i + 1) continue;
        ERR( IOS_CMD "vm #%lu -%lums tid=%04lx process=%p addr=%p (%s) class=%lx status=%08lx base=%p size=%Ix state=%lx "
             "protect=%lx type=%lx\n", i, now - v->tick, v->tid, v->process, (void *)v->addr,
             ios_cmd_where( v->addr, w1, sizeof(w1) ), v->cls, v->status, (void *)v->base, v->size, v->state, v->protect,
             v->type );
    }
    for (i = 0; i < ARRAY_SIZE(ios_cmd_dbgq); i++)
    {
        char hex[16 * 3 + 1];
        ios_cmd_hex( hex, ios_cmd_dbga[i].data, 16, 16 );
        if (!ios_cmd_dbga[i].count) ERR( IOS_CMD "debug-query %s: never asked\n", ios_cmd_dbgq[i].name );
        else ERR( IOS_CMD "debug-query %s: %ld calls, last -%lums tid=%04lx status=%08lx len=%lu data=%s\n",
                  ios_cmd_dbgq[i].name, ios_cmd_dbga[i].count, now - ios_cmd_dbga[i].tick, ios_cmd_dbga[i].tid,
                  ios_cmd_dbga[i].status, ios_cmd_dbga[i].len, hex );
    }
    {
        ULONG heap_flags[2] = { ~0u, ~0u };
        UCHAR kd = 0xff;
        ios_cmd_read( (ULONG_PTR)peb->ProcessHeap + 0x70, heap_flags, sizeof(heap_flags) );
        ios_cmd_read( (ULONG_PTR)user_shared_data + 0x2d4, &kd, 1 );
        ERR( IOS_CMD "debugger fields now: PEB BeingDebugged=%u NtGlobalFlag=%08lx; heap %p Flags=%08lx ForceFlags=%08lx "
             "(x64 offsets 0x70/0x74); KUSER_SHARED_DATA+0x2d4 KdDebuggerEnabled=%02x\n", peb->BeingDebugged,
             peb->NtGlobalFlag, peb->ProcessHeap, heap_flags[0], heap_flags[1], kd );
    }
    n = (ULONG)ios_cmd_unw_next;
    first = n > IOS_CMD_UNW_N ? n - IOS_CMD_UNW_N : 0;
    ERR( IOS_CMD "unwinds by the game in or right after an exception handler: %ld in all, last %lu (regs: rip rsp rbx rbp rsi "
         "rdi r12 r13 r14 r15; match bits rbx rbp rsi rdi r12-r15 xmm6 xmm7 = value equals the slot it was restored from)\n",
         ios_cmd_unw_total, n - first );
    for (i = first; i < n; i++)
    {
        const struct ios_cmd_unw *u = &ios_cmd_unw[i % IOS_CMD_UNW_N];
        if (u->seq != i + 1) continue;
        ERR( IOS_CMD "unw #%lu -%lums tid=%04lx %s handler-depth=%lu since-exc=%ldms pc=%p (%s) base=%p target=%p frame=%p "
             "status=%08lx checked=%03lx match=%03lx\n", i, now - u->tick, u->tid,
             u->kind == 2 ? "RtlUnwindEx" : "RtlVirtualUnwind", u->depth, (long)u->since_exc, (void *)u->pc,
             ios_cmd_where( u->pc, w1, sizeof(w1) ), (void *)u->base, (void *)u->target, (void *)u->frame, u->status,
             u->checked, u->match );
        ERR( IOS_CMD "unw   pre  %I64x %I64x %I64x %I64x %I64x %I64x %I64x %I64x %I64x %I64x xmm6=%016I64x%016I64x "
             "xmm7=%016I64x%016I64x\n", u->pre[0], u->pre[1], u->pre[2], u->pre[3], u->pre[4], u->pre[5], u->pre[6],
             u->pre[7], u->pre[8], u->pre[9], u->x6[0].High, u->x6[0].Low, u->x7[0].High, u->x7[0].Low );
        ERR( IOS_CMD "unw   post %I64x %I64x %I64x %I64x %I64x %I64x %I64x %I64x %I64x %I64x xmm6=%016I64x%016I64x "
             "xmm7=%016I64x%016I64x\n", u->post[0], u->post[1], u->post[2], u->post[3], u->post[4], u->post[5], u->post[6],
             u->post[7], u->post[8], u->post[9], u->x6[1].High, u->x6[1].Low, u->x7[1].High, u->x7[1].Low );
    }
    n = (ULONG)ios_cmd_gc_next;
    first = n > IOS_CMD_GC_N ? n - IOS_CMD_GC_N : 0;
    ERR( IOS_CMD "NtGetContextThread on other threads: %lu calls, last %lu (target and suspend are read now, at the "
         "dump; 0000/-1 when the handle is gone)\n", n, n - first );
    for (i = first; i < n; i++)
    {
        struct ios_cmd_gc *c = &ios_cmd_gc[i % IOS_CMD_GC_N];
        THREAD_BASIC_INFORMATION tbi;
        if (c->seq != i + 1) continue;
        if (!syscall_NtQueryInformationThread( (HANDLE)c->handle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL ))
            c->target = HandleToULong( tbi.ClientId.UniqueThread );
        syscall_NtQueryInformationThread( (HANDLE)c->handle, ThreadSuspendCount, &c->suspend, sizeof(c->suspend), NULL );
        ERR( IOS_CMD "getctx #%lu -%lums tid=%04lx target=%04lx suspend=%ld want=%08lx status=%08lx got=%08lx rip=%I64x (%s) "
             "eflags=%08lx dr0=%I64x dr1=%I64x dr2=%I64x dr3=%I64x dr6=%I64x dr7=%I64x\n", i, now - c->tick, c->tid,
             c->target, (long)c->suspend, c->want, c->status, c->ctxflags, c->rip, ios_cmd_where( c->rip, w1, sizeof(w1) ),
             c->eflags, c->dr[0], c->dr[1], c->dr[2], c->dr[3], c->dr[4], c->dr[5] );
        if (!c->status) ios_cmd_regs( "getctx", c->gpr );
    }

    /* 7. files */
    for (k = 0; k < 2; k++)
    {
        const struct ios_cmd_file *ring = k ? ios_cmd_fw : ios_cmd_f;
        ULONG cap = k ? IOS_CMD_FW_N : IOS_CMD_F_N;
        n = (ULONG)(k ? ios_cmd_fw_next : ios_cmd_f_next);
        first = n > cap ? n - cap : 0;
        ERR( IOS_CMD "%s: last %lu of %lu NtCreateFile calls, oldest first\n", k ? "files-written" : "files", n - first, n );
        for (i = first; i < n; i++)
        {
            const struct ios_cmd_file *f = &ring[i % cap];
            if (f->seq != i + 1) continue;
            ERR( IOS_CMD "%s #%lu -%lums tid=%04lx access=%08lx dispo=%lx options=%lx status=%08lx root=%p handle=%p %s\n",
                 k ? "fw" : "f", i, now - f->tick, f->tid, f->access, f->dispo, f->options, f->status, (void *)f->root,
                 (void *)f->handle, debugstr_wn( f->name, f->len ) );
        }
    }
    {
        ULONG ret = 0, shown = 0, mine = 0;
        NTSTATUS st = syscall_NtQuerySystemInformation( SystemExtendedHandleInformation, &ios_cmd_handles,
                                                        sizeof(ios_cmd_handles), &ret );
        if (st) ERR( IOS_CMD "handles: SystemExtendedHandleInformation failed %08lx (needs %lu bytes)\n", st, ret );
        else
        {
            ULONG_PTR pid = (ULONG_PTR)teb->ClientId.UniqueProcess, j;
            ULONG_PTR count = min( ios_cmd_handles.info.NumberOfHandles,
                                   (sizeof(ios_cmd_handles) - offsetof(SYSTEM_HANDLE_INFORMATION_EX, Handles)) /
                                   sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) );
            for (j = 0; j < count && mine < 4096 && shown < 64; j++)
            {
                static struct { UNICODE_STRING str; WCHAR buf[520]; } on;
                const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *h = (const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *)
                    (ios_cmd_handles.buf + offsetof(SYSTEM_HANDLE_INFORMATION_EX, Handles)) + j;
                ULONG got = 0;
                if (h->UniqueProcessId != pid) continue;
                mine++;
                if (syscall_NtQueryObject( (HANDLE)h->HandleValue, ObjectNameInformation, &on, sizeof(on) - sizeof(WCHAR),
                                           &got ) || !on.str.Buffer || on.str.Length < 8 * sizeof(WCHAR))
                    continue;
                /* files: \??\X:\... ; and named pipes */
                if (!(on.str.Buffer[0] == '\\' && on.str.Buffer[1] == '?' && on.str.Buffer[2] == '?' && on.str.Buffer[5] == ':') &&
                    !ios_cmd_wcsistr( on.str.Buffer, on.str.Length / sizeof(WCHAR), "\\device\\namedpipe" ))
                    continue;
                shown++;
                ERR( IOS_CMD "handle %04Ix access=%08lx type=%u %s\n", h->HandleValue, h->GrantedAccess,
                     h->ObjectTypeIndex, debugstr_wn( on.str.Buffer, on.str.Length / sizeof(WCHAR) ) );
            }
            ERR( IOS_CMD "handles: %lu of this process looked at, %lu file/pipe names shown (at most 64)\n", mine, shown );
        }
    }
    if (!ioscmd_NtQuerySystemTime( &sys_now ))
    {
        static WCHAR exe_dir[300], temp[300];
        LONGLONG since = sys_now.QuadPart - 60 * (LONGLONG)10000000;
        USHORT dir_len = ios_cmd_pstr( peb->ProcessParameters, &peb->ProcessParameters->ImagePathName, exe_dir,
                                       ARRAY_SIZE(exe_dir) );
        UNICODE_STRING var, value;

        while (dir_len && exe_dir[dir_len - 1] != '\\') dir_len--;
        if (dir_len) dir_len--;
        ios_cmd_scan_root( "the game folder", exe_dir, dir_len, 3, since, sys_now.QuadPart );
        /* the folder above CrashMailer's x64\, when it is not under the game folder */
        len = image_len;
        for (k = 0; k < 2; k++)
        {
            while (len && image[len - 1] != '\\') len--;
            if (len) len--;
        }
        if (len && (len < dir_len || memcmp( image, exe_dir, dir_len * sizeof(WCHAR) )))
        {
            const WCHAR *img = image;
            if (len > 4 && img[0] == '\\' && img[1] == '?' && img[2] == '?' && img[3] == '\\') { img += 4; len -= 4; }
            ios_cmd_scan_root( "CrashMailer's folder", img, len, 2, since, sys_now.QuadPart );
        }
        RtlInitUnicodeString( &var, L"TEMP" );
        value.Buffer = temp;
        value.Length = 0;
        value.MaximumLength = sizeof(temp) - sizeof(WCHAR);
        if (!RtlQueryEnvironmentVariable_U( NULL, &var, &value ) && value.Length)
        {
            USHORT tl = value.Length / sizeof(WCHAR);
            if (tl && temp[tl - 1] == '\\') tl--;
            ios_cmd_scan_root( "TEMP", temp, tl, 1, since, sys_now.QuadPart );
        }
    }
    ERR( IOS_CMD "images seen by this dump (base size name):\n" );
    for (i = 0; i < ios_cmd_nmods; i++)
        ERR( IOS_CMD "image %p %08Ix %s\n", (void *)ios_cmd_mods[i].base, ios_cmd_mods[i].size, ios_cmd_mods[i].name );
    ERR( IOS_CMD "end of dump (%lu ms)\n", NtGetTickCount() - now );
}

/* the NtCreateUserProcess hook: dumps when the image is CrashMailer and this is the process's first one */
static void ios_cmd_check( const RTL_USER_PROCESS_PARAMETERS *params, ULONG process_flags, ULONG thread_flags )
{
    static WCHAR image[300];
    USHORT len;
    LONG internal;

    if (ios_cmd_mode != 2 || !params || ios_cmd_done) return;
    if (!ios_cmd_readable( (ULONG_PTR)params, sizeof(*params), NULL )) return;   /* the block itself is readable */
    len = ios_cmd_pstr( params, &params->ImagePathName, image, ARRAY_SIZE(image) );
    if (!ios_cmd_wcsistr( image, len, "crashmailer" ))
    {
        /* no image path in the block: the program is the start of the command line */
        if (len) return;
        len = ios_cmd_pstr( params, &params->CommandLine, image, ARRAY_SIZE(image) );
        if (!ios_cmd_wcsistr( image, len, "crashmailer" )) return;
    }
    if (InterlockedExchange( &ios_cmd_done, 1 )) return;
    internal = ios_cmd_internal_enter();
    InterlockedExchange( &ios_cmd_dumping, 1 );
    ios_cmd_dump( params, image, len, process_flags, thread_flags );
    InterlockedExchange( &ios_cmd_dumping, 0 );
    ios_cmd_internal_leave( internal );
}

NTSTATUS SYSCALL_API NtCreateUserProcess( HANDLE *process_handle_ptr, HANDLE *thread_handle_ptr,
                                          ACCESS_MASK process_access, ACCESS_MASK thread_access,
                                          OBJECT_ATTRIBUTES *process_attr, OBJECT_ATTRIBUTES *thread_attr,
                                          ULONG process_flags, ULONG thread_flags,
                                          RTL_USER_PROCESS_PARAMETERS *params, PS_CREATE_INFO *info,
                                          PS_ATTRIBUTE_LIST *ps_attr )
{
    LONG dumped = ios_cmd_done;
    NTSTATUS status;

    ios_cmd_check( params, process_flags, thread_flags );   /* madeira [crashmailer-dump] */
    status = syscall_NtCreateUserProcess( process_handle_ptr, thread_handle_ptr, process_access, thread_access,
                                          process_attr, thread_attr, process_flags, thread_flags, params, info, ps_attr );
    if (!dumped && ios_cmd_done)
        ERR( IOS_CMD "NtCreateUserProcess for CrashMailer returned %08lx\n", status );
    return status;
}

NTSTATUS SYSCALL_API NtQueryInformationProcess( HANDLE handle, PROCESSINFOCLASS class, void *info, ULONG size, ULONG *ret_len )
{
    NTSTATUS status = syscall_NtQueryInformationProcess( handle, class, info, size, ret_len );
    if (ios_cmd_rec()) ios_cmd_q_record( IOS_CMD_QIP, handle, class, status, info, size, ret_len );
    return status;
}

NTSTATUS SYSCALL_API NtSetInformationProcess( HANDLE handle, PROCESSINFOCLASS class, void *info, ULONG size )
{
    NTSTATUS status = syscall_NtSetInformationProcess( handle, class, info, size );
    if (ios_cmd_rec()) ios_cmd_q_record( IOS_CMD_SIP, handle, class, status, info, size, NULL );
    return status;
}

NTSTATUS SYSCALL_API NtQueryInformationThread( HANDLE handle, THREADINFOCLASS class, void *data, ULONG length, ULONG *ret_len )
{
    NTSTATUS status = syscall_NtQueryInformationThread( handle, class, data, length, ret_len );
    if (ios_cmd_rec()) ios_cmd_q_record( IOS_CMD_QIT, handle, class, status, data, length, ret_len );
    return status;
}

NTSTATUS SYSCALL_API NtSetInformationThread( HANDLE handle, THREADINFOCLASS class, const void *data, ULONG length )
{
    NTSTATUS status = syscall_NtSetInformationThread( handle, class, data, length );
    if (ios_cmd_rec()) ios_cmd_q_record( IOS_CMD_SIT, handle, class, status, data, length, NULL );
    return status;
}

NTSTATUS SYSCALL_API NtQuerySystemInformationEx( SYSTEM_INFORMATION_CLASS class, void *query, ULONG query_len,
                                                 void *info, ULONG size, ULONG *ret_size )
{
    NTSTATUS status = syscall_NtQuerySystemInformationEx( class, query, query_len, info, size, ret_size );
    if (ios_cmd_rec()) ios_cmd_q_record( IOS_CMD_QSIX, NULL, class, status, info, size, ret_size );
    return status;
}

NTSTATUS SYSCALL_API NtQueryObject( HANDLE handle, OBJECT_INFORMATION_CLASS info_class, void *ptr, ULONG len, ULONG *used_len )
{
    NTSTATUS status = syscall_NtQueryObject( handle, info_class, ptr, len, used_len );
    if (ios_cmd_rec()) ios_cmd_q_record( IOS_CMD_QO, handle, info_class, status, ptr, len, used_len );
    return status;
}

NTSTATUS SYSCALL_API NtQueryVirtualMemory( HANDLE process, LPCVOID addr, MEMORY_INFORMATION_CLASS info_class,
                                           PVOID buffer, SIZE_T len, SIZE_T *res_len )
{
    NTSTATUS status = syscall_NtQueryVirtualMemory( process, addr, info_class, buffer, len, res_len );
    if (ios_cmd_rec()) ios_cmd_vm_record( process, addr, info_class, status, len >= sizeof(MEMORY_BASIC_INFORMATION) ? buffer : NULL );
    return status;
}

NTSTATUS SYSCALL_API NtCreateFile( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr, IO_STATUS_BLOCK *io,
                                   LARGE_INTEGER *alloc_size, ULONG attributes, ULONG sharing, ULONG disposition,
                                   ULONG options, void *ea_buffer, ULONG ea_length )
{
    NTSTATUS status = syscall_NtCreateFile( handle, access, attr, io, alloc_size, attributes, sharing, disposition,
                                            options, ea_buffer, ea_length );
    if (ios_cmd_rec() && status != STATUS_ACCESS_VIOLATION)
        ios_cmd_file_record( handle, access, attr, disposition, options, status );
    return status;
}

/* [crashmailer-dump]: after the existing NtGetContextThread wrapper, for another thread */
/* no syscalls here (GC-style suspend/GetThreadContext loops call this per thread): the handle's thread id and
 * suspend count are looked up at the dump */
static void ios_cmd_getctx( HANDLE handle, const CONTEXT *context, ULONG want, NTSTATUS status )
{
    struct ios_cmd_gc *c;
    ULONG n, target = 0, suspend = ~0u;

    if (!ios_cmd_rec() || handle == GetCurrentThread()) return;
    n = (ULONG)InterlockedIncrement( &ios_cmd_gc_next );
    c = &ios_cmd_gc[(n - 1) % IOS_CMD_GC_N];
    c->seq = 0;
    c->tick = NtGetTickCount();
    c->tid = ios_cmd_tid();
    c->target = target;
    c->suspend = suspend;
    c->want = want;
    c->status = status;
    c->handle = (ULONG_PTR)handle;
    c->ctxflags = status ? 0 : context->ContextFlags;
    c->eflags = status ? 0 : context->EFlags;
    if (!status)
    {
        memcpy( c->gpr, &context->Rax, sizeof(c->gpr) );
        c->rip = context->Rip;
        c->dr[0] = context->Dr0; c->dr[1] = context->Dr1; c->dr[2] = context->Dr2; c->dr[3] = context->Dr3;
        c->dr[4] = context->Dr6; c->dr[5] = context->Dr7;
    }
    else
    {
        memset( c->gpr, 0, sizeof(c->gpr) );
        memset( c->dr, 0, sizeof(c->dr) );
        c->rip = 0;
    }
    c->seq = n;
}


NTSTATUS SYSCALL_API NtTerminateProcess( HANDLE handle, LONG exit_code )
{
    NTSTATUS status;

    if (!handle || handle == GetCurrentProcess())   /* [crashmailer-exit-probe] */
        ios_xp_exit_event( exit_code ? "NtTerminateProcess (exit code not 0)" : "NtTerminateProcess" );
    if (!handle || handle == GetCurrentProcess()) ios_xr_dump( "process exit", exit_code );   /* [exc-ring] */

    if (!handle && pProcessTerm && enter_syscall_callback())
    {
        pProcessTerm( handle, FALSE, 0 );
        status = syscall_NtTerminateProcess( handle, exit_code );
        pProcessTerm( handle, TRUE, status );
        leave_syscall_callback();
        return status;
    }
    return syscall_NtTerminateProcess( handle, exit_code );
}

NTSTATUS SYSCALL_API NtTerminateThread( HANDLE handle, LONG exit_code )
{
    NTSTATUS status;

    if (pThreadTerm && enter_syscall_callback())
    {
        pThreadTerm( handle, exit_code );
        status = syscall_NtTerminateThread( handle, exit_code );
        leave_syscall_callback();
        return status;
    }
    return syscall_NtTerminateThread( handle, exit_code );
}

NTSTATUS SYSCALL_API NtUnmapViewOfSection( HANDLE process, void *addr )
{
    BOOL is_current = RtlIsCurrentProcess( process );
    NTSTATUS status;

    if (is_current) ios_chrome_clear_view( addr );
    if (is_current && pNotifyUnmapViewOfSection && enter_syscall_callback())
    {
        ios_log_unmap( addr );
        pNotifyUnmapViewOfSection( addr, FALSE, 0 );
        status = syscall_NtUnmapViewOfSection( process, addr );
        pNotifyUnmapViewOfSection( addr, TRUE, status );
        leave_syscall_callback();
        return status;
    }
    return syscall_NtUnmapViewOfSection( process, addr );
}

NTSTATUS SYSCALL_API NtUnmapViewOfSectionEx( HANDLE process, void *addr, ULONG flags )
{
    BOOL is_current = RtlIsCurrentProcess( process );
    NTSTATUS status;

    if (is_current) ios_chrome_clear_view( addr );
    if (is_current && pNotifyUnmapViewOfSection && enter_syscall_callback())
    {
        ios_log_unmap( addr );
        pNotifyUnmapViewOfSection( addr, FALSE, 0 );
        status = syscall_NtUnmapViewOfSectionEx( process, addr, flags );
        pNotifyUnmapViewOfSection( addr, TRUE, status );
        leave_syscall_callback();
        return status;
    }
    return syscall_NtUnmapViewOfSectionEx( process, addr, flags );
}


asm( ".section .rdata, \"dr\"\n\t"
     ".balign 8\n\t"
     ".globl arm64ec_syscalls\n"
     "arm64ec_syscalls:\n\t"
#define SYSCALL_ENTRY(id,name,args) ".quad \"#" #name "$hp_target\"\n\t"
     ALL_SYSCALLS
#undef SYSCALL_ENTRY
     ".text" );


/***********************************************************************
 *           LdrpGetX64Information
 */
static NTSTATUS WINAPI LdrpGetX64Information( ULONG type, void *output, void *extra_info )
{
    switch (type)
    {
    case 0:
    {
        UINT64 fpcr, fpsr;

        __asm__ __volatile__( "mrs %0, fpcr; mrs %1, fpsr" : "=r" (fpcr), "=r" (fpsr) );
        *(UINT *)output = fpcsr_to_mxcsr( fpcr, fpsr );
        return STATUS_SUCCESS;
    }
    case 2:
        *(UINT *)output = 0x27f;  /* hard-coded x87 control word */
        return STATUS_SUCCESS;
    default:
        FIXME( "not implemented type %lu\n", type );
        return STATUS_INVALID_PARAMETER;
    }
}

/***********************************************************************
 *           LdrpSetX64Information
 */
static NTSTATUS WINAPI LdrpSetX64Information( ULONG type, ULONG_PTR input, void *extra_info )
{
    switch (type)
    {
    case 0:
    {
        UINT64 fpcsr = mxcsr_to_fpcsr( input );
        __asm__ __volatile__( "msr fpcr, %0; msr fpsr, %1" :: "r" (fpcsr), "r" (fpcsr >> 32) );
        return STATUS_SUCCESS;
    }
    default:
        FIXME( "not implemented type %lu\n", type );
        return STATUS_INVALID_PARAMETER;
    }
}


/**********************************************************************
 *           ProcessPendingCrossProcessEmulatorWork  (ntdll.@)
 */
void WINAPI ProcessPendingCrossProcessEmulatorWork(void)
{
    CHPEV2_PROCESS_INFO *info = RtlGetCurrentPeb()->ChpeV2ProcessInfo;
    CROSS_PROCESS_WORK_LIST *list = (void *)info->CrossProcessWorkList;
    CROSS_PROCESS_WORK_ENTRY *entry;
    BOOLEAN flush = FALSE;
    UINT next;

    if (!list) return;
    entry = RtlWow64PopAllCrossProcessWorkFromWorkList( &list->work_list, &flush );

    if (flush)
    {
        if (pFlushInstructionCacheHeavy) pFlushInstructionCacheHeavy( NULL, 0 );
        while (entry)
        {
            next = entry->next;
            RtlWow64PushCrossProcessWorkOntoFreeList( &list->free_list, entry );
            entry = next ? CROSS_PROCESS_LIST_ENTRY( &list->work_list, next ) : NULL;
        }
        return;
    }

    while (entry)
    {
        switch (entry->id)
        {
        case CrossProcessPreVirtualAlloc:
        case CrossProcessPostVirtualAlloc:
            if (!pNotifyMemoryAlloc) break;
            pNotifyMemoryAlloc( (void *)entry->addr, entry->size, entry->args[0], entry->args[1],
                                entry->id == CrossProcessPostVirtualAlloc, entry->args[2] );
            break;
        case CrossProcessPreVirtualFree:
        case CrossProcessPostVirtualFree:
            if (!pNotifyMemoryFree) break;
            pNotifyMemoryFree( (void *)entry->addr, entry->size, entry->args[0],
                               entry->id == CrossProcessPostVirtualFree, entry->args[1] );
            break;
        case CrossProcessPreVirtualProtect:
        case CrossProcessPostVirtualProtect:
            if (!pNotifyMemoryProtect) break;
            /* iOS-Madeira ml206: THE path the 16GB wipe actually arrived on. Our
             * pseudo-processes share one address space, so RtlIsCurrentProcess() is FALSE
             * for a sibling handle and the protect is queued here rather than taking the
             * is_current branch ml203 guarded — which is why that fix logged nothing while
             * the wipe still happened. Guard it identically. */
            if (ios_bulk_protect_suppressed( "xproc", (void *)entry->addr, entry->size,
                                             entry->args[0] )) break;
            pNotifyMemoryProtect( (void *)entry->addr, entry->size, entry->args[0],
                                  entry->id == CrossProcessPostVirtualProtect, entry->args[1] );
            break;
        case CrossProcessFlushCache:
            if (!pBTCpu64FlushInstructionCache) break;
            pBTCpu64FlushInstructionCache( (void *)entry->addr, entry->size );
            break;
        case CrossProcessFlushCacheHeavy:
            if (!pFlushInstructionCacheHeavy) break;
            pFlushInstructionCacheHeavy( (void *)entry->addr, entry->size );
            break;
        case CrossProcessMemoryWrite:
            if (!pBTCpu64NotifyMemoryDirty) break;
            pBTCpu64NotifyMemoryDirty( (void *)entry->addr, entry->size );
            break;
        }
        next = entry->next;
        RtlWow64PushCrossProcessWorkOntoFreeList( &list->free_list, entry );
        entry = next ? CROSS_PROCESS_LIST_ENTRY( &list->work_list, next ) : NULL;
    }
}


/**********************************************************************
 *           virtual_unwind
 */
static NTSTATUS virtual_unwind( ULONG type, DISPATCHER_CONTEXT_ARM64EC *dispatch,
                                ARM64EC_NT_CONTEXT *context )
{
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 *nonvol_regs;
    DWORD64 pc = context->Pc;
    int i;

    /* iOS: pc is a JIT-pool VA when captured from executing code; the
     * function tables live at PE VAs. Reverse-translate so the walk runs
     * in PE space (identity for non-pool addresses / pre-init). */
    pc = (DWORD64)xlate_ios_jit_rev( (void *)pc );

    dispatch->ScopeIndex = 0;
    dispatch->ControlPc  = pc;
    dispatch->ControlPcIsUnwound = (context->ContextFlags & CONTEXT_UNWOUND_TO_CALL) != 0;
    if (dispatch->ControlPcIsUnwound && RtlIsEcCode( pc )) pc -= 4;

    nonvol_regs = (DISPATCHER_CONTEXT_NONVOLREG_ARM64 *)dispatch->NonVolatileRegisters;
    nonvol_regs->GpNvRegs[0]  = context->X19;
    nonvol_regs->GpNvRegs[1]  = context->X20;
    nonvol_regs->GpNvRegs[2]  = context->X21;
    nonvol_regs->GpNvRegs[3]  = context->X22;
    nonvol_regs->GpNvRegs[4]  = 0;
    nonvol_regs->GpNvRegs[5]  = 0;
    nonvol_regs->GpNvRegs[6]  = context->X25;
    nonvol_regs->GpNvRegs[7]  = context->X26;
    nonvol_regs->GpNvRegs[8]  = context->X27;
    nonvol_regs->GpNvRegs[9]  = 0;
    nonvol_regs->GpNvRegs[10] = context->Fp;
    for (i = 0; i < 8; i++) nonvol_regs->FpNvRegs[i] = context->V[i + 8].D[0];

    dispatch->FunctionEntry = RtlLookupFunctionEntry( pc, &dispatch->ImageBase, dispatch->HistoryTable );

    if (RtlVirtualUnwind2( type, dispatch->ImageBase, pc, dispatch->FunctionEntry, &context->AMD64_Context,
                           NULL, &dispatch->HandlerData, &dispatch->EstablisherFrame,
                           NULL, NULL, NULL, &dispatch->LanguageHandler, 0 ))
    {
        WARN( "exception data not found for pc %p\n", (void *)pc );
        return STATUS_INVALID_DISPOSITION;
    }
    return STATUS_SUCCESS;
}


/**********************************************************************
 *           unwind_exception_handler
 *
 * Handler for exceptions happening while calling an unwind handler.
 */
EXCEPTION_DISPOSITION WINAPI unwind_exception_handler( EXCEPTION_RECORD *record, void *frame,
                                                       CONTEXT *context, DISPATCHER_CONTEXT_ARM64EC *dispatch )
{
    DISPATCHER_CONTEXT_ARM64EC *orig_dispatch = ((DISPATCHER_CONTEXT_ARM64EC **)frame)[-2];

    /* copy the original dispatcher into the current one, except for the TargetPc */
    dispatch->ControlPc          = orig_dispatch->ControlPc;
    dispatch->ImageBase          = orig_dispatch->ImageBase;
    dispatch->FunctionEntry      = orig_dispatch->FunctionEntry;
    dispatch->EstablisherFrame   = orig_dispatch->EstablisherFrame;
    dispatch->LanguageHandler    = orig_dispatch->LanguageHandler;
    dispatch->HandlerData        = orig_dispatch->HandlerData;
    dispatch->HistoryTable       = orig_dispatch->HistoryTable;
    dispatch->ScopeIndex         = orig_dispatch->ScopeIndex;
    dispatch->ControlPcIsUnwound = orig_dispatch->ControlPcIsUnwound;
    *dispatch->ContextRecord     = *orig_dispatch->ContextRecord;
    memcpy( dispatch->NonVolatileRegisters, orig_dispatch->NonVolatileRegisters,
            sizeof(DISPATCHER_CONTEXT_NONVOLREG_ARM64) );
    TRACE( "detected collided unwind\n" );
    return ExceptionCollidedUnwind;
}


/**********************************************************************
 *           call_unwind_handler
 */
static DWORD __attribute__((naked)) call_unwind_handler( EXCEPTION_RECORD *rec, ULONG_PTR frame,
                                                         CONTEXT *context, void *dispatch,
                                                         PEXCEPTION_ROUTINE handler )
{
    asm( ".seh_proc call_unwind_handler\n\t"
         "stp x29, x30, [sp, #-32]!\n\t"
         ".seh_save_fplr_x 32\n\t"
         ".seh_endprologue\n\t"
         ".seh_handler unwind_exception_handler, @except\n\t"
         "str x3, [sp, #16]\n\t"    /* frame[-2] = dispatch */
         "mov x11, x4\n\t" /* handler */
         "adr x10, $iexit_thunk$cdecl$i8$i8i8i8i8\n\t"
         "adrp x16, __os_arm64x_dispatch_icall\n\t"
         "ldr x16, [x16, #:lo12:__os_arm64x_dispatch_icall]\n\t"
         "blr x16\n\t"
         "blr x11\n\t"
         "ldp x29, x30, [sp], #32\n\t"
         "ret\n\t"
         ".seh_endproc" );
}


/*******************************************************************
 *         nested_exception_handler
 */
EXCEPTION_DISPOSITION WINAPI nested_exception_handler( EXCEPTION_RECORD *rec, void *frame,
                                                       CONTEXT *context, void *dispatch )
{
    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) return ExceptionContinueSearch;
    return ExceptionNestedException;
}


/***********************************************************************
 *		call_seh_handler
 */
static DWORD __attribute__((naked)) call_seh_handler( EXCEPTION_RECORD *rec, ULONG_PTR frame,
                                                      CONTEXT *context, void *dispatch, PEXCEPTION_ROUTINE handler )
{
    asm( ".seh_proc call_seh_handler\n\t"
         "stp x29, x30, [sp, #-16]!\n\t"
         ".seh_save_fplr_x 16\n\t"
         ".seh_endprologue\n\t"
         ".seh_handler nested_exception_handler, @except\n\t"
         "mov x11, x4\n\t" /* handler */
         "adr x10, $iexit_thunk$cdecl$i8$i8i8i8i8\n\t"
         "adrp x16, __os_arm64x_dispatch_icall\n\t"
         "ldr x16, [x16, #:lo12:__os_arm64x_dispatch_icall]\n\t"
         "blr x16\n\t"
         "blr x11\n\t"
         "ldp x29, x30, [sp], #16\n\t"
         "ret\n\t"
         ".seh_endproc" );
}


/**********************************************************************
 *           ios_seh_xlate_note   (iOS-Madeira ml603)
 *
 * Report SEH language-handler translation ONCE PER DISTINCT HANDLER.
 *
 * The ml477 revert note asked for every translation to be logged, because a
 * 4-per-process cap is what hid the x86-64-guest-handler case that broke ml476.
 * Logging all of them literally would mean ~790k lines — the exact volume that
 * drowned the log pipeline in ml602 — and would add no information, since the
 * same handful of handlers repeat. Distinct-once gives the full set (which is
 * what makes an unexpected guest handler visible) at negligible cost, and the
 * census proves the probe stayed alive.
 */
static void ios_seh_xlate_note( PEXCEPTION_ROUTINE orig, PEXCEPTION_ROUTINE final, BOOLEAN is_ec )
{
    static void *seen[64];
    static unsigned int seen_n;
    static unsigned int overflow_logged;
    static unsigned int n_ec, n_guest;
    unsigned int i;

    if (is_ec) n_ec++; else n_guest++;

    /* Census on a power-of-two boundary: cheap, and proves the gate is live. */
    if (((n_ec + n_guest) & 0xffff) == 0)
        ERR( "[seh-xlate] ml603 census: ec_translated=%u guest_untouched=%u distinct=%u\n",
             n_ec, n_guest, seen_n );

    for (i = 0; i < seen_n; i++) if (seen[i] == (void *)orig) return;

    if (seen_n >= ARRAY_SIZE(seen))
    {
        if (!overflow_logged++)
            ERR( "[seh-xlate] ml603 distinct table FULL (%u) — further new handlers unlogged\n",
                 (unsigned int)ARRAY_SIZE(seen) );
        return;
    }
    seen[seen_n++] = (void *)orig;

    {
        void *mod = NULL;
        const WCHAR *name = NULL;
        LDR_DATA_TABLE_ENTRY *ldr;

        if (!LdrFindEntryForAddress( (void *)orig, &ldr ))
        {
            mod = ldr->DllBase;
            name = ldr->BaseDllName.Buffer;
        }
        ERR( "[seh-xlate] ml603 handler=%p %s -> %p  module=%s+0x%x\n",
             orig, is_ec ? "EC/native TRANSLATED" : "GUEST left in PE space (icall -> FEX)",
             final, name ? debugstr_w(name) : "?",
             mod ? (unsigned int)((ULONG_PTR)orig - (ULONG_PTR)mod) : 0 );
    }
}


/**********************************************************************
 *           call_seh_handlers
 *
 * Call the SEH handlers.
 */
/* iOS-Madeira ml812: bounded, fault-safe string dump for exception parameters.
 *
 * ml811 proved the fatal arrives as a SOFTWARE exception, not a C++ throw:
 * PoolThread 5 raised OutputDebugStringW (0x4001000a), then OutputDebugStringA
 * (0x40010006), then the game's own report code 0x4000 -- and that same thread
 * owns the deadlocked allocator lock. The failure TEXT is sitting in those
 * parameters; ml811 logged that they existed but not what they said.
 *
 * Reads go through NtReadVirtualMemory so a bad pointer returns a status
 * instead of faulting inside exception dispatch. No allocation, no locks. */
static int ios_exc_dump_str( const char *what, ULONG_PTR addr, SIZE_T len, int wide )
{
    char out[224];
    SIZE_T got = 0, n, i;

    if (!addr || !len) return 0;
    memset( out, 0, sizeof(out) );
    n = len;
    if (wide)
    {
        WCHAR wbuf[110];
        if (n > 110) n = 110;
        if (NtReadVirtualMemory( GetCurrentProcess(), (void *)addr, wbuf, n * sizeof(WCHAR), &got ) || !got)
        {
            ERR( "[exc] ml812   %s UNREADABLE at %p\n", what, (void *)addr );
            return 0;
        }
        n = got / sizeof(WCHAR);
        for (i = 0; i < n && i < sizeof(out) - 1; i++)
        {
            WCHAR c = wbuf[i];
            if (!c) break;
            out[i] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        out[i] = 0;
    }
    else
    {
        if (n > sizeof(out) - 1) n = sizeof(out) - 1;
        if (NtReadVirtualMemory( GetCurrentProcess(), (void *)addr, out, n, &got ) || !got)
        {
            ERR( "[exc] ml812   %s UNREADABLE at %p\n", what, (void *)addr );
            return 0;
        }
        for (i = 0; i < got && i < sizeof(out) - 1; i++)
        {
            if (!out[i]) break;
            if (out[i] < 32 || (unsigned char)out[i] >= 127) out[i] = '.';
        }
        out[i] = 0;
    }
    ERR( "[exc] ml812   %s: \"%s\"\n", what, out );
    return strstr( out, "LowLevelFatalError" ) != NULL;
}

/* ---------------------------------------------------------------------------
 * iOS-Madeira ml843 [fatal-probe]: WHO handed the emulator stack top to the
 * engine allocator?
 *
 * Two fresh UE5 runs both died in FMallocBinned2::Free with a pointer that was
 * exactly the failing thread's own FEX EmulatorStackBase (CPU area +0x8),
 * during thread-detach cleanup. Provenance is settled; the PATH is not. The
 * fatal reaches us as a debug-string exception with the guest context intact,
 * so this is the one place the guest call chain can still be read.
 *
 * Reads are bounded and go through NtReadVirtualMemory; the module list is
 * walked WITHOUT the loader lock because the failing thread is mid-detach and
 * may hold it, or be blocked on it -- a probe that deadlocks the thread it is
 * observing tells us nothing. Return addresses are CALL-validated the way the
 * unix-side ml660 scanner does it, so a code-like value that merely sits on
 * the stack is marked '?' rather than reported as a frame. */
static const char *ios_probe_module( ULONG_PTR addr, ULONG_PTR *base, char *buf, size_t buflen )
{
    LIST_ENTRY *mark, *e;
    unsigned n = 0;
    PEB *peb = NtCurrentTeb()->Peb;

    if (!peb || !peb->LdrData) return NULL;
    mark = &peb->LdrData->InLoadOrderModuleList;
    for (e = mark->Flink; e && e != mark && n < 512; e = e->Flink, n++)
    {
        LDR_DATA_TABLE_ENTRY *m = CONTAINING_RECORD( e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
        ULONG_PTR b = (ULONG_PTR)m->DllBase;
        if (addr >= b && addr < b + m->SizeOfImage)
        {
            unsigned i;
            for (i = 0; i + 1 < buflen && i < m->BaseDllName.Length / sizeof(WCHAR); i++)
            {
                WCHAR c = m->BaseDllName.Buffer[i];
                buf[i] = (c >= 32 && c < 127) ? (char)c : '?';
            }
            buf[i] = 0;
            *base = b;
            return buf;
        }
    }
    return NULL;
}

static void ios_fatal_probe( const CONTEXT *ctx )
{
    static LONG fired;
    CHPE_V2_CPU_AREA_INFO *area;
    ULONG_PTR top, lim, sp;
    ULONG_PTR stk[256];
    SIZE_T got = 0, i;
    unsigned printed = 0, hits = 0;

    if (InterlockedIncrement( &fired ) > 2) return;
    area = get_arm64ec_cpu_area();
    top = area ? (ULONG_PTR)area->EmulatorStackBase : 0;
    lim = area ? (ULONG_PTR)area->EmulatorStackLimit : 0;
    sp = ctx ? (ULONG_PTR)ctx->Rsp : 0;

    ERR( "[fatal-probe] ml843 tid=%04x Rip=%p Rsp=%p emulator-stack=[%p..%p) area=%p\n",
         (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
         ctx ? (void *)ctx->Rip : NULL, (void *)sp, (void *)lim, (void *)top, (void *)area );
    if (ctx)
        ERR( "[fatal-probe]   Rcx=%p Rdx=%p R8=%p Rax=%p Rbx=%p Rsi=%p Rdi=%p\n",
             (void *)ctx->Rcx, (void *)ctx->Rdx, (void *)ctx->R8, (void *)ctx->Rax,
             (void *)ctx->Rbx, (void *)ctx->Rsi, (void *)ctx->Rdi );

    /* Is the stack-top value sitting in a TLS slot right now? */
    for (i = 0; i < 64; i++)
    {
        ULONG_PTR v = (ULONG_PTR)NtCurrentTeb()->TlsSlots[i];
        if (!v) continue;
        if (v == top)
            ERR( "[fatal-probe]   TlsSlots[%u] = %p == EMULATOR STACK TOP\n", (unsigned)i, (void *)v );
        else if (area && v >= (ULONG_PTR)area && v < (ULONG_PTR)area + 0x58)
            ERR( "[fatal-probe]   TlsSlots[%u] = %p points INTO the CPU area (+0x%x)\n",
                 (unsigned)i, (void *)v, (unsigned)(v - (ULONG_PTR)area) );
    }
    if (NtCurrentTeb()->TlsExpansionSlots)
        for (i = 0; i < 1024; i++)
        {
            ULONG_PTR v = (ULONG_PTR)NtCurrentTeb()->TlsExpansionSlots[i];
            if (v && (v == top || (area && v >= (ULONG_PTR)area && v < (ULONG_PTR)area + 0x58)))
                ERR( "[fatal-probe]   TlsExpansionSlots[%u] = %p %s\n", (unsigned)i, (void *)v,
                     v == top ? "== EMULATOR STACK TOP" : "points INTO the CPU area" );
        }
    else
        ERR( "[fatal-probe]   TlsExpansionSlots = NULL\n" );

    /* Guest stack: the argument to the failing free was spilled somewhere
     * between FMallocBinned2::Free and the fatal, and the return addresses
     * name the callers. */
    if (!sp || NtReadVirtualMemory( GetCurrentProcess(), (void *)sp, stk, sizeof(stk), &got ) || got < 8)
    {
        ERR( "[fatal-probe]   guest stack at %p unreadable\n", (void *)sp );
        return;
    }
    for (i = 0; i < got / sizeof(ULONG_PTR) && printed < 48; i++)
    {
        ULONG_PTR v = stk[i], base = 0;
        char name[40];
        if (v == top)
        {
            ERR( "[fatal-probe]   sp+%03x = %p  <== EMULATOR STACK TOP on the guest stack\n",
                 (unsigned)(i * 8), (void *)v );
            hits++; printed++;
            continue;
        }
        if (v < 0x10000 || !ios_probe_module( v, &base, name, sizeof(name) )) continue;
        {
            unsigned char b[6];
            SIZE_T g2 = 0;
            const char *tag = "?";
            if (!NtReadVirtualMemory( GetCurrentProcess(), (void *)(v - 6), b, sizeof(b), &g2 ) && g2 == 6)
            {
                if (b[1] == 0xE8) tag = "CALL";                                   /* E8 rel32      */
                else if (b[0] == 0xFF && b[1] == 0x15) tag = "CALL";              /* FF 15 disp32  */
                else if (b[4] == 0xFF && (b[5] & 0xF8) == 0xD0) tag = "CALL";     /* FF D0..D7     */
                else if (b[3] == 0xFF && (b[4] & 0xF8) == 0x50) tag = "CALL";     /* FF 50..57 d8  */
            }
            ERR( "[fatal-probe]   sp+%03x: %-4s %s+0x%llx\n", (unsigned)(i * 8), tag, name,
                 (unsigned long long)(v - base) );
            printed++;
        }
    }
    ERR( "[fatal-probe]   scanned %u qwords, %u stack-top hit(s), %u code-like\n",
         (unsigned)(got / sizeof(ULONG_PTR)), hits, printed - hits );
}

/* madeira-bcd [wild-exec] (env MADEIRA_WILD_EXEC_PROBE = 0 turns it off). Log only.
 *
 * Overwatch 2 on 0.2.60 (log 7747ade4) died on "AV EXEC of 1533C7640": x64 code went to an
 * address that is in no loaded module of the process (it sits in JIT-pool space that earlier
 * held another pseudo-process's DLL copies). The log has no guest registers or stack for it, so
 * the producer (a ret, a call through a stale pointer, a table) can't be named. When an execute
 * fault's target is outside every module, print the full guest register set and the first 24
 * raw stack qwords (with module+offset when one matches), then the ml843 call-chain scan. Up to
 * 4 reports per process; nothing is changed. */
/* wild-exec v2: hex dump of guest memory, 32 bytes per line, never faults (NtReadVirtualMemory).
 * Each line is read on its own so a locked page after a readable one doesn't hide the readable part. */
static void ios_wild_exec_hex( const char *what, ULONG_PTR addr, SIZE_T len )
{
    static const char hx[] = "0123456789abcdef";
    unsigned char buf[32];
    SIZE_T got, off, j;
    char line[3 * 32 + 1];

    if (len > 0x200) len = 0x200;
    for (off = 0; off < len; off += 32)
    {
        SIZE_T want = len - off < 32 ? len - off : 32;
        got = 0;
        if (addr + off < 0x10000 ||
            NtReadVirtualMemory( GetCurrentProcess(), (void *)(addr + off), buf, want, &got ) || !got)
        {
            ERR( "[wild-exec]   %s @%p: unreadable\n", what, (void *)(addr + off) );
            continue;
        }
        for (j = 0; j < got; j++)
        {
            line[j * 3] = hx[buf[j] >> 4];
            line[j * 3 + 1] = hx[buf[j] & 15];
            line[j * 3 + 2] = ' ';
        }
        line[j * 3] = 0;
        ERR( "[wild-exec]   %s @%p: %s\n", what, (void *)(addr + off), line );
    }
}

/* wild-exec v3: 1 when the module at base is a Windows system DLL (its full path has \windows\).
 * Fills sec (64 bytes) with "+0xRVA sect=<name> ch=<characteristics> exec=<0|1>", or "sect=none"
 * when the RVA is in a gap between sections. Headers are read with NtReadVirtualMemory, so a bad
 * header prints instead of faulting. */
static int ios_wild_exec_sysdll( ULONG_PTR addr, ULONG_PTR base, char sec[64] )
{
    static const WCHAR win[] = {'\\','w','i','n','d','o','w','s','\\'};
    LIST_ENTRY *mark, *e;
    unsigned n = 0, i, j, len, nsec;
    PEB *peb = NtCurrentTeb()->Peb;
    int sys = 0;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    IMAGE_SECTION_HEADER sh;
    WCHAR path[260];
    ULONG rva = (ULONG)(addr - base);
    ULONG_PTR shoff;
    SIZE_T got;

    if (!peb || !peb->LdrData) return 0;
    mark = &peb->LdrData->InLoadOrderModuleList;
    for (e = mark->Flink; e && e != mark && n < 512; e = e->Flink, n++)
    {
        LDR_DATA_TABLE_ENTRY *m = CONTAINING_RECORD( e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
        if ((ULONG_PTR)m->DllBase != base) continue;
        len = m->FullDllName.Length / sizeof(WCHAR);
        if (len > ARRAY_SIZE(path)) len = ARRAY_SIZE(path);
        if (!m->FullDllName.Buffer ||
            NtReadVirtualMemory( GetCurrentProcess(), m->FullDllName.Buffer, path, len * sizeof(WCHAR), &got ) ||
            got != len * sizeof(WCHAR)) break;
        for (i = 0; !sys && i + ARRAY_SIZE(win) <= len; i++)
        {
            for (j = 0; j < ARRAY_SIZE(win); j++)
            {
                WCHAR c = path[i + j];
                if (c >= 'A' && c <= 'Z') c += 32;
                if (c != win[j]) break;
            }
            if (j == ARRAY_SIZE(win)) sys = 1;
        }
        break;
    }
    if (!sys) return 0;

    sprintf( sec, " +0x%x sect=none", (unsigned)rva );
    if (NtReadVirtualMemory( GetCurrentProcess(), (void *)base, &dos, sizeof(dos), &got ) || got != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000 ||
        NtReadVirtualMemory( GetCurrentProcess(), (void *)(base + dos.e_lfanew), &nt, sizeof(nt), &got ) ||
        got != sizeof(nt) || nt.Signature != IMAGE_NT_SIGNATURE)
    {
        sprintf( sec, " +0x%x headers unreadable", (unsigned)rva );
        return 1;
    }
    nsec = nt.FileHeader.NumberOfSections < 64 ? nt.FileHeader.NumberOfSections : 64;
    shoff = base + dos.e_lfanew + FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +
            nt.FileHeader.SizeOfOptionalHeader;
    for (i = 0; i < nsec; i++)
    {
        ULONG vs;
        if (NtReadVirtualMemory( GetCurrentProcess(), (void *)(shoff + i * sizeof(sh)), &sh, sizeof(sh), &got ) ||
            got != sizeof(sh))
        {
            sprintf( sec, " +0x%x sect=? (header read failed)", (unsigned)rva );
            break;
        }
        vs = sh.Misc.VirtualSize ? sh.Misc.VirtualSize : sh.SizeOfRawData;
        if (rva >= sh.VirtualAddress && rva - sh.VirtualAddress < vs)
        {
            char nm[9];
            memcpy( nm, sh.Name, 8 );
            nm[8] = 0;
            for (j = 0; j < 8 && nm[j]; j++) if (nm[j] < 32 || nm[j] > 126) nm[j] = '?';
            /* longest: " +0x" 8 " sect=" 8 " ch=" 8 " exec=" 1 = 4+8+6+8+4+8+6+1 = 45 < 64 */
            sprintf( sec, " +0x%x sect=%s ch=%08x exec=%d", (unsigned)rva, nm,
                     (unsigned)sh.Characteristics, (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 1 : 0 );
            break;
        }
    }
    return 1;
}

static void ios_wild_exec_probe( const EXCEPTION_RECORD *rec, const CONTEXT *ctx )
{
    static LONG mode, reports;
    ULONG_PTR target, base = 0, stk[24], from;
    SIZE_T got = 0, i;
    char name[40], sec[64] = "";
    const char *where;
    LONG n;

    if (!ctx || reports >= 4) return;   /* skip the unlocked module walks once the cap is used up */
    if (!mode)   /* v3: read the off switch before any module walk (int3s are frequent) */
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        RtlInitUnicodeString( &var, L"MADEIRA_WILD_EXEC_PROBE" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        mode = (!RtlQueryEnvironmentVariable_U( NULL, &var, &value ) &&
                value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
    }
    if (mode != 2) return;
    if (rec->ExceptionCode == STATUS_ACCESS_VIOLATION && rec->NumberParameters >= 2 &&
        rec->ExceptionInformation[0] == EXCEPTION_EXECUTE_FAULT)
        target = rec->ExceptionInformation[1];
    else if (rec->ExceptionCode == STATUS_BREAKPOINT || rec->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)
        target = (ULONG_PTR)rec->ExceptionAddress;
    else return;
    if (ios_probe_module( target, &base, name, sizeof(name) ))
    {
        /* v3: inside a module is normal, except a Windows system DLL other than ntdll (the game's own
         * loader raises int3 on purpose; system DLLs don't). 0.2.70 log ff1dc334: Overwatch died on
         * "Unhandled exception code 80000003 flags 0 addr 0x70eedd7640" = win32u.dll+0x37640. */
        if (!strcmp( name, "ntdll.dll" ) || !ios_wild_exec_sysdll( target, base, sec )) return;
        where = "in system DLL ";
    }
    else if (rec->ExceptionCode != STATUS_ACCESS_VIOLATION) return;   /* v1/v2 scope: EXEC faults only */
    else
    {
        where = "in no module";
        name[0] = 0;
    }
    if ((n = InterlockedIncrement( &reports )) > 4) return;

    ERR( "[wild-exec] #%ld tid=%04x code=%08x target=%p (%s%s%s) Rip=%p Rsp=%p Rbp=%p EFlags=%08x rev=wild-exec-3\n",
         n, (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread, (unsigned)rec->ExceptionCode,
         (void *)target, where, name, sec,
         (void *)ctx->Rip, (void *)ctx->Rsp, (void *)ctx->Rbp, (unsigned)ctx->EFlags );
    if (rec->ExceptionCode != STATUS_ACCESS_VIOLATION)
        ios_wild_exec_hex( "[target-0x20]", target - 0x20, 0x40 );   /* is it padding (cc cc) or real code? */
    ERR( "[wild-exec]   Rax=%p Rbx=%p Rcx=%p Rdx=%p Rsi=%p Rdi=%p\n", (void *)ctx->Rax, (void *)ctx->Rbx,
         (void *)ctx->Rcx, (void *)ctx->Rdx, (void *)ctx->Rsi, (void *)ctx->Rdi );
    ERR( "[wild-exec]   R8=%p R9=%p R10=%p R11=%p R12=%p R13=%p R14=%p R15=%p\n", (void *)ctx->R8,
         (void *)ctx->R9, (void *)ctx->R10, (void *)ctx->R11, (void *)ctx->R12, (void *)ctx->R13,
         (void *)ctx->R14, (void *)ctx->R15 );
    /* from Rsp-0x10: after a ret the popped target sits at rsp-8 (if the dispatch frame left it) */
    from = (ULONG_PTR)ctx->Rsp - 0x10;
    if (NtReadVirtualMemory( GetCurrentProcess(), (void *)from, stk, sizeof(stk), &got ) || got < 8)
        ERR( "[wild-exec]   stack at %p unreadable\n", (void *)from );
    else
        for (i = 0; i < got / sizeof(ULONG_PTR); i++)
        {
            if (ios_probe_module( stk[i], &base, name, sizeof(name) ))
                ERR( "[wild-exec]   rsp%+04d = %p  %s+0x%llx\n", (int)(i * 8) - 0x10, (void *)stk[i], name,
                     (unsigned long long)(stk[i] - base) );
            else
                ERR( "[wild-exec]   rsp%+04d = %p\n", (int)(i * 8) - 0x10, (void *)stk[i] );
        }

    /* v2: the data the registers point at (jump tables / decoded pointers), and the code of the
     * function that made the jump: the first CALL-validated return address on the stack names its
     * caller, and an E8 rel32 there names the callee's entry. Code pages the game keeps
     * NOACCESS print "unreadable". */
    ios_wild_exec_hex( "[rax-0x20]", (ULONG_PTR)ctx->Rax - 0x20, 0x60 );
    ios_wild_exec_hex( "[rbx]", (ULONG_PTR)ctx->Rbx, 0x40 );
    ios_wild_exec_hex( "[rdx]", (ULONG_PTR)ctx->Rdx, 0x40 );
    ios_wild_exec_hex( "[r12]", (ULONG_PTR)ctx->R12, 0x40 );
    {
        /* optional extra address from the game's config: env.MADEIRA_WILD_EXEC_DUMP = <hex> (0x80 bytes) */
        UNICODE_STRING var, value;
        WCHAR buffer[24];
        ULONG_PTR extra = 0;
        unsigned k;
        RtlInitUnicodeString( &var, L"MADEIRA_WILD_EXEC_DUMP" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        if (!RtlQueryEnvironmentVariable_U( NULL, &var, &value ))
            for (k = 0; k < value.Length / sizeof(WCHAR); k++)
            {
                WCHAR c = buffer[k];
                if (k == 1 && (c == 'x' || c == 'X') && buffer[0] == '0') { extra = 0; continue; }
                if (c >= '0' && c <= '9') extra = extra * 16 + (c - '0');
                else if (c >= 'a' && c <= 'f') extra = extra * 16 + (c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') extra = extra * 16 + (c - 'A' + 10);
                else { extra = 0; break; }
                if (k >= 17) { extra = 0; break; }   /* more than 16 hex digits */
            }
        if (extra) ios_wild_exec_hex( "[extra]", extra, 0x80 );
        else if (value.Length) ERR( "[wild-exec]   MADEIRA_WILD_EXEC_DUMP ignored (want plain hex, e.g. 141C5CFC0)\n" );
    }
    if (got >= 8)
        for (i = 2; i < got / sizeof(ULONG_PTR); i++)   /* 2 = Rsp itself (the dump starts at Rsp-0x10) */
        {
            unsigned char b[6];
            SIZE_T g2 = 0;
            ULONG_PTR ret = stk[i];
            if (!ios_probe_module( ret, &base, name, sizeof(name) )) continue;
            if (NtReadVirtualMemory( GetCurrentProcess(), (void *)(ret - 6), b, sizeof(b), &g2 ) || g2 != 6) continue;
            if (b[1] == 0xE8)
            {
                LONG rel = (LONG)((ULONG)b[2] | ((ULONG)b[3] << 8) | ((ULONG)b[4] << 16) | ((ULONG)b[5] << 24));
                ULONG_PTR callee = ret + (LONG_PTR)rel;
                ERR( "[wild-exec]   caller ret %p (%s+0x%llx) at rsp+%03x calls %p directly\n", (void *)ret, name,
                     (unsigned long long)(ret - base), (unsigned)((i - 2) * 8), (void *)callee );
                ios_wild_exec_hex( "[caller]", ret - 0x40, 0x48 );
                ios_wild_exec_hex( "[callee]", callee, 0x200 );
                break;
            }
            if (b[0] == 0xFF && b[1] == 0x15)
            {
                ERR( "[wild-exec]   caller ret %p (%s+0x%llx) at rsp+%03x calls through [rip+disp32]\n", (void *)ret, name,
                     (unsigned long long)(ret - base), (unsigned)((i - 2) * 8) );
                ios_wild_exec_hex( "[caller]", ret - 0x40, 0x48 );
                break;
            }
        }
    /* v3: only an EXEC fault spends ios_fatal_probe's 2-report budget; a breakpoint the game
     * may still handle must not use up the real fatal's report */
    if (rec->ExceptionCode == STATUS_ACCESS_VIOLATION) ios_fatal_probe( ctx );
}

static void ios_tlswatch_pe_arm( const char *where );
/* madeira [crashmailer-dump]: ntdll's own SEH walk; its unwinds are not the game's */
static NTSTATUS call_seh_handlers_impl( EXCEPTION_RECORD *rec, CONTEXT *orig_context );
NTSTATUS call_seh_handlers( EXCEPTION_RECORD *rec, CONTEXT *orig_context )
{
    LONG internal = ios_cmd_internal_enter();
    NTSTATUS status = call_seh_handlers_impl( rec, orig_context );

    ios_cmd_internal_leave( internal );
    return status;
}

static NTSTATUS call_seh_handlers_impl( EXCEPTION_RECORD *rec, CONTEXT *orig_context )
{
    if (rec && rec->ExceptionCode == 0x406D1388) ios_tlswatch_pe_arm( "call_seh_handlers entry" );
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvol_regs;
    UNWIND_HISTORY_TABLE table;
    DISPATCHER_CONTEXT_ARM64EC dispatch;
    ARM64EC_NT_CONTEXT context;
    NTSTATUS status;
    ULONG_PTR frame;
    DWORD res;

    /* iOS-Madeira ml409 (#66): third bracket point — see [ki-path]. If Rsp is
     * already corrupt here but was clean at [veh], the vectored handlers (or
     * the emulator trip that ran them) are the corruptor. AV-only, capped. */
    if (rec->ExceptionCode == STATUS_ACCESS_VIOLATION)
    {
        static LONG sehent_n;
        if (sehent_n < 60 && InterlockedIncrement( &sehent_n ) <= 60)
            ERR( "[seh-entry] ctx=%p Rsp=%p Rip=%p\n", orig_context,
                 (void *)(ULONG_PTR)orig_context->Rsp, (void *)(ULONG_PTR)orig_context->Rip );
        ios_wild_exec_probe( rec, orig_context );   /* madeira-bcd [wild-exec], log only */

    }
    else if (rec->ExceptionCode == STATUS_BREAKPOINT || rec->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION)
        ios_wild_exec_probe( rec, orig_context );   /* wild-exec v3: int3 / ud in a system DLL, log only */

    /* iOS-Madeira ml633: ESTABLISH THE GUEST-STACK WINDOW IN PHASE ONE TOO.
     * ec_stack_window_begin() was only called on the phase-two unwind path, yet phase
     * one consults ec_win — so a thread could validate frames against another
     * exception's bounds, or none at all. Re-establish from the ORIGINAL Rsp here.
     *
     * ml742: this call used to sit INSIDE the access-violation-only diagnostic
     * block above -- a brace-placement slip, since the comment describes a
     * requirement for phase one generally. Any exception that is not an access
     * violation therefore ran phase one against whatever window the previous
     * exception left behind, and ec_win is AUTHORITATIVE in
     * is_valid_arm64ec_frame(): when ec_win.hi is set the TEB bounds are never
     * consulted. A stale window rejects a perfectly good frame, and the caller
     * treats that as a bogus context and kills the thread.
     *
     * That is what stopped a UE4 title from starting: it raised 0x406D1388 --
     * the benign code a thread raises purely to NAME itself -- while running its
     * DLL_THREAD_ATTACH callbacks. Not an access violation, so no window; the
     * frame was rejected despite sitting inside the printed stack bounds, and
     * one of the game's own threads was terminated during initialisation. */
    ec_stack_window_begin( (ULONG_PTR)orig_context->Rsp );

    /* iOS-Madeira 2026-07-04: [SEH_RATE] — the render worker burns ~75% of
     * its frame in virtual_unwind/RtlVirtualUnwind2/memset below this
     * function (PROF), yet nothing logs: these are HANDLED exceptions
     * (likely software RaiseException/C++ throws — no Mach fault, TRACE
     * muted). Sampled ERR every 1024 dispatches: total count + code +
     * faulting address names the thrower and quantifies the rate. */
    {
        static LONG seh_dispatch_count;
        LONG n = InterlockedIncrement( &seh_dispatch_count );
        if (n == 1 || (n & 0x3FF) == 0)
            ERR( "[SEH_RATE] n=%d code=%08x addr=%p flags=%x\n",
                 (int)n, (int)rec->ExceptionCode, rec->ExceptionAddress,
                 (int)rec->ExceptionFlags );
    }

    /* iOS-Madeira ml811: name EVERY non-benign exception, and decode C++ throws.
     *
     * A game died with "Unhandled Exception: 0x20474343" -- the LLVM/mingw C++
     * exception code -- raised from inside our own d3d11.dll's unwinder. Nothing
     * in our logs showed it: [SEH_RATE] above prints only dispatch #1 and every
     * 1024th, so the only exception ever logged was the benign thread-naming
     * one. This closes that gap.
     *
     * Deliberately NOT limited to 0x20474343: the run that produced that code is
     * not necessarily the run being diagnosed, and a fatal error may arrive
     * under a different code entirely. Rate limiting is PER CODE so a storm of
     * one kind cannot hide a single occurrence of another.
     *
     * ⛔ This runs inside exception dispatch. It must not allocate, must not
     * lock, must not recurse, and must not fault -- an earlier probe died
     * formatting its own log text. Every guest pointer is read through
     * NtReadVirtualMemory, which returns a status instead of faulting. */
    if (rec->ExceptionCode != 0x406d1388)   /* thread naming: genuinely benign, and constant */
    {
        static LONG seen_code[16], seen_hits[16];
        static LONG seen_n, in_probe;
        LONG i, slot = -1;

        /* Recursion guard: if decoding ever raises, do not decode again. */
        if (InterlockedCompareExchange( &in_probe, 1, 0 ) == 0)
        {
            for (i = 0; i < seen_n && i < 16; i++)
                if (seen_code[i] == (LONG)rec->ExceptionCode) { slot = i; break; }
            if (slot < 0 && seen_n < 16)
            {
                slot = seen_n++;
                seen_code[slot] = (LONG)rec->ExceptionCode;
            }
            if (slot >= 0 && ++seen_hits[slot] <= 4)
            {
                ERR( "[exc] ml811 code=%08x addr=%p flags=%x nparams=%u tid=%04x hit=%d\n",
                     (int)rec->ExceptionCode, rec->ExceptionAddress, (int)rec->ExceptionFlags,
                     (unsigned)rec->NumberParameters,
                     (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread,
                     (int)seen_hits[slot] );

                /* 0x20474343 == 'GCC ' is the code BOTH libstdc++ and LLVM's
                 * libunwind raise for a C++ throw on Windows. The runtime that
                 * threw is identified by the 8-byte exception_class, not by the
                 * status code -- this build is libc++abi, whose class is
                 * "CLNGC++\0"; a GNUCC++-only check would reject exactly the
                 * exception we need to see. */
                /* ml812: OutputDebugString carries UE4's failure text verbatim.
                 * ANSI form is (len, ptr); the wide form appends (len, ptr). */
                if (rec->ExceptionCode == 0x40010006 && rec->NumberParameters >= 2)
                {
                    if (ios_exc_dump_str( "OutputDebugStringA", rec->ExceptionInformation[1],
                                          rec->ExceptionInformation[0], 0 ))
                        ios_fatal_probe( orig_context );
                }
                if (rec->ExceptionCode == 0x4001000a && rec->NumberParameters >= 4)
                {
                    ios_exc_dump_str( "OutputDebugStringA", rec->ExceptionInformation[1],
                                      rec->ExceptionInformation[0], 0 );
                    ios_exc_dump_str( "OutputDebugStringW", rec->ExceptionInformation[3],
                                      rec->ExceptionInformation[2], 1 );
                }
                /* ml812: the game's own software-report codes. Its reporter reads
                 * the single parameter as a pointer to { const WCHAR *msg; int
                 * skip; } -- so the parameter is NOT the string, and printing it
                 * as one would show garbage. Follow both levels safely. */
                if ((rec->ExceptionCode == 0x00004000 || rec->ExceptionCode == 0x00008000)
                    && rec->NumberParameters >= 1)
                {
                    ULONG_PTR msg = 0;
                    SIZE_T g2 = 0;
                    if (!NtReadVirtualMemory( GetCurrentProcess(),
                                              (void *)rec->ExceptionInformation[0],
                                              &msg, sizeof(msg), &g2 )
                        && g2 == sizeof(msg) && msg)
                        ios_exc_dump_str( "FATAL report message", msg, 200, 1 );
                    else
                        ERR( "[exc] ml812   report struct at %p unreadable\n",
                             (void *)rec->ExceptionInformation[0] );
                }

                if (rec->ExceptionCode == 0x20474343 && rec->NumberParameters >= 1)
                {
                    ULONG_PTR ue = rec->ExceptionInformation[0];
                    ULONG64 cls = 0;
                    SIZE_T got = 0;

                    if (!NtReadVirtualMemory( GetCurrentProcess(), (void *)ue, &cls, sizeof(cls), &got )
                        && got == sizeof(cls))
                    {
                        char cbuf[9];
                        int k;
                        for (k = 0; k < 8; k++)
                        {
                            unsigned char c = (unsigned char)(cls >> (56 - 8 * k));
                            cbuf[k] = (c >= 32 && c < 127) ? (char)c : '.';
                        }
                        cbuf[8] = 0;

                        /* Layout verified against BOTH the libc++abi source and
                         * the shipped binary: unwindHeader sits at the END of
                         * __cxa_exception (+0x60), so exceptionType is at
                         * unwind-0x50. Do NOT subtract sizeof(__cxa_exception). */
                        if ((cls >> 8) == (0x434C4E47432B2Bull) ||    /* CLNGC++ */
                            (cls >> 8) == (0x474E5543432B2Bull))      /* GNUCC++ */
                        {
                            ULONG_PTR ti = 0, namep = 0;
                            char nm[96];

                            if (!NtReadVirtualMemory( GetCurrentProcess(), (void *)(ue - 0x50),
                                                      &ti, sizeof(ti), &got ) && got == sizeof(ti) && ti
                                && !NtReadVirtualMemory( GetCurrentProcess(), (void *)(ti + 8),
                                                         &namep, sizeof(namep), &got ) && got == sizeof(namep)
                                && namep)
                            {
                                memset( nm, 0, sizeof(nm) );
                                if (!NtReadVirtualMemory( GetCurrentProcess(), (void *)namep,
                                                          nm, sizeof(nm) - 1, &got ) && got)
                                {
                                    SIZE_T j;
                                    for (j = 0; j < sizeof(nm) - 1; j++)
                                        if (nm[j] && (nm[j] < 32 || (unsigned char)nm[j] >= 127)) { nm[j] = 0; break; }
                                    nm[sizeof(nm) - 1] = 0;
                                    ERR( "[exc] ml811   C++ throw class=\"%s\" type=\"%s\" "
                                         "(mangled; _ZSt9bad_alloc etc) unwind=%p\n",
                                         cbuf, nm, (void *)ue );
                                }
                                else
                                    ERR( "[exc] ml811   C++ throw class=\"%s\" type-name UNREADABLE "
                                         "(ti=%p namep=%p)\n", cbuf, (void *)ti, (void *)namep );
                            }
                            else
                                ERR( "[exc] ml811   C++ throw class=\"%s\" but exceptionType "
                                     "UNREADABLE at unwind-0x50 (ue=%p)\n", cbuf, (void *)ue );
                        }
                        else
                            ERR( "[exc] ml811   C++-coded exception with UNKNOWN runtime class "
                                 "\"%s\" (%016llx) -- not decoding its layout\n",
                                 cbuf, (unsigned long long)cls );
                    }
                    else
                        ERR( "[exc] ml811   param[0]=%p is not readable as an unwind header\n",
                             (void *)ue );
                }
            }
            InterlockedExchange( &in_probe, 0 );
        }
    }

    context.AMD64_Context = *orig_context;
    context.ContextFlags &= ~0x40; /* Clear xstate flag. */

    dispatch.TargetPc      = 0;
    dispatch.ContextRecord = &context.AMD64_Context;
    dispatch.HistoryTable  = &table;
    dispatch.NonVolatileRegisters = nonvol_regs.Buffer;

    /* iOS-Madeira 2026-07-04: no-progress guard. A dispatch whose context
     * holds JIT-pool VAs finds no unwind tables (function tables are
     * registered for the PE VAs), so RtlVirtualUnwind2's leaf-frame
     * fallback can cycle without advancing — measured: ONE stuck dispatch
     * spun 1.2e9 unwind steps against the same RtlRaiseException frame,
     * pegging a P-core since boot. If neither ControlPc nor the frame
     * advances between iterations, or the walk exceeds a sane depth,
     * bail with EXCEPTION_STACK_INVALID instead of spinning forever. */
    {
        ULONG64 prev_pc = 0, prev_frame = 0;
        unsigned int walk_steps = 0;
        /* ml222: ring of the last few unwind steps, dumped ONLY if the walk ends badly.
         * The failing dispatch reported ControlPc=0, which has two readings needing
         * opposite fixes: the walk covered several sane frames and reached the genuine
         * end of stack (so the exception really is unhandled, and the question is why no
         * handler matched), or ControlPc was 0 from step 1 (the incoming context is
         * broken). Recording the trajectory instead of the endpoint distinguishes them,
         * and costs nothing on the paths that succeed. */
        ULONG64 trace_pc[8] = { 0 }, trace_frame[8] = { 0 };
        unsigned int trace_n = 0;

    for (;;)
    {
        status = virtual_unwind( UNW_FLAG_EHANDLER, &dispatch, &context );
        if (status != STATUS_SUCCESS) return status;

    unwind_done:
        trace_pc[trace_n & 7] = dispatch.ControlPc;
        trace_frame[trace_n & 7] = dispatch.EstablisherFrame;
        trace_n++;

        if (!dispatch.EstablisherFrame) break;

        /* iOS-Madeira ml246: ControlPc == 0 is the END OF THE STACK -- there is nothing to
         * unwind to, and continuing just walks memory until it faults.
         *
         * The existing no-progress guard needs BOTH pc and frame to repeat, so it cannot
         * catch the observed degeneration: pc stays 0 while the frame creeps upward 8 bytes
         * per step. Measured 2074 steps ending at a fresh SEGV in ntdll's own walk
         * (ntdll+0x69c48) reading unmapped memory, which became SEGV LOOP FATAL and killed
         * the process -- while unwinding an exception raised inside Steam's CEF surface
         * (chromehtml.dll+0xdc70 via tier0_s64). Stopping here turns a process-killing walk
         * into an ordinary unhandled exception. */
        /* ml266 FIX: ControlPc == 0 is the NORMAL END OF THE STACK, not a broken one.
         *
         * The ml246 guard above lumped it in with the degenerate cases and set
         * EXCEPTION_STACK_INVALID, which NtRaiseException turns into
         *   "Exception frame is not in stack limits => unable to dispatch exception"
         * followed by an IMMEDIATE NtTerminateProcess. That short-circuits second
         * chance entirely -- so the process dies before the guest's unhandled-exception
         * filter (SetUnhandledExceptionFilter, which Chromium installs for crash
         * reporting) ever runs, and before the debugger event.
         *
         * Measured in ml266: FEX did everything right -- reconstructed the guest
         * context, mapped host pc 0x157424650 -> guest rip 0x7E200E0080, and rethrew
         * onto the guest stack -- then
         *   call_seh_handlers unwind stuck: pc=0 frame=703f3ff350 steps=1
         * with frame == ecRsp + 8, i.e. the leaf pop RAN and read a return address of
         * ZERO. A guest that jumped to a bogus RIP simply has no caller. That is an
         * unhandled exception, which is a normal outcome, NOT an invalid stack.
         *
         * So: end the search quietly and let the exception take the ordinary unhandled
         * path. Keep EXCEPTION_STACK_INVALID for what it actually means -- a walk that
         * degenerates (no forward progress) or runs away. */
        if (!dispatch.ControlPc)
        {
            WARN( "unwind reached end of stack after %u steps (frame=%I64x) —"
                  " exception is unhandled, dispatching normally\n",
                  walk_steps, dispatch.EstablisherFrame );
            break;
        }

        if ((dispatch.ControlPc == prev_pc && dispatch.EstablisherFrame == prev_frame) ||
            ++walk_steps > 0x10000)
        {
            /* iOS-Madeira ml327 LIVELOCK BREAKER.
             *
             * Abandoning the walk ends THIS dispatch, but nothing stops the same fault
             * from recurring: a live run was caught repeating
             *   unwind stuck: pc=149dc0110 frame=71e01fdfb0 steps=2 — abandoning walk
             * 58,045 times with byte-identical pc and frame, spinning until the user
             * killed the app (20MB of log, battery burn, no progress). Faults became
             * survivable in #38, which is right for ordinary guest faults, but a fault
             * whose handler cannot make progress just retries the same instruction
             * forever.
             *
             * Count CONSECUTIVE abandons at the same (pc, frame). A different site
             * resets the counter, so genuinely distinct unwindable faults are unaffected.
             * Past the threshold, stop pretending this is recoverable and terminate with
             * the real exception code -- a diagnosable crash beats an infinite loop. */
            {
                static ULONG64 stuck_pc, stuck_frame;
                static unsigned stuck_n;

                if ((ULONG64)dispatch.ControlPc == stuck_pc && dispatch.EstablisherFrame == stuck_frame)
                {
                    if (++stuck_n >= 16)
                    {
                        ERR( "unwind stuck: SAME site pc=%I64x frame=%I64x abandoned %u times in a row"
                             " — livelock, terminating with code %08lx\n",
                             (ULONG64)dispatch.ControlPc, dispatch.EstablisherFrame, stuck_n,
                             rec->ExceptionCode );
                        NtTerminateProcess( GetCurrentProcess(), rec->ExceptionCode );
                    }
                }
                else
                {
                    stuck_pc = (ULONG64)dispatch.ControlPc;
                    stuck_frame = dispatch.EstablisherFrame;
                    stuck_n = 1;
                }
            }
            ERR( "unwind stuck: pc=%I64x frame=%I64x steps=%u — abandoning walk\n",
                 (ULONG64)dispatch.ControlPc, dispatch.EstablisherFrame, walk_steps );
            rec->ExceptionFlags |= EXCEPTION_STACK_INVALID;
            break;
        }
        prev_pc = dispatch.ControlPc;
        prev_frame = dispatch.EstablisherFrame;

        /* iOS-Madeira ml633: THE TERMINAL ROOT FRAME IS LEGAL — DO NOT REJECT IT.
         *
         * Usable frames are [lo, hi), but the OUTERMOST frame of a thread sits exactly
         * AT hi. In the ml632 ULTRAKILL run the walk reached
         *   ControlPc = ntdll!RtlUserThreadStart+0x2c, EstablisherFrame = 0x703ec60000
         * which is precisely StackBase, and its unwind record has ExceptionDataPresent
         * with handler RVA 0x25388 = call_unhandled_exception_handler — i.e. THE frame
         * whose whole job is to run Unity's unhandled-exception filter. Rejecting it
         * produced "Exception frame is not in stack limits => unable to dispatch" and
         * terminated before the game's own filter ever ran. Stock Wine accepts
         * frame <= StackBase.
         *
         * ⛔ Do NOT relax every `< hi` to `<= hi` — that would bless any one-past-the-end
         * address and re-open what ml617 closed. This predicate is deliberately narrow:
         * the frame must be EXACTLY hi, the unwound Rsp must ALSO be exactly hi, and it
         * is honoured at most once per walk, so a loop cannot exploit it. */
        {
            if (walk_steps <= 1) ml633_root_used = 0;   /* new walk */
            if (ec_win.hi && !ml633_root_used &&
                dispatch.EstablisherFrame == (ULONG64)ec_win.hi &&
                context.AMD64_Context.Rsp == (ULONG64)ec_win.hi &&
                !is_valid_arm64ec_frame( dispatch.EstablisherFrame ))
            {
                ml633_root_used = 1;
                ERR( "[unwind-root] ml633 ACCEPTING terminal root frame %I64x (== stack hi) "
                     "ControlPc=%I64x handler=%p — this is the unhandled-exception filter frame\n",
                     dispatch.EstablisherFrame, (ULONG64)dispatch.ControlPc,
                     dispatch.LanguageHandler );
                goto ml633_frame_ok;
            }
        }

        if (!is_valid_arm64ec_frame( dispatch.EstablisherFrame ))
        {
            /* ml742: print the bounds the decision was ACTUALLY made against.
             * The existing report below prints only the TEB stack, but ec_win
             * overrides it when set -- so a frame plainly inside the printed
             * range can still be rejected, which reads as a contradiction and
             * sent one investigation down the wrong path. Show both, plus
             * whether the plain TEB test would have passed. Bounded. */
            {
                static LONG ml742_n;
                if (InterlockedIncrement( &ml742_n ) <= 24)
                    ERR( "[ec-frame] ml742 REJECT frame=%p code=%08x | ec_win lo=%p hi=%p "
                         "emu lo=%p hi=%p | origRsp=%p tebStack=%p-%p | teb_test=%d\n",
                         (void *)dispatch.EstablisherFrame, (int)rec->ExceptionCode,
                         (void *)ec_win.lo, (void *)ec_win.hi,
                         (void *)ec_win.emu_lo, (void *)ec_win.emu_hi,
                         (void *)(ULONG_PTR)orig_context->Rsp,
                         NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase,
                         is_valid_frame( dispatch.EstablisherFrame ) );
            }
            /* ml221: report WHY the walk produced this frame, not just that it did.
             *
             * The frame that killed the webhelper was 0x73c9f70008 -- 8 bytes into
             * DWrite.dll's read-only headers, i.e. the walk had run off the end of the
             * guest stack. That happens when ControlPc stays a JIT-pool VA: function
             * tables are registered at PE VAs, so no unwind info is found and the frames
             * are garbage. virtual_unwind reverse-translates via
             * p_ios_jit_reverse_translate_addr, but that pointer lives in ntdll's .data
             * and every pseudo-process gets a CLONED copy -- if a child's copy is NULL the
             * translation silently degrades to identity. Print it, plus ControlPc, so the
             * two cases are distinguishable instead of guessed at. */
            ERR( "invalid frame %I64x (%p-%p) ControlPc=%I64x xlate_rev=%p%s\n",
                 dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase,
                 (ULONG64)dispatch.ControlPc, p_ios_jit_reverse_translate_addr,
                 p_ios_jit_reverse_translate_addr ? "" : "  <-- NULL: unwind ran in POOL space" );
            /* ml260 (#38): name WHERE the garbage frame came from.
             *
             * Symbolised, the failing walk is our OWN dispatch stack:
             *   #0 set_int_reg (unwind.c:1815)  <- the AV, *val on a garbage frame
             *   #1 virtual_unwind  #2 call_seh_handlers  #3 dispatch_exception
             *   #4 KiUserExceptionDispatcher   frame=0x40001131  <- garbage
             * and the AV address 0x40001171 is exactly frame+0x40, i.e. a saved-register
             * slot. 0x40001131 is not a corrupted pointer -- it has the shape of a FRAME
             * REGISTER value, which matters because virtual_unwind above zeroes several
             * ARM64EC nonvolatile slots (GpNvRegs[4], [5], [9] = 0): if the unwind info
             * for this pc selects a frame register we do not populate, Rsp is set from
             * junk and every subsequent slot read is wild.
             *
             * So print the x64 nonvolatiles plus the UNWIND_INFO's frame-register fields.
             * If one of these registers equals the bad frame, the culprit is named
             * outright; if none do, the frame came from an opcode instead and the fix is
             * elsewhere. Fires only on this already-fatal path, so it costs nothing. */
            {
                CONTEXT *c = &context.AMD64_Context;
                ERR( "[unwind-why] frame=%I64x | Rsp=%I64x Rbp=%I64x Rbx=%I64x Rsi=%I64x Rdi=%I64x\n",
                     dispatch.EstablisherFrame, c->Rsp, c->Rbp, c->Rbx, c->Rsi, c->Rdi );
                ERR( "[unwind-why]   R12=%I64x R13=%I64x R14=%I64x R15=%I64x ImageBase=%I64x FnEntry=%p\n",
                     c->R12, c->R13, c->R14, c->R15, dispatch.ImageBase,
                     (void *)dispatch.FunctionEntry );
                /* ml274 CORRECTION: decode per ABI, not blindly as x64.
                 *
                 * The first version of this probe read the entry as an x64
                 * RUNTIME_FUNCTION (12 bytes: Begin/End/UnwindData) and its UnwindData as
                 * x64 UNWIND_INFO. For EC code that is the WRONG STRUCT, and it produced
                 * confident nonsense: entry[8840] of ntdll's ExtraRFETable is
                 * Begin=0x59730 UnwindData=0xb71ec and entry[8841] Begin=0x59770, which the
                 * probe reported as "begin=59730 end=b71ec unwind=59770" -- inventing a
                 * 383KB function whose xdata sat inside .text, then decoding a valid ARM64
                 * unwind RVA as x64 UNWIND_INFO (hence "version 3, 188 codes, framereg R9").
                 * There was never a fabricated RUNTIME_FUNCTION.
                 *
                 * RtlLookupFunctionTable picks the table with RtlIsEcCode: true ->
                 * ExtraRFETable (ARM64EC, 8-byte entries), false ->
                 * IMAGE_DIRECTORY_ENTRY_EXCEPTION (x64, 12-byte entries). Report which one
                 * applies and decode accordingly. */
                if (dispatch.FunctionEntry && dispatch.ImageBase)
                {
                    BOOLEAN is_ec = RtlIsEcCode( dispatch.ControlPc );

                    if (is_ec)
                    {
                        /* ARM64 RUNTIME_FUNCTION: BeginAddress + UnwindData. UnwindData with
                         * either of the low 2 bits set is PACKED unwind data; otherwise it is
                         * an RVA to .xdata. */
                        const DWORD *fn = (const DWORD *)dispatch.FunctionEntry;
                        DWORD begin = fn[0], ud = fn[1];

                        if (ud & 3)
                            ERR( "[unwind-why]   EC entry (ARM64, 8B): Begin=%x UnwindData=%x"
                                 " PACKED (flag=%u)\n", begin, ud, ud & 3 );
                        else
                        {
                            const DWORD *xd = (const DWORD *)(dispatch.ImageBase + ud);
                            ERR( "[unwind-why]   EC entry (ARM64, 8B): Begin=%x UnwindData=%x"
                                 " .xdata hdr[0]=%08x hdr[1]=%08x\n", begin, ud, xd[0], xd[1] );
                        }
                    }
                    else
                    {
                        const RUNTIME_FUNCTION *fn = (const RUNTIME_FUNCTION *)dispatch.FunctionEntry;
                        const BYTE *info = (const BYTE *)dispatch.ImageBase + fn->UnwindData;

                        ERR( "[unwind-why]   x64 entry (12B): begin=%x end=%x unwind=%x |"
                             " ver/flags=%02x prolog=%02x ncodes=%02x framereg=%u frameoff=%u\n",
                             (unsigned)fn->BeginAddress, (unsigned)fn->EndAddress,
                             (unsigned)fn->UnwindData, info[0], info[1], info[2],
                             info[3] & 0xf, (info[3] >> 4) & 0xf );
                    }
                    ERR( "[unwind-why]   table=%s ImageBase=%I64x ControlPc=%I64x\n",
                         is_ec ? "ExtraRFETable(ARM64EC)" : "DIRECTORY_ENTRY_EXCEPTION(x64)",
                         dispatch.ImageBase, (ULONG64)dispatch.ControlPc );
                }
            }
            {
                unsigned int k, shown = trace_n < 8 ? trace_n : 8;
                ERR( "[unwind-trace] %u steps total, last %u:\n", trace_n, shown );
                for (k = 0; k < shown; k++)
                {
                    unsigned int idx = (trace_n - shown + k) & 7;
                    ERR( "[unwind-trace]   #%u pc=%I64x frame=%I64x\n",
                         trace_n - shown + k, trace_pc[idx], trace_frame[idx] );
                }
            }
            /* ml377: a FIRST-STEP bad frame is an UNHANDLED exception, not a corrupt
             * stack — do not set EXCEPTION_STACK_INVALID for it.
             *
             * Same reasoning as the ml266 ControlPc==0 fix directly above, and the same
             * measured consequence: EXCEPTION_STACK_INVALID makes NtRaiseException print
             * "Exception frame is not in stack limits" and IMMEDIATELY NtTerminateProcess,
             * which short-circuits second chance — so Chromium's own
             * SetUnhandledExceptionFilter never runs and the WHOLE APP dies, not just the
             * offending pseudo-process.
             *
             * ml377 measured exactly that: the guest context handed to us was already
             * bogus (Rip=0x7c861802f1, inside FEX's HOST band, and a truncated
             * Rsp=0x1db59fba0 whose true value 0x71db59fba0 is in the TEB stack), so step
             * #0 produced an unusable frame. A guest that jumped to a garbage RIP has no
             * caller — that is an ordinary unhandled exception. Deep CEF work (profile /
             * extensions / GAIA sign-in) was lost to a process kill here.
             *
             * Keep EXCEPTION_STACK_INVALID for what it is meant to describe: a walk that
             * PROGRESSED and then degenerated (trace_n > 1). */
            if (trace_n > 1) rec->ExceptionFlags |= EXCEPTION_STACK_INVALID;
            else
            {
                ERR( "[unwind-why] first-step bad frame — guest context was already bogus\n" );
                /* ml395 (task #60/#66): a bogus-context thread has no recoverable
                 * caller and no useful SEH — but letting it run the unhandled path
                 * kills the whole PSEUDO-PROCESS (ml395: webhelper died c0000005 in
                 * exactly this state moments after parking its chrome-ipc server;
                 * steam's IPC poller died the same way).  Terminate ONLY this
                 * thread: its work is lost either way, and the process — with the
                 * handshake threads we need alive — survives.  Known cost: any
                 * locks the thread held stay taken (ml389-class convoy risk) —
                 * still strictly better than process death. */
                ERR( "[bogus-ctx] terminating THREAD only (code=%lx) — process survives\n",
                     rec->ExceptionCode );
                NtTerminateThread( NtCurrentThread(), rec->ExceptionCode );
                /* not reached */
            }
            break;
        }

    ml633_frame_ok:
        if (dispatch.LanguageHandler)
        {
            TRACE( "calling handler %p (rec=%p, frame=%I64x context=%p, dispatch=%p)\n",
                   dispatch.LanguageHandler, rec, dispatch.EstablisherFrame, orig_context, &dispatch );
            /* iOS-Madeira #81 — RE-LANDED ml603, GATED, exactly as the ml477
             * revert note below instructed.
             *
             * The problem: LanguageHandler is ImageBase + unwind handler RVA,
             * i.e. a PE VA, and PE .text is non-executable here, so
             * call_seh_handler's `blr x11` faults on instruction fetch.  The
             * Mach handler redirects it correctly every time, but the pointer
             * is recomputed from unwind data on EVERY dispatch, so the
             * stale-VA healer can never make it stick — one kernel round-trip
             * per SEH handler call, forever.  ml475 proved wrapping it in
             * xlate_ios_jit() eliminates that: 786k faults -> 0.
             *
             * ml477 reverted it for two reasons, ONE OF WHICH IS NOW FALSE:
             *
             *  (a) "the storm ONLY occurs with --js-flags=--jitless OFF, and
             *      jitless-off is convicted anyway, so the fix buys nothing."
             *      >>> FALSIFIED by ml602 (db 7252): jitless was ON
             *      ([proc-gate] V8 JITLESS (interpreted) MADEIRA_JITLESS=1,
             *      cmdline-tail shows --js-flags=--jitless) and the storm still
             *      reached 791,552 exec faults, 749/1029 sampled at this exact
             *      handler.  The dominant site is ntdll's own
             *      nested_exception_handler (RVA 0x5b3c0) — installed by
             *      call_seh_handler's own .seh_handler directive, so every SEH
             *      dispatch pays it.  It spiralled: chrome_elf fast-fail ->
             *      exception -> nested handler exec-fault -> exception, until
             *      thread 00cc took c00000fd STATUS_STACK_OVERFLOW
             *      ([stack-ovf] showed libcef.dll+0x690ca2c x15) and the whole
             *      Steam UI froze with ~12 threads parked ~95s on events.
             *
             *  (b) "translating a handler that is x86-64 GUEST code defeats the
             *      __os_arm64x_dispatch_icall classification (see #52), so the
             *      emulator never gets it" — STILL TRUE, and is why the gate
             *      below is mandatory.  RtlIsEcCode() is the classifier's own
             *      predicate: translate only what is genuinely EC/native and
             *      leave guest handlers at their PE address so the icall thunk
             *      can route them into FEX.
             *
             * The revert note also said to log EVERY translation rather than
             * the first 4 per process, because that cap is what hid the guest
             * handler case.  Logging all ~790k would drown the log (and our own
             * Swift log pipeline), so instead every DISTINCT handler is logged
             * exactly once with its EC verdict — which is what actually makes an
             * unexpected guest handler visible — plus a periodic census.  If the
             * distinct table fills, that is logged too, so we are never
             * silently blind. */
            {
                PEXCEPTION_ROUTINE handler = dispatch.LanguageHandler;
                BOOLEAN is_ec = RtlIsEcCode( (ULONG_PTR)handler );
                LONG cmd_saved;   /* madeira [crashmailer-dump] */

                if (is_ec)
                {
                    void *xl = xlate_ios_jit( handler );
                    if (xl) handler = (PEXCEPTION_ROUTINE)xl;
                }
                ios_seh_xlate_note( dispatch.LanguageHandler, handler, is_ec );

                cmd_saved = ios_cmd_handler( rec, 2, dispatch.LanguageHandler, 0, 0 );
                res = call_seh_handler( rec, dispatch.EstablisherFrame, orig_context,
                                        &dispatch, handler );
                ios_cmd_handler( rec, 2, dispatch.LanguageHandler, res, 1 );
                ios_cmd_internal_leave( cmd_saved );
            }
            rec->ExceptionFlags &= EXCEPTION_NONCONTINUABLE;
            TRACE( "handler at %p returned %lu\n", dispatch.LanguageHandler, res );

            switch (res)
            {
            case ExceptionContinueExecution:
                if (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) return STATUS_NONCONTINUABLE_EXCEPTION;
                return STATUS_SUCCESS;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                rec->ExceptionFlags |= EXCEPTION_NESTED_CALL;
                TRACE( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind:
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                                  dispatch.ControlPc, dispatch.FunctionEntry,
                                  &context.AMD64_Context, &dispatch.HandlerData, &frame, NULL );
                goto unwind_done;
            default:
                return STATUS_INVALID_DISPOSITION;
            }
        }
        /* hack: call wine handlers registered in the tib list */
        else while (is_valid_frame( (ULONG_PTR)teb_frame ) && (ULONG64)teb_frame < context.Sp)
        {
            TRACE( "calling TEB handler %p (rec=%p frame=%p context=%p dispatch=%p) sp=%I64x\n",
                   teb_frame->Handler, rec, teb_frame, orig_context, &dispatch, context.Sp );
            {
                LONG cmd_saved = ios_cmd_handler( rec, 3, teb_frame->Handler, 0, 0 );   /* madeira [crashmailer-dump] */
                res = call_seh_handler( rec, (ULONG_PTR)teb_frame, orig_context,
                                        &dispatch, (PEXCEPTION_ROUTINE)teb_frame->Handler );
                ios_cmd_handler( rec, 3, teb_frame->Handler, res, 1 );
                ios_cmd_internal_leave( cmd_saved );
            }
            TRACE( "TEB handler at %p returned %lu\n", teb_frame->Handler, res );

            switch (res)
            {
            case ExceptionContinueExecution:
                if (rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE) return STATUS_NONCONTINUABLE_EXCEPTION;
                return STATUS_SUCCESS;
            case ExceptionContinueSearch:
                break;
            case ExceptionNestedException:
                rec->ExceptionFlags |= EXCEPTION_NESTED_CALL;
                TRACE( "nested exception\n" );
                break;
            case ExceptionCollidedUnwind:
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase,
                                  dispatch.ControlPc, dispatch.FunctionEntry,
                                  &context.AMD64_Context, &dispatch.HandlerData, &frame, NULL );
                teb_frame = teb_frame->Prev;
                goto unwind_done;
            default:
                return STATUS_INVALID_DISPOSITION;
            }
            teb_frame = teb_frame->Prev;
        }

        if (context.Sp == (ULONG64)NtCurrentTeb()->Tib.StackBase) break;
    }
    } /* no-progress guard scope */
    return STATUS_UNHANDLED_EXCEPTION;
}


static void init_xcontext( struct xcontext *ctx, ARM64_NT_CONTEXT *arm_ctx )
{
    XSTATE *xs = (XSTATE *)(((ULONG_PTR)ctx->xs + 63) & ~63ull);

    if (ios_xstate_revert())
    {
        /* madeira [xstate-revert]: Wine 11.21's context_arm_to_x64(): no XSTATE, flags taken
         * from the ARM context. CONTEXT_EX and the XSTATE area are left zeroed. */
        memset( &ctx->c_ex, 0, sizeof(*ctx) - FIELD_OFFSET( struct xcontext, c_ex ) );
        context_arm_to_x64( &ctx->c, arm_ctx, ctx_flags_arm_to_x64( arm_ctx->ContextFlags ) );
        return;
    }

    ctx->c_ex.Legacy.Length = sizeof(CONTEXT);
    ctx->c_ex.Legacy.Offset = -(LONG)sizeof(CONTEXT);
    ctx->c_ex.XState.Length = sizeof(*xs);
    ctx->c_ex.XState.Offset = (char *)xs - (char *)&ctx->c_ex;
    ctx->c_ex.All.Offset = ctx->c_ex.Legacy.Offset;
    ctx->c_ex.All.Length = sizeof(CONTEXT) + ctx->c_ex.XState.Offset + ctx->c_ex.XState.Length;

    xs->Mask = XSTATE_MASK_AVX & RtlGetEnabledExtendedFeatures( XSTATE_MASK_AVX );
    xs->CompactionMask = 0;
    memset( xs->Reserved, 0, sizeof(xs->Reserved) );

    context_arm_to_x64( &ctx->c, arm_ctx, CONTEXT_AMD64_FULL | CONTEXT_AMD64_XSTATE );
}


/*******************************************************************
 *		KiUserEmulationDispatcher (NTDLL.@)
 */
void dispatch_emulation( ARM64_NT_CONTEXT *arm_ctx )
{
    struct xcontext *context = (void *)get_arm64ec_cpu_area()->ContextAmd64;

    init_xcontext( context, arm_ctx );
    ios_pfaf_apply( (CONTEXT *)&context->c );   /* madeira [pfaf-keep] */
    ios_df_apply( (CONTEXT *)&context->c );     /* madeira [df-ctx] */
    pBeginSimulation();
}
__ASM_GLOBAL_FUNC( "#KiUserEmulationDispatcher",
                   ".seh_context\n\t"
                   ".seh_endprologue\n\t"
                   "mov x0, sp\n\t"   /* context */
                   "bl dispatch_emulation\n\t"
                   "brk #1" )


/*******************************************************************
 *		dispatch_syscall
 */
static void dispatch_syscall( ARM64_NT_CONTEXT *context )
{
    if (context->X8 < __nb_syscalls)  /* syscall number in rax */
    {
        context->X0 = context->X4;  /* get first param from r10 */
        context->X4 = context->Pc;  /* and save return address to syscall thunk */
        context->Pc = (ULONG_PTR)invoke_arm64ec_syscall;
    }
    else context->X8 = STATUS_INVALID_SYSTEM_SERVICE;  /* set return value in rax */

    /* return to x64 code so that the syscall entry thunk is invoked properly */
    get_arm64ec_cpu_area()->InSimulation = 1;
    dispatch_emulation( context );
}


/* madeira-bcd [ccall-peek] (env MADEIRA_CCALL_PEEK_FIXUP = 0 turns it off).
 *
 * arm64x_check_call reads the first bytes of an x64 call target to spot the
 * fast-forward, syscall and "jmp [rip+x]" sequences. That is an optimisation
 * only: a target that is not one of them takes the exit thunk and the emulator
 * runs it. Overwatch 2 keeps Overwatch.exe .text PAGE_NOACCESS and decrypts a
 * page when x64 code first faults on it. On 0.2.57 (log 90020f6b) the peek hit
 * such a page from native ntdll code: "Exception: Code: C0000005 Address:
 * 70F0179074 AV READ of 1405431E0", host insn f9400170 = ldr x16,[x11], view
 * vprot 20 (NOACCESS). The loader's x64 hook can't handle a fault in native
 * code (it stepped Rip by 2: "AV EXEC of 154101076") and the game died 0xc0000005.
 * So a read fault on one of those peeks resumes at the exit-thunk path, as if
 * the bytes matched nothing; the emulator then fetches the target itself and
 * the fault is an ordinary x64 one at the target, which is what the guest's
 * handler expects. x11 still holds the target at every peek (it is only
 * overwritten by a load that completed). Only this ntdll's own peek range is
 * matched; Pc and the labels are both addresses in the code copy that ran. */
extern const char madeira_ccall_peek_begin[], madeira_ccall_peek_exit[];

static void ccall_peek_fixup( EXCEPTION_RECORD *rec, ARM64_NT_CONTEXT *arm_ctx )
{
    static LONG mode;   /* 0 not read yet, 1 off, 2 on */
    ULONG_PTR pc = arm_ctx->Pc;

    if (pc < (ULONG_PTR)madeira_ccall_peek_begin || pc >= (ULONG_PTR)madeira_ccall_peek_exit) return;
    if (rec->NumberParameters < 2 || rec->ExceptionInformation[0] != 0) return;   /* read faults only */
    if (!mode)
    {
        UNICODE_STRING name, value;
        WCHAR buffer[2];

        RtlInitUnicodeString( &name, L"MADEIRA_CCALL_PEEK_FIXUP" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        mode = (!RtlQueryEnvironmentVariable_U( NULL, &name, &value ) &&
                value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
    }
    if (mode != 2) return;
    {
        static LONG n;
        if (n < 16 && InterlockedIncrement( &n ) <= 16)
            ERR( "[ccall-peek] #%ld read fault at %p on target %p (read of %p) -> exit thunk path rev=ccall-peek\n",
                 n, (void *)pc, (void *)(ULONG_PTR)arm_ctx->X11, (void *)rec->ExceptionInformation[1] );
    }
    arm_ctx->Pc = (ULONG_PTR)madeira_ccall_peek_exit;
    syscall_NtContinue( arm_ctx, FALSE );   /* returns only on failure: then dispatch as before */
    arm_ctx->Pc = pc;
}

static void * __attribute__((used)) prepare_exception_arm64ec( EXCEPTION_RECORD *rec, struct xcontext *context, ARM64_NT_CONTEXT *arm_ctx )
{
    LONG xr_index;   /* madeira [crashmailer-dump] */

    if (rec->ExceptionCode == STATUS_EMULATION_SYSCALL) dispatch_syscall( arm_ctx );
    if (rec->ExceptionCode == STATUS_ACCESS_VIOLATION) ccall_peek_fixup( rec, arm_ctx );
    xr_index = ios_xr_record( rec, arm_ctx->Sp );   /* madeira-bcd [exc-ring], before note_av so the arm is not counted */
    if (rec->ExceptionCode == STATUS_ACCESS_VIOLATION) ios_sp_note_av( rec, arm_ctx->Sp );   /* madeira-bcd [subpage-sweep] */
    init_xcontext( context, arm_ctx );
    if (rec->ExceptionCode != STATUS_EMULATION_SYSCALL)
        ios_pfaf_int3( (CONTEXT *)&context->c );   /* madeira [pfaf-int3] */
    ios_dr_fill( (CONTEXT *)&context->c );   /* madeira [dr-pass]: real x64 exception contexts carry Dr0-Dr7 */
    ios_ctx_x64_fields( (CONTEXT *)&context->c );   /* madeira [ctx-x64-fields] */
    /* rtcs-diag: the first 6 non-syscall exceptions whose hook pointer is NULL or differs from the value stored at init. */
    if (rtcs_diag_enabled() && (!pResetToConsistentState || (void *)pResetToConsistentState != rtcs_diag_init) &&
        rec->ExceptionCode != STATUS_EMULATION_SYSCALL && rtcs_diag_hits < 6 && InterlockedIncrement( &rtcs_diag_hits ) <= 6)
    {
        ERR( "[rtcs-ptr] exception #%d: code=%08x pc=%p pointer=%p stored-at-init=%p export=%p %s rev=rtcs-diag\n",
             (int)rtcs_diag_hits, (unsigned int)rec->ExceptionCode, (void *)(ULONG_PTR)arm_ctx->Pc,
             (void *)pResetToConsistentState, rtcs_diag_init, rtcs_diag_raw,
             !pResetToConsistentState ? (rtcs_diag_init ? "NULL NOW, was set at init (cleared later)"
                                                        : "NULL here (all three statics 0: page cleared or another ntdll instance)")
                                      : "CHANGED since init" );
        rtcs_diag_where( "exception" );
    }
    /* iOS-Madeira task#34 probe: FEX's LogMan output is invisible on iOS (its
     * write(2) resolves to the PE CRT's WriteFile → unplumbed std handle),
     * so trace the guest-exception conversion from the wine side. Rate-
     * capped; STATUS_EMULATION_SYSCALL is the hot syscall path and is
     * excluded. Log BEFORE and AFTER ResetToConsistentState so we can see
     * whether FEX reconstructed the guest Rip or the pool/JIT host pc leaks
     * through to the dispatchers. RtCS may not return (NtContinueNative). */
    {
        static LONG rtcs_n;
        if (rtcs_n < 40 && InterlockedIncrement( &rtcs_n ) <= 40)
            /* ml266 (#47): WHY did the guest fault? Name the guest RIP's memory.
             *
             * FEX's side is correct -- it reconstructs the context and rethrows onto the
             * guest stack -- so the fault is a genuine guest fault, and the interesting
             * question is what the guest RIP points at. Across two runs the value is
             * suspiciously structured, not random:
             *   ml265 rip=0x7e600e0080
             *   ml266 rip=0x7e200e0080
             * identical low 32 bits (0x000e0080) with a high half differing by exactly
             * 0x400000000 (16GB). A stable low half plus a 16GB-aligned high half is the
             * shape of a CORRUPTED POINTER, not a wild jump -- and 16GB is exactly the
             * PartitionAlloc pool granularity.
             *
             * Three outcomes need different fixes: the page is unmapped (the guest jumped
             * into nothing), mapped but NOT executable (a permissions/exec-interval bug
             * of the kind #36 fixed), or mapped+executable (then FEX's translation is at
             * fault, not the memory). Query it instead of theorising. Capped, and only
             * for access violations whose address IS the reported guest RIP. */
            if (rec->ExceptionCode == STATUS_ACCESS_VIOLATION)
            {
                static int ripq;
                ULONG64 grip = (ULONG64)(ULONG_PTR)rec->ExceptionAddress;

                /* ml273 CORRECTION #2. The ml270 attempt used xlate_ios_jit_rev to spot
                 * pool addresses, but that only translates addresses with a PE equivalent
                 * -- FEX-EMITTED dispatcher code in the pool tail has none, so it returned
                 * identity and the bogus "NOT COMMITTED (jumped into nothing)" verdict
                 * still printed for 0x15cbf8650.
                 *
                 * Use the real discriminator instead, straight out of the measured data:
                 * memory Wine does not own comes back with AllocationBase == 0 AND
                 * Type == 0 (ml270 0x1577f8700 and ml273 0x15cbf8650 both did), whereas a
                 * genuine Wine region always has both set (ml273 0x7c600e0080 gave
                 * alloc=0x7C60000000, type=MEM_PRIVATE). No pool bounds needed on the PE
                 * side, and it generalises to any foreign mapping. */
                if (ripq < 8 && grip > 0x1000)
                {
                    MEMORY_BASIC_INFORMATION mbi;
                    SIZE_T len = 0;
                    ripq++;
                    NTSTATUS qst = NtQueryVirtualMemory( NtCurrentProcess(),
                                                        (void *)(ULONG_PTR)grip,
                                                        MemoryBasicInformation, &mbi,
                                                        sizeof(mbi), &len );
                    /* ml274: query ONCE. The else-if used to re-invoke it, which printed a
                     * spurious second "FAILED" line for every verdict (5 vs 6 in ml274). */
                    if (!qst && !mbi.AllocationBase && !mbi.Type)
                        ERR( "[guest-rip] 0x%I64x -> Wine has NO VIEW of this address"
                             " (AllocationBase=0, Type=0) -- it is a foreign/JIT-pool"
                             " mapping, so no protection verdict is meaningful\n", grip );
                    else if (!qst)
                        ERR( "[guest-rip] 0x%I64x -> base=%p alloc=%p size=%I64x state=%lx "
                             "protect=%lx allocprot=%lx type=%lx %s\n",
                             grip, mbi.BaseAddress, mbi.AllocationBase,
                             (ULONG64)mbi.RegionSize, mbi.State, mbi.Protect,
                             mbi.AllocationProtect, mbi.Type,
                             mbi.State != MEM_COMMIT      ? "<-- NOT COMMITTED (jumped into nothing)" :
                             !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                                                          ? "<-- COMMITTED but NOT EXECUTABLE"
                                                          : "<-- code address is VALID (fault is in the DATA the "
                                                            "instruction touches, not the RIP)" );
                    /* ml273: when the guest jumps somewhere non-executable, the useful
                     * question is WHO called it. The recurring target is alloc + 0xe0080
                     * with the same 0xe0080 offset every run (0x7e600e0080, 0x7e200e0080,
                     * 0x7c600e0080) into a private READ-WRITE PartitionAlloc region that
                     * is never protected executable -- so this is a call through a function
                     * pointer aimed at heap DATA, not a lost W^X flip. Dump the top of the
                     * guest stack and reverse-translate each slot, so the calling module is
                     * named instead of guessed. */
                    if (mbi.State == MEM_COMMIT &&
                        !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                    {
                        ULONG64 grsp = context->c.AMD64_Context.Rsp;
                        SIZE_T qlen = 0;
                        MEMORY_BASIC_INFORMATION smbi;

                        if (grsp && !NtQueryVirtualMemory( NtCurrentProcess(), (void *)(ULONG_PTR)grsp,
                                                           MemoryBasicInformation, &smbi,
                                                           sizeof(smbi), &qlen )
                            && smbi.State == MEM_COMMIT)
                        {
                            const ULONG64 *sp = (const ULONG64 *)(ULONG_PTR)grsp;
                            int k;
                            ERR( "[guest-caller] guest rsp=%I64x, top of stack:\n", grsp );
                            for (k = 0; k < 6; k++)
                            {
                                void *pe = xlate_ios_jit_rev( (void *)(ULONG_PTR)sp[k] );
                                ERR( "[guest-caller]   [%d] %I64x%s%p\n", k, sp[k],
                                     (pe && (ULONG64)(ULONG_PTR)pe != sp[k]) ? "  (pool -> PE " : "  (",
                                     pe );
                            }
                        }
                        else
                            ERR( "[guest-caller] guest rsp=%I64x is not readable —"
                                 " cannot name the caller\n", grsp );
                    }

                    /* iOS-Madeira ml631: THIS `else` WAS DANGLING.
                     *
                     * It hangs off the INNER committed-but-non-executable test, not off
                     * the `else if (!qst)` chain, so ANY executable page printed
                     * "NtQueryVirtualMemory FAILED" immediately after the successful
                     * query had already printed valid attributes. That read as the VM
                     * layer contradicting itself and cost a whole wrong hypothesis about
                     * why Mono declined the ULTRAKILL null fault. (The comment further up
                     * records ml274 fixing a DIFFERENT spurious "FAILED" on the same line
                     * — this is the second bug in one diagnostic.) Report the failure only
                     * when the query genuinely failed. */
                    else if (qst)
                        ERR( "[guest-rip] 0x%I64x -> NtQueryVirtualMemory FAILED status=%08x"
                             " (address is not in this address space at all)\n",
                             grip, (unsigned int)qst );

                    /* ml631: GUEST BYTES FROM BOTH VIEWS, at the RECONSTRUCTED guest RIP.
                     *
                     * ULTRAKILL dies on `ldaprb w6,[x8]` with x8=0, and FEX computed that
                     * zero twelve bytes earlier (`movz w7,#0` + `madd w8,w6,w7,wzr`). Only
                     * the guest x86 can say whether that is faithful. Print 32 bytes either
                     * side, and — because the page is a Mono JIT buffer with an RW alias —
                     * the SAME range through the alias, so a disagreement between the two
                     * views is visible immediately.
                     *
                     * Bounded and read-only: capped firings, no allocation, no locks; the
                     * unix probe is a pure table walk. */
                    /* iOS-Madeira ml636: DO NOT GATE ON "the page is executable".
                     *
                     * The ml635 gate required NtQueryVirtualMemory to classify the
                     * reconstructed RIP as executable — which CANNOT hold for the very case
                     * this telemetry exists for: a RIP exactly one-past a Mono alias. The
                     * probe now also matches an alias ENDING at the RIP, so let it decide. */
                    if (rec->ExceptionCode == 0xc0000005)
                    {
                        static int gb_n;
                        if (gb_n < 4)
                        {
                            struct ios_jit_alias_probe_params pp;
                            const unsigned char *rx = (const unsigned char *)(ULONG_PTR)(grip - 32);
                            char line[3 * 64 + 8];
                            unsigned i, off = 0;
                            gb_n++;

                            /* ml635: ask FIRST, so the byte dump can be clipped to the
                             * mapping. The ml634 fatal RIP was EXACTLY one-past the alias
                             * end, so reading RIP+31 would fault inside the handler. */
                            memset( &pp, 0, sizeof(pp) );
                            pp.size = sizeof(pp); pp.version = 1; pp.addr = grip;
                            WINE_UNIX_CALL( unix_ios_jit_alias_probe, &pp );
                            if (!pp.base)   /* not an end match — ask about the byte window */
                            {
                                memset( &pp, 0, sizeof(pp) );
                                pp.size = sizeof(pp); pp.version = 1; pp.addr = grip - 32;
                                WINE_UNIX_CALL( unix_ios_jit_alias_probe, &pp );
                            }
                            {
                                /* ml948: THIS DUMP USED TO CRASH THE HANDLER.
                                 *
                                 * It dereferenced (grip - 32) directly. `lim` was clipped only
                                 * when the alias probe returned an `end`, so whenever the probe
                                 * found NOTHING mapped -- exactly the case for a wild
                                 * reconstructed RIP, which is when this telemetry matters most --
                                 * it read 64 bytes from an unmapped address INSIDE exception
                                 * dispatch and faulted recursively.
                                 *
                                 * Measured: a run whose guest RIP became 0x204d5241 then showed
                                 * a native fault at 0x204d5221 = RIP-32, i.e. this loop, and the
                                 * faulting `ldrb w2,[x25],#1` is the byte-formatting read. That
                                 * artefact was mistaken for a guest string parser and cost a
                                 * whole line of investigation. Same recurrence at 0x48d28a41-32.
                                 *
                                 * Copy through NtReadVirtualMemory instead: it returns a status
                                 * and cannot fault us. An alias-probe hit is NOT a lifetime
                                 * guarantee, so the probe's `end` is now only a clip hint, never
                                 * the safety check -- do not go back to query-then-dereference.
                                 * Underflow is handled explicitly. */
                                unsigned lim = 64;
                                unsigned char buf[64];
                                SIZE_T got = 0;
                                NTSTATUS rst;

                                if (pp.end && grip - 32 < pp.end && pp.end - (grip - 32) < 64)
                                    lim = (unsigned)(pp.end - (grip - 32));
                                if (grip < 32)
                                {
                                    ERR( "[guest-bytes] ml948 #%d RIP=0x%I64x < 32 — no window to dump\n",
                                         gb_n, grip );
                                }
                                else if (!NT_SUCCESS( (rst = NtReadVirtualMemory( GetCurrentProcess(),
                                                                (const void *)(ULONG_PTR)(grip - 32),
                                                                buf, lim, &got )) ) || !got)
                                {
                                    ERR( "[guest-bytes] ml948 #%d RIP=0x%I64x window [-32,+%u) UNREADABLE "
                                         "(status %08x, got %u) — dump skipped, handler intact\n",
                                         gb_n, grip, lim, (unsigned int)rst, (unsigned)got );
                                }
                                else
                                {
                                    for (i = 0; i < (unsigned)got; i++)
                                        off += sprintf( line + off, "%02x ", buf[i] );
                                    /* ml637: `lim - 32 - 1` wrapped when lim==32 and printed
                                     * "+4294967295". Print the byte count, not a signed range. */
                                    ERR( "[guest-bytes] ml631 #%d RIP=0x%I64x RX from -32, %u of %u bytes: %s%s\n",
                                         gb_n, grip, (unsigned)got, lim, line,
                                         (unsigned)got < 64 ? "   (short read / clipped)" : "" );
                                }
                            }
                            if (pp.base)
                            {
                                ERR( "[smc-gen] ml636 #%d alias=[0x%I64x,0x%I64x) size=0x%I64x write_gen=%u "
                                     "written16k=%08x highest=0x%I64x RIP_off=0x%I64x %s\n",
                                     gb_n, pp.base, pp.end, pp.end - pp.base, pp.write_gen, pp.written,
                                     pp.highest, grip - pp.base,
                                     pp.at_end ? "<== RIP IS EXACTLY THE ALIAS END (one past)" : "" );
                                /* ml637: `highest` is the highest store START seen (+1), not the
                                 * highest byte written — note_write() only receives the address,
                                 * so a 2/4/8/16/32-byte store understates the extent by up to 31.
                                 * The tail verdict's 256-byte tolerance absorbs that, but do not
                                 * read it as byte-exact. */
                                ERR( "[smc-gen] ml637 #%d NOTE: highest = highest store START +1 "
                                     "(understates by up to 31 bytes; width not plumbed through)\n", gb_n );
                                ERR( "[smc-gen] ml636 #%d TAIL VERDICT: highest written 0x%I64x of 0x%I64x — %s\n",
                                     gb_n, pp.highest, pp.end - pp.base,
                                     !pp.highest ? "**NEVER WRITTEN AT ALL**" :
                                     pp.highest + 256 >= pp.end - pp.base
                                         ? "tail WAS written (reaches the very end)"
                                         : "**TAIL NEVER WRITTEN** — control ran past the real code" );
                                /* iOS-Madeira ml639: WHICH OF THE THREE VIEWS DETACHED?
                                 *
                                 * guest = user_va+off, poolRX = jit_rx_alias+off,
                                 * poolRW = jit_rw_alias+off. All three are the SAME physical
                                 * pages when the dual-map and the vm_remap are both intact.
                                 * Hashing the first 16KB -- the only chunk ever written, and
                                 * where the divergence lives -- localises the break:
                                 *   guest==RX != RW  -> the pool's RX/RW pair detached
                                 *   guest != RX==RW  -> the guest vm_remap detached
                                 *   guest==RW != RX  -> the pool RX mapping alone detached
                                 *   all three differ -> stale slot / multiple remaps
                                 * dup_end also settles the "matched a duplicate entry" theory. */
                                if (pp.rw_base && pp.rx_base)
                                {
                                    const unsigned char *g  = (const unsigned char *)(ULONG_PTR)pp.base;
                                    const unsigned char *px = (const unsigned char *)(ULONG_PTR)pp.rx_base;
                                    const unsigned char *pw = (const unsigned char *)(ULONG_PTR)pp.rw_base;
                                    ULONG64 hg = 1469598103934665603ull, hx = hg, hw = hg;
                                    unsigned k;
                                    for (k = 0; k < 0x4000; k++)
                                    {
                                        hg = (hg ^ g[k])  * 1099511628211ull;
                                        hx = (hx ^ px[k]) * 1099511628211ull;
                                        hw = (hw ^ pw[k]) * 1099511628211ull;
                                    }
                                    ERR( "[3view] ml639 #%d slot=%u dup_end=%u guest=%p poolRX=%p poolRW=%p\n",
                                         gb_n, pp.slot, pp.dup_end, (void *)(ULONG_PTR)pp.base,
                                         (void *)(ULONG_PTR)pp.rx_base, (void *)(ULONG_PTR)pp.rw_base );
                                    ERR( "[3view] ml639 #%d HASH16K guest=%016I64x poolRX=%016I64x poolRW=%016I64x => %s\n",
                                         gb_n, hg, hx, hw,
                                         (hg == hx && hx == hw) ? "ALL THREE AGREE" :
                                         (hg == hx)             ? "guest==poolRX, poolRW DETACHED" :
                                         (hx == hw)             ? "poolRX==poolRW, GUEST vm_remap DETACHED" :
                                         (hg == hw)             ? "guest==poolRW, poolRX DETACHED" :
                                                                  "ALL THREE DIFFER (stale slot / multiple remaps)" );
                                    {
                                        ULONG64 offs[2];
                                        unsigned oi;
                                        offs[0] = 0x1368;                                   /* verified coherent earlier */
                                        offs[1] = pp.highest >= 32 ? pp.highest - 32 : 0;   /* the divergence */
                                        for (oi = 0; oi < 2; oi++)
                                        {
                                            char a[3*32+4], b[3*32+4], c[3*32+4];
                                            unsigned q = 0, r = 0, t = 0;
                                            ULONG64 o = offs[oi];
                                            for (k = 0; k < 32; k++)
                                            {
                                                q += sprintf( a + q, "%02x ", g[o+k] );
                                                r += sprintf( b + r, "%02x ", px[o+k] );
                                                t += sprintf( c + t, "%02x ", pw[o+k] );
                                            }
                                            ERR( "[3view] ml639 #%d @+0x%I64x  guest: %s\n", gb_n, o, a );
                                            ERR( "[3view] ml639 #%d @+0x%I64x poolRX: %s\n", gb_n, o, b );
                                            ERR( "[3view] ml639 #%d @+0x%I64x poolRW: %s\n", gb_n, o, c );
                                        }
                                    }
                                }

                                /* ml637: dump the LAST WRITTEN bytes, not the last bytes of the
                                 * buffer. ml636 printed [end-128,end) — all zeros by definition when
                                 * the tail was never written, which told us nothing. The bytes that
                                 * matter are just below `highest`: in the ml636 run that is
                                 * 0x33e0..0x33fd, i.e. the block FEX started at and the last code
                                 * Mono ever emitted. This is what shows whether that block is a
                                 * complete, correctly terminated sequence. */
                                if (pp.highest >= 128 && pp.rw)
                                {
                                    const unsigned char *wrx = (const unsigned char *)(ULONG_PTR)
                                                               (pp.base + pp.highest - 128);
                                    const unsigned char *wrw = (const unsigned char *)(ULONG_PTR)
                                                               (pp.rw + pp.highest - 128);
                                    char w1[3*128+8], w2[3*128+8];
                                    unsigned k, q1 = 0, q2 = 0, wdiff = 0;
                                    for (k = 0; k < 128; k++)
                                    {
                                        q1 += sprintf( w1 + q1, "%02x ", wrx[k] );
                                        q2 += sprintf( w2 + q2, "%02x ", wrw[k] );
                                        if (wrx[k] != wrw[k]) wdiff = 1;
                                    }
                                    ERR( "[smc-gen] ml637 #%d LASTWRITTEN[0x%I64x-128,0x%I64x) RX: %s\n",
                                         gb_n, pp.highest, pp.highest, w1 );
                                    ERR( "[smc-gen] ml637 #%d LASTWRITTEN RW: %s (%s)\n", gb_n, w2,
                                         wdiff ? "**RX/RW DIFFER**" : "RX/RW match" );
                                }
                                if (pp.end - pp.base >= 128 && pp.rw)
                                {
                                    const unsigned char *trx = (const unsigned char *)(ULONG_PTR)(pp.end - 128);
                                    const unsigned char *trw = (const unsigned char *)(ULONG_PTR)
                                                               (pp.rw + (pp.end - 128 - pp.base));
                                    char t1[3*128+8], t2[3*128+8];
                                    unsigned k, o1 = 0, o2 = 0, diff = 0;
                                    for (k = 0; k < 128; k++)
                                    {
                                        o1 += sprintf( t1 + o1, "%02x ", trx[k] );
                                        o2 += sprintf( t2 + o2, "%02x ", trw[k] );
                                        if (trx[k] != trw[k]) diff = 1;
                                    }
                                    ERR( "[smc-gen] ml636 #%d TAIL RX -128: %s\n", gb_n, t1 );
                                    ERR( "[smc-gen] ml636 #%d TAIL RW -128: %s (%s)\n", gb_n, t2,
                                         diff ? "**RX/RW DIFFER**" : "RX/RW match" );
                                }
                            }
                            /* ml637: SKIP the generic dump at an end match. It compares
                             * pp.rw[0..63] — the START of the RW buffer — against rx[0..63]
                             * where rx = RIP-32, so rx[32..63] lies OUTSIDE the mapping. That
                             * is both a mismatched comparison and a potential fault INSIDE the
                             * exception handler. The tail/last-written dumps above supersede it. */
                            if (pp.at_end)
                                ERR( "[guest-bytes] ml637 #%d generic RX/RW compare SKIPPED (end match — "
                                     "would read past the mapping)\n", gb_n );
                            else if (pp.rw)
                            {
                                const unsigned char *rw = (const unsigned char *)(ULONG_PTR)pp.rw;
                                int differ = 0;
                                off = 0;
                                for (i = 0; i < 64; i++)
                                {
                                    off += sprintf( line + off, "%02x ", rw[i] );
                                    if (rw[i] != rx[i]) differ = 1;
                                }
                                ERR( "[guest-bytes] ml631 #%d rw=0x%I64x alias=[0x%I64x,0x%I64x) RW  -32..+31: %s\n",
                                     gb_n, pp.rw, pp.base, pp.end, line );
                                ERR( "[guest-bytes] ml631 #%d VERDICT: RX and RW %s\n",
                                     gb_n, differ ? "**DIFFER** — alias coherency/finalisation"
                                                  : "MATCH — the guest bytes are what FEX compiled" );
                            }
                            else
                                ERR( "[guest-bytes] ml631 #%d no RW alias for 0x%I64x"
                                     " (not an anon-JIT page)\n", gb_n, grip );
                        }
                    }
                }
            }
            ERR( "[rtcs] pre: code=%08x addr=%p armPc=%p ecRip=%p rtcs=%p insim=%u\n",
                 (unsigned int)rec->ExceptionCode, rec->ExceptionAddress,
                 (void *)(ULONG_PTR)arm_ctx->Pc, (void *)(ULONG_PTR)context->c.AMD64_Context.Rip,
                 pResetToConsistentState, get_arm64ec_cpu_area()->InSimulation );
    }
    if (pResetToConsistentState) pResetToConsistentState( rec, &context->c.AMD64_Context, arm_ctx );
    {
        static LONG rtcs_m;
        if (rtcs_m < 40 && InterlockedIncrement( &rtcs_m ) <= 40)
            ERR( "[rtcs] post: code=%08x addr=%p ecRip=%p ecRsp=%p armPc=%p\n",
                 (unsigned int)rec->ExceptionCode, rec->ExceptionAddress,
                 (void *)(ULONG_PTR)context->c.AMD64_Context.Rip, (void *)(ULONG_PTR)context->c.AMD64_Context.Rsp,
                 (void *)(ULONG_PTR)arm_ctx->Pc );
    }
    if (rec->ExceptionCode != STATUS_EMULATION_SYSCALL)   /* madeira [crashmailer-dump]: the context handlers get */
        ios_cmd_exc_ctx( xr_index, rec, &context->c.AMD64_Context );
    /* call x64 dispatcher if the thunk or the function pointer was modified */
    /* iOS-Madeira ml409 (#66): the fatal [bogus-ctx] walks a context whose Rsp
     * high dword became exactly 1 and whose Rip/Rbp/R12 turned into FEX-band
     * host pointers with recurring low bits, while [rtcs] post had printed the
     * SAME context fields correct moments earlier. The corruption window is
     * prepare-return → call_seh_handlers, which contains exactly two guest
     * re-entry points: the patched-thunk redirect below, and the vectored
     * handlers in dispatch_exception. Bracket it: name the path taken here,
     * and log the context around each guest handler (exception.c [veh],
     * call_seh_handlers [seh-entry]). Capped, AV-only. */
    {
        int patched = memcmp( KiUserExceptionDispatcher_thunk, KiUserExceptionDispatcher_orig,
                              sizeof(KiUserExceptionDispatcher_orig) ) != 0;
        if (rec->ExceptionCode == STATUS_ACCESS_VIOLATION)
        {
            static LONG kipath_n;
            if (kipath_n < 60 && InterlockedIncrement( &kipath_n ) <= 60)
                ERR( "[ki-path] code=%08x ctx=%p Rsp=%p Rip=%p -> %s (patched=%d wow64=%p)\n",
                     (unsigned int)rec->ExceptionCode, context,
                     (void *)(ULONG_PTR)context->c.AMD64_Context.Rsp,
                     (void *)(ULONG_PTR)context->c.AMD64_Context.Rip,
                     (pWow64PrepareForException || patched) ? "x64-THUNK (guest hook runs)" : "direct dispatch",
                     patched, pWow64PrepareForException );
        }
        if (pWow64PrepareForException || patched)
        {
            if (patched) ios_cmd_note_ki( rec, KiUserExceptionDispatcher_thunk );   /* madeira [crashmailer-dump] */
            return KiUserExceptionDispatcher_thunk;
        }
    }
    return NULL;
}

/* madeira-bcd [ki-legacy-frame] (env MADEIRA_KI_LEGACY_FRAME = 0 turns it off).
 *
 * Wine 11.x grew the KiUserExceptionDispatcher frame from ARM64EC_NT_CONTEXT
 * (0x4d0) to struct xcontext (0x670: + CONTEXT_EX + XSTATE), so for x64 code
 * the ARM64 context now sits at rsp+0x670 and the EXCEPTION_RECORD at
 * rsp+0xa20 instead of rsp+0x4d0 / rsp+0x880. Overwatch 2's loader hooks the
 * x64 dispatcher (it sets Wow64PrepareForException and handles its own int3
 * checks there). On bnettest23 (old frame) the hook handled the first int3 and
 * resumed ("[pool-rip-fix] #8 ... invoke_arm64ec_syscall", then "[set-ctx]");
 * on 0.2.47 (new frame) it declines the same int3 at Overwatch_loader+0x871be0,
 * the loader's SEH handler writes a dump and the process ends 0x80000003.
 * So when the x64 hook path is taken, hand x64 code the old frame: move the
 * CONTEXT up by 0x1a0 so it ends right where the ARM64 context starts, and drop
 * CONTEXT_XSTATE from it (its CONTEXT_EX is overwritten). Only the hooked path
 * changes; the native dispatcher keeps the 11.x frame. Returns the shift.
 * The 11.x frame also sets CONTEXT_XSTATE and fills CONTEXT_EX, which is the
 * other suspected cause: MADEIRA_KI_LEGACY_FRAME = 2 keeps the new frame and only
 * drops CONTEXT_XSTATE. */
static LONG ki_legacy_frame_mode;   /* 0 not read yet, 1 off, 2 on (shift + no XSTATE), 3 XSTATE flag only */

static ULONG_PTR __attribute__((used)) ki_legacy_frame_enter( struct xcontext *ctx )
{
    CONTEXT *moved;

    if (!ki_legacy_frame_mode)
    {
        UNICODE_STRING name, value;
        WCHAR buffer[2];

        RtlInitUnicodeString( &name, L"MADEIRA_KI_LEGACY_FRAME" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ki_legacy_frame_mode = 2;
        if (!RtlQueryEnvironmentVariable_U( NULL, &name, &value ) && value.Length == sizeof(WCHAR))
        {
            if (buffer[0] == '0') ki_legacy_frame_mode = 1;
            else if (buffer[0] == '2') ki_legacy_frame_mode = 3;
        }
    }
    if (ki_legacy_frame_mode == 1) return 0;
    if (ki_legacy_frame_mode == 3)
    {
        /* = 2: keep the 11.x frame, only drop CONTEXT_XSTATE (tells the two
         * suspected causes apart). */
        ctx->c.AMD64_Context.ContextFlags &= ~(CONTEXT_AMD64_XSTATE & ~CONTEXT_AMD64);
        return 0;
    }

    moved = (CONTEXT *)((char *)ctx + sizeof(struct xcontext) - sizeof(ARM64EC_NT_CONTEXT));
    memmove( moved, &ctx->c, sizeof(ARM64EC_NT_CONTEXT) );
    moved->ContextFlags &= ~(CONTEXT_AMD64_XSTATE & ~CONTEXT_AMD64);
    {
        static LONG kl_n;
        if (kl_n < 8 && InterlockedIncrement( &kl_n ) <= 8)
            ERR( "[ki-legacy-frame] #%ld x64 hook gets the 0x4d0 frame: ctx %p -> %p rec at %p rev=ki-legacy-frame\n",
                 kl_n, ctx, moved, (char *)moved + sizeof(ARM64EC_NT_CONTEXT) + 0x3b0 );
    }
    return sizeof(struct xcontext) - sizeof(ARM64EC_NT_CONTEXT);
}

/* The x64 hook returned instead of resuming (not expected; Windows gives it no
 * return address). Put the CONTEXT back so the native dispatcher below sees a
 * normal frame; XSTATE stays dropped. */
static void __attribute__((used)) ki_legacy_frame_leave( struct xcontext *ctx )
{
    CONTEXT *moved = (CONTEXT *)((char *)ctx + sizeof(struct xcontext) - sizeof(ARM64EC_NT_CONTEXT));

    memmove( &ctx->c, moved, sizeof(ARM64EC_NT_CONTEXT) );
}

/*******************************************************************
 *		KiUserExceptionDispatcher (NTDLL.@)
 */
void __attribute__((naked)) KiUserExceptionDispatcher( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    asm( ".seh_proc \"#KiUserExceptionDispatcher\"\n\t"
         ".seh_context\n\t"
         "sub sp, sp, #0x670\n\t"       /* sizeof(xcontext) */
         ".seh_stackalloc 0x670\n\t"
         ".seh_endprologue\n\t"
         "add x0, sp, #0x3b0+0x670\n\t" /* rec */
         "mov x1, sp\n\t"               /* context */
         "add x2, sp, #0x670\n\t"       /* arm_ctx (context + 1) */
         "bl \"#prepare_exception_arm64ec\"\n\t"
         "cbz x0, 1f\n\t"
         /* bypass exit thunk to avoid messing up the stack */
         "adrp x16, __os_arm64x_dispatch_call_no_redirect\n\t"
         "ldr x16, [x16, #:lo12:__os_arm64x_dispatch_call_no_redirect]\n\t"
         /* iOS-Madeira (task#29): in a child pseudo-process's private ntdll copy
          * this slot is sometimes still NULL (per-process ntdll global not
          * populated; arm64ec_process_init_dispatchers SKIPs ntdll re-patch).
          * A NULL x16 here → `blr x16` to 0 → SEGV loop → dead thread (observed
          * killing steam.exe). The `blr x16` path is only a stack-cleanliness
          * optimization; label 1 (dispatch_exception) is the full, correct
          * ARM64EC SEH dispatcher. So if the slot is NULL, fall through to it. */
         "cbz x16, 1f\n\t"
         /* madeira-bcd [ki-legacy-frame]: x19/x20 hold the target and the
          * dispatch helper across the C call, x21 the shift (x19-x22 are
          * r12-r15 for x64 code, preserved if it ever returns). This function
          * never returns, so the callee-saved registers are free here. */
         "mov x19, x0\n\t"
         "mov x20, x16\n\t"
         "mov x0, sp\n\t"
         "bl \"#ki_legacy_frame_enter\"\n\t"
         "mov x21, x0\n\t"
         "add sp, sp, x21\n\t"
         "mov x9, x19\n\t"
         "mov x16, x20\n\t"
         "mov x0, x19\n\t"                /* x64 code sees rcx = target, as before */
         "blr x16\n\t"
         "sub sp, sp, x21\n\t"
         "cbz x21, 1f\n\t"
         "mov x0, sp\n\t"
         "bl \"#ki_legacy_frame_leave\"\n"
         "1:\tadd x0, sp, #0x3b0+0x670\n\t" /* rec */
         "mov x1, sp\n\t"                   /* context */
         "bl #dispatch_exception\n\t"
         "brk #1\n\t"
         ".seh_endproc" );
}


/*******************************************************************
 *		KiUserApcDispatcher (NTDLL.@)
 */
static void __attribute__((used)) dispatch_apc( void (CALLBACK *func)(ULONG_PTR,ULONG_PTR,ULONG_PTR,CONTEXT*),
                                                ULONG_PTR arg1, ULONG_PTR arg2, ULONG_PTR arg3,
                                                BOOLEAN alertable, ARM64_NT_CONTEXT *arm_ctx )
{
    struct xcontext context;

    init_xcontext( &context, arm_ctx );
    func( arg1, arg2, arg3, &context.c.AMD64_Context );
    NtContinue( &context.c.AMD64_Context, alertable );
}
__ASM_GLOBAL_FUNC( "#KiUserApcDispatcher",
                   ".seh_context\n\t"
                   "nop\n\t"
                   ".seh_stackalloc 0x30\n\t"
                   ".seh_endprologue\n\t"
                   "ldp x0, x1, [sp]\n\t"         /* func, arg1 */
                   "ldp x2, x3, [sp, #0x10]\n\t"  /* arg2, arg3 */
                   "ldr w4, [sp, #0x20]\n\t"      /* alertable */
                   "add x5, sp, #0x30\n\t"        /* context */
                   "bl \"#dispatch_apc\"\n\t"
                   "brk #1" )


/*******************************************************************
 *		KiUserCallbackDispatcher (NTDLL.@)
 */
__ASM_GLOBAL_FUNC( "#KiUserCallbackDispatcher",
                   ".seh_pushframe\n\t"
                   "nop\n\t"
                   ".seh_stackalloc 0x20\n\t"
                   "nop\n\t"
                   ".seh_save_reg lr, 0x18\n\t"
                   ".seh_endprologue\n\t"
                   ".seh_handler user_callback_handler, @except\n\t"
                   "ldr x0, [sp]\n\t"             /* args */
                   "ldp w1, w2, [sp, #0x08]\n\t"  /* len, id */
                   "ldr x3, [x18, 0x60]\n\t"      /* peb */
                   "ldr x3, [x3, 0x58]\n\t"       /* peb->KernelCallbackTable */
                   "ldr x15, [x3, x2, lsl #3]\n\t"
                   "blr x15\n\t"
                   ".globl \"#KiUserCallbackDispatcherReturn\"\n"
                   "\"#KiUserCallbackDispatcherReturn\":\n\t"
                   "mov x2, x0\n\t"               /* status */
                   "mov x1, #0\n\t"               /* ret_len */
                   "mov x0, x1\n\t"               /* ret_ptr */
                   "bl \"#NtCallbackReturn\"\n\t"
                   "bl \"#RtlRaiseStatus\"\n\t"
                   "brk #1" )


/**************************************************************************
 *              RtlIsEcCode (NTDLL.@)
 */
/* iOS-Madeira: highest address the EcCodeBitMap can actually represent.
 *
 * The 0x800000000000 (48-bit) bound below was WRONG for this port. alloc_arm64ec_map()
 * sizes the bitmap from min(address_space_limit, host_addr_space_limit) rather than
 * Windows' theoretical 128TB, because at one bit per 4KB page the full range costs a
 * 4.06GB reservation — the single largest tenant of a VA window we cannot spare. On
 * iOS that yields 0x8000000000 (512GB) of coverage, i.e. a 16MB view.
 *
 * That sizing was justified with "every other bitmap user derives its index from the
 * ADDRESS being marked, so none can index past the smaller view". RtlIsEcCode breaks
 * the assumption: it is a READER, and it is handed addresses that never came from our
 * allocator — guest/unwind contexts carry legal *Windows* pointers far above our VA.
 * Steam hit exactly that: RtlIsEcCode(0x7300ffffffff) passed the 128TB check, indexed
 * 0x74d6ddfff8 (past the 16MB view) and segfaulted, killing the thread 5 times per
 * spawn and looping ~9 times (ml161).
 *
 * Derive the bound from the view's ACTUAL size so it can never disagree with the
 * allocation, whatever the ceiling does later. Wine answers this query from its own
 * view list, so RegionSize is the exact view size (no host adjacent-region merging).
 * Coverage = bytes * 8 bits * page_size. */
static ULONG_PTR ec_code_map_limit( void )
{
    static ULONG_PTR cached;   /* benign race: all racers compute the same value */

    if (!cached)
    {
        MEMORY_BASIC_INFORMATION mbi;
        const char *map = NtCurrentTeb()->Peb->EcCodeBitMap;
        ULONG_PTR limit = 0x800000000000ULL;
        SIZE_T total = 0, len = 0;
        const char *p = map;
        unsigned int guard;

        /* Walk the WHOLE allocation. A single MemoryBasicInformation query returns only
           the first run of uniform protection, and this view is a patchwork: pages that
           get marked are committed RW by set_vprot while the rest stay RO. ml163 measured
           RegionSize = 0x24000 (144KB) for a view that [ec-map] reports as 0x1000000
           (16MB) — a 116x under-estimate that failed the self-check below. Accumulate
           every sub-region sharing our AllocationBase to recover the true size. */
        for (guard = 0; map && guard < 4096; guard++)
        {
            if (NtQueryVirtualMemory( NtCurrentProcess(), p, MemoryBasicInformation,
                                      &mbi, sizeof(mbi), &len )) break;
            if (len < sizeof(mbi) || !mbi.RegionSize) break;
            if (mbi.AllocationBase != (void *)map) break;
            total += mbi.RegionSize;
            p += mbi.RegionSize;
        }

        if (total)
        {
            ULONG_PTR cover = (ULONG_PTR)total * 8 * page_size;

            /* SELF-CHECK before trusting the query. Reporting a genuinely-EC address as
               non-EC is far worse than the OOB read this bound exists to prevent: the
               caller would dispatch EC code through the x64 path and jump wild (the
               "BUS EXEC in JIT .data" signature). This very function is EC code, so a
               correct limit must cover it. If the query says otherwise, distrust it and
               keep the old 48-bit bound rather than break dispatch.

               Two floors, because &RtlIsEcCode resolves to the JIT-POOL copy (~0x1xxxxxxxx)
               and would be satisfied by a coverage still far too small for the PE module
               range (~0x73xxxxxxxx). The bitmap is itself allocated in that high region,
               so a correct coverage must also exceed its own address. */
            if (cover > (ULONG_PTR)&RtlIsEcCode && cover > (ULONG_PTR)map && cover < limit)
                limit = cover;
            else if (cover)
                ERR( "EcCodeBitMap coverage %p too small (own code %p, map %p) — keeping %p\n",
                     (void *)cover, (void *)&RtlIsEcCode, map, (void *)limit );
        }
        TRACE( "EcCodeBitMap map=%p limit=%p\n", map, (void *)limit );
        cached = limit;
    }
    return cached;
}

/* madeira [isec-bound] (env MADEIRA_EC_ISEC_BOUND = 0 turns it off). rev=isec-bound-1.
 *
 * Credit: BOR1NG (Avery Felts, https://github.com/aaf2tbz), MetalSharp-Wine 554d343543 (0135) "ntdll: Bound
 * RtlIsEcCode to the user address space, and end a frame walk at a return address that isn't user code"
 * (LGPL-2.1, https://github.com/metalsharp/MetalSharp-Wine). Overwatch's stack walk reached a frame whose
 * return address was data (0x80e300a70070) and faulted inside ntdll, again and again. As on Windows, an
 * address past the user address space is no EC code, and RtlWalkFrameChain() ends the walk at a return
 * address that can't be user code instead of recording it and unwinding past it.
 * Ours keeps Madeira's own bound (ec_code_map_limit(), the bitmap's real coverage, which already rejects
 * Overwatch's address) and adds his on top; the frame-walk stop is the part that is new here. */
static LONG ios_isec_mode;   /* 0 not read, 1 off, 2 on */

static BOOL ios_isec_bound(void)
{
    if (!ios_isec_mode)
    {
        UNICODE_STRING var, value;
        WCHAR buffer[2];
        PEB *peb = NtCurrentTeb()->Peb;
        WCHAR *env;

        /* no environment yet (not expected): answer with the default, read it on a later call */
        if (!peb->FastPebLock && !peb->ProcessParameters) return TRUE;
        /* as in ios_xstate_revert(): before loader_init() FastPebLock is NULL, so read the block itself */
        env = peb->FastPebLock ? NULL : peb->ProcessParameters->Environment;
        RtlInitUnicodeString( &var, L"MADEIRA_EC_ISEC_BOUND" );
        value.Buffer = buffer;
        value.Length = 0;
        value.MaximumLength = sizeof(buffer);
        ios_isec_mode = (!RtlQueryEnvironmentVariable_U( env, &var, &value ) &&
                         value.Length == sizeof(WCHAR) && buffer[0] == '0') ? 1 : 2;
        ERR( "[isec-bound] rev=isec-bound-1 %s\n", ios_isec_mode == 2 ? "on" : "off (MADEIRA_EC_ISEC_BOUND=0)" );
    }
    return ios_isec_mode == 2;
}

/* [isec-bound]: the highest address of the user address space of a 64-bit process on x64 Windows.
 * Ours: a constant, not SystemBasicInformation as in his patch. Madeira's HighestUserAddress
 * is a REPORT that can sit far below where code really lives (env.MADEIRA_USER_VA_GB = n tells a
 * process n GiB while its PE images are at 0x71..-0x73..), so bounding by it would call real EC
 * code "not EC" and end every frame walk at its first frame. Nothing on iOS can be mapped this
 * high, so the constant drops no real frame; it also takes no syscall on the first RtlIsEcCode call. */
static inline ULONG_PTR ios_highest_user_address(void)
{
    return 0x7ffffffeffff;
}

BOOLEAN WINAPI RtlIsEcCode( ULONG_PTR ptr )
{
    const UINT64 *map = (const UINT64 *)NtCurrentTeb()->Peb->EcCodeBitMap;
    ULONG_PTR page = ptr / page_size;
    /* The EcCodeBitMap covers only what alloc_arm64ec_map actually reserved. Querying
       any pointer beyond that — a legal Windows address above our VA, or a corrupted
       one from a damaged unwind context — must not segfault. */
    if (!map || ptr >= ec_code_map_limit()) return FALSE;
    /* madeira [isec-bound] Credit: BOR1NG (Avery Felts, https://github.com/aaf2tbz), MetalSharp-Wine 554d343543
     * (LGPL-2.1): an address past the user address space is no EC code, as on Windows */
    if (ptr > ios_highest_user_address() && ios_isec_bound()) return FALSE;
    return (map[page / 64] >> (page & 63)) & 1;
}


/* unwind context by one call frame */
/* iOS-Madeira ml703: returns whether a real function entry was found and used.
 *
 * Unwind info is registered for PE VAs, but code physically executes from the
 * JIT-pool alias, so context->Rip is a POOL VA here.  RtlLookupFunctionEntry
 * then finds nothing, RtlVirtualUnwind treats the frame as a leaf, pops a zero
 * return address off the stack and yields Rip=0 -- which do_setjmpex used to
 * copy over a perfectly good jump buffer (LibreMines/Qt5: libjpeg's longjmp
 * error path unwound to RIP 0 and the guest branched to address zero).
 * virtual_unwind() already reverse-translates for exactly this reason; mirror
 * it.  xlate_ios_jit_rev() resolves by REGISTERED ALIAS IDENTITY and returns
 * its input unchanged when there is no PE counterpart, so addresses that were
 * never pool-mapped are unaffected -- it is not guessing from address ranges. */
static BOOL unwind_one_frame( CONTEXT *context )
{
    extern void *xlate_ios_jit_rev( void *ptr );
    void *data;
    ULONG_PTR base, frame, pc = context->Rip - 4;
    ULONG_PTR lookup_pc = (ULONG_PTR)xlate_ios_jit_rev( (void *)pc );
    RUNTIME_FUNCTION *func = RtlLookupFunctionEntry( lookup_pc, &base, NULL );

    LONG internal;

    if (!func) return FALSE;
    internal = ios_cmd_internal_enter();   /* madeira [crashmailer-dump]: ntdll's own unwind */
    RtlVirtualUnwind( UNW_FLAG_NHANDLER, base, lookup_pc, func, context, &data, &frame, NULL );
    ios_cmd_internal_leave( internal );
    return TRUE;
}

static void __attribute__((used)) unwind_entry_thunk( CONTEXT *context )
{
    CONTEXT unwind_context = *context;
    unwind_one_frame( &unwind_context );
    /* if the caller is emulated, we're in an entry thunk, so use the caller's context instead */
    if (!RtlIsEcCode( unwind_context.Rip ))
        memcpy( &context->Rax, &unwind_context.Rax, offsetof(CONTEXT,FltSave) - offsetof(CONTEXT,Rax) );
}

/* capture context information; helper for RtlCaptureContext */
static void __attribute__((used)) capture_context( CONTEXT *context, UINT cpsr, UINT fpcr, UINT fpsr )
{
    context->ContextFlags = CONTEXT_AMD64_FULL;
    context->EFlags = cpsr_to_eflags( cpsr );
    context->MxCsr = fpcsr_to_mxcsr( fpcr, fpsr );
    context->FltSave.ControlWord = 0x27f;
    context->FltSave.StatusWord = 0;
    context->FltSave.MxCsr = context->MxCsr;
    unwind_entry_thunk( context );
}

/***********************************************************************
 *		RtlCaptureContext (NTDLL.@)
 */
void __attribute__((naked)) RtlCaptureContext( CONTEXT *context )
{
    asm( ".seh_proc \"#RtlCaptureContext\"\n\t"
         ".seh_endprologue\n\t"
         "stp x8, x0,   [x0, #0x78]\n\t"    /* context->Rax,Rcx */
         "stp x1, x27,  [x0, #0x88]\n\t"    /* context->Rdx,Rbx */
         "mov x1, sp\n\t"
         "stp x1, x29,  [x0, #0x98]\n\t"    /* context->Rsp,Rbp */
         "stp x25, x26, [x0, #0xa8]\n\t"    /* context->Rsi,Rdi */
         "stp x2, x3,   [x0, #0xb8]\n\t"    /* context->R8,R9 */
         "stp x4, x5,   [x0, #0xc8]\n\t"    /* context->R10,R11 */
         "stp x19, x20, [x0, #0xd8]\n\t"    /* context->R12,R13 */
         "stp x21, x22, [x0, #0xe8]\n\t"    /* context->R14,R15 */
         "str x30,      [x0, #0xf8]\n\t"    /* context->Rip */
         "ubfx x1, x16, #0, #16\n\t"
         "stp x30, x1,  [x0, #0x120]\n\t"   /* context->FloatRegisters[0] */
         "ubfx x1, x16, #16, #16\n\t"
         "stp x6, x1,   [x0, #0x130]\n\t"   /* context->FloatRegisters[1] */
         "ubfx x1, x16, #32, #16\n\t"
         "stp x7, x1,   [x0, #0x140]\n\t"   /* context->FloatRegisters[2] */
         "ubfx x1, x16, #48, #16\n\t"
         "stp x9, x1,   [x0, #0x150]\n\t"   /* context->FloatRegisters[3] */
         "ubfx x1, x17, #0, #16\n\t"
         "stp x10, x1,  [x0, #0x160]\n\t"   /* context->FloatRegisters[4] */
         "ubfx x1, x17, #16, #16\n\t"
         "stp x11, x1,  [x0, #0x170]\n\t"   /* context->FloatRegisters[5] */
         "ubfx x1, x17, #32, #16\n\t"
         "stp x12, x1,  [x0, #0x180]\n\t"   /* context->FloatRegisters[6] */
         "ubfx x1, x17, #48, #16\n\t"
         "stp x15, x1,  [x0, #0x190]\n\t"   /* context->FloatRegisters[7] */
         "stp q0, q1,   [x0, #0x1a0]\n\t"   /* context->Xmm0,Xmm1 */
         "stp q2, q3,   [x0, #0x1c0]\n\t"   /* context->Xmm2,Xmm3 */
         "stp q4, q5,   [x0, #0x1e0]\n\t"   /* context->Xmm4,Xmm5 */
         "stp q6, q7,   [x0, #0x200]\n\t"   /* context->Xmm6,Xmm7 */
         "stp q8, q9,   [x0, #0x220]\n\t"   /* context->Xmm8,Xmm9 */
         "stp q10, q11, [x0, #0x240]\n\t"   /* context->Xmm10,Xmm11 */
         "stp q12, q13, [x0, #0x260]\n\t"   /* context->Xmm12,Xmm13 */
         "stp q14, q15, [x0, #0x280]\n\t"   /* context->Xmm14,Xmm15 */
         "mrs x1, nzcv\n\t"
         "mrs x2, fpcr\n\t"
         "mrs x3, fpsr\n\t"
         "b \"#capture_context\"\n\t"
         ".seh_endproc" );
}

/* fixup jump buffer information; helper for _setjmpex */
static int __attribute__((used)) do_setjmpex( _JUMP_BUFFER *buf, UINT fpcr, UINT fpsr )
{
    CONTEXT context = { .ContextFlags = CONTEXT_AMD64_FULL };

    buf->MxCsr = fpcsr_to_mxcsr( fpcr, fpsr );
    buf->FpCsr = 0x27f;

    context.Rbx = buf->Rbx;
    context.Rsp = buf->Rsp;
    context.Rbp = buf->Rbp;
    context.Rsi = buf->Rsi;
    context.Rdi = buf->Rdi;
    context.R12 = buf->R12;
    context.R13 = buf->R13;
    context.R14 = buf->R14;
    context.R15 = buf->R15;
    context.Rip = buf->Rip;
    memcpy( &context.Xmm6, &buf->Xmm6, 10 * sizeof(context.Xmm6) );

    /* ml703: the copy-back below replaces the registers NTDLL__setjmpex just
     * stored with the unwound caller's.  That is only correct when the unwind
     * ACTUALLY SUCCEEDED and landed on x64 code.  A failed unwind yields
     * Rip=0, which RtlIsEcCode() reports as "not EC" -- i.e. it used to be
     * misread as "the caller is x64", zeroing a valid buffer.  Require all
     * three: the lookup found a function entry, the result is plausible, and
     * it really is x64 code. */
    {
        BOOL unwound = unwind_one_frame( &context );
        static int n_sj;

        if (n_sj < 24)   /* [setjmp-life] ml702 probe, retained */
        {
            n_sj++;
            ERR( "[setjmp-life] ml702 setjmp#%d buf=%p | STORED Frame=%p Rip=%p Rsp=%p Rbx=%p"
                 " | UNWOUND ok=%d Rip=%p Rsp=%p | isEc(post)=%d -> %s\n",
                 n_sj, buf, (void *)buf->Frame, (void *)buf->Rip, (void *)buf->Rsp, (void *)buf->Rbx,
                 unwound, (void *)context.Rip, (void *)context.Rsp,
                 (int)RtlIsEcCode( context.Rip ),
                 (unwound && context.Rip && !RtlIsEcCode( context.Rip ))
                     ? "COPY-BACK (real x64 caller)" : "KEEP stores" );
        }

        if (unwound && context.Rip && !RtlIsEcCode( context.Rip ))
    {
        buf->Rbx = context.Rbx;
        buf->Rsp = context.Rsp;
        buf->Rbp = context.Rbp;
        buf->Rsi = context.Rsi;
        buf->Rdi = context.Rdi;
        buf->R12 = context.R12;
        buf->R13 = context.R13;
        buf->R14 = context.R14;
        buf->R15 = context.R15;
        buf->Rip = context.Rip;
        memcpy( &buf->Xmm6, &context.Xmm6, 10 * sizeof(context.Xmm6) );
        }
    }
    {
        static int n_out;
        if (n_out < 24)
        {
            n_out++;
            ERR( "[setjmp-life] ml702 setjmp-exit#%d buf=%p FINAL Frame=%p Rip=%p Rsp=%p Rbx=%p\n",
                 n_out, buf, (void *)buf->Frame, (void *)buf->Rip, (void *)buf->Rsp, (void *)buf->Rbx );
        }
    }
    return 0;
}

/***********************************************************************
 *		_setjmpex (NTDLL.@)
 */
int __attribute__((naked)) NTDLL__setjmpex( _JUMP_BUFFER *buf, void *frame )
{
    asm( ".seh_proc \"#NTDLL__setjmpex\"\n\t"
         ".seh_endprologue\n\t"
         "stp x1, x27,  [x0]\n\t"          /* jmp_buf->Frame,Rbx */
         "mov x1, sp\n\t"
         "stp x1, x29,  [x0, #0x10]\n\t"   /* jmp_buf->Rsp,Rbp */
         "stp x25, x26, [x0, #0x20]\n\t"   /* jmp_buf->Rsi,Rdi */
         "stp x19, x20, [x0, #0x30]\n\t"   /* jmp_buf->R12,R13 */
         "stp x21, x22, [x0, #0x40]\n\t"   /* jmp_buf->R14,R15 */
         "str x30,      [x0, #0x50]\n\t"   /* jmp_buf->Rip */
         "stp d8, d9,   [x0, #0x80]\n\t"   /* jmp_buf->Xmm8,Xmm9 */
         "stp d10, d11, [x0, #0xa0]\n\t"   /* jmp_buf->Xmm10,Xmm11 */
         "stp d12, d13, [x0, #0xc0]\n\t"   /* jmp_buf->Xmm12,Xmm13 */
         "stp d14, d15, [x0, #0xe0]\n\t"   /* jmp_buf->Xmm14,Xmm15 */
         "mrs x1, fpcr\n\t"
         "mrs x2, fpsr\n\t"
         "b \"#do_setjmpex\"\n\t"
         ".seh_endproc" );
}


/**********************************************************************
 *           call_consolidate_callback
 *
 * Wrapper function to call a consolidate callback from a fake frame.
 * If the callback executes RtlUnwindEx (like for example done in C++ handlers),
 * we have to skip all frames which were already processed. To do that we
 * trick the unwinding functions into thinking the call came from somewhere
 * else.
 */
static void __attribute__((naked,noreturn)) consolidate_callback( CONTEXT *context,
                                                                  void *(CALLBACK *callback)(EXCEPTION_RECORD *),
                                                                  EXCEPTION_RECORD *rec )
{
    asm( ".seh_proc consolidate_callback\n\t"
         "stp x29, x30, [sp, #-16]!\n\t"
         ".seh_save_fplr_x 16\n\t"
         "sub sp, sp, #0x4d0\n\t"
         ".seh_stackalloc 0x4d0\n\t"
         ".seh_endprologue\n\t"
         "mov x4, sp\n\t"
         /* copy the context onto the stack */
         "mov x5, #0x4d0/16\n"      /* sizeof(CONTEXT) */
         "1:\tldp x6, x7, [x0], #16\n\t"
         "stp x6, x7, [x4], #16\n\t"
         "subs x5, x5, #1\n\t"
         "b.ne 1b\n\t"
         "ldr w5, [sp, #0x30]\n\t"  /* ContextFlags */
         "and w5, w5, #~0x40\n\t"
         "str w5, [sp, #0x30]\n\t"
         "mov x0, x2\n\t"           /* rec */
         "b invoke_callback\n\t"
         ".seh_endproc\n\t"
         ".seh_proc invoke_callback\n"
         "invoke_callback:\n\t"
         ".seh_ec_context\n\t"
         ".seh_endprologue\n\t"
         "mov x11, x1\n\t"          /* callback */
         "adr x10, $iexit_thunk$cdecl$i8$i8\n\t"
         "adrp x16, __os_arm64x_dispatch_icall\n\t"
         "ldr x16, [x16, #:lo12:__os_arm64x_dispatch_icall]\n\t"
         "blr x16\n\t"
         "blr x11\n\t"
         "str x0, [sp, #0xf8]\n\t"  /* context->Rip */
         "mov x0, sp\n\t"           /* context */
         "mov w1, #0\n\t"
         "bl \"#NtContinue\"\n\t"
         ".seh_endproc" );
}


/*******************************************************************
 *              RtlRestoreContext (NTDLL.@)
 */
void CDECL RtlRestoreContext( CONTEXT *context, EXCEPTION_RECORD *rec )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;

    if (rec && rec->ExceptionCode == STATUS_LONGJUMP && rec->NumberParameters >= 1)
    {
        struct _JUMP_BUFFER *jmp = (struct _JUMP_BUFFER *)rec->ExceptionInformation[0];

        context->Rbx   = jmp->Rbx;
        context->Rsp   = jmp->Rsp;
        context->Rbp   = jmp->Rbp;
        context->Rsi   = jmp->Rsi;
        context->Rdi   = jmp->Rdi;
        context->R12   = jmp->R12;
        context->R13   = jmp->R13;
        context->R14   = jmp->R14;
        context->R15   = jmp->R15;
        context->Rip   = jmp->Rip;
        context->MxCsr = jmp->MxCsr;
        context->FltSave.MxCsr = jmp->MxCsr;
        context->FltSave.ControlWord = jmp->FpCsr;
        memcpy( &context->Xmm6, &jmp->Xmm6, 10 * sizeof(M128A) );
    }
    else if (rec && rec->ExceptionCode == STATUS_UNWIND_CONSOLIDATE && rec->NumberParameters >= 1)
    {
        void * (CALLBACK *consolidate)(EXCEPTION_RECORD *) = (void *)rec->ExceptionInformation[0];
        TRACE( "calling consolidate callback %p (rec=%p)\n", consolidate, rec );
        consolidate_callback( context, consolidate, rec );
    }

    /* hack: remove no longer accessible TEB frames */
    while (is_valid_frame( (ULONG_PTR)teb_frame ) && (ULONG64)teb_frame < context->Rsp)
    {
        TRACE( "removing TEB frame: %p\n", teb_frame );
        teb_frame = __wine_pop_frame( teb_frame );
    }

    TRACE( "returning to %p stack %p\n", (void *)context->Rip, (void *)context->Rsp );
    NtContinue( context, FALSE );
}


/* iOS-Madeira ml846 [tlswatch]: arm the unix-side write watch from PE code.
 * The engine's thread-naming exception is dispatched entirely PE-side, so the
 * unix NtRaiseException hook never saw it (ml845: zero arm lines). The one
 * channel from here into the unix fault handler that needs no new syscall is
 * NtProtectVirtualMemory itself: a size no real caller could pass marks the
 * request, and the unix side arms the watch on the block instead of
 * protecting anything. Idle unless the slot is still zero. */
static void ios_tlswatch_pe_arm( const char *where )
{
    static LONG lines;
    void **blocks = NtCurrentTeb()->ThreadLocalStoragePointer;
    void *addr; SIZE_T size = 0x0BAD0038; ULONG old = 0; ULONG_PTR now; NTSTATUS st;
    if (!blocks || !blocks[0]) return;
    now = ((ULONG_PTR *)blocks[0])[7];
    if (now)
    {
        /* ml847: say so. ml846 returned silently here, which made "the write
         * came earlier" indistinguishable from "the mark never arrived". */
        if (InterlockedIncrement( &lines ) <= 24)
            ERR( "[tlswatch-pe] ml847 %s: slot ALREADY SET (%p) tid=%04x -- the write precedes this point\n",
                 where, (void *)now, (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
        return;
    }
    addr = blocks[0];
    st = NtProtectVirtualMemory( GetCurrentProcess(), &addr, &size, PAGE_READONLY, &old );
    if (InterlockedIncrement( &lines ) <= 24)
        ERR( "[tlswatch-pe] ml847 %s: slot=0, sent mark for block %p -> status %08x tid=%04x\n",
             where, blocks[0], (int)st, (unsigned)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread );
}

/*******************************************************************
 *		RtlUnwindEx (NTDLL.@)
 */
void WINAPI RtlUnwindEx( PVOID end_frame, PVOID target_ip, EXCEPTION_RECORD *rec,
                         PVOID retval, CONTEXT *context, UNWIND_HISTORY_TABLE *table )
{
    EXCEPTION_REGISTRATION_RECORD *teb_frame = NtCurrentTeb()->Tib.ExceptionList;
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 nonvol_regs;
    EXCEPTION_RECORD record;
    DISPATCHER_CONTEXT_ARM64EC dispatch;
    ARM64EC_NT_CONTEXT new_context;
    NTSTATUS status;
    ULONG_PTR frame;
    DWORD i, res;
    BOOL is_target_ec = RtlIsEcCode( (ULONG_PTR)target_ip );
    int cmd_tok;          /* madeira [crashmailer-dump] */
    LONG cmd_internal;

    RtlCaptureContext( context );
    cmd_tok = ios_cmd_unwind_pre( 2, 0, (ULONG_PTR)target_ip, context );
    cmd_internal = ios_cmd_internal_enter();
    new_context.AMD64_Context = *context;
    if (rec && rec->ExceptionCode == 0x406D1388) ios_tlswatch_pe_arm( "RtlUnwindEx entry" );

    /* build an exception record, if we do not have one */
    if (!rec)
    {
        record.ExceptionCode    = STATUS_UNWIND;
        record.ExceptionFlags   = 0;
        record.ExceptionRecord  = NULL;
        record.ExceptionAddress = (void *)context->Rip;
        record.NumberParameters = 0;
        rec = &record;
    }

    rec->ExceptionFlags |= EXCEPTION_UNWINDING | (end_frame ? 0 : EXCEPTION_EXIT_UNWIND);

    /* iOS-Madeira 2026-07-04: [UNW_RATE] — [SEH_RATE] in call_seh_handlers
     * stayed at zero while PROF shows the render worker living in
     * virtual_unwind/RtlVirtualUnwind2, so THIS entry point (phase-2
     * unwind without dispatch = longjmp / handled unwinds) must be the
     * hot caller. code=STATUS_UNWIND (0xC0000027) with a synthesized
     * record means a NULL-rec caller — longjmp's signature. Log first +
     * every 1024th: rate, code, source Rip, target. */
    {
        static LONG unw_count;
        LONG n = InterlockedIncrement( &unw_count );
        if (n == 1 || (n & 0x3FF) == 0)
            ERR( "[UNW_RATE] n=%d code=%08x from=%p target=%p\n",
                 (int)n, (int)rec->ExceptionCode, rec->ExceptionAddress, target_ip );
    }

    TRACE( "code=%lx flags=%lx end_frame=%p target_ip=%p\n",
           rec->ExceptionCode, rec->ExceptionFlags, end_frame, target_ip );
    for (i = 0; i < min( EXCEPTION_MAXIMUM_PARAMETERS, rec->NumberParameters ); i++)
        TRACE( " info[%ld]=%016I64x\n", i, rec->ExceptionInformation[i] );
    TRACE_CONTEXT( context );

    dispatch.TargetIp         = (ULONG64)target_ip;
    dispatch.ContextRecord    = context;
    dispatch.HistoryTable     = table;
    dispatch.NonVolatileRegisters = nonvol_regs.Buffer;

    /* ml617: establish the guest-stack window from the ORIGINAL RSP before the
     * first step, so every frame below is bounded by the allocation the thread
     * was actually running on. */
    ec_stack_window_begin( (ULONG_PTR)context->Rsp );

    for (;;)
    {
        status = virtual_unwind( UNW_FLAG_UHANDLER, &dispatch, &new_context );
        if (status != STATUS_SUCCESS) raise_status( status, rec );

    unwind_done:
        if (!dispatch.EstablisherFrame) break;

        {
            if (rec && rec->ExceptionCode == 0x406D1388) ios_tlswatch_pe_arm( "RtlUnwindEx step" );
            const char *why = ec_stack_window_step( dispatch.EstablisherFrame,
                                                    (ULONG_PTR)dispatch.ControlPc );
            if (why)
            {
                /* ⛔ Do NOT synthesize a replacement exception. ml616 lost the real
                 * fault (execute AV at private RW heap) and reported a stack
                 * fragment as the status. Report everything needed to trust this
                 * rejection, then stop unwinding and let the ORIGINAL record go. */
                ERR( "[unwind-guard] ml617 STOPPING unwind: %s | orig_code=%08x orig_addr=%p "
                     "orig_rsp=%I64x stack=[%I64x..%I64x) emu=[%I64x..%I64x] "
                     "rejected_frame=%I64x prev_frame=%I64x ControlPc=%I64x steps=%u budget=%u\n",
                     why, (int)rec->ExceptionCode, rec->ExceptionAddress,
                     (ULONG64)context->Rsp, (ULONG64)ec_win.lo, (ULONG64)ec_win.hi,
                     (ULONG64)ec_win.emu_lo, (ULONG64)ec_win.emu_hi,
                     (ULONG64)dispatch.EstablisherFrame, (ULONG64)ec_win.last_frame,
                     (ULONG64)dispatch.ControlPc, ec_win.steps, ec_win.budget );
                rec->ExceptionFlags |= EXCEPTION_STACK_INVALID;
                break;
            }
        }

        if (!is_valid_arm64ec_frame( dispatch.EstablisherFrame ))
        {
            /* ml221: report WHY the walk produced this frame, not just that it did.
             *
             * The frame that killed the webhelper was 0x73c9f70008 -- 8 bytes into
             * DWrite.dll's read-only headers, i.e. the walk had run off the end of the
             * guest stack. That happens when ControlPc stays a JIT-pool VA: function
             * tables are registered at PE VAs, so no unwind info is found and the frames
             * are garbage. virtual_unwind reverse-translates via
             * p_ios_jit_reverse_translate_addr, but that pointer lives in ntdll's .data
             * and every pseudo-process gets a CLONED copy -- if a child's copy is NULL the
             * translation silently degrades to identity. Print it, plus ControlPc, so the
             * two cases are distinguishable instead of guessed at. */
            ERR( "invalid frame %I64x (%p-%p) ControlPc=%I64x xlate_rev=%p%s\n",
                 dispatch.EstablisherFrame,
                 NtCurrentTeb()->Tib.StackLimit, NtCurrentTeb()->Tib.StackBase,
                 (ULONG64)dispatch.ControlPc, p_ios_jit_reverse_translate_addr,
                 p_ios_jit_reverse_translate_addr ? "" : "  <-- NULL: unwind ran in POOL space" );
            rec->ExceptionFlags |= EXCEPTION_STACK_INVALID;
            break;
        }

        if (dispatch.LanguageHandler)
        {
            if (end_frame && (dispatch.EstablisherFrame > (ULONG64)end_frame))
            {
                ERR( "invalid end frame %I64x/%p\n", dispatch.EstablisherFrame, end_frame );
                raise_status( STATUS_INVALID_UNWIND_TARGET, rec );
            }
            if (dispatch.EstablisherFrame == (ULONG64)end_frame) rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;

            TRACE( "calling handler %p (rec=%p, frame=%I64x context=%p, dispatch=%p)\n",
                   dispatch.LanguageHandler, rec, dispatch.EstablisherFrame,
                   dispatch.ContextRecord, &dispatch );
            res = call_unwind_handler( rec, dispatch.EstablisherFrame, dispatch.ContextRecord,
                                       &dispatch, dispatch.LanguageHandler );
            TRACE( "handler %p returned %lx\n", dispatch.LanguageHandler, res );

            switch (res)
            {
            case ExceptionContinueSearch:
                rec->ExceptionFlags &= ~EXCEPTION_COLLIDED_UNWIND;
                break;
            case ExceptionCollidedUnwind:
                new_context.AMD64_Context = *context;
                RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase, dispatch.ControlPc,
                                  dispatch.FunctionEntry, &new_context.AMD64_Context,
                                  &dispatch.HandlerData, &frame, NULL );
                rec->ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
                goto unwind_done;
            default:
                raise_status( STATUS_INVALID_DISPOSITION, rec );
                break;
            }
        }
        else  /* hack: call builtin handlers registered in the tib list */
        {
            while (is_valid_arm64ec_frame( (ULONG_PTR)teb_frame ) &&
                   (ULONG64)teb_frame < new_context.Sp &&
                   (ULONG64)teb_frame < (ULONG64)end_frame)
            {
                TRACE( "calling TEB handler %p (rec=%p, frame=%p context=%p, dispatch=%p)\n",
                       teb_frame->Handler, rec, teb_frame, dispatch.ContextRecord, &dispatch );
                res = call_unwind_handler( rec, (ULONG_PTR)teb_frame, dispatch.ContextRecord, &dispatch,
                                           (PEXCEPTION_ROUTINE)teb_frame->Handler );
                TRACE( "handler at %p returned %lu\n", teb_frame->Handler, res );
                teb_frame = __wine_pop_frame( teb_frame );

                switch (res)
                {
                case ExceptionContinueSearch:
                    rec->ExceptionFlags &= ~EXCEPTION_COLLIDED_UNWIND;
                    break;
                case ExceptionCollidedUnwind:
                    new_context.AMD64_Context = *context;
                    RtlVirtualUnwind( UNW_FLAG_NHANDLER, dispatch.ImageBase, dispatch.ControlPc,
                                      dispatch.FunctionEntry, &new_context.AMD64_Context,
                                      &dispatch.HandlerData, &frame, NULL );
                    rec->ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
                    goto unwind_done;
                default:
                    raise_status( STATUS_INVALID_DISPOSITION, rec );
                    break;
                }
            }
            if ((ULONG64)teb_frame == (ULONG64)end_frame && (ULONG64)end_frame < new_context.Sp) break;
        }

        if (dispatch.EstablisherFrame == (ULONG64)end_frame)
        {
            if (is_target_ec) break;
            if (!RtlIsEcCode( dispatch.ControlPc )) break;
            /* we just crossed into x64 code, unwind one more frame */
        }
        *context = new_context.AMD64_Context;
    }

    if (rec->ExceptionCode != STATUS_UNWIND_CONSOLIDATE)
        context->Rip = (ULONG64)target_ip;
    else if (rec->ExceptionInformation[10] == -1)
        rec->ExceptionInformation[10] = (ULONG_PTR)&nonvol_regs;

    if (is_target_ec) context->Rcx = (ULONG64)retval;
    else context->Rax = (ULONG64)retval;
    ios_cmd_internal_leave( cmd_internal );   /* madeira [crashmailer-dump] */
    ios_cmd_unwind_post( cmd_tok, context, 0, NULL, (ULONG_PTR)target_ip, (ULONG_PTR)end_frame );
    RtlRestoreContext( context, rec );
}


/*************************************************************************
 *		RtlGetNativeSystemInformation (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetNativeSystemInformation( SYSTEM_INFORMATION_CLASS class,
                                               void *info, ULONG size, ULONG *ret_size )
{
    NTSTATUS status = syscall_NtQuerySystemInformation( class, info, size, ret_size );

    /* madeira [cpu-x64-identity] (see ios_x64_identity): GetNativeSystemInfo says AMD64, as on Windows on ARM */
    if (!status && class == SystemCpuInformation && pUpdateProcessorInformation && ios_x64_identity())
        pUpdateProcessorInformation( info );
    return status;
}


/***********************************************************************
 *           RtlIsProcessorFeaturePresent [NTDLL.@]
 */
BOOLEAN WINAPI RtlIsProcessorFeaturePresent( UINT feature )
{
    static const ULONGLONG arm64_features =
        (1ull << PF_COMPARE_EXCHANGE_DOUBLE) |
        (1ull << PF_NX_ENABLED) |
        (1ull << PF_ARM_VFP_32_REGISTERS_AVAILABLE) |
        (1ull << PF_ARM_NEON_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_SECOND_LEVEL_ADDRESS_TRANSLATION) |
        (1ull << PF_FASTFAIL_AVAILABLE) |
        (1ull << PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE) |
        (1ull << PF_ARM_64BIT_LOADSTORE_ATOMIC) |
        (1ull << PF_ARM_EXTERNAL_CACHE_AVAILABLE) |
        (1ull << PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V8_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE2_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE2_1_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_PMULL128_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_BITPERM_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_BF16_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_EBF16_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_B16B16_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_SHA3_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_SM4_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_I8MM_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_F32MM_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_SVE_F64MM_INSTRUCTIONS_AVAILABLE) |
        (1ull << PF_ARM_LSE2_AVAILABLE);

    if (feature >= PROCESSOR_FEATURE_MAX) return FALSE;
    if (arm64_features & (1ull << feature)) return user_shared_data->ProcessorFeatures[feature];
    return emulated_processor_features[feature];
}


/**********************************************************************
 *              RtlGetEnabledExtendedFeatures   (NTDLL.@)
 */
ULONG64 WINAPI RtlGetEnabledExtendedFeatures( ULONG64 feature_mask )
{
    if (!emulated_processor_features[PF_AVX_INSTRUCTIONS_AVAILABLE]) return 0;
    return user_shared_data->XState.EnabledFeatures & feature_mask;
}


/*************************************************************************
 *		RtlWalkFrameChain (NTDLL.@)
 */
ULONG WINAPI RtlWalkFrameChain( void **buffer, ULONG count, ULONG flags )
{
    UNWIND_HISTORY_TABLE table;
    RUNTIME_FUNCTION *func;
    PEXCEPTION_ROUTINE handler;
    ULONG_PTR pc, frame, base;
    CONTEXT context;
    void *data;
    ULONG i, skip = flags >> 8, num_entries = 0;
    LONG internal = ios_cmd_internal_enter();   /* madeira [crashmailer-dump]: ntdll's own unwind */

    RtlCaptureContext( &context );

    for (i = 0; i < count; i++)
    {
        pc = context.Rip;
        if ((context.ContextFlags & CONTEXT_UNWOUND_TO_CALL) && RtlIsEcCode( pc )) pc -= 4;
        func = RtlLookupFunctionEntry( pc, &base, &table );
        if (RtlVirtualUnwind2( UNW_FLAG_NHANDLER, base, pc, func, &context, NULL,
                               &data, &frame, NULL, NULL, NULL, &handler, 0 ))
            break;
        if (!context.Rip) break;
        /* madeira [isec-bound] Credit: BOR1NG (Avery Felts, https://github.com/aaf2tbz), MetalSharp-Wine
         * 554d343543 (LGPL-2.1): a return address that can't be user code ends the walk, as on Windows:
         * past it the frames are data */
        if ((context.Rip < 0x10000 || context.Rip > ios_highest_user_address()) && ios_isec_bound()) break;
        if (!frame || !is_valid_frame( frame )) break;
        if (context.Rsp == (ULONG_PTR)NtCurrentTeb()->Tib.StackBase) break;
        if (i >= skip) buffer[num_entries++] = (void *)context.Rip;
    }
    ios_cmd_internal_leave( internal );
    return num_entries;
}


/*************************************************************************
 *		__wine_unix_call_arm64ec
 */
NTSTATUS __attribute__((naked)) __wine_unix_call_arm64ec( unixlib_handle_t handle, unsigned int code, void *args )
{
    asm( ".seh_proc \"#__wine_unix_call_arm64ec\"\n\t"
         ".seh_endprologue\n\t"
         "adrp x16, __wine_unix_call_dispatcher_arm64ec\n\t"
         "ldr x16, [x16, #:lo12:__wine_unix_call_dispatcher_arm64ec]\n\t"
         "br x16\n\t"
         ".seh_endproc" );
}

NTSTATUS (WINAPI *__wine_unix_call_dispatcher_arm64ec)( unixlib_handle_t, unsigned int, void * ) = __wine_unix_call_arm64ec;

static void __attribute__((naked)) arm64x_check_call_early(void)
{
    asm( "mov x11, x9\n\t"
         "ret" );
}

static void __attribute__((naked)) arm64x_check_icall_early(void)
{
    asm( "ret" );
}

/**************************************************************************
 *		arm64x_check_call
 *
 * Implementation of __os_arm64x_check_call.
 */
static void __attribute__((naked)) arm64x_check_call(void)
{
    asm( ".seh_proc \"#arm64x_check_call\"\n\t"
         ".seh_endprologue\n\t"
         /* check for EC code */
         /* iOS-Madeira ml238 ROOT-CAUSE FIX: read the TEB from TPIDRRO_EL0 + TSD slot 275,
          * NOT from x18. iOS clobbers x18 (every SEGV dump in this port shows x18=0), so
          * `ldr x16,[x18,#0x60]` fetched a garbage PEB, the EcCodeBitMap pointer was
          * garbage, the bit test read 0, and this function reported EVERY target as
          * non-EC. __os_arm64x_check_icall then selected the EC->x64 exit thunk even for
          * genuinely native targets -- while RtlIsEcCode (C, via NtCurrentTeb()'s TSD
          * path) correctly said EC, which is exactly the contradiction we measured:
          * IsEcCode(fp)=1 yet the exit thunk still ran.
          *
          * For variadic callees that thunk does `stp x4,x5,[sp,#0x20]`, flattening the
          * ARM64EC variadic descriptor (x4 = stack-arg pointer, x5 = size) into the x64
          * arg5/arg6 slots -- producing ROpenSCManagerW's dwDesiredAccess = a pointer and
          * lpScHandle = 0x10 (the SIZE), i.e. the ccontext == 0x10 livelock.
          *
          * FEX's own check_target_ec already does this (IOS_LOAD_TEB); Wine's copy never
          * did. x16 is scratch here, so the load is free of side effects. */
         /* iOS-Madeira ml246: this x18 read IS WRONG, and is deliberately kept anyway.
          *
          * iOS clobbers x18 (every SEGV dump in this port shows x18=0), so this fetches a
          * garbage PEB, the EcCodeBitMap pointer is garbage, the bit test reads 0, and this
          * function reports EVERY target as non-EC. FEX's check_target_ec reads the TEB via
          * TPIDRRO_EL0 + TSD slot 275 (IOS_LOAD_TEB) for exactly this reason.
          *
          * Correcting it (mrs TPIDRRO_EL0 / and #~7 / ldr [#0x898] / ldr [#0x60]) was tried
          * and A/B-PROVEN to break CEF: cef_log.txt went unwritten for 8 consecutive runs
          * and returned the moment this line was restored (ml246, run depth also 20-24k ->
          * 28929 calls). Reporting everything non-EC forces all indirect calls through the
          * x64 exit thunk, which is slow and breaks VARIADIC callees (the ccontext == 0x10
          * RPC crash) -- but that detour also absorbs whatever EcCodeBitMap false positive
          * the correct version turns into a direct branch into x64 bytes executed as ARM64.
          *
          * So: correct-but-unlandable until that false positive is found. The fixed version
          * is preserved in the task notes. Do not "fix" this without re-running the CEF
          * check -- verifying IsEcCode flips 0->1 does NOT prove the outcome still works. */
         /* iOS-Madeira ml975: BOUNDS-CHECK THE TARGET BEFORE INDEXING THE BITMAP.
          *
          * RtlIsEcCode (the C reader, same file) already does this, and its comment
          * records why: alloc_arm64ec_map() sizes EcCodeBitMap from
          * min(address_space_limit, host_addr_space_limit) rather than Windows'
          * 128TB, because one bit per 4KB page over the full range would cost a
          * 4.06GB reservation. On iOS that yields 0x8000000000 (512GB) of coverage
          * in a 16MB view. Steam hit the unchecked case in ml161:
          * RtlIsEcCode(0x7300ffffffff) indexed 0x74d6ddfff8, past the view, and
          * segfaulted. This asm fast path never received the same guard.
          *
          * rdr38/rdr39 is the same failure from a different caller: the guest made
          * an indirect call to a garbage target (x11 = 0xc0be0f4800b60f00, eight
          * bytes that disassemble as x86 -- read out of an instruction stream), the
          * `ldr x16,[x16,x17,lsl #3]` below indexed 0x1817c1e900168 past the bitmap
          * base and faulted at 0x1818775d80168. x18, the PEB and the bitmap pointer
          * were all VALID; only the target was bad.
          *
          * iOS user VA is 39-bit (512GB), which is also exactly the bitmap's
          * coverage, so one shift tests both: any bit at or above 2^39 means the
          * address can be neither legitimate code nor representable in the map.
          * Branch to .Lexit -- the "not EC code, use the x64 exit thunk" path, which
          * is the same answer RtlIsEcCode gives for an out-of-range pointer, and the
          * only exit that does NOT dereference x11 (both .Ljmp and the
          * fast-forward/syscall checks load from [x11], so they would fault too).
          * The guest's bad call then faults in the guest, attributed to the guest,
          * instead of killing a thread inside ntdll.
          *
          * Deliberately does NOT touch the `ldr x16,[x18,#0x60]` line below: ml246
          * A/B-proved over 8 runs that "correcting" that read breaks CEF. This only
          * changes addresses that currently crash, and it moves them in the same
          * direction ml246 documents as safe (more targets taking the exit thunk).
          *
          * Not covered, deliberately, to keep the scope to the observed fault: a
          * NULL or small-but-invalid target still reaches `ldr x16,[x11]` below and
          * faults there, which is what Windows would also do. */
         "lsr x16, x11, #39\n\t"            /* ml975: beyond 39-bit VA / map coverage? */
         "cbnz x16, .Lexit\n\t"             /*        -> not EC code, exit thunk */
         "ldr x16, [x18, #0x60]\n\t"        /* peb -- see above, intentionally x18 */
         "lsr x17, x11, #18\n\t"            /* dest / page_size / 64 */
         "ldr x16, [x16, #0x368]\n\t"       /* peb->EcCodeBitMap */
         "lsr x9, x11, #12\n\t"             /* dest / page_size */
         "ldr x16, [x16, x17, lsl #3]\n\t"
         "lsr x16, x16, x9\n\t"
         "tbnz x16, #0, .Ldone\n\t"
         /* check if dest is aligned */
         "tst x11, #15\n\t"                 /* dest & 15 */
         "b.ne .Ljmp\n\t"
         "madeira_ccall_peek_begin:\n\t"   /* [ccall-peek]: loads from [x11] start here */
         "ldr x16, [x11]\n\t"               /* dest code */
         /* check for fast-forward sequence */
         "ldr x17, .Lffwd_seq\n\t"
         "cmp x16, x17\n\t"
         "b.ne .Lhotpatch\n\t"
         "ldr x16, [x11, #8]\n\t"
         "ldr x17, .Lffwd_seq + 8\n\t"
         "eor x17, x16, x17\n\t"            /* compare only first two bytes */
         "tst x17, #0xffff\n\t"
         "b.ne .Lexit\n\t"
         "add x11, x11, #14\n\t"            /* address after jump */
         "lsr x9, x16, #16\n\t"
         "add x11, x11, w9, sxtw\n\t"       /* add offset */
         "ret\n"
         /* Madeira [hotpatch-thunks]: hotpatch prologue (lea 0x0(%rsp),%rsp) that the loader puts
          * before x64 export thunks when env MADEIRA_ARM64X_HOTPATCH_THUNKS = 1; step over it to
          * the jmp, only when an ff 25 jmp follows (idea: DroidDeck-Proton 269ca79) */
         ".Lhotpatch:\n\t"
         "ldr x17, .Lhotpatch_seq\n\t"
         "cmp x16, x17\n\t"
         "b.ne .Lsyscall\n\t"
         "ldrh w17, [x11, #8]\n\t"
         "mov w9, #0x25ff\n\t"             /* ff 25 */
         "cmp w17, w9\n\t"
         "b.ne .Lsyscall\n\t"
         "add x11, x11, #8\n\t"
         "b .Ljmp\n"
         /* check for syscall sequence */
         ".Lsyscall:\n\t"
         "ldr w17, .Lsyscall_seq\n\t"
         "cmp w16, w17\n\t"
         "b.ne .Ljmp\n\t"
         "ubfx x9, x16, #32, #12\n\t"       /* syscall number */
         "ldr x16, [x11, #8]\n\t"
         "ldr x17, .Lsyscall_seq + 8\n\t"
         "cmp x16, x17\n\t"
         "b.ne .Lexit\n\t"
         "ldr x16, [x11, #16]\n\t"
         "ldr x17, .Lsyscall_seq + 16\n\t"
         "cmp x16, x17\n\t"
         "b.ne .Lexit\n\t"
         "cmp x9, #%0\n\t"
         "b.hs .Lexit\n\t"
         "adr x11, arm64ec_syscalls\n\t"
         "ldr x11, [x11, x9, lsl #3]\n\t"
         "ret\n"
         /* check for jmp sequence */
         ".Ljmp:\n\t"
         "ldrb w16, [x11]\n\t"
         "cmp w16, #0xff\n\t"
         "b.ne .Lexit\n\t"
         "ldrb w16, [x11, #1]\n\t"
         "cmp w16, #0x25\n\t"               /* ff 25 jmp *xxx(%rip) */
         "b.ne .Lexit\n\t"
         "ldr w9, [x11, #2]\n\t"
         "add x16, x11, #6\n\t"             /* address after jump */
         "ldr x11, [x16, w9, sxtw]\n\t"
         "b \"#arm64x_check_call\"\n"       /* restart checks with jump destination */
         /* not a special sequence, call the exit thunk */
         "madeira_ccall_peek_exit:\n\t"    /* [ccall-peek]: a faulting peek resumes here */
         ".Lexit:\n\t"
         "mov x9, x11\n\t"
         "mov x11, x10\n\t"
         ".Ldone:\n\t"
         "ret\n"
         ".seh_endproc\n\t"

         ".balign 8\n"                      /* keep the 8-byte literals aligned */
         ".Lhotpatch_seq:\n\t"
         ".byte 0x48, 0x8d, 0xa4, 0x24, 0, 0, 0, 0\n"  /* lea 0x0(%rsp),%rsp */
         ".Lffwd_seq:\n\t"
         ".byte 0x48, 0x8b, 0xc4\n\t"       /* mov  %rsp,%rax */
         ".byte 0x48, 0x89, 0x58, 0x20\n\t" /* mov  %rbx,0x20(%rax) */
         ".byte 0x55\n"                     /* push %rbp */
         ".byte 0x5d\n\t"                   /* pop  %rbp */
         ".byte 0xe9\n\t"                   /* jmp  arm_code */
         ".byte 0, 0, 0, 0, 0, 0\n"

         ".Lsyscall_seq:\n\t"
         ".byte 0x4c, 0x8b, 0xd1\n\t"       /* mov  %rcx,%r10 */
         ".byte 0xb8, 0, 0, 0, 0\n\t"       /* mov  $xxx,%eax */
         ".byte 0xf6, 0x04, 0x25, 0x08\n\t" /* testb $0x1,0x7ffe0308 */
         ".byte 0x03, 0xfe, 0x7f, 0x01\n\t"
         ".byte 0x75, 0x03\n\t"             /* jne 1f */
         ".byte 0x0f, 0x05\n\t"             /* syscall */
         ".byte 0xc3\n\t"                   /* ret */
         ".byte 0xcd, 0x2e\n\t"             /* 1: int $0x2e */
         ".byte 0xc3"                       /* ret */
         :: "i" (__nb_syscalls) );
}


/**************************************************************************
 *		__chkstk_arm64ec (NTDLL.@)
 *
 * Supposed to touch all the stack pages, but we shouldn't need that.
 */
void __attribute__((naked)) __chkstk_arm64ec(void)
{
    asm( "ret" );
}


/*******************************************************************
 *		__C_ExecuteExceptionFilter
 */
LONG __attribute__((naked)) __C_ExecuteExceptionFilter( EXCEPTION_POINTERS *ptrs, void *frame,
                                                        PEXCEPTION_FILTER filter, BYTE *nonvolatile )
{
    asm( ".seh_proc _C_ExecuteExceptionFilter\n\t"
         "stp x29, x30, [sp, #-80]!\n\t"
         ".seh_save_fplr_x 80\n\t"
         "stp x19, x20, [sp, #16]\n\t"
         ".seh_save_regp x19, 16\n\t"
         "stp x21, x22, [sp, #32]\n\t"
         ".seh_save_regp x21, 32\n\t"
         "stp x25, x26, [sp, #48]\n\t"
         ".seh_save_regp x25, 48\n\t"
         "str x27, [sp, #64]\n\t"
         ".seh_save_reg x27, 64\n\t"
         ".seh_endprologue\n\t"
         "ldp x19, x20, [x3, #0]\n\t" /* nonvolatile regs */
         "ldp x21, x22, [x3, #16]\n\t"
         "ldp x25, x26, [x3, #48]\n\t"
         "ldr x27, [x3, #64]\n\t"
         "ldr x1,  [x3, #80]\n\t"     /* x29 = frame */
         "blr x2\n\t"                 /* filter */
         "ldp x19, x20, [sp, #16]\n\t"
         "ldp x21, x22, [sp, #32]\n\t"
         "ldp x25, x26, [sp, #48]\n\t"
         "ldr x27,      [sp, #64]\n\t"
         "ldp x29, x30, [sp], #80\n\t"
         "ret\n\t"
         ".seh_endproc" );
}


/***********************************************************************
 *		RtlRaiseException (NTDLL.@)
 */
void __attribute((naked)) RtlRaiseException( EXCEPTION_RECORD *rec )
{
    asm( ".seh_proc \"#RtlRaiseException\"\n\t"
         "sub sp, sp, #0x4d0\n\t"     /* sizeof(context) */
         ".seh_stackalloc 0x4d0\n\t"
         "stp x29, x30, [sp, #-0x20]!\n\t"
         ".seh_save_fplr_x 0x20\n\t"
         "str x0, [sp, #0x10]\n\t"
         ".seh_save_any_reg x0, 0x10\n\t"
         ".seh_endprologue\n\t"
         "add x0, sp, #0x20\n\t"
         "bl \"#RtlCaptureContext\"\n\t"
         "add x0, sp, #0x20\n\t"       /* context pointer */
         "add x1, x0, #0x4d0\n\t"      /* orig stack pointer */
         "str x1, [x0, #0x98]\n\t"     /* context->Rsp */
         "ldr x1, [sp, #0x10]\n\t"     /* rec */
         "str x1, [x0, #0x80]\n\t"     /* context->Rcx */
         "ldr x1, [sp, #0x08]\n\t"     /* return address */
         "str x1, [x0, #0xf8]\n\t"     /* context->Rip */
         "ldr w1, [x0, #0x30]\n\t"     /* context->ContextFlags */
         "orr w1, w1, #0x20000000\n\t" /* CONTEXT_UNWOUND_TO_CALL */
         "str w1, [x0, #0x30]\n\t"
         "bl \"#unwind_entry_thunk\"\n\t"
         "ldr x0, [sp, #0x10]\n\t"     /* rec */
         "add x1, sp, #0x20\n\t"       /* context pointer */
         "ldr x2, [x1, #0xf8]\n\t"     /* ctx->Rip */
         "str x2, [x0, #0x10]\n\t"     /* rec->ExceptionAddress */
         "bl \"#ios_xp_raise\"\n\t"   /* madeira [crashmailer-exit-probe]: log only */
         "ldr x0, [sp, #0x10]\n\t"     /* rec */
         "add x1, sp, #0x20\n\t"       /* context pointer */
         "ldr x3, [x18, #0x60]\n\t"    /* peb */
         "ldrb w2, [x3, #2]\n\t"       /* peb->BeingDebugged */
         "cbnz w2, 1f\n\t"
         "bl \"#dispatch_exception\"\n"
         "1:\tmov w2, #1\n\t"
         "bl \"#NtRaiseException\"\n\t"
         "b \"#RtlRaiseStatus\"\n\t" /* does not return */
         ".seh_endproc" );
}


/*******************************************************************
 *		longjmp (NTDLL.@)
 */
void __cdecl NTDLL_longjmp( _JUMP_BUFFER *buf, int retval )
{
    EXCEPTION_RECORD rec;

    if (!retval) retval = 1;

    {   /* ml702 [setjmp-life]: what the buffer holds at the moment of use.  If
         * this is zero the unwind target is zero and the guest branches to 0. */
        static int n_lj;
        if (n_lj < 24)
        {
            n_lj++;
            ERR( "[setjmp-life] ml702 longjmp#%d buf=%p retval=%d Frame=%p Rip=%p Rsp=%p Rbx=%p Rsi=%p Rdi=%p\n",
                 n_lj, buf, retval, (void *)buf->Frame, (void *)buf->Rip, (void *)buf->Rsp,
                 (void *)buf->Rbx, (void *)buf->Rsi, (void *)buf->Rdi );
        }
    }

    rec.ExceptionCode = STATUS_LONGJUMP;
    rec.ExceptionFlags = 0;
    rec.ExceptionRecord = NULL;
    rec.ExceptionAddress = NULL;
    rec.NumberParameters = 1;
    rec.ExceptionInformation[0] = (DWORD_PTR)buf;
    RtlUnwind( (void *)buf->Frame, (void *)buf->Rip, &rec, IntToPtr(retval) );
}


/***********************************************************************
 *           RtlUserThreadStart (NTDLL.@)
 */
void __attribute__((naked)) RtlUserThreadStart( PRTL_THREAD_START_ROUTINE entry, void *arg )
{
    asm( ".seh_proc \"#RtlUserThreadStart\"\n\t"
         "stp x29, x30, [sp, #-16]!\n\t"
         ".seh_save_fplr_x 16\n\t"
         ".seh_endprologue\n\t"
         "adrp x11, pBaseThreadInitThunk\n\t"
         "ldr x11, [x11, #:lo12:pBaseThreadInitThunk]\n\t"
         "adr x10, $iexit_thunk$cdecl$v$i8i8i8\n\t"
         "mov x2, x1\n\t"
         "mov x1, x0\n\t"
         "mov x0, #0\n\t"
         "adrp x16, __os_arm64x_dispatch_icall\n\t"
         "ldr x16, [x16, #:lo12:__os_arm64x_dispatch_icall]\n\t"
         "blr x16\n\t"
         "blr x11\n\t"
         "brk #1\n\t"
         ".seh_handler call_unhandled_exception_handler, @except\n\t"
         ".seh_endproc" );
}


/******************************************************************
 *		LdrInitializeThunk (NTDLL.@)
 */
void WINAPI LdrInitializeThunk( CONTEXT *arm_context, ULONG_PTR unk2, ULONG_PTR unk3, ULONG_PTR unk4 )
{
    struct xcontext context;

    if (!__os_arm64x_check_call)
    {
        __os_arm64x_check_call = arm64x_check_call_early;
        __os_arm64x_check_icall = arm64x_check_icall_early;
        __os_arm64x_check_icall_cfg = arm64x_check_icall_early;
        __os_arm64x_get_x64_information = LdrpGetX64Information;
        __os_arm64x_set_x64_information = LdrpSetX64Information;
    }

    init_xcontext( &context, (ARM64_NT_CONTEXT *)arm_context );
    ios_cmd_read_switch();   /* madeira [crashmailer-dump]: first thread, before loader_init() */
    loader_init( &context.c.AMD64_Context, (void **)&context.c.X0 );
    TRACE_(relay)( "\1Starting thread proc %p (arg=%p)\n", (void *)context.c.X0, (void *)context.c.X1 );
    NtContinue( &context.c.AMD64_Context, TRUE );
}


/***********************************************************************
 *           process_breakpoint
 */
__ASM_GLOBAL_FUNC( "#process_breakpoint",
                   ".seh_endprologue\n\t"
                   ".seh_handler process_breakpoint_handler, @except\n\t"
                   "brk #0xf000\n\t"
                   "ret\n"
                   "process_breakpoint_handler:\n\t"
                   "ldr x4, [x2, #0xf8]\n\t"  /* context->Rip */
                   "add x4, x4, #4\n\t"
                   "str x4, [x2, #0xf8]\n\t"
                   "mov w0, #0\n\t"           /* ExceptionContinueExecution */
                   "ret" )


/***********************************************************************
 *		DbgUiRemoteBreakin   (NTDLL.@)
 */
void __attribute__((naked)) DbgUiRemoteBreakin( void *arg )
{
    asm( ".seh_proc \"#DbgUiRemoteBreakin\"\n\t"
         "stp x29, x30, [sp, #-16]!\n\t"
         ".seh_save_fplr_x 16\n\t"
         ".seh_endprologue\n\t"
         ".seh_handler DbgUiRemoteBreakin_handler, @except\n\t"
         "ldr x0, [x18, #0x60]\n\t"  /* NtCurrentTeb()->Peb */
         "ldrb w0, [x0, 0x02]\n\t"   /* peb->BeingDebugged */
         "cbz w0, 1f\n\t"
         "bl \"#DbgBreakPoint\"\n"
         "1:\tmov w0, #0\n\t"
         "bl \"#RtlExitUserThread\"\n"
         "DbgUiRemoteBreakin_handler:\n\t"
         "mov sp, x1\n\t"            /* frame */
         "b 1b\n\t"
         ".seh_endproc" );
}


/**********************************************************************
 *              DbgBreakPoint   (NTDLL.@)
 */
void __attribute__((naked)) DbgBreakPoint(void)
{
    asm( ".seh_proc \"#DbgBreakPoint\"\n\t"
         ".seh_endprologue\n\t"
         "brk #0xf000\n\t"
         "ret\n\t"
         ".seh_endproc" );
}


/**********************************************************************
 *              DbgUserBreakPoint   (NTDLL.@)
 */
void __attribute__((naked)) DbgUserBreakPoint(void)
{
    asm( ".seh_proc \"#DbgUserBreakPoint\"\n\t"
         ".seh_endprologue\n\t"
         "brk #0xf000\n\t"
         "ret\n\t"
         ".seh_endproc" );
}

#endif  /* __arm64ec__ */
