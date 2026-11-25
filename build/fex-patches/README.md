# Madeira's FEX patches

Changes to FEX that Madeira needs and that live in this repository, not in
the FEX submodule's repository. `apply.sh` applies them, in file-name order,
to the FEX working tree before `build/fex-arm64ec/build.sh` and
`build/fex-wow64/build.sh` build `xtajit64.dll` and `xtajit.dll`; it skips a
patch that is already applied, and `apply.sh --revert` takes them out. The
FEX submodule pin does not change.

These patches are for Madeira only and are not to be sent to FEX-Emu.

| Patch | What it fixes |
|---|---|
| `0001-windows-ios-smc-traps-per-16k-host-page.patch` | Self-modifying-code write traps per 16 KB iOS host page, both modules (The Escapists 2, Project Zomboid) |
| `0002-windows-skip-own-memory-notifications-during-invalidation.patch` | FEX's own frees during a code invalidation no longer re-enter the invalidation and deadlock on CodeBufferListLock, both modules (.NET games: Stardew Valley, Slay the Spire 2) |
| `0003-windows-skip-own-code-flushes-under-the-invalidation-lock.patch` | FEX's own code flushes while it holds the code invalidation lock no longer wait for ThreadCreationMutex, which deadlocked against a write fault on another thread, ARM64EC module (PvZ Fusion with MelonLoader: black screen) |

A patch must apply on the current FEX pin. When the pin moves, rebase the
patches onto it (or drop a patch the new pin already covers).
| `0005-windows-ios-section-views.patch` | Overwatch 2: several views of one file mapping are tracked so a write through one view invalidates translated code in the others, and the changed-code block sits right after the current block (`MADEIRA_EC_SECTION_VIEWS=0` off). Contains code from MetalSharp (AGPL-3.0); see THIRD-PARTY-NOTICES.md |
| `0006-windows-ios-fo4-alias-miss-probe.patch` | Fallout 4: log only. Names why an image was never pushed to the alias table (`MADEIRA_ALIAS_PUSH_PROBE=0` off) |
| `0016-fexcore-crashmailer-dump.patch` | Overwatch 2, log only: when the game starts CrashMailer, dumps the program state, stack, exception history and the last blocks it ran (the block history is on for Overwatch.exe only). `MADEIRA_EC_CRASHMAILER_DUMP=0` off; `MADEIRA_BLOCK_RING=0` turns only the block history off. |
| `0017-fexcore-kuser-rebase.patch` | Reads of the shared system data page (KUSER_SHARED_DATA) are rebased when the code is compiled instead of failing each time. After BOR1NG's MetalSharp FEX patch 0001 (MIT). `MADEIRA_FEX_KUSER_REBASE=0` off. |
| `0018-fexcore-cpu-identity.patch` | CPU brand text shows a speed ("@ x.xxGHz") and the CPU reports its own details. After BOR1NG's MetalSharp FEX patch 0028 (MIT). `MADEIRA_CPU_IDENTITY=0` off; `MADEIRA_FEX_CPUID_FREQ=1` turns the speed leaf on. |
| `0019-fexcore-code-buffer-big.patch` | Overwatch 2, opt-in: `MADEIRA_FEX_CODE_BUFFER_MB=256` lets one ARM64EC FEX code buffer grow past 128 MB from the JIT-pool region (needs the matching change in build/ntdll-unix/virtual_ios.c). Idea after BOR1NG's MetalSharp FEX patch 0045 (MIT). |
| `0020-fexcore-multiblock-fault-rip.patch` | Overwatch 2: when a fault happens inside a multiblock translation, the guest RIP reported is the right one. `MADEIRA_FEX_MB_FAULT_RIP=0` off. |
| `0021-fexcore-cpu-identity-2.patch` | Overwatch 2: the CPU count the emulator reports matches Wine and the registry (leaf 0xB, hyper-threading, APIC id size); x64 identity (Intel Core i3-N305, AMD64) where programs read it. `MADEIRA_CPU_IDENTITY=0` off; parts `MADEIRA_CPU_IDENTITY_BRAND`, `MADEIRA_FEX_CPU_COUNT`, `MADEIRA_CPU_X64_IDENTITY` = 0; opt-in `MADEIRA_CPU_X64_NATIVE=1`. |
| `0022-fexcore-getctx-guest.patch` | Overwatch 2: reading another thread's context while it runs emulated code returns its x64 state. `MADEIRA_GETCTX_GUEST=0` off (and `MADEIRA_CTX_FRAME=0` for the system-call-frame part). |
| `0023-fexcore-crashmailer-exit-probe-2.patch` | Overwatch 2, log only: a 65536-block history for Overwatch.exe, logged at process end, at the known crash addresses and at the first unrecoverable raise. `MADEIRA_EC_EXIT_PROBE=0` off. |
| `0024-fexcore-pfaf-int3-2.patch` | Overwatch 2: the alignment flag reaches the handler for int3, invalid-instruction and single-step traps. `MADEIRA_EC_PFAF_INT3=0` off. |
| `0025-stellar-blade-slot-trace.patch` | Fork diagnostic, ARM64EC module: with `MADEIRA_BLOCK_RING=1` and `MADEIRA_SB_SLOT_TRACE=1`, adds the slot address and incoming pointer of each call to Stellar Blade's ref-pointer setter (`0x140f8cda0`) to the block ring (was 0005 before the 0.2.100 port) |
| `0026-stellar-blade-slot-select.patch` | Fork diagnostic, ARM64EC module: with `MADEIRA_SB_SLOT_TRACE=1`, the block ring keeps only the setter and the uniform-buffer commit blocks (`0x142e3ebd0`, `0x142e3ecd9`, `0x142e6be00`), so it holds a long slot history (was 0006) |

In this fork FEX is an ordinary folder, not a submodule, so `apply.sh` applies the patches from
the repository root with `--directory=FEX` (inside a subfolder, `git apply` skips any patch with
`diff --git` headers without saying so). 0001-0024 are already applied in the FEX folder, as in the
nightly's release copy; 0025 and 0026 are applied at build time.
