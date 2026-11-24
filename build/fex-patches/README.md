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
| `0004-windows-ios-mono-miss-store-outside-the-invalidation-lock.patch` | A Mono backpatch store that misses the RW alias is done outside the code invalidation lock, which deadlocked against ThreadCreationMutex (64-bit Unity games stuck loading) |
| `0005-stellar-blade-slot-trace.patch` | Diagnostic, ARM64EC module: with `MADEIRA_BLOCK_RING=1` and `MADEIRA_SB_SLOT_TRACE=1`, adds the slot address and incoming pointer of each call to Stellar Blade's ref-pointer setter (`0x140f8cda0`) to the block ring |
| `0006-stellar-blade-slot-select.patch` | Diagnostic, ARM64EC module: with `MADEIRA_SB_SLOT_TRACE=1`, the block ring keeps only the setter and the uniform-buffer commit blocks (`0x142e3ebd0`, `0x142e3ecd9`, `0x142e6be00`), so it holds a long slot history |

A patch must apply on the current FEX pin. When the pin moves, rebase the
patches onto it (or drop a patch the new pin already covers).
