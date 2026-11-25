# Madeira test build notes

This branch (`nightly-0.2.100`) is Madeira Nightly 0.2.100 og (build 178, Nov 24; see
`FORK-SOURCE-INFO.txt` for the build, branch and commits) with one outside patch and this fork's
fixes added, built on GitHub's own macOS runners. It was ported from `main` (Madeira Nightly 0.2.29
plus the same patches); see "Port to 0.2.100" below for what moved, changed or was dropped. Madeira is GPL-3.0-or-later with the Madeira Converter Exception; see `LICENSE`,
`LICENSE-EXCEPTION.md`, `LICENSES/` and `THIRD-PARTY-NOTICES.md`.

## Outside patch (kept exactly as supplied)

- `build/ntdll-unix/signal_arm64_ios.c`: written with Gemini, applied unchanged. Repairs
  sign-extended 32-bit addresses (`0xffffffff80000000`..`0xfffffffffffeffff`) that match a
  sub-floor window or a low alias, for data accesses and for jump/call targets at FEX's dispatcher
  (`[sext-lowalias]` log lines). On by default; `env.MADEIRA_SEXT_LOWALIAS = 0` turns it off.
  Untested. Ported by hand onto 0.2.100's file (helpers, the data-fault and dispatcher-RIP
  sites, `ios_subfloor_service`).

## How it differs from the source bundle

Layout:
- `FEX`, `wine`, `dxmt` and `madeira-dock` are ordinary folders (the trees the IPA was built
  from, including its local changes), not submodules: their commits are not all on the public
  repositories. `.gitmodules` is removed and the build no longer runs `git submodule update`
  for them (`.github/workflows/build.yml`, `tools/build/build-runtime-component.sh`).
- The bundle's Linux (WSL) build-script changes are reverted to the macOS originals:
  `build/gnutls-ios/build.sh`, `build/luajit-x64/build.sh`, `build/wineserver/build.sh` (the
  lld-duplicate renames only; 0.2.100's new sock/pipe census and stored-ACL objects are kept),
  `tools/build/build-runtime-component.sh` (submodule updates, and the release builder's
  MoltenVK-from-IPA shim: MoltenVK is built from source here so its patches apply),
  `tools/build/build-wine.sh`, `tools/build/runtime-components.py`. The one in
  `build/win32u-unix/build.sh` is kept (an `rm -f` of the old archive, harmless on macOS).
- `build/fex-patches/apply.sh`: with FEX a folder, `git apply` inside it skipped every patch
  with `diff --git` headers without an error, so they were reported applied without being
  applied. It now applies from the repository root with `--directory=FEX` when FEX has no
  `.git` of its own.

Build:
- `.github/workflows/build.yml`: the bundle's, on the same `xcode-27` runners (GitHub's Xcode 27
  image), with an extra "Select newest Xcode" step and no submodule updates. An earlier build here
  used `macos-26` (Xcode 26.6, iOS 26.5 SDK), which can't compile the iOS 27 TV/AirPlay code in
  `MadeiraApp.swift`.
- `tools/build/build-shader-headers.sh`: asks the Metal compiler which form of
  `__metal_atomic_fetch_add_explicit` it accepts (GitHub's Xcode 26.6 defines the flag macro
  but takes four arguments, so the bundle's `#ifdef` picks the wrong form there).

Fixes:
- `build/moltenvk-ios/0001-madeira-evict-pipeline-states.patch`,
  `0002-madeira-drop-shader-libraries.patch` and
  `0003-madeira-null-pipeline-bind.patch`, applied to MoltenVK v1.4.2 by a loop in
  `build/moltenvk-ios/build.sh`. 0001 and 0002 are off unless
  `MADEIRA_MVK_EVICT_PIPELINES=1` / `MADEIRA_MVK_DROP_SHADER_LIBRARIES=1` is set (Detroit:
  Become Human's shader compile). 0003 is always on: a game that binds the null handle of a
  pipeline whose compile failed no longer crashes MoltenVK; those draws are skipped.
- `madeira-d3d12/src/pe/madeira_d3d12.c`: an optional per-call log of the `ID3D12Device`
  methods, off unless `MADEIRA_D3D12_CALL_LOG` is set (1 = failures and each method's first
  call, 2 = every call). For tracing a game's Direct3D 12 setup.

Not in this build: the Get Help key (private), so Get Help does not work. There is no
`en.lproj` in the bundle, so English is not offered in the language picker.

## Prebuilt files

The source bundle leaves out the built files that the Madeira repository keeps in git.
They are restored so the tree has the shape the build expects:
- `app/Madeira/arm64ec-windows/`, `app/Madeira/aarch64-windows/` and
  `app/Madeira/vulkan/arm64ec-windows/{vulkan-1,winevulkan}.dll` come from the matching IPA
  (Madeira Nightly 0.2.100 og). `app/Madeira/i386-windows/` is not restored: the workflow's
  i386 job builds it (`build/wine-i386/build.sh`, which upstream says has not been run on
  macOS yet).
  Left out: `dockhost.exe`, `dock-notices.txt` (built by the dock component) and the
  `*.source` build stamp. The file names in the two runtime folders select which Wine modules
  the build compiles (`build/windows-runtime/targets.py`).
- `app/Madeira/d3d12/libmetalirconverter.dylib` comes from the public Madeira repository
  (8b52c18), carried over from `main` (the pin did not change). The build pins its SHA-256 (`build/madeira-d3d12/deps.sh`); the copy inside an
  IPA has been re-signed and no longer matches.
- The diagnostic test programs under `tests/`, the test shaders in `madeira-d3d12/shaders/`
  and `build/tftrace/tftrace-x64.dll` come from the public Madeira repository (8b52c18).
- Not restored: `app/Madeira/lib{gmp,gnutls,hogweed,nettle}.a` and `app/libdxmt_unix.a`.
  The build compiles these.

## Port to 0.2.100

Commits on this branch: the nightly as released (import), then main's later commits merged
three ways (base `0ef6e036`), then the fixes from main's first commit ported by hand, then the
FEX patches.
- Dropped because 0.2.100 has its own: the LiveContainer wineserver socket retry
  (`build/wineserver/request_ios.c`; 0.2.100's `ws-bind-fallback`), the Vulkan `system32`
  link cleanup in `WineProcessBridge.m` (identical code) and the `check-control-presets.py`
  `editorCanvas(top:)` fix.
- KUSER: 0.2.100 adds FEX patch 0017 (`[kuser-rebase]`, constant-address loads,
  `MADEIRA_FEX_KUSER_REBASE=0` off). `env.MADEIRA_KUSER_REMAP` stays for the register-based
  reads it does not cover; the rebase rewrites the address before the remap's window test,
  so a load is never translated twice.
- Stellar Blade: FEX patches 0005/0006 are 0025/0026 here (0.2.100 uses 0005/0006); the
  null-uniform-buffer skip is called with the new `struct xcontext` (`&context->c.AMD64_Context`).

## Later additions (game config switches, all off by default)
- `env.MADEIRA_SRW_HOLDER`, `env.MADEIRA_SRW_SHARED_WHEN_FREE`, `env.MADEIRA_SRW_DEADLOCK_BREAK`
  (`wine/dlls/ntdll/sync.c`): SRW lock holder diagnostics, Windows-style shared acquire of a
  free lock while a writer waits, and a breaker for two-thread SRW deadlocks (PRAGMATA's job
  threads after its intro movie).
- `pso-mem-log`, `pso-evict-idle`, `pso-evict-headroom-mb` (`madeira-d3d12/src/pe/madeira_d3d12.c`):
  Direct3D 12 pipeline memory census and idle pipeline eviction (692e6ef).
- `env.MADEIRA_KUSER_REMAP` (08472dc, 983c978): KUSER_SHARED_DATA reads from FEX-compiled code
  are handed to FEX once per JIT site, which learns the instruction's 4 KB guest page and
  recompiles every load in it with the address translated inline (page learning since the
  instruction table filled on PRAGMATA) (`build/ntdll-unix/signal_arm64_ios.c`, `FEX/Source/Windows/ARM64EC/`,
  `FEX/FEXCore/Source/Interface/Core/`). Log prefix `[kuser-remap]`.
- `env.MADEIRA_SB_NULL_UB_SKIP` (`wine/dlls/ntdll/signal_arm64ec.c`, `ios_sb_null_ub_skip`):
  Stellar Blade's crash at `SB-Win64-Shipping.exe+0x2e3ec81` (access violation reading 0x18) is
  Unreal's D3D11 renderer reading an empty pixel-stage uniform-buffer slot (in the Nov 24 log the
  shader wanted slots 0, 2, 3 and the game had bound 0, 1, 2). With `= 1` the fault is resumed at
  the loop's next-slot test before the game's handlers see it, so that draw goes on without the
  missing buffer's textures (visual glitches are possible). The x86 bytes on both sides of the
  fault are checked first. Each new shader is logged once (`[sb-ub-skip] new shader`), then a
  count every 1000 skips; the Unix SEGV handler stops repeating its per-fault lines for reads
  at 0x18 after 8 (`build/ntdll-unix/signal_arm64_ios.c`). A workaround, not the cause: why the
  slot is empty is still open.
