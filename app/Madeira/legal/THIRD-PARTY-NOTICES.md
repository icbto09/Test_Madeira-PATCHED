# Third-party components

Madeira is built from several upstream projects plus original work. Each
component keeps its own license. This file records what is here, what ships in
the binary, and what is still unresolved.

Madeira's own code, and the combined application as distributed, are under
**GPL-3.0-or-later** (`LICENSE`). Each upstream keeps its own license; the
dependency license texts are in `LICENSES/`. See "Why GPL-3.0-or-later" below.

## Components that ship in the built app

| Component | Upstream license | **Madeira's fork** | Notes |
|---|---|---|---|
| **Wine** | LGPL-2.1-or-later | **GPL-3.0-or-later** | Fork relicensed under LGPL-2.1 §3, which expressly permits applying the ordinary GPL to a copy. `ntdll`, `wineserver`, `win32u`, ARM64EC loader modified for iOS. |
| **FEX-Emu** | MIT | upstream MIT + **modifications GPL-3.0-or-later** | Forked. x86-64 → ARM64 translation. |
| **DXMT** | MIT | upstream MIT + **modifications GPL-3.0-or-later** | Forked. D3D11 → Metal. |
| **DXMT — Direct3D 9 / DXSO frontend** | **LGPL-2.1-or-later** | **LGPL-2.1-or-later**, kept as received | Written by **David Acevedo** (his commit `fe69cd3`, "feat(d3d9): add a Direct3D 9 frontend") and imported into `dxmt` from his fork of the same upstream: `https://github.com/dacevedo12/dxmt.git`, tag `v0.4-d3d9`, commit `e8dd4c656dcb74a6d970a30a397d1558b0e3fb2b`. That tree's licence is the DXMT project notice ("Copyright (c) 2023-2026 Feifan He for CodeWeavers", LGPL-2.1-or-later), which postdates upstream's MIT→LGPL relicense, so the import is **not** MIT. It is kept under LGPL-2.1-or-later as received: the LGPL-2.1 §3 option to distribute a copy under the ordinary GPL is not exercised, and that choice is left to the maintainer. 125hz's additions to the D3D9 path are licensed like the DXMT row. Licence text in `dxmt/COPYING.LIB` and `LICENSES/LGPL-2.1.txt`; the file-by-file list is in `dxmt/LICENSE-MADEIRA.md`. |
| **rpmalloc** | 0BSD | 0BSD + **Will Faust's modifications GPL-3.0-or-later** | Nested submodule of FEX, forked to `willfaust/rpmalloc`. Commits by Ryan Houdek are **not** relicensed. |
| **GMP** 6.3.0 | **LGPL-3.0-or-later** or GPL-2.0-or-later | Static (`libgmp.a`). |
| **Nettle / Hogweed** 3.10.1 | **LGPL-3.0-or-later** or GPL-2.0-or-later | Static (`libnettle.a`, `libhogweed.a`). |
| **GnuTLS** 3.8.9 | LGPL-2.1-or-later | Static (`libgnutls.a`). Used by Wine's bcrypt/secur32/crypt32. |
| **FFmpeg** 7.1.1 — libavformat, libavcodec, libavutil, libswresample | **LGPL-2.1-or-later** | Static (`libavformat.a`, `libavcodec.a`, `libavutil.a`, `libswresample.a`). Configured `--disable-gpl --disable-nonfree --disable-version3 --disable-everything`, then only: the WMA-family decoders (`wmav1,wmav2,wmapro,wmalossless,xma1,xma2`), the `mp1,mp2,mp3` and `pcm_u8,pcm_s16le,pcm_s24le,pcm_s32le,pcm_f32le,pcm_f64le` decoders, the `mp3`, `wav` and `mov` (MP4/MOV/M4A) demuxers and the `mpegaudio` parser. No H.264, HEVC or AAC decoder or parser (those streams are decoded by Apple's VideoToolbox/AudioToolbox), no protocols, no muxers, no zlib. No GPL, version3 or non-free component is enabled, so the result is LGPL-2.1-or-later. Used only by `build/ntdll-unix/winegstreamer_unixlib_ios.c` and `build/ntdll-unix/wg_parser_av_ios.c`, winegstreamer's unix side on this port (the Windows WMA decoder MFT/DMO, and the wg_parser behind quartz's MP3/WAV splitters and Media Foundation's MP4 source); upstream Wine implements both with GStreamer, which does not exist on iOS. |
| **{fmt}** | MIT | Static (`libfmt.a`), via FEX. |
| **xxHash** | BSD-2-Clause | Static (`libxxhash.a`). |
| **Cephes** | permissive (Moshier) | Static (`libcephes_128bit.a`), via FEX. |
| **Berkeley SoftFloat 3e** | BSD-3-Clause | Static (`libsoftfloat_3e.a`), via FEX. |
| **Steam sign-in, owned library and downloads (`app/Madeira/SwiftSteam/`)** | Derived from Jfishin's Madeira Steam client, used with the author's permission (see below); Jfishin confirmed that he wrote the depot downloader himself | GPL-3.0-or-later + Converter Exception, Copyright 2026 Jfishin, 125hz | Sign-in to Steam's public `IAuthenticationService` over HTTPS and a Keychain token store; a Steam connection (WebSocket over TLS) that lists the account's owned games; downloads from Steam's content servers into Madeira Dock's Steam library folder. File-by-file provenance and the licence audit of the downloader: `docs/STEAM_SIGNIN.md`, `docs/STEAM_LIBRARY.md`. No Valve or third-party Steam code or binaries, and no Steam Cloud, launch-emulator or DRM code. |
| **Zstandard educational decoder** | BSD-3-Clause or GPL-2.0 | BSD-3-Clause selected | `app/Madeira/SwiftSteam/zstd_edu.c/.h` (Meta Platforms). Decodes Steam's zstd content chunks. Madeira's error-recovery wrapper (Jfishin's, kept) is serialized across threads. Licence text in `LICENSES/ZSTD-BSD.txt`. |
| **liblzma** | Public domain / 0BSD | System library | Linked dynamically from the iOS SDK (`liblzma.tbd`) for Steam's LZMA content chunks; nothing is bundled. |
| **Madeira Dock (`madeira-dock`, built into `arm64ec-windows/dockhost.exe`)** | original work, Copyright 2026 125hz | GPL-3.0-or-later + Converter Exception | Headless host for Valve's Steam client, a separate Windows program started in the Wine session. Built from the submodule by `build/madeira-dock/build.sh`; not committed as a binary. Its statically linked LLVM/MinGW-w64 runtime notices ship in `dock-notices.txt`. Valve's client files are downloaded by the user from Valve and are not covered by Madeira's licence. See `docs/MADEIRA_DOCK.md`. |
| **Mesa** 25.0.7 (OSMesa, Zink, softpipe) | MIT (+ permissive, see `docs/license.rst`) | Patched (`build/mesa-ios/patches`). Separate dylib `gl/libOSMesa.dylib`, desktop OpenGL backend. |
| **MoltenVK** 1.4.2 | Apache-2.0 | Unmodified. Separate dylib `gl/libMoltenVK.dylib`; contains SPIRV-Cross, SPIRV-Tools (Apache-2.0) and cereal (BSD-3-Clause). |
| **LuaJIT** 2.1 | MIT | Unmodified. Separate x86-64 Windows DLL (`compat/love/lua51.dll`, built by `build/luajit-x64/build.sh`), loaded in place of a game's `lua51.dll` when that is an x64 LuaJIT needing memory below 2 GB (`build/wineserver/luajit_compat.c`); game files are not modified. |
| **StikJIT** 1.9.0 | MPL-2.0 | Bundled XCFramework in the iOS 26 JIT helper | Enables JIT for Madeira through the device's RSD tunnel. Exact corresponding source: [`StikDebug/StikJIT` tag `1.9.0`](https://github.com/StikDebug/StikJIT/tree/1.9.0); bundled license text: `LICENSE-StikJIT-MPL-2.0.txt`. The framework contains **idevice**, Copyright 2026 Jackson Coxson, under MIT; source: [`jkcoxson/idevice`](https://github.com/jkcoxson/idevice), bundled license text: `LICENSE-idevice-MIT.txt`. |
| **On-device pairing, signing refresh and Apple ID sign-in** (`libmadeira_rppairing.a`) | **idevice** 0.1.68, Copyright 2026 Jackson Coxson, MIT; **isideload** 0.4.4, Copyright (c) 2025 nab138, MIT; their Rust dependencies under MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0 or CDLA-Permissive-2.0, and one, **apple-codesign-quick** 0.1.0 (Dadoum/apple-crates, which isideload signs apps with), under LGPL-2.1-or-later | Madeira's wrapper (`build/rppairing-ios`) **GPL-3.0-or-later**; dependencies unmodified, static in the app | iOS 27 on-device remote pairing for Built-in StikJIT (`app/Madeira/JITPairing.swift`), and installing a new provisioning profile with the pairing file (`app/Madeira/SigningRefresh.swift`) and the Apple ID sign-in that asks Apple for one (`app/Madeira/AppleSignIn.swift`, isideload); docs/JIT.md. Built from crates.io at the versions pinned in `build/rppairing-ios/Cargo.lock`. Every crate in the binary, with its licence files, is listed in `LICENSES-rppairing-crates.txt`, regenerated by `build/rppairing-ios/build.sh`. idevice's licence text: `LICENSE-idevice-MIT.txt`. isideload's: `LICENSE-isideload-MIT.txt`. apple-codesign-quick's: `LICENSES/LGPL-2.1.txt`; Madeira calls none of its code, and its source is the crate at the pinned version. |
| **libxml2** 2.12.10 and **libxslt** 1.1.45 | MIT (Daniel Veillard and contributors) | Unmodified, statically linked into Wine's `msxml3.dll` (`arm64ec-windows`) | Wine's bundled copies (`wine/libs/xml2`, `wine/libs/xslt`), built with the module by `build/wine-pe/build-modules.sh`. Licence texts in `LICENSES/MIT-libxml2.txt` and `LICENSES/MIT-libxslt.txt`. |
| **NVAPI SDK headers** | MIT (NVIDIA Corporation & affiliates) | Unmodified headers, compiled into DXMT's `nvapi64.dll` (`arm64ec-windows`) | `dxmt/external/nvapi`. DXMT's own NVAPI implementation answers only with Madeira's opt-in "Report an NVIDIA GPU" switch; no NVIDIA binary is shipped. Licence text in `LICENSES/MIT-NVAPI.txt`. |
| **Noto Sans JP** (Noto Sans CJK, SubsetOTF Regular) | SIL OFL 1.1 | Unmodified font file `app/Madeira/fonts-ja/NotoSansJP-Regular.otf` from [`notofonts/noto-cjk`](https://github.com/notofonts/noto-cjk) commit `f8d1575`, SHA-256 `dff723ba59d57d136764a04b9b2d03205544f7cd785a711442d6d2d085ac5073` | Copied into the prefix's `C:\windows\Fonts` only for a game with **Japanese locale** on, so Japanese text has a font. Licence text in `app/Madeira/fonts-ja/LICENSE-NotoSansJP-OFL-1.1.txt`. Wine's code page tables `c_932/936/949/950.nls` (`app/Madeira/nls/extra`) come unmodified from the Wine fork. |
| **Wine Mono** 11.0.0 | Mono: LGPL or MIT X11 per part; FNA: Ms-PL and MIT; FAudio, FNA3D, MojoShader, SDL3: zlib; winforms, wpf, monoDX, System.Speech and Wine Mono's own code: MIT (`build/wine-mono/COPYING`) | Prebuilt runtime, unmodified except `lib/mono/4.5/mscorlib.dll` (4 IL bytes in `GC.Collect`, `build/wine-mono/bundle.sh`), bundled as `wine-mono/` with that COPYING only in a development build made after `build/wine-mono/fetch.sh`; **release builds do not include it** (the packaging step removes `wine-mono/`). Instead the app downloads it from WineHQ when the user asks (setup or Settings › .NET Framework, `app/Madeira/WineMono.swift`), checks it against the same SHA-256, unpacks it without `lib/mono/*-api` and applies the same mscorlib patch on the device | Runs .NET Framework programs; Wine's mscoree loads it. The x86 tarball from `dl.winehq.org`, SHA-256 pinned in `build/wine-mono/pin.sh`. The compile-time reference assemblies (`lib/mono/*-api`, which include the GPL-licensed ICSharpCode.SharpZipLib) are not bundled. Exact corresponding source: `wine-mono-11.0.0-src.tar.xz` from the same folder; see "Corresponding source" below. |
| **Mesa** 26.2.4 — `opengl32.dll`, `libgallium_wgl.dll` (`x86_64-opengl`, when built) | MIT (most files; each file's SPDX identifier governs), with BSL-1.0 (`src/c11/impl/threads_win32.c`), BLAKE3 (Apache-2.0 selected of CC0-1.0 / Apache-2.0), Berkeley SoftFloat 3e (BSD-3-Clause), zlib 1.3.1 (Zlib) and DirectX-Headers v1.619.1 (MIT) | upstream licences + **Madeira's two patches GPL-3.0-or-later** (`build/mesa-d3d12/patches/`) | Windows x64 OpenGL driver on D3D12 (OpenGL → D3D12 → `madeira_d3d12` → Metal). Built from the pinned release tarball by `build/mesa-d3d12/build.sh`; not committed as a binary. Licence texts in `LICENSES/MIT-Mesa.txt`, `BSL-1.0-Mesa.txt`, `Apache-2.0-BLAKE3.txt`, `BSD-3-SoftFloat-3e.txt`, `Zlib-zlib.txt`, `MIT-DirectX-Headers.txt`. |

## Why GPL-3.0-or-later

The intent is that derivatives stay open source. LGPL deliberately permits
proprietary applications to link against the covered work, which does not serve
that intent; GPL requires distributed derivative and combined works to remain
GPL-compatible and to offer source.

The dependencies permit this. Wine, GnuTLS and FFmpeg are LGPL-2.1-**or-later** and GMP
and Nettle are LGPL-3.0-or-later; LGPL explicitly allows a combined work to be
distributed under GPL terms, and the MIT and BSD components impose no obstacle.

What GPL does and does not achieve here, stated plainly so it is not
over-relied on:

- Obligations attach on **distribution**. Someone may modify this privately and
  never publish anything.
- It does **not** cover games, data files or other independent programs merely
  run through Madeira. They are separate works.
- It cannot stop anyone independently reimplementing the same functionality.
- FEX-Emu and DXMT code already published under MIT **remains available under
  MIT**. Choosing GPL here cannot revoke a grant those projects already made.
  If the intent is for changes inside the submodule forks to be GPL too, those
  repositories need their own licensing decision; this file governs the main
  repository.

## Each fork carries its own license notice

`THIRD-PARTY-NOTICES.md` in this repository does **not** relicense code that
lives in a separate submodule. Each fork therefore carries its own
`LICENSE-MADEIRA.md` and `CONTRIBUTING.md` stating what is licensed how:

- `wine/LICENSE-MADEIRA.md` — the LGPL-2.1 §3 conversion, exactly what changed
  and the two deliberate exceptions.
- `FEX/LICENSE-MADEIRA.md`, `dxmt/LICENSE-MADEIRA.md` — upstream MIT
  preserved; Madeira's modifications GPL-3.0-or-later. `dxmt`'s notice
  also records the Direct3D 9 / DXSO import, file by file, which is kept under
  LGPL-2.1-or-later as received.
- `FEX/External/rpmalloc/LICENSE-MADEIRA.md` — 0BSD preserved; only Will
  Faust's commits are GPL, and authorship is distinguishable via `git log`.

### What relicensing does and does not achieve

The goal is that **distributed** derivatives stay open source. Stated honestly:

- **It is not retroactive.** The FEX, DXMT and Wine forks were public before
  this change, under their upstream permissive/lesser licenses. Anyone who
  already obtained a copy keeps those rights, and that grant cannot be revoked.
  Only contributions from 2026-08-28 onward are GPL-only.
- Upstream projects are unaffected and their code stays available from them
  under its original license.
- The GPL constrains distribution, not private modification or internal use.
- It does not cover games or other independent programs merely run through
  Madeira.

## Original vs. derived work in this repository

Do **not** assume that everything outside the submodules is original. It is not.

- `build/ntdll-unix/`, `build/wineserver/`, `build/win32u-unix/` and similar are
  substantially **Wine-derived**. Files such as `build/ntdll-unix/loader_ios.c`
  are forks of upstream Wine sources and retain upstream copyright headers
  (e.g. "Copyright (C) 2020 Alexandre Julliard"). Roughly 2,700 files under
  `build/` carry an upstream copyright notice of some kind.
- `build/gnutls-ios/` contains build scripting only; the library sources are
  fetched separately (see the open issue below).
- `app/`, `tools/` and `tests/` are largely original, but contain vendored and
  derived files too.
- `app/Madeira/SwiftSteam/` is derived from Jfishin's Madeira Steam client. Jfishin
  gave permission to use it ("do whatever you want with it") in the Madeira
  Discord server on 2026-09-22; Will Faust is a member of that server and saw
  the message. Details and a per-file audit: `docs/STEAM_SIGNIN.md`.

Rather than claim authorship of whole directories: **original Madeira-authored
files that do not carry another license notice are licensed under
GPL-3.0-or-later.** Files carrying their own copyright or license header are
governed by that header.

## Microsoft Visual C++ runtime redistributables — NOT DISTRIBUTED

Games built with MSVC require Microsoft's Visual C++ runtime DLLs. Those are
Microsoft-authored binaries, redistributable only under the Visual Studio
redistributable terms and only in unmodified form. They are **not** covered by
this project's license and are **no longer tracked in this repository**;
`app/Madeira/x86_64-vcruntime/*.dll` is gitignored and must be supplied locally.
See `tools/fetch-vcruntime.md`.

### Earlier malformed copies were purged from history

Twelve such DLLs were previously committed here, and they had been modified:
each one's Authenticode signature had been truncated away, removing exactly the
advertised certificate payload and leaving a PE header still claiming a
signature the file no longer contained.

Those blobs have been removed from this repository's history entirely. Anyone
holding a clone or fork taken before the rewrite may still have them, and should
not redistribute those copies.

## Microsoft DXIL validator (`dxil.dll`) — NOT TRACKED

Mesa's D3D12 driver signs the DXIL shaders it compiles with Microsoft's
validator, `dxil.dll`. It is a Microsoft-authored binary under Microsoft's own
licence terms (`LICENSE-MS.txt` in the DirectXShaderCompiler release), not under
this project's licence. It is **not tracked in this repository**:
`build/mesa-d3d12/build.sh` downloads the official release
(DirectXShaderCompiler v1.9.2609, `dxc_2026_09_29.zip`), checks its SHA-256,
and copies `bin/x64/dxil.dll` unmodified into `app/Madeira/x86_64-opengl/`
with that licence beside it as `LICENSE-dxil.txt`. Whether a published build
includes it is the maintainer's decision.

## Corresponding source for the statically linked libraries

`libgmp.a`, `libnettle.a`, `libhogweed.a` and `libgnutls.a` are tracked as
compiled binaries, so the exact sources they were built from are tracked too:

- `build/gnutls-ios/src/gmp-6.3.0.tar.xz`
- `build/gnutls-ios/src/nettle-3.10.1.tar.gz`
- `build/gnutls-ios/src/gnutls-3.8.9.tar.xz`
- `build/gnutls-ios/src/SHA256SUMS` -- checksums for the above
- `build/gnutls-ios/build.sh` -- the exact build machinery and configure flags

All three are unmodified upstream releases; no patches are applied. A reference
to an upstream project would not have been enough on its own, which is why the
tarballs themselves are here.

FFmpeg's archives are git-ignored outputs of its build script (like
`libntdll_unix.a`), but the app links them, so a built package contains them
and the exact source they are built from is tracked here in the same way:

- `build/ffmpeg/src/ffmpeg-7.1.1.tar.xz` -- the unmodified upstream release
  from `ffmpeg.org`
- `build/ffmpeg/src/SHA256SUMS` -- its checksum
  (`733984395e0dbbe5c046abda2dc49a5544e7e0e1e2366bba849222ae9e3a03b1`), which
  every run of the build script verifies before extracting
- `build/ffmpeg/build.sh` -- the exact build machinery and configure flags. No
  patches are applied, and the script needs no network.

## Relinking and static linking

The Wine-derived unix libraries, the crypto stack and FFmpeg are linked **statically**
into the app binary.

LGPL section 6 (v2.1) / section 4 (v3) contemplates a recipient being able to
relink the application against a modified version of the library. Providing the
library's source alone does not satisfy this; the relevant clauses also
contemplate supplying the application in a form — object code or source — that
permits relinking. This repository does not currently ship such a package.

Note the distinction between publishing source and distributing binaries.
Publishing this repository alone distributes no combined binary, so the
question does not arise. **Handing someone a built `.ipa` does distribute one.**

For any `.ipa` given to a tester, supply the corresponding source at that exact
commit together with the build and signing instructions needed to reproduce it.
That is a practice to follow, not something the repository can satisfy on its
own.

If relinking needs to be supported properly, shipping the Wine-derived parts as
a dynamic framework is one possible approach, and easier to plan for than to
retrofit -- though on iOS it is not a complete answer by itself, since code
signing may still prevent a recipient from substituting a modified framework
into a signed app.

## Present in the working tree but not distributed

`LiveContainer/` and `research/LiveContainer/` are AGPL-3.0 reference copies
used for local research. Both are gitignored, untracked, and no part of them is
linked into or shipped with the app. They form no part of the combined work.

## Code from MetalSharp (AGPL-3.0)

Nightly 0.2.83 and later contain code ported from **MetalSharp** (patches `fex/0025`, `fex/0026` and `fex/0031`,
and MetalSharp-Wine), written by **BOR1NG (Avery Felts, <https://github.com/aaf2tbz>)** and licensed **AGPL-3.0**.
Madeira thanks BOR1NG for this work. It is used in these fixes:

| Fix | Where | What |
|---|---|---|
| Overwatch 2 "section views" (`env.MADEIRA_EC_SECTION_VIEWS = 0` off) | `build/fex-patches/0005-windows-ios-section-views.patch` (FEX `Core.cpp`, `Module.cpp`, `InvalidationTracker.cpp/.h`) and `wine/dlls/ntdll/signal_arm64ec.c` | Several views of one file mapping are tracked so a write through one view invalidates translated code in the others; the changed-code block is placed right after the current block (MetalSharp `fex/0025`, `fex/0026`). |
| Overwatch 2 debug registers (`env.MADEIRA_EC_DEBUG_REGS = 0` off) | `wine/dlls/ntdll/signal_arm64ec.c`, FEX `Module.cpp` | The x86 debug registers pass through a thread's context (the idea is cited from MetalSharp-Wine `4614051`). |
| Overwatch 2 XSAVE state revert (`env.MADEIRA_EC_XSTATE_REVERT = 0` off) | `wine/dlls/ntdll/signal_arm64ec.c`, `wine/dlls/ntdll/unix/system.c` | Credit in the source comments: BOR1NG, MetalSharp-Wine. |
| Intel flag behaviour (`env.MADEIRA_FEX_INTEL_FLAGS = 1` on, off by default) | `build/fex-patches/0010-fexcore-intel-flags.patch` (FEXCore `ALUOps.cpp`, `OpcodeDispatcher.cpp/.h`, `OpcodeDispatcher/Flags.cpp`) | Where x86 leaves a flag undefined, the emulator gives what Intel hardware gives (MetalSharp `fex/0031`). |
| Overwatch 2 clock and CPU speed (`env.MADEIRA_EC_TSC_MHZ = 0` off; MetalSharp-Wine patch 0134, LGPL) | `wine/dlls/ntdll/unix/system.c`, `wine/programs/wineboot/wineboot.c` | The CPU speed the system reports follows the timer's own frequency. Credit: BOR1NG (Avery Felts). |
| Overwatch 2 x64 context fields (`env.MADEIRA_EC_CTX_X64_FIELDS = 0` off; MetalSharp-Wine d100ac4215, LGPL) | `wine/dlls/ntdll/signal_arm64ec.c` | The x64 fields of a thread context are carried through. Credit: BOR1NG (Avery Felts). |

As that code is AGPL-3.0, the complete corresponding source of every build that contains it is published with that
build's release at <https://github.com/camhoc/Madeira> (AGPL-3.0 section 13). Madeira's own code remains
GPL-3.0-or-later (GPL-3.0 section 13 and AGPL-3.0 section 13 let the two be combined).

## Code from MetalSharp-Wine (LGPL-2.1) and MetalSharp's FEX patches (MIT)

Nightlies 0.2.91 and 0.2.92 contain fourteen Overwatch 2 items (nine in 0.2.91, four more in 0.2.92, one opt-in in 0.2.93) ported from MetalSharp-Wine (<https://github.com/metalsharp/MetalSharp-Wine>)
and MetalSharp's FEX patches, written by **BOR1NG (Avery Felts, <https://github.com/aaf2tbz>)**. The Wine changes are
**LGPL-2.1**, the FEX changes **MIT**. Madeira thanks BOR1NG for all of them.

| Fix (off switch) | MetalSharp source | Where |
|---|---|---|
| bsd-sockets (`env.MADEIRA_BSD_SOCKETS = 0`) | MetalSharp-Wine 0155 (LGPL-2.1) | `wine/dlls/ntdll/unix/socket.c`, `virtual.c`, `unix_private.h`, `wine/dlls/ws2_32/unixlib.c`, `wine/server/fd.c`, `file.h`, `sock.c`, `build/wineserver/fd_ios.c`, `build/ntdll-unix/virtual_ios.c` |
| isec-bound (`env.MADEIRA_EC_ISEC_BOUND = 0`) | MetalSharp-Wine 554d343543 (LGPL-2.1) | `wine/dlls/ntdll/signal_arm64ec.c` |
| ro-view-cow (opt-in `env.MADEIRA_EC_RO_VIEW_COW = 1`) | MetalSharp-Wine (LGPL-2.1) | `build/ntdll-unix/virtual_ios.c` |
| selector-answer (`env.MADEIRA_EC_SELECTOR_ANSWER = 0`) | MetalSharp-Wine (LGPL-2.1) | `build/ntdll-unix/signal_arm64_ios.c` |
| partial-copy (`env.MADEIRA_SRV_PARTIAL_COPY = 0`) | MetalSharp-Wine 9df1933a57 (LGPL-2.1) | `build/wineserver/mach_ios.c` |
| pop-rsp-fault (`env.MADEIRA_FEX_POP_RSP_FAULT = 0`) | FEX patch 0003 (MIT) | `build/fex-patches/0012-fexcore-pop-rsp-fault.patch` |
| x87-flags (`env.MADEIRA_FEX_X87_FLAGS = 0`) | FEX patch 0006 (MIT) | `build/fex-patches/0013-fexcore-x87-flags.patch` |
| x87-ctx (`env.MADEIRA_EC_X87_CTX = 0`) | FEX patch 0033 (MIT) | `build/fex-patches/0014-windows-ios-x87-ctx.patch` |
| df-ctx (`env.MADEIRA_EC_DF_CTX = 0`) | FEX patch 0004 (MIT) | `build/fex-patches/0015-windows-ios-df-ctx.patch`, `wine/dlls/ntdll/signal_arm64ec.c`, `unwind.h` |
| kuser-rebase (`env.MADEIRA_FEX_KUSER_REBASE = 0`) | FEX patch 0001 (MIT) | `build/fex-patches/0017-fexcore-kuser-rebase.patch` |
| cpu-identity (`env.MADEIRA_CPU_IDENTITY = 0`) | FEX patch 0028 (MIT) and a Wine idea from 198a71f8fa (LGPL-2.1) | `build/fex-patches/0018-fexcore-cpu-identity.patch`, `build/ntdll-unix/server_ios.c`, `hw_registry_ios.h` |
| code-buffer-big (opt-in `env.MADEIRA_FEX_CODE_BUFFER_MB = 256`) | idea from FEX patch 0045 (MIT) | `build/fex-patches/0019-fexcore-code-buffer-big.patch`, `build/ntdll-unix/virtual_ios.c` |
| hard-error-log (`env.MADEIRA_HARD_ERROR_LOG = 0`) | MetalSharp-Wine 0084 (LGPL-2.1) | `wine/dlls/ntdll/unix/system.c` |
| globalroot (`env.MADEIRA_GLOBALROOT = 0`) | MetalSharp-Wine 0085 (LGPL-2.1) | `wine/dlls/ntdll/unix/file.c` |

## Code from Mullion (LGPL-2.1-or-later)

Nightly 0.2.89 and later contain six Direct3D 11 fixes ported from **Mullion** (<https://github.com/dttdrv/mullion>, by
dttdrv and contributors, a DXMT fork under **LGPL-2.1-or-later**, the same license as the DXMT files they touch): a null
FinishCommandList, illegal constant-buffer ranges, releasing an object already at zero, a draw with no vertex shader,
fences on video-support devices, and fence events. The change is `src/d3d11` and `src/util/util_mullion_fix.hpp` in the
`dxmt` folder; each call site names the Mullion commit it came from. Off switch: `env.MADEIRA_DXMT_MULLION_FIXES = 0`
(and one switch per fix). Thank you, dttdrv.

