#!/bin/bash
# OpenAL Soft (LGPL-2 or later) as OpenAL32.dll for programs that need OpenAL and do not
# ship their own (BIT.TRIP BEAT: dep\oalinst.exe only). Two builds with llvm-mingw:
#   ARM64EC  -> $DEST/arm64ec-windows/OpenAL32.dll   (x64 programs, native code like DXMT)
#   i686     -> $DEST/i386-windows/OpenAL32.dll      (32-bit programs, run under the emulator)
# WineProcessBridge.m (madeira_overlay_openal) links them into system32 + sysx64 (EC) and
# syswow64 (i686) only where the prefix has no OpenAL32.dll of its own; a real file there
# is never replaced. env.MADEIRA_OPENAL = 0 leaves them out and removes earlier links.
#
#   OAL_SRC      upstream checkout at OAL_TAG (default toolchains/openal-soft; cloned when absent)
#   OAL_WORK     build trees (default toolchains/openal-soft-build)
#   LLVM_MINGW   llvm-mingw (as build/vkd3d-proton/build.sh)
#   DEST         default app/Madeira/openal
# Host tools: cmake, ninja. The x18 check is the one build/vkd3d-proton/build.sh runs.
#
# Windows backends only (WASAPI required, DirectSound and WinMM kept as fallbacks, wave
# writer kept). Every other backend is switched off and CMake looks for libraries,
# headers and packages only under the toolchain's sysroot, so Homebrew's PortAudio, JACK,
# PulseAudio, PipeWire, SDL or SndFile on the build Mac are never picked up. The import
# check after each build fails on anything but Windows system DLLs, in particular on
# libc++.dll, libunwind.dll and libwinpthread-1.dll (which would mean -static did not take).
#
# ARM64EC (v3): clang defines __x86_64__ for ARM64EC on purpose (next to __arm64ec__), and
# OpenAL Soft 1.24.3 reads that as x86: x87 inline asm in common/alnumeric.h and the SSE
# branch of common/pffft.cpp get compiled and fail, even with ALSOFT_CPUEXT_SSE=OFF.
# patches/0001-arm64ec-treat-as-arm64.patch adds "not ARM64EC" to those x86 guards (no
# change for i686/x86_64), and the EC configure below turns SSE off and requires NEON.
#
# LGPL: the corresponding source is upstream at OAL_TAG plus patches/*.patch (applied in
# order by step 1); the licence texts are copied into app/Madeira/licenses and the source
# offer is in THIRD-PARTY-NOTICES.md.
set -euo pipefail

BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$BUILD_DIR/../.." && pwd)"
OAL_TAG="${OAL_TAG:-1.24.3}"   # tag exists (git ls-remote, Nov 21: dc7d7054a5b4); patches/ are written for this tag
OAL_URL=https://github.com/kcat/openal-soft.git
OAL_SRC="${OAL_SRC:-$REPO_ROOT/toolchains/openal-soft}"
OAL_WORK="${OAL_WORK:-$REPO_ROOT/toolchains/openal-soft-build}"
DEST="${DEST:-$REPO_ROOT/app/Madeira/openal}"
if [ -z "${LLVM_MINGW:-}" ]; then
    for d in "$REPO_ROOT/toolchains/llvm-mingw-20260421-ucrt-macos-universal" \
             "$REPO_ROOT/toolchains/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64" "$REPO_ROOT/toolchains/llvm-mingw"; do
        [ -x "$d/bin/arm64ec-w64-mingw32-clang" ] && { LLVM_MINGW=$d; break; }
    done
fi
[ -n "${LLVM_MINGW:-}" ] || { echo "llvm-mingw not found (see docs/BUILDING.md); set LLVM_MINGW"; exit 1; }
for t in cmake ninja; do command -v $t >/dev/null || { echo "missing host tool: $t"; exit 1; }; done
# CMake runs with CMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH=OFF, so it cannot find ninja on PATH
# by itself: pass the full path (CMAKE_MAKE_PROGRAM) and use the same binary for the build.
NINJA="${NINJA:-$(command -v ninja)}"
if command -v llvm-objdump >/dev/null; then OBJDUMP=llvm-objdump; else OBJDUMP="$LLVM_MINGW/bin/llvm-objdump"; fi

# 1. Upstream source at the pinned tag.
if [ ! -d "$OAL_SRC/.git" ]; then git clone -q "$OAL_URL" "$OAL_SRC"; fi
git -C "$OAL_SRC" fetch -q --tags origin || true
git -C "$OAL_SRC" checkout -q -f "$OAL_TAG"   # -f: drops patches applied by an earlier run
git -C "$OAL_SRC" clean -q -fd
echo "OpenAL Soft $OAL_TAG = $(git -C "$OAL_SRC" rev-parse HEAD)"
for p in "$BUILD_DIR"/patches/*.patch; do
    [ -e "$p" ] || continue
    git -C "$OAL_SRC" apply --whitespace=nowarn "$p" || { echo "patch did not apply: $p"; exit 1; }
    echo "applied $(basename "$p")"
done

# 2. One build per target.
build_one() {   # triple, cmake processor, dest subfolder, extra cmake args...
    local triple=$1 proc=$2 sub=$3 B="$OAL_WORK/$3"
    shift 3
    # The toolchain's sysroot for this triple (llvm-mingw layout: $LLVM_MINGW/<triple>).
    # NOT CHECKED that the pinned llvm-mingw has an arm64ec-w64-mingw32 folder; if not,
    # CMake finds nothing there, which is fine (OpenAL Soft needs only the Windows SDK
    # headers the compiler finds by itself).
    local root="$LLVM_MINGW/$triple"
    rm -rf "$B" && mkdir -p "$B"   # fresh dir each time: no stale CMake cache (e.g. HAVE_SSE_INTRINSICS from v2)
    # -include cstdlib: the bundled fmt uses malloc/free without including <cstdlib>, which
    # the PC build of 1.24.3 failed on (undeclared malloc in fmt). Remove when upstream fixes it.
    cmake -S "$OAL_SRC" -B "$B" -G Ninja -DCMAKE_MAKE_PROGRAM="$NINJA" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_FLAGS="-include cstdlib" \
        -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_SYSTEM_PROCESSOR="$proc" \
        -DCMAKE_C_COMPILER="$LLVM_MINGW/bin/$triple-clang" \
        -DCMAKE_CXX_COMPILER="$LLVM_MINGW/bin/$triple-clang++" \
        -DCMAKE_RC_COMPILER="$LLVM_MINGW/bin/$triple-windres" \
        -DCMAKE_FIND_ROOT_PATH="$root" \
        -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER \
        -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY \
        -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY \
        -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY \
        -DCMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH=OFF \
        -DCMAKE_IGNORE_PREFIX_PATH="/opt/homebrew;/usr/local;/opt/local" \
        -DCMAKE_SHARED_LINKER_FLAGS="-static -static-libstdc++" \
        -DLIBTYPE=SHARED -DALSOFT_UTILS=OFF -DALSOFT_NO_CONFIG_UTIL=ON -DALSOFT_EXAMPLES=OFF \
        -DALSOFT_INSTALL=OFF -DALSOFT_TESTS=OFF \
        -DALSOFT_REQUIRE_WASAPI=ON -DALSOFT_BACKEND_WASAPI=ON -DALSOFT_BACKEND_DSOUND=ON -DALSOFT_BACKEND_WINMM=ON \
        -DALSOFT_BACKEND_PORTAUDIO=OFF -DALSOFT_BACKEND_PULSEAUDIO=OFF -DALSOFT_BACKEND_JACK=OFF \
        -DALSOFT_BACKEND_PIPEWIRE=OFF -DALSOFT_BACKEND_SDL2=OFF -DALSOFT_BACKEND_SDL3=OFF \
        -DALSOFT_BACKEND_ALSA=OFF -DALSOFT_BACKEND_OSS=OFF -DALSOFT_BACKEND_SNDIO=OFF \
        -DALSOFT_BACKEND_SOLARIS=OFF -DALSOFT_BACKEND_OPENSL=OFF -DALSOFT_BACKEND_OBOE=OFF \
        -DALSOFT_BACKEND_COREAUDIO=OFF "$@" > "$B/setup.log" 2>&1 || { tail -40 "$B/setup.log"; exit 1; }
    echo "$sub SIMD: $(grep -E '^#define HAVE_(SSE|SSE2|SSE3|SSE4_1|SSE_INTRINSICS|NEON) ' "$B/config_simd.h" | awk '{printf "%s=%s ", $2, $3}')"
    if [ "$sub" = arm64ec-windows ]; then
        # ARM64EC must come out as NEON with every SSE path off (see the v3 note at the top).
        grep -qE '^#define HAVE_NEON 1' "$B/config_simd.h" &&
        ! grep -qE '^#define HAVE_SSE[0-9_A-Z]* 1' "$B/config_simd.h" ||
            { echo "ERROR: ARM64EC configure did not give NEON on / SSE off; see $B/setup.log"; exit 1; }
    fi
    "$NINJA" -C "$B" > "$B/build.log" 2>&1 || { grep -E "error|FAILED" "$B/build.log" | head -30; exit 1; }
    mkdir -p "$DEST/$sub"
    "$LLVM_MINGW/bin/$triple-strip" --strip-debug -o "$DEST/$sub/OpenAL32.dll" "$B/OpenAL32.dll"

    # Imports: Windows system DLLs only. libc++/libunwind/winpthread named first so the
    # message says what went wrong; then anything not on the allow list.
    local imports bad
    imports=$("$OBJDUMP" -p "$DEST/$sub/OpenAL32.dll" | awk '/DLL Name:/{print $3}')
    echo "$sub/OpenAL32.dll imports: $(echo $imports)"
    bad=$(echo "$imports" | grep -iE '^(libc\+\+|libunwind|libwinpthread)' || true)
    [ -z "$bad" ] || { echo "ERROR: $sub/OpenAL32.dll imports the toolchain runtime (-static did not take):"; echo "$bad"; exit 1; }
    bad=$(echo "$imports" | grep -viE '^(kernel32|ntdll|user32|advapi32|ole32|oleaut32|ws2_32|winmm|mmdevapi|ksuser|msvcrt|ucrtbase|api-ms-win-crt-.*|api-ms-win-core-.*|avrt|shell32|shlwapi|setupapi|dsound|combase|version|rpcrt4)\.dll$' || true)
    [ -z "$bad" ] || { echo "ERROR: unexpected imports in $sub/OpenAL32.dll:"; echo "$bad"; exit 1; }
    echo "$sub/OpenAL32.dll: $(wc -c < "$DEST/$sub/OpenAL32.dll") bytes"
}
# ARM64EC: an AArch64 build that keeps the x64 ABI. No SSE (clang cannot compile x86
# intrinsics for it); NEON required (mixer_neon.cpp and pffft's NEON branch).
build_one arm64ec-w64-mingw32 ARM64 arm64ec-windows \
    -DALSOFT_CPUEXT_SSE=OFF -DALSOFT_CPUEXT_SSE2=OFF -DALSOFT_CPUEXT_SSE3=OFF -DALSOFT_CPUEXT_SSE4_1=OFF \
    -DALSOFT_CPUEXT_NEON=ON -DALSOFT_REQUIRE_NEON=ON
# i686 (32-bit WOW64, run by the emulator): plain x86 build, unchanged by the patch; SSE2
# is required and used for float maths (upstream default), so the x87 asm is not used.
build_one i686-w64-mingw32 i686 i386-windows \
    -DALSOFT_REQUIRE_SSE2=ON -DALSOFT_ENABLE_SSE2_CODEGEN=ON

# 3. x18 check on the ARM64EC DLL (same forms as build/vkd3d-proton/build.sh).
out="$DEST/arm64ec-windows/OpenAL32.dll"
total=$("$OBJDUMP" -d "$out" 2>/dev/null | grep -cE '\bx18\b' || true)
odd=$("$OBJDUMP" -d "$out" 2>/dev/null | grep -E '\bx18\b' |
      grep -vE '\b(ldr|ldrb|ldrh|ldrsw|ldrsb|ldrsh|ldur|ldurb|ldurh|str|strb|strh|stur|sturb|sturh|ldp|stp)\b[^[]*\[x18' |
      grep -vE '\b(ldr|ldrb|ldrh|str|strb|strh)\b.*\[x[0-9]+, x18' |
      grep -vE '\b(mov|add|sub)\b +x[0-9]+, x18\b' | grep -vE '\badd\b +x[0-9]+, x[0-9]+, x18\b' || true)
echo "arm64ec-windows/OpenAL32.dll: $total x18 instructions"
[ -z "$odd" ] || { echo "WARNING: x18 instructions the load-time patcher may not rewrite:"; echo "$odd" | head -20; }

# 4. Licence texts (app/Madeira/licenses, a bundled folder). Fails loudly when missing.
LIC="${LIC_DEST:-$REPO_ROOT/app/Madeira/licenses}"
[ -d "$LIC" ] || { echo "licence folder $LIC missing"; exit 1; }
cp "$OAL_SRC/COPYING" "$LIC/OpenAL-Soft-LGPL-2.txt"
# Bundled code whose licences ask for the notice in binary copies: pffft (LICENSE-pffft)
# and the BSD-3-Clause parts (BSD-3Clause). fmt's licence has an exception for object code.
for f in LICENSE-pffft:OpenAL-Soft-pffft.txt BSD-3Clause:OpenAL-Soft-BSD-3-Clause.txt; do
    [ -f "$OAL_SRC/${f%%:*}" ] || { echo "ERROR: upstream has no ${f%%:*} at $OAL_TAG"; exit 1; }
    cp "$OAL_SRC/${f%%:*}" "$LIC/${f#*:}"
done
# HRTF: the 1.24.3 default data set is MIT KEMAR (docs/hrtf.txt). Apache-2.0 HRTF data came later upstream.
[ -f "$OAL_SRC/docs/hrtf.txt" ] || { echo "ERROR: upstream has no docs/hrtf.txt at $OAL_TAG"; exit 1; }
{ cat "$OAL_SRC/docs/hrtf.txt"; echo; echo "KEMAR HRTF data: Bill Gardner and Keith Martin, MIT Media Lab, 1994."; } > "$LIC/OpenAL-Soft-HRTF-KEMAR.txt"
# When the pinned tag moves past upstream cb3c3f34, it ships Apache-2.0 HRTF data: copy that licence too.
if [ -f "$OAL_SRC/LICENSE.Apache-2.0.txt" ]; then cp "$OAL_SRC/LICENSE.Apache-2.0.txt" "$LIC/OpenAL-Soft-HRTF-Apache-2.0.txt"; fi
echo "OpenAL Soft $OAL_TAG -> $DEST"
