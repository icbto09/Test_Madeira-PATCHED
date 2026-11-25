#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
#
# Graphics versions (app/Madeira/GraphicsVersions.swift, WineProcessBridge.m
# madeira_vulkan_version_dir): DXVK and vkd3d-proton builds besides the bundle's.
#
#  - madeira_pe_arch_path, compiled on its own, names x64, ARM64EC (AMD64 machine with a CHPE
#    metadata pointer), ARM64, ARM64X, i386, and refuses files that are not PE images.
#  - The Swift labeller (GraphicsVersions.peArch) reads the same fields.
#  - The keys, folders and DLL names agree between the app and the native side.
#  - GraphicsVersions.swift is in the app target, the catalog lists both keys, and the
#    Settings and Game details pages link to the picker.
#  - The version builder workflow only runs by hand.
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
APP = os.path.join(ROOT, "app", "Madeira")
failed = False


def check(ok, what):
    global failed
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failed = True


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def pe(machine, chpe=0, lc=True, magic=0x20B):
    """A minimal PE: DOS header, COFF header, PE32+ optional header, one section holding a load config."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    opt_size = 0xF0
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, opt_size, 0x2022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, magic)
    sec_raw = 0x200
    lc_rva = 0x1000
    if lc:
        struct.pack_into("<II", opt, 112 + 10 * 8, lc_rva, 0x140)   # IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
    section = bytearray(40)
    section[0:8] = b".rdata\0\0"
    struct.pack_into("<IIII", section, 8, 0x200, lc_rva, 0x200, sec_raw)
    head = bytes(dos) + coff + bytes(opt) + bytes(section)
    body = bytearray(0x200)
    struct.pack_into("<I", body, 0, 0x140)
    struct.pack_into("<Q", body, 0xC8, chpe)
    return head + bytes(sec_raw - len(head)) + bytes(body)


src = read("app", "Madeira", "WineProcessBridge.m")
m = re.search(r"static const char \*madeira_pe_arch_path\(const char \*path\)\n\{.*?\n\}\n", src, re.S)
check(m is not None, "WineProcessBridge.m has madeira_pe_arch_path")

cases = {
    "x64": pe(0x8664),
    "x64-nolc": pe(0x8664, lc=False),
    "ARM64EC": pe(0x8664, chpe=0x180012340),
    "ARM64": pe(0xAA64),
    "ARM64X": pe(0xAA64, chpe=0x180012340),
    "i386": pe(0x14C, magic=0x10B),
    "notpe": b"hello, this is not a PE file" + bytes(64),
    "pe32-amd64": pe(0x8664, magic=0x10B),
}
expect = {"x64": "x64", "x64-nolc": "x64", "ARM64EC": "ARM64EC", "ARM64": "ARM64", "ARM64X": "ARM64X",
          "i386": "i386", "notpe": "not a PE file", "pe32-amd64": "unknown machine", "missing": "missing"}

if m:
    with tempfile.TemporaryDirectory(prefix="madeira-vulkan-versions-") as tmp:
        for name, data in cases.items():
            with open(os.path.join(tmp, name + ".dll"), "wb") as f:
                f.write(data)
        c = os.path.join(tmp, "check.c")
        with open(c, "w") as f:
            f.write("#include <fcntl.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n"
                    "#include <unistd.h>\n#include <sys/types.h>\n" + m.group(0) +
                    "int main(int argc, char **argv) { for (int i = 1; i < argc; i++) "
                    "printf(\"%s\\n\", madeira_pe_arch_path(argv[i])); return 0; }\n")
        exe = os.path.join(tmp, "check")
        r = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", c, "-o", exe],
                           capture_output=True, text=True)
        check(r.returncode == 0, "madeira_pe_arch_path compiles on its own" + ("" if r.returncode == 0 else ":\n" + r.stderr))
        if r.returncode == 0:
            names = list(cases) + ["missing"]
            out = subprocess.run([exe] + [os.path.join(tmp, n + ".dll") for n in names],
                                 capture_output=True, text=True).stdout.splitlines()
            for n, got in zip(names, out):
                check(got == expect[n], f"{n}: {got!r} (want {expect[n]!r})")

sw = read("app", "Madeira", "GraphicsVersions.swift")
check("0xC8" in sw and "0x20B" in sw and "112 + 80" in sw and "0x8664" in sw and "0xAA64" in sw and "0x14C" in sw,
      "GraphicsVersions.peArch reads the same PE fields (CHPE pointer at load config + 0xC8)")
check('"dxvk-version"' in sw and '"vkd3d-version"' in sw, "Swift keys dxvk-version and vkd3d-version")
check('madeira_vulkan_version_dir("dxvk-version", "dxvk", @[@"d3d11.dll", @"dxgi.dll"],' in src
      and '@[@"d3d10core.dll"]' in src, "native DXVK version: d3d11.dll + dxgi.dll required, d3d10core.dll optional")
check('madeira_vulkan_version_dir("vkd3d-version", "vkd3d", @[@"d3d12.dll"],' in src
      and '@[@"d3d12core.dll"]' in src, "native vkd3d version: d3d12.dll required, d3d12core.dll optional")
check('["d3d11.dll", "dxgi.dll"]' in sw and '["d3d10core.dll"]' in sw and '["d3d12.dll"]' in sw and '["d3d12core.dll"]' in sw,
      "Swift kinds list the same required and optional DLLs")
check('appendingPathComponent("vulkan-versions"' in sw and '@"vulkan-versions"' in src,
      "both sides use Documents/vulkan-versions/<kind>")
check('case dxvk, vkd3d' in sw and '"dxvk-version", "dxvk",' in src and '"vkd3d-version", "vkd3d",' in src,
      "kind folder names are dxvk and vkd3d on both sides")
check('strcasecmp(v, "bundled")' in src and '"bundled"' in sw, "\"bundled\" means the bundle's build on both sides")
check("strchr(v, '/')" in src and '".."' in src, "native side refuses values that are not a plain folder name")

pbx = read("app", "Madeira.xcodeproj", "project.pbxproj")
check(pbx.count("GraphicsVersions.swift in Sources") == 2 and pbx.count("/* GraphicsVersions.swift */") >= 3,
      "GraphicsVersions.swift is in the app target (build file, file reference, group, sources)")
ids = re.findall(r"^\t\t([0-9A-F]{8,24}) /\*", pbx, re.M)
check(len(ids) == len(set(ids)), "project object IDs are unique")

cat = read("app", "Madeira", "ConfigCatalog.generated.swift")
check('key: "dxvk-version"' in cat and 'key: "vkd3d-version"' in cat, "the config catalog lists both keys")

lib = read("app", "Madeira", "Library.swift")
check("GraphicsVersionsView(scope: .global, only: kind)" in lib, "Settings › Graphics links to the version pickers")
check("GraphicsVersionsView(scope: .game(windowsPath: entry.windowsPath))" in lib,
      "Game details › Advanced links to this game's Graphics versions")

wf = read(".github", "workflows", "graphics-versions.yml")
on = re.search(r"^on:\n((?:  .*\n|\n)+)", wf, re.M)
check(on is not None and re.findall(r"^  (\w+):", on.group(1), re.M) == ["workflow_dispatch"],
      "graphics-versions.yml runs by hand only (workflow_dispatch)")
check("DXVK_REF" in read("build", "dxvk", "build.sh") and "VKD3D_REF" in read("build", "vkd3d-proton", "build.sh"),
      "the DXVK and vkd3d-proton build scripts take a ref to build")

if failed:
    print("FAILED")
    sys.exit(1)
print("PASS")
