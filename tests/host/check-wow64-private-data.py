#!/usr/bin/env python3
"""Host check: wow64_NtUserCallHwndParam converts Get/SetPrivateData pointers.
Usage: python3 -I check-wow64-private-data.py <path to wine/dlls/wow64win/user.c>"""
import os, re, sys
root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "wine", "dlls", "wow64win", "user.c")
s = open(src).read()
start = s.index("NTSTATUS WINAPI wow64_NtUserCallHwndParam( UINT *args )")
body = s[start:s.index("\n}\n", start)]
dflt = body.index("default:")
ok = True
for code in ("NtUserCallHwndParam_GetPrivateData", "NtUserCallHwndParam_SetPrivateData"):
    m = re.search(r"case %s:" % code, body)
    if not m or m.start() > dflt:
        print("FAIL: no case for", code); ok = False
seg = body[body.find("case NtUserCallHwndParam_GetPrivateData:"):dflt] if ok else ""
if ok and "guest_ptr32( param )" not in seg:
    print("FAIL: private data param not converted with guest_ptr32"); ok = False
if ok and "wow64_private_data_enabled()" not in seg:
    print("FAIL: no off switch"); ok = False
if "MADEIRA_WOW64_PRIVATE_DATA" not in s:
    print("FAIL: off switch name missing"); ok = False
print("PASS" if ok else "FAILED")
sys.exit(0 if ok else 1)
