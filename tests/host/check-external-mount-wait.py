#!/usr/bin/env python3
"""Host check for external-mount-wait. Usage: python3 -I check-external-mount-wait.py <ContentView.swift> <ExternalDrives.swift>"""
import os, sys
root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
cv = open(sys.argv[1] if len(sys.argv) > 2 else os.path.join(root, "app/Madeira/ContentView.swift")).read()
ed = open(sys.argv[2] if len(sys.argv) > 2 else os.path.join(root, "app/Madeira/ExternalDrives.swift")).read()
i = cv.index("private func startWineserver()"); body = cv[i:cv.index("private func startWineProcess()", i)]
checks = [
 ("off switch", 'MadeiraConfig.flag("MADEIRA_EXTERNAL_MOUNT_WAIT", fallback: true)' in body),
 ("bounded wait", "mounted.wait(timeout: .now() + 10)" in body),
 ("own thread", "Thread { mount() }" in body),
 ("old path kept", body.count("ExternalDrives.shared.mountAll()") == 2),
 ("mount before wineserver_start", body.rindex("mountAll()") < body.index("wineserver_start(")),
 ("step log opening", '): opening")' in ed),
 ("step log opened", '): opened")' in ed),
 ("step log links done", "links done; listing Steam libraries" in ed),
]
ok = True
for name, good in checks:
    if not good: print("FAIL:", name); ok = False
print("PASS" if ok else "FAILED"); sys.exit(0 if ok else 1)
