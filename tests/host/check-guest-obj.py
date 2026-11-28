#!/usr/bin/env python3
"""ml-guest-obj: at a guest fault, the objects behind the live guest registers are
logged, and PRAGMATA's hash lookup (rva 0x4fdabe3) gets its table walked."""
import pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
failures = 0

def check(ok, what):
    global failures
    print(('ok   ' if ok else 'FAIL ') + what)
    if not ok:
        failures += 1

src = (ROOT / 'build/ntdll-unix/signal_arm64_ios.c').read_text(encoding='utf-8', errors='replace')
check('static void ios_guest_obj_probe( ucontext_t *context, uint64_t rip )' in src, 'the probe exists')
check('ios_guest_obj_probe( context, xrip );   /* ml-guest-obj */' in src, 'the guest fault path calls it')
check('getenv( "MADEIRA_GUEST_OBJ" )' in src, 'MADEIRA_GUEST_OBJ=0 turns it off')
check('0x4a,0x8b,0x0c,0xc1, 0x48,0x8b,0x09, 0x48,0x39,0x41,0x10' in src, 'the table walk is keyed on the lookup code bytes')
check('r13 + 0x108' in src and 'r13 + 0x98' in src, 'it follows the caller\'s table and key source')
cat = (ROOT / 'app/Madeira/ConfigCatalog.generated.swift').read_text(encoding='utf-8')
check('key: "env.MADEIRA_GUEST_OBJ"' in cat, 'the config catalog documents env.MADEIRA_GUEST_OBJ')

print(f'check-guest-obj: {"OK" if not failures else f"{failures} FAILED"}')
sys.exit(1 if failures else 0)
