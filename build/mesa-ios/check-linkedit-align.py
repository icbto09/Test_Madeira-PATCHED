#!/usr/bin/env python3
"""Fail unless a thin arm64 Mach-O dylib has the @rpath install name its build gives it and every
__LINKEDIT table offset dyld checks is 8-byte aligned (dyld: "mis-aligned LINKEDIT string pool")."""
import struct, sys
p = sys.argv[1]; d = open(p, 'rb').read(); off = 32; bad = []; name = None
assert struct.unpack_from('<I', d)[0] == 0xfeedfacf, 'not a thin 64-bit Mach-O'
for _ in range(struct.unpack_from('<I', d, 16)[0]):
    cmd, size = struct.unpack_from('<II', d, off)
    if cmd == 0x2:   # LC_SYMTAB
        symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', d, off + 8)
        bad += ['%s=%#x' % (n, v) for n, v in (('symoff', symoff), ('stroff', stroff)) if v % 8]
    elif cmd in (0x1d, 0x26, 0x29, 0x80000033, 0x80000034):   # code sig, function starts, data in code, exports trie, chained fixups
        v = struct.unpack_from('<I', d, off + 8)[0]
        if v % 8: bad.append('cmd %#x dataoff=%#x' % (cmd, v))
    elif cmd == 0xd:   # LC_ID_DYLIB
        n = struct.unpack_from('<I', d, off + 8)[0]
        name = d[off + n:off + size].split(b'\0')[0].decode()
    off += size
if bad: sys.exit('%s: LINKEDIT not 8-aligned: %s' % (p, ', '.join(bad)))
if name != '@rpath/libvulkan_kosmickrisp.dylib': sys.exit('%s: install name is %r' % (p, name))
print('%s: LINKEDIT offsets 8-aligned, install name %s' % (p, name))
