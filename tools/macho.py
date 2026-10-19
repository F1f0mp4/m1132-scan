"""Minimal x86_64 Mach-O reader: sections, vmaddr->bytes, cfstring table."""
import struct, sys
class MachO:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        magic, cpu, sub, ft, ncmds, sz, flags, _ = struct.unpack_from('<IiiIIIII', self.d, 0)
        assert magic == 0xfeedfacf, hex(magic)
        self.sects = []
        off = 32
        for _ in range(ncmds):
            cmd, csz = struct.unpack_from('<II', self.d, off)
            if cmd == 0x19:  # LC_SEGMENT_64
                nsects = struct.unpack_from('<I', self.d, off + 64)[0]
                so = off + 72
                for i in range(nsects):
                    sn, sg, addr, size, foff = struct.unpack_from('<16s16sQQI', self.d, so)
                    self.sects.append((sg.rstrip(b'\0').decode(), sn.rstrip(b'\0').decode(), addr, size, foff))
                    so += 80
            off += csz
    def sect(self, seg, name):
        for s in self.sects:
            if s[0] == seg and s[1] == name: return s
    def read(self, addr, n):
        for sg, sn, a, size, foff in self.sects:
            if a <= addr < a + size and foff:
                o = foff + (addr - a); return self.d[o:o + n]
        return None
    def cstr(self, addr):
        b = self.read(addr, 4096)
        return b.split(b'\0', 1)[0].decode('latin-1') if b else None
    def u64(self, addr): return struct.unpack('<Q', self.read(addr, 8))[0]
    def u32(self, addr): return struct.unpack('<I', self.read(addr, 4))[0]
    def cfstrings(self):
        s = self.sect('__DATA', '__cfstring'); out = {}
        if not s: return out
        for a in range(s[2], s[2] + s[3], 32):
            isa, flags, ptr, ln = struct.unpack('<QQQQ', self.read(a, 32))
            txt = self.read(ptr, ln)
            out[a] = txt.decode('latin-1') if txt else '?'
        return out
if __name__ == '__main__':
    m = MachO(sys.argv[1])
    for a, t in sorted(m.cfstrings().items()): print('%x\t%r' % (a, t))
