import sys, struct, re
sys.path.insert(0, sys.argv[1]); from macho import MachO
m = MachO(sys.argv[2]); dis = open(sys.argv[3]).read().split('\n')
base = 0x10000b344
names = {0x10000b1f7: 'handleStartScanJob', 0x10000b21a: 'log only (ignored)', 0x10000b22d: 'handleStartPage',
         0x10000b244: 'handleEndPage', 0x10000b25b: 'reply sendMessage(0x18)', 0x10000b280: 'log only (ignored) #2',
         0x10000b289: 'handleEndJob -> done', 0x10000b2ad: 'handleAbortScan', 0x10000b2d6: 'handleScanData:',
         0x10000b2d1: 'default: error 0x3ea'}
for i in range(21):
    off = struct.unpack('<i', m.read(base + 4 * i, 4))[0]
    t = base + off
    print('msg %2d (0x%02x) -> %x  %s' % (i + 4, i + 4, t, names.get(t, '?')))
# log strings at each case
for a in sorted(names):
    for l in dis:
        if l.startswith('%016x' % a) and 'cfstring' in l: print('  %x: %s' % (a, l.split('## ')[-1][:90]))
f = struct.unpack('<f', m.read(0x10000b453 + 8 + 0x71dd, 4))[0]
print('scan-window divisor float =', f)
