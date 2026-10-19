"""Replace otool's 'bad cfstring ref' with the real string (rip-relative target)."""
import re, sys
cf = {}
for line in open(sys.argv[1]):
    a, t = line.rstrip('\n').split('\t', 1); cf[int(a, 16)] = t
lines = open(sys.argv[2]).read().split('\n')
addr_re = re.compile(r'^([0-9a-f]{16})\t')
rip_re = re.compile(r'(-?0x[0-9a-f]+)\(%rip\)')
out = []
for i, l in enumerate(lines):
    if 'bad cfstring ref' in l:
        m = rip_re.search(l)
        nxt = None
        for j in range(i + 1, min(i + 4, len(lines))):
            mm = addr_re.match(lines[j])
            if mm: nxt = int(mm.group(1), 16); break
        if m and nxt:
            tgt = nxt + int(m.group(1), 16)
            l = l.replace('@"bad cfstring ref"', '@' + cf.get(tgt, '<%x?>' % tgt))
    out.append(l)
open(sys.argv[3], 'w').write('\n'.join(out))
