"""Print one function from annotated otool output. usage: fn.py dis.txt 'name' [filter-regex]"""
import re, sys
lines = open(sys.argv[1]).read().split('\n'); name = sys.argv[2]
flt = re.compile(sys.argv[3]) if len(sys.argv) > 3 else None
start = next((i for i, l in enumerate(lines) if l == name + ':'), None)
if start is None: sys.exit('not found: ' + name)
for l in lines[start:]:
    if l != lines[start] and re.match(r'^([-+]\[.*\]|_\w.*|__\w.*):$', l): break
    if not flt or flt.search(l) or l == lines[start]: print(l)
