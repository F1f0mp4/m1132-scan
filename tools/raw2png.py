"""Convert m1132scan pixels.raw to PNGs under different layout guesses (no external libs)."""
import sys, zlib, struct
def png(path, w, h, rows, mode):  # rows: list of bytes, mode 'RGB' or 'L'
    ct = 2 if mode == 'RGB' else 0
    raw = b''.join(b'\0' + r for r in rows)
    def chunk(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    open(path, 'wb').write(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, ct, 0, 0, 0))
                           + chunk(b'IDAT', zlib.compress(raw, 6)) + chunk(b'IEND', b''))
src, out, W = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = open(src, 'rb').read()
lines = [d[i:i + W] for i in range(0, len(d) - W + 1, W)]   # one channel-line each
H = len(lines) // 3
for name, order in (('lines-RGB', (0, 1, 2)), ('lines-BGR', (2, 1, 0))):
    rows = []
    for y in range(H):
        p = [lines[3 * y + k] for k in order]
        rows.append(bytes(b for px in zip(*p) for b in px))
    png(f'{out}/{name}.png', W, H, rows, 'RGB')
png(f'{out}/channel0-gray.png', W, H, [lines[3 * y] for y in range(H)], 'L')
print('lines:', len(lines), 'image rows:', H, 'width:', W)
