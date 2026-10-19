# m1132scan

Open-source scanner tool for the **HP LaserJet Professional M1132 MFP** on
macOS (Apple Silicon or Intel), with no HP software. It talks to the scanner
directly over USB using the protocol documented in [PROTOCOL.md](PROTOCOL.md).

## Use

```
m1132scan                                  # A4, colour, 300 dpi, PDF in ~/Downloads
m1132scan --mode gray --dpi 150            # greyscale
m1132scan --mode bw --format png           # black & white (1-bit)
m1132scan --size 100x150mm --offset 20x30mm --format jpg
m1132scan --size letter -o ~/Desktop/page.pdf
m1132scan --help
```

Put the page face down in the top-left corner of the glass. Ctrl-C cancels a
scan cleanly. Close the Image Capture app first if it is open.

| Option | Values | Default |
|---|---|---|
| `--size` | `a4`, `letter`, `max`, `WxHmm` | `a4` |
| `--offset` | `XxYmm` from the top-left corner | `0x0mm` |
| `--mode` | `color`, `gray`, `bw` | `color` |
| `--dpi` | 150, 300, 600, 1200 | 300 |
| `--format` | `pdf`, `png`, `jpg` | `pdf` (or from `-o`) |
| `-o` | output file | `~/Downloads/Scan <date> at <time>.<format>` |

Timing on the test unit: A4 colour at 150 or 300 dpi about 15 s of scanning,
600 dpi about 83 s. The glass is 11.22 in long, so A4 stops 0.47 in short of
the page's full 11.69 in.

## Build

```
swiftc -O -framework IOUSBHost -o m1132scan m1132scan.swift
```

Needs the Xcode command line tools only. Debug options: `--verbose` (USB trace),
`--raw DIR` (save the packet stream), `m1132scan probe` (read settings, no scan).

## Status

Tested on one M1132 with macOS 27.0.1 on Apple Silicon: colour and grey at
150/300/600 dpi, black & white, offset areas, cancel. Not yet tried: 1200 dpi.

Files: `m1132scan.swift` (the tool), `PROTOCOL.md` (protocol notes and test
results), `probe.swift` (first-contact probe), `tools/` (Mach-O analysis
scripts used to read HP's driver), `logs/` (USB traces of every test run; the
scanned images themselves are not published because they show a personal
document).

## License and trademarks

MIT, see [LICENSE](LICENSE). No HP code is included: the protocol was worked out
from HP's macOS driver for interoperability, then tested on the device.
HP and LaserJet are trademarks of HP Inc.; this project is not affiliated with
or endorsed by HP.
