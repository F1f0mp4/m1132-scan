# HP LaserJet Professional M1132 MFP — USB scan protocol

Notes from static analysis of HP's macOS Image Capture module
`/Library/Image Capture/Devices/HP M1130_M1210 Scanner.app` (x86_64 slice,
2017 build, from Apple's "HP Printer Drivers 5.1.1" package). HP calls this the
"Marvell" scan protocol; on Linux the same protocol is implemented only by the
closed HPLIP plugin `bb_marvell.so`.

**Status:** derived from disassembly. The session commands (§3: `0x15`, Lock,
GetScanJobSettings, Unlock), the message header (§2) and the settings block
(§4) were **confirmed on a real M1132 on 2026-10-19** with `probe.swift`; see
§10 and `logs/probe-run1.log`. A first 150 dpi colour scan (§11, `logs/run1.log`) confirmed the scan stream (§5)
and the image format (§6). Items still marked *unverified* need confirming on
the device.

Method: `otool -ov` (Objective-C metadata, which keeps class, method, ivar and
struct type names), `otool -tV` disassembly, and a small Mach-O reader to
resolve `CFString` constants that otool could not (see `tools/`). Addresses
below refer to the x86_64 slice.

---

## 1. Transport

| Item | Value | Source |
|---|---|---|
| USB device | VID `0x03F0`, PID `0x042A` | ioreg on the test machine |
| Scan interface | the one with class/subclass/protocol **FF/FF/FF** (interface 2 on the test unit, 3 endpoints) | `_get_usb_interfaceclass` @ `0x10000bbd4` |
| Other interfaces | 7/1/2 = printer (interface 0), FF/02/10 = "EWS" (interface 1), FF/01/00 = "Fax" | same function |
| Pipes | first **bulk OUT** and first **bulk IN** endpoint of that interface | `-[USBInterface open]` |
| Device URI used by HP | `usb://3f0/42a/SCAN` (format `%s%x/%x/SCAN`) | `-[MarvellScanner openUSBDevce]` |
| Network models | same protocol over TCP port **8290** (`net://host:port`) | `DeviceMatchingInfo.plist`, `TCPInterface` |
| Read timeouts | 60 000 ms no-data and completion timeout on every read | `-[ScanProtocol readToBuffer:readSize:]` |

HP's `USBInterface` keeps any bytes a bulk read returned beyond what the caller
asked for (`fillExtraDataBuffer…`, `copyExtraDataBytes…`) and serves them to
the next read. **Treat the IN pipe as a byte stream**, not as one message per
transfer.

All multi-byte integers on the wire are **32-bit big-endian**.

## 2. Message header (32 bytes)

Every command, every reply and every packet in the scan stream starts with this
header. Built by `initScanHeader:in_Message:[in_Param1:in_Param2:]`
(`0x100009a10`, `0x100009a3e`); decoded by `convertScanHeaderToHost:`.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0x00 | 4 | magic | bytes `41 53 50 01` ("ASP\x01"), i.e. `0x41535001` big-endian. Replies are checked against it ("Bad cookie"). |
| 0x04 | 4 | message ID | see §3 and §5 |
| 0x08 | 4 | param1 | 0 in every call site found |
| 0x0C | 4 | param2 | 0 in every call site found |
| 0x10 | 4 | status | in replies: **0 = OK** |
| 0x14 | 4 | payload length | bytes that follow the header (100 for job settings, data size for image packets) |
| 0x18 | 4 | reserved | 0 |
| 0x1C | 4 | reserved | 0 |

Request/reply rule (`sendMessageAndReturn:`): the reply's magic must match and
its message ID must **echo the request's ID**; then status at 0x10 is checked.

## 3. Commands (computer → scanner)

| ID | Name (from HP strings where present) | Reply? | Notes |
|---|---|---|---|
| `0x00` | Lock | yes | Retried until status = 0, for at most 30 s (`lockScanner`) |
| `0x01` | Unlock | yes | |
| `0x02` | StartScan | yes | After an OK reply the scan packet stream (§5) begins on the IN pipe |
| `0x03` | CancelScanJob | no (not read) | |
| `0x06` | e_GetScanJobSettings | yes + 100-byte payload | Reply header has length 100 at 0x14, then the §4 block |
| `0x07` | SetScanJobSettings | yes | Header with length 100 at 0x14, **followed by** the 100-byte §4 block (132 bytes written in one transfer). Reply ID must be 7 and status 0. |
| `0x08` | e_SetDefaultScanJobSettings | yes | |
| `0x0F` | ADF paper status | yes | Sibling models only; the M1132 has no feeder |
| `0x15` | *unknown* | no (not read) | Sent once right before the Lock loop. *Unverified:* whether the scanner answers it. If it does, that reply would sit in front of the Lock reply. |
| `0x18` | ack for e_NewScanPage | no | Sent when packet `0x18` arrives during a scan |

## 4. Scan job settings block (100 bytes, 25 × int32 BE)

Layout from the Objective-C type string `SCAN_JOB_SETTINGS` and the
`setScanJobSettings:` / `getScanJobSettings:` byte-swapping code.

| Offset | Field | What HP's driver puts there |
|---|---|---|
| 0x00 | Gamma | from device defaults |
| 0x04 | Brightness | from device defaults |
| 0x08 | Contrast | from device defaults |
| 0x0C | **Resolution** (dpi) | user's choice; fallback 300. Flatbed offers 150 / 300 / 600 / 1200 |
| 0x10 | XYScale.x_numerator | defaults |
| 0x14 | XYScale.x_denominator | defaults |
| 0x18 | XYScale.y_numerator | defaults |
| 0x1C | XYScale.y_denominator | defaults |
| 0x20 | Sharp | defaults |
| 0x24 | Smooth | defaults |
| 0x28 | BitsPerPixel | defaults (capabilities list bit depth 1 or 8) |
| 0x2C–0x38 | reserved1–4 | defaults |
| 0x3C | DataType | defaults |
| 0x40 | **scan_window.top** | 1/100 inch |
| 0x44 | **scan_window.left** | 1/100 inch |
| 0x48 | **scan_window.bottom** | 1/100 inch |
| 0x4C | **scan_window.right** | 1/100 inch |
| 0x50 | ScannableArea.top | read-only limits reported by the device |
| 0x54 | ScannableArea.left | |
| 0x58 | ScannableArea.bottom | |
| 0x5C | ScannableArea.right | |
| 0x60 | **ColorType** | 0 or 1 (see below); HP's value 3 = black & white is sent as 0 and thresholded on the host |

HP's sequence never builds this block from scratch: it sends `0x08` (reset to
defaults), reads it back with `0x06`, edits Resolution, the scan window and
ColorType, and writes it with `0x07`. If the requested window falls outside
ScannableArea, HP replaces it with the whole ScannableArea.

Units: in `handleStartScanJob` HP computes rows = (bottom − top) / 100.0 × dpi,
so the window is in **hundredths of an inch**. The capability plist gives the
glass as 81664 × 112265 in 1/10000 inch (8.17 × 11.23 in), so ScannableArea
should read back as about 0, 0, 1122, 816 (*unverified*).

ColorType: `setSelectedFunctionalUnitParams:` writes 0 when Image Capture's
current scan mode is 0 and 1 otherwise. Which of 0/1 is colour and which is
grey is *unverified*; the DataType in the image packets (§6) tells them apart.

## 5. Scan packet stream (scanner → computer)

After StartScan, HP loops on `readNextPacket:` (`0x10000b113`): read one 32-byte
header, check magic, dispatch on message ID (jump table at `0x10000b344`,
IDs 4–24). Names come from HP's own log strings.

| ID | Name | Extra bytes after header | HP's action |
|---|---|---|---|
| `0x04` | e_AbortScanJob | 0 | abort, unlock |
| `0x05` | **e_ScanImageData** | header.length: 24-byte data header + pixels | §6 |
| `0x09` | e_StartJob | 100 (settings block as applied) | reads dpi (0x0C), ColorType (0x60), window → expected row count |
| `0x0A` | e_StartSheet | 0 | ignored |
| `0x0B` | e_StartPage | 0 | opens output file |
| `0x0C` | e_EndJob | 0 | finished; loop ends |
| `0x0D` | e_EndSheet | 0 | ignored |
| `0x0E` | e_EndPage | 0 | closes output file |
| `0x18` | e_NewScanPage | 0 | host replies with command `0x18` |
| other | — | — | treated as protocol error |

Order for one flatbed page, **confirmed**: `StartJob` (length 100) →
`StartSheet` → `StartPage` → `ScanImageData` × N → `EndPage` → `EndSheet` →
`EndJob`. No `e_NewScanPage` was sent for a single flatbed page.

## 6. Image data packets (`0x05`)

`handleScanData:` (`0x10000b6f0`) reads a 24-byte data header (6 × int32 BE),
then `header.length − 24` bytes of image data, which it writes to disk
unchanged. The image is later built with `CGImageCreate` over a plain data
provider; there is no JPEG or other decoder in the module, so the payload is
**raw, uncompressed pixel rows**.

| Data header offset | Field | Meaning |
|---|---|---|
| 0x00 | DataType | HP's channel count: 6 → 1 (grey), 1 → 4, 0 / 10 / 12 / other → 3. Seen: **10 = 8-bit RGB, line-interleaved**; **6 = 8-bit grey** |
| 0x04 | first line index | index of this packet's first *channel line* (0, 45, 90, …) — confirmed |
| 0x08 | lines in this packet | counts **channel lines**, i.e. 3 per RGB image row — confirmed |
| 0x0C | bytes per component | 1 seen |
| 0x10 | width? | colour: always equal to the padded stride (608, 1248, 2480); grey: the real width (600 for a 608 stride). Not reliable; crop to the requested width instead |
| 0x14 | pixels per row (stride) | padded up to a multiple of 16: 600 → 608, 1240 → 1248, 2480 → 2480 |

Colour data (type 10) is **line-interleaved**: each image row is sent as a red
line, then a green line, then a blue line, each `pixels per row` bytes. Pixel
interleaving gives a smeared image; R,G,B line order gives correct colours.
Rows are padded on the right (600 → 608 at 150 dpi / 4 in); crop to
dpi × width / 100.

## 7. HP's full session

1. Open the FF/FF/FF interface (`mvOpenDevice`). No message is sent.
2. Lock: send `0x15` (no reply read), then `0x00` until status = 0 (≤ 30 s).
3. `0x08` SetDefaultScanJobSettings.
4. `0x06` GetScanJobSettings: read defaults, scannable area.
5. When the user clicks Scan: Lock again (no-op if already locked), `0x07`
   SetScanJobSettings with the edited block, `0x02` StartScan, then read the §5
   stream until `e_EndJob`.
6. Close: `0x01` Unlock, close the interface.

## 8. Open questions for the first device tests

1. ~~Does the scanner reply to `0x15`?~~ No (§10).
2. ~~Values of every settings field, and the real ScannableArea.~~ Read (§10);
   ScannableArea overstates the glass length. Defaults after `0x08` still unread.
3. Which ColorType value is colour and which is grey, and the matching DataType
   and bytes-per-component values.
4. The two unknown data-header fields (0x04, 0x10), and whether rows are padded.
5. Packet order during a scan, and how long the lamp warm-up / calibration takes
   before the first data packet (60 s read timeouts suggest it can be slow).
6. Whether Image Capture's own HP module must be quit first so it doesn't hold
   the interface.

## 9. Proposed first contact (lowest risk, nothing moves)

Open the FF/FF/FF interface only (printing uses interface 0 and is not
touched) → `0x15` and drain → `0x00` Lock → `0x06` GetScanJobSettings and dump
the 100 bytes → `0x01` Unlock → close. No StartScan, so the lamp and motor stay
off. A real 150 dpi scan comes only after these replies match this document.

## 10. First-contact results (2026-10-19, macOS 27.0.1, Apple Silicon)

Tool: `probe.swift` (IOUSBHost, native arm64). Full byte log: `logs/probe-run1.log`.
The Image Capture app was not running; printing on interface 0 kept working.

- Scan interface 2 has exactly two endpoints: bulk OUT `0x05` and bulk IN
  `0x85`, both max packet 512 (USB 2.0 high speed). No interrupt endpoint.
- `0x15`: **no reply** within 1.5 s. Open question 1 answered: it is fire-and-forget.
- `0x00` Lock: granted on the first attempt. Reply = header echoing ID 0, status 0, length 0.
- `0x06` GetScanJobSettings: reply header with **length 100 at 0x14**, then the
  100-byte block. No extra bytes after it.
- `0x01` Unlock: reply echoes ID 1, status 0.
- Every reply's magic was `41 53 50 01`. Reply param1/param2 were 0.

Current settings as read back (these are the device's, not HP's defaults; `0x08` was not sent):

| Field | Value | Notes |
|---|---|---|
| Gamma | 24 | likely gamma 2.4 |
| Brightness / Contrast | 6 / 6 | |
| Resolution | 150 | |
| XYScale | 1/1, 1/1 | |
| Sharp / Smooth | 0 / 0 | |
| BitsPerPixel | 8 | |
| reserved1–3 | 0 | |
| reserved4 | 256 | non-zero; keep it as read |
| DataType | 2 | |
| scan_window | 0, 0, 1500, 850 | |
| ScannableArea | 0, 0, **1500, 850** | |
| ColorType | 1 | |

Findings:

- Width 850 = 8.50 in matches the glass. **Bottom 1500 = 15.00 in is longer
  than the glass** (8.17 × 11.23 in per HP's plist). The firmware seems to report
  a generic limit, so a client must clamp the window to about 1122 itself, as HP's
  driver does with its plist sizes.
- The window equalling ScannableArea fits HP's "fall back to the whole area" logic.
- ColorType 1 with DataType 2 is the current mode. Which mode that is (colour or grey) is
  still to be seen from the first image packet's DataType (§6).

## 11. First scan (2026-10-19, `m1132scan scan run1 150 400 300`)

Log: `logs/run1.log`. (Raw stream and image are not published: they show a personal document.)

- Sequence used, all replies status 0: `0x15`, Lock, `0x08` SetDefault,
  `0x06` Get, `0x07` Set (132 bytes), `0x06` Get (to confirm), `0x02` StartScan.
- **Defaults after `0x08`:** Resolution **600**, window 0, 0, **1100, 850**
  (8.5 × 11 in), reserved4 **0** (it was 256 before the reset), everything else as in §10.
  ScannableArea still reports bottom 1500.
- `0x07` was accepted unchanged: read-back and the `e_StartJob` payload both
  matched the block that was sent (150 dpi, window 0, 0, 300, 400, ColorType 1, DataType 2).
- Timing: `e_StartJob` at once, `e_StartSheet`/`e_StartPage` 0.13 s, first
  data 1.24 s, then one packet every ~0.13 s; whole job 5.1 s for 4 × 3 in.
- 30 × `e_ScanImageData`, each length 27 384 = 24-byte data header + 27 360 bytes
  = 45 channel lines × 608 bytes = 15 RGB rows. Data header: type 10, first line
  0, 45, …, 1305, lines 45, bytes/comp 1, field 0x10 = 608, px/row 608.
- 1350 channel lines → **600 × 450 px RGB** after de-interleaving and cropping —
  exactly 4 × 3 in at 150 dpi. Image is sharp with correct colours.
- So **ColorType 1 + DataType 2 = colour**.

## 12. Full page, 300 dpi and grey (2026-10-19)

All three runs: every reply status 0, packet order as in §5, settings read back
exactly as sent, clean unlock, printing unaffected. Page length was capped at the
device's own default bottom (1100 = 11 in after `0x08`), not at the reported
ScannableArea (1500).

| Run | Command | Result | Time (StartPage → EndJob) | Data packets |
|---|---|---|---|---|
| `run2-a4-150` | `scan … 150 827 1169 color` | 1240 × 1650 px RGB (8.27 × 11 in), stride 1248 | 15.4 s | 110 × 45 lines |
| `run3-a4-300` | `scan … 300 827 1169 color` | 2480 × 3300 px RGB, stride 2480 | 15.4 s | 220 × 45 lines |
| `run4-gray`   | `scan … 150 400 300 gray`   | 600 × 450 px grey, stride 608 | 1.7 s | 45 × 10 rows |

- Colour packets always carry 45 channel lines (15 RGB rows); their size grows
  with width (56 160 B at 1248, 111 600 B at 2480).
- Scan time does not change between 150 and 300 dpi in colour: the head runs at
  one speed and only the data rate doubles (~1.6 MB/s at 300 dpi).
- **ColorType 0 = grey**: DataType in the packets becomes 6, one 8-bit channel,
  10 rows per packet. Grey scans the same area about 3× faster than colour.
- 300 dpi detail is sharp with no colour fringing, so the R/G/B line order and
  alignment are right at that resolution too.

Still open: black & white (HP sends ColorType 0 and thresholds on the host, so
this is grey + threshold), 600 and 1200 dpi, a window with top/left ≠ 0, and
cancel (`0x03`) mid-scan.

## 13. Offset, cancel, 600 dpi and output (2026-10-19, `m1132scan` CLI)

- **Offset window works.** `--size 50x50mm --offset 100x150mm` (window 591, 394,
  788, 591) gave the same region as a crop of the full-page scan, about 1 mm
  (6 px at 150 dpi) lower. The head travels to the offset first (4 s for 15 cm).
- **Row width is rounded by the firmware** to a multiple of 16 px, sometimes up
  (600 → 608, 1240 → 1248) and sometimes down (295 → 288, 1181 → 1168). A client
  must accept a stride narrower than requested; m1132scan keeps
  min(requested, stride).
- **The last packet can overrun the window**: 300 rows arrived for a 295-row
  window (grey packets are 10 rows). Trim to (bottom − top) × dpi / 100.
- **Cancel:** after `0x03` no further image packets arrive; the scanner replies
  with **`e_AbortScanJob` (0x04)**, not `e_EndJob`, about 4.7 s later (the head
  returning). Unlock and a following session both work normally.
  Tested with `--cancel-after 5` and with SIGINT (Ctrl-C).
- **600 dpi colour A4:** 4960 × 6732 px (8.27 × 11.22 in) in 83 s, so the head
  moves much slower than at 150/300 dpi (15 s). Peak memory of m1132scan:
  425 MB. 1200 dpi (≈ 4× the data) has not been tried.
- **Grey 300 dpi** of a 100 mm square took 13 s: grey is only faster than colour at 150 dpi.
- **Page length:** scans are capped at 1122 (11.22 in), HP's physical glass height;
  A4 runs to that limit without trouble.
- Black & white = grey scan + threshold at 128 on the host (as HP does);
  PNG/PDF store it as 1-bit.
