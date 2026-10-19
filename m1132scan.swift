// m1132scan: open-source scanner tool for the HP LaserJet Professional M1132 MFP.
// Native arm64, Apple frameworks only (IOUSBHost, CoreGraphics, ImageIO).
// Protocol notes: PROTOCOL.md.
//
//   m1132scan [options]          scan and save to ~/Downloads (see --help)
//   m1132scan probe              lock, read settings, unlock (no motion)
//
// Build: swiftc -O -framework IOUSBHost -o m1132scan m1132scan.swift

import Foundation
import IOKit
import IOUSBHost

let vendorID = 0x03F0, productID = 0x042A
let magic: UInt32 = 0x4153_5001

var verbose = false
/// Protocol trace; printed only with --verbose.
func log(_ s: String) { if verbose { print(s); fflush(stdout) } }
/// Messages for the person running the tool.
func say(_ s: String, terminator: String = "\n") { FileHandle.standardError.write((s + terminator).data(using: .utf8)!) }
func hex(_ d: Data) -> String {
    stride(from: 0, to: d.count, by: 16).map { o in
        let row = d[d.startIndex + o ..< d.startIndex + min(o + 16, d.count)]
        return String(format: "  %04x  ", o) + row.map { String(format: "%02x", $0) }.joined(separator: " ")
    }.joined(separator: "\n")
}
func be32(_ d: Data, _ off: Int) -> UInt32 {
    d[d.startIndex + off ..< d.startIndex + off + 4].reduce(0) { $0 << 8 | UInt32($1) }
}
func header(_ msg: UInt32, length: UInt32 = 0) -> Data {
    var d = Data()
    for v in [magic, msg, 0, 0, 0, length, 0, 0] { withUnsafeBytes(of: v.bigEndian) { d.append(contentsOf: $0) } }
    return d
}

struct ProbeError: Error, CustomStringConvertible { let description: String }

final class Scanner {
    let iface: IOUSBHostInterface
    let pipeOut: IOUSBHostPipe
    let pipeIn: IOUSBHostPipe
    var pending = Data()  // bytes read past the end of the last message

    init() throws {
        // Find interface FF/FF/FF of 03F0:042A (the scan interface).
        let match = IOUSBHostInterface.__createMatchingDictionary(
            withVendorID: NSNumber(value: vendorID), productID: NSNumber(value: productID),
            bcdDevice: nil, interfaceNumber: nil, configurationValue: nil,
            interfaceClass: 0xFF, interfaceSubclass: 0xFF, interfaceProtocol: 0xFF,
            speed: nil, productIDArray: nil).takeRetainedValue()
        let service = IOServiceGetMatchingService(kIOMainPortDefault, match)
        guard service != 0 else { throw ProbeError(description: "scan interface FF/FF/FF of 03F0:042A not found (printer off or unplugged?)") }
        defer { IOObjectRelease(service) }
        iface = try IOUSBHostInterface(__ioService: service, options: [], queue: nil, interestHandler: nil)

        // Walk the configuration descriptor for this interface's endpoints.
        let ifNum = Int(iface.interfaceDescriptor.pointee.bInterfaceNumber)
        let cfg = iface.configurationDescriptor
        let total = Int(cfg.pointee.wTotalLength)
        let raw = UnsafeRawPointer(cfg)
        var off = 0, inThis = false
        var outAddr: UInt8?, inAddr: UInt8?
        var desc: [String] = []
        while off + 2 <= total {
            let len = Int(raw.load(fromByteOffset: off, as: UInt8.self))
            let type = raw.load(fromByteOffset: off + 1, as: UInt8.self)
            if len == 0 { break }
            if type == 4 { inThis = Int(raw.load(fromByteOffset: off + 2, as: UInt8.self)) == ifNum
                && raw.load(fromByteOffset: off + 3, as: UInt8.self) == 0 }
            if type == 5 && inThis {
                let addr = raw.load(fromByteOffset: off + 2, as: UInt8.self)
                let attr = raw.load(fromByteOffset: off + 3, as: UInt8.self) & 3
                let mps = UInt16(raw.load(fromByteOffset: off + 4, as: UInt8.self)) | UInt16(raw.load(fromByteOffset: off + 5, as: UInt8.self)) << 8
                desc.append(String(format: "0x%02x %@ maxPacket %d", addr, ["control", "isoch", "bulk", "interrupt"][Int(attr)], mps))
                if attr == 2 && addr & 0x80 == 0 && outAddr == nil { outAddr = addr }
                if attr == 2 && addr & 0x80 != 0 && inAddr == nil { inAddr = addr }
            }
            off += len
        }
        log("interface \(ifNum) endpoints: " + desc.joined(separator: ", "))
        guard let o = outAddr, let i = inAddr else { throw ProbeError(description: "no bulk OUT/IN pair on the scan interface") }
        pipeOut = try iface.copyPipe(withAddress: Int(o))
        pipeIn = try iface.copyPipe(withAddress: Int(i))
        log(String(format: "using bulk OUT 0x%02x, bulk IN 0x%02x", o, i))
    }

    deinit { iface.destroy() }

    func write(_ d: Data, label: String) throws {
        log("→ \(label) (\(d.count) bytes)\n" + hex(d))
        let buf = NSMutableData(data: d)
        var n = 0
        try pipeOut.__sendIORequest(with: buf, bytesTransferred: &n, completionTimeout: 5)
        if n != d.count { throw ProbeError(description: "short write \(n)/\(d.count)") }
    }

    /// One bulk IN transfer; returns nil on timeout.
    func readChunk(timeout: TimeInterval) throws -> Data? {
        let buf = NSMutableData(length: 16384)!
        var n = 0
        do {
            try pipeIn.__sendIORequest(with: buf, bytesTransferred: &n, completionTimeout: timeout)
        } catch let e as NSError where e.code == Int(kIOReturnTimeout) || e.code == Int(kIOReturnAborted) {
            return nil
        }
        return Data(bytes: buf.bytes, count: n)
    }

    /// Exactly `count` bytes from the IN stream (keeps any surplus for next time).
    func read(_ count: Int, timeout: TimeInterval = 10) throws -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        while pending.count < count {
            let left = deadline.timeIntervalSinceNow
            if left <= 0 { throw ProbeError(description: "timeout waiting for \(count) bytes (have \(pending.count))") }
            if let c = try readChunk(timeout: left) { pending.append(c) }
        }
        let out = pending.prefix(count)
        pending.removeFirst(count)
        return Data(out)
    }

    /// Read whatever arrives within `timeout` (used after 0x15).
    func drain(timeout: TimeInterval) throws -> Data {
        var got = pending; pending.removeAll()
        let deadline = Date().addingTimeInterval(timeout)
        while deadline.timeIntervalSinceNow > 0 {
            guard let c = try readChunk(timeout: deadline.timeIntervalSinceNow) else { break }
            got.append(c)
        }
        return got
    }

    struct Reply { let raw: Data; let magic, msg, p1, p2, status, length: UInt32 }

    func readReply(_ label: String) throws -> Reply {
        let d = try read(32)
        let r = Reply(raw: d, magic: be32(d, 0), msg: be32(d, 4), p1: be32(d, 8), p2: be32(d, 12),
                      status: be32(d, 16), length: be32(d, 20))
        log("← \(label) reply\n" + hex(d))
        log(String(format: "   magic %@  msg 0x%02x  status %u  length %u  (p1 %u p2 %u)",
                   r.magic == magic ? "OK" : String(format: "BAD 0x%08x", r.magic), r.msg, r.status, r.length, r.p1, r.p2))
        return r
    }
}

// MARK: - Settings block (PROTOCOL.md §4)

let fields = ["Gamma", "Brightness", "Contrast", "Resolution",
              "XYScale.x_num", "XYScale.x_den", "XYScale.y_num", "XYScale.y_den",
              "Sharp", "Smooth", "BitsPerPixel", "reserved1", "reserved2", "reserved3", "reserved4",
              "DataType", "window.top", "window.left", "window.bottom", "window.right",
              "Scannable.top", "Scannable.left", "Scannable.bottom", "Scannable.right", "ColorType"]
enum F: Int { case resolution = 3, top = 16, left = 17, bottom = 18, right = 19,
              sTop = 20, sLeft = 21, sBottom = 22, sRight = 23, colorType = 24 }

struct Settings {
    var v: [UInt32]
    init(_ d: Data) { v = (0..<25).map { be32(d, $0 * 4) } }
    subscript(f: F) -> UInt32 { get { v[f.rawValue] } set { v[f.rawValue] = newValue } }
    var data: Data { var d = Data(); for x in v { withUnsafeBytes(of: x.bigEndian) { d.append(contentsOf: $0) } }; return d }
    func dump(_ title: String, against old: Settings? = nil) {
        log(title)
        for (i, name) in fields.enumerated() {
            let changed = old.map { $0.v[i] != v[i] } ?? false
            log(String(format: "   0x%02x  %-17@ %11d%@", i * 4, name as NSString, Int32(bitPattern: v[i]),
                       changed ? String(format: "   (was %d)", Int32(bitPattern: old!.v[i])) : ""))
        }
    }
}

// MARK: - Session helpers

extension Scanner {
    func command(_ msg: UInt32, _ label: String) throws -> Reply {
        try write(header(msg), label: String(format: "0x%02x %@", msg, label))
        let r = try readReply(label)
        guard r.magic == magic, r.msg == msg else { throw ProbeError(description: "\(label): reply does not echo 0x\(String(msg, radix: 16))") }
        return r
    }
    func lock() throws {
        try write(header(0x15), label: "0x15 (pre-lock)")
        let extra = try drain(timeout: 1.0)
        if !extra.isEmpty { log("note: \(extra.count) bytes after 0x15:\n" + hex(extra)) }
        for attempt in 1...10 {
            if try command(0x00, "Lock (attempt \(attempt))").status == 0 { log("lock granted"); return }
            Thread.sleep(forTimeInterval: 1)
        }
        throw ProbeError(description: "scanner did not grant the lock")
    }
    func unlock() {
        do { _ = try command(0x01, "Unlock") } catch { log("unlock failed: \(error)") }
    }
    func getSettings() throws -> Settings {
        let r = try command(0x06, "GetScanJobSettings")
        guard r.status == 0, r.length == 100 else { throw ProbeError(description: "GetScanJobSettings: status \(r.status) length \(r.length)") }
        return Settings(try read(100))
    }
}

// MARK: - probe

func probe() throws {
    let s = try Scanner()
    try s.lock()
    defer { s.unlock() }
    try s.getSettings().dump("current settings:")
}

// MARK: - Scan engine

/// Area and mode for one scan. Lengths are in 1/100 inch, like the protocol.
struct ScanRequest {
    var dpi: UInt32 = 300
    var left: UInt32 = 0, top: UInt32 = 0
    var width: UInt32 = 827, height: UInt32 = 1169      // A4
    var gray = false
    var rawDir: URL? = nil                              // save packets.bin for debugging
    var cancelAfter: TimeInterval? = nil                // testing: cancel after N seconds
}

struct ScanImage {
    var width: Int, height: Int, channels: Int          // channels: 1 grey, 3 RGB
    var dpi: Int
    var pixels: Data                                    // interleaved, 8 bits per component
}

struct Cancelled: Error, CustomStringConvertible { var description: String { "scan cancelled" } }

/// HP's glass is 8.17 x 11.23 in (ICAP_PHYSICALWIDTH/HEIGHT in its plist); the
/// firmware's ScannableArea claims 8.5 x 15 in, so the length is capped here.
let glassBottom: UInt32 = 1122

var cancelRequested = false
let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())

func performScan(_ req: ScanRequest) throws -> ScanImage {
    var raw: FileHandle?
    if let dir = req.rawDir {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent("packets.bin")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        raw = try FileHandle(forWritingTo: url)
    }
    defer { try? raw?.close() }

    let s = try Scanner()
    try s.lock()
    defer { s.unlock() }

    // HP's order (PROTOCOL.md §7): reset to defaults, read back, edit, write, verify.
    let r8 = try s.command(0x08, "SetDefaultScanJobSettings")
    guard r8.status == 0 else { throw ProbeError(description: "scanner refused default settings (status \(r8.status))") }
    let defaults = try s.getSettings()
    defaults.dump("defaults after 0x08:")

    var job = defaults
    job[.resolution] = req.dpi
    job[.left] = min(job[.sLeft] + req.left, job[.sRight] - 1)
    job[.top] = min(job[.sTop] + req.top, min(job[.sBottom], glassBottom) - 1)
    job[.right] = min(job[.left] + req.width, job[.sRight])
    job[.bottom] = min(job[.top] + req.height, job[.sBottom], glassBottom)
    job[.colorType] = req.gray ? 0 : 1                 // PROTOCOL.md §11–12
    job.dump("job settings:", against: defaults)

    var msg7 = header(0x07, length: 100); msg7.append(job.data)
    try s.write(msg7, label: "0x07 SetScanJobSettings")
    let r7 = try s.readReply("SetScanJobSettings")
    guard r7.magic == magic, r7.msg == 0x07, r7.status == 0 else { throw ProbeError(description: "scanner rejected the settings (status \(r7.status))") }
    let applied = try s.getSettings()
    applied.dump("settings as stored:", against: job)

    var width = Int(applied[.right] - applied[.left]) * Int(req.dpi) / 100
    let expectedRows = Int(applied[.bottom] - applied[.top]) * Int(req.dpi) / 100
    let channels = req.gray ? 1 : 3
    var pixels = Data(capacity: max(width * expectedRows * channels, 0))
    var carry = Data()          // channel lines not yet forming a whole image row

    let r2 = try s.command(0x02, "StartScan")
    guard r2.status == 0 else { throw ProbeError(description: "scanner would not start (status \(r2.status))") }
    var jobOpen = true
    var cancelling = false
    defer {
        if jobOpen {            // error or cancel before e_EndJob: stop the scanner first
            try? s.write(header(0x03), label: "0x03 CancelScanJob")
            _ = try? s.drain(timeout: 3)
        }
    }

    let names: [UInt32: String] = [0x04: "e_AbortScanJob", 0x05: "e_ScanImageData", 0x09: "e_StartJob",
        0x0a: "e_StartSheet", 0x0b: "e_StartPage", 0x0c: "e_EndJob", 0x0d: "e_EndSheet", 0x0e: "e_EndPage", 0x18: "e_NewScanPage"]
    let started = Date()
    var cancelSentAt: Date?
    var lastPct = -1
    var packets = 0
    while true {
        if !cancelling && (cancelRequested || req.cancelAfter.map { Date().timeIntervalSince(started) >= $0 } == true) {
            cancelling = true
            cancelSentAt = Date()
            say("\rCancelling…            ")
            try s.write(header(0x03), label: "0x03 CancelScanJob")
        }
        if let t = cancelSentAt, Date().timeIntervalSince(t) > 20 {
            throw ProbeError(description: "scanner did not end the job within 20 s of cancel")
        }
        guard Date().timeIntervalSince(started) < 900 else { throw ProbeError(description: "scan took over 15 minutes") }

        let hdr = try s.read(32, timeout: cancelling ? 20 : 60)
        raw?.write(hdr)
        packets += 1
        let m = be32(hdr, 4), len = be32(hdr, 20)
        guard be32(hdr, 0) == magic else { log("BAD MAGIC\n" + hex(hdr)); throw ProbeError(description: "lost sync with the scanner") }
        log(String(format: "%6.2fs ← #%d msg 0x%02x %@ status %u length %u%@", Date().timeIntervalSince(started), packets, m,
                   names[m] ?? "UNKNOWN", be32(hdr, 16), len, cancelling ? "  [after cancel]" : ""))
        let bodyLen = (m == 0x09 && len == 0) ? 100 : Int(len)
        let body = bodyLen > 0 ? try s.read(bodyLen, timeout: 60) : Data()
        raw?.write(body)

        switch m {
        case 0x05:
            let dh = (0..<6).map { be32(body, $0 * 4) }
            let stride = Int(dh[5])
            log("        data: type \(dh[0]) first line \(dh[1]) lines \(dh[2]) B/comp \(dh[3]) f4 \(dh[4]) stride \(stride)")
            guard dh[3] == 1, (dh[0] == 10 && channels == 3) || (dh[0] == 6 && channels == 1) else {
                throw ProbeError(description: "unexpected image format (data type \(dh[0]), \(dh[3]) bytes/component)")
            }
            // The firmware rounds the row to the nearest multiple of 16 px (PROTOCOL.md §13),
            // which can be narrower than asked; keep at most what it sends.
            if stride < width {
                guard pixels.isEmpty else { throw ProbeError(description: "row width changed mid-scan") }
                log("        scanner rows are \(stride) px, requested \(width) px; using \(stride)")
                width = stride
            }
            carry.append(body.dropFirst(24))
            // Colour: R, G, B lines per row (PROTOCOL.md §6). Grey: one line per row.
            let rowBytes = stride * channels
            let whole = carry.count / rowBytes
            carry.withUnsafeBytes { (src: UnsafeRawBufferPointer) in
                var row = [UInt8](repeating: 0, count: width * channels)
                for y in 0..<whole {
                    let base = y * rowBytes
                    for x in 0..<width { for c in 0..<channels { row[x * channels + c] = src[base + c * stride + x] } }
                    pixels.append(contentsOf: row)
                }
            }
            carry.removeFirst(whole * rowBytes)
            if !verbose && !cancelling {
                let pct = min(99, pixels.count * 100 / max(width * expectedRows * channels, 1))
                if pct != lastPct { say("\rScanning… \(pct)%", terminator: ""); lastPct = pct }
            }
        case 0x09:
            Settings(body).dump("e_StartJob payload:", against: applied)
        case 0x18:
            try s.write(header(0x18), label: "0x18 ack e_NewScanPage")
        case 0x0c:
            jobOpen = false
            if cancelling { log("job ended after cancel in \(String(format: "%.2f", Date().timeIntervalSince(cancelSentAt!))) s"); throw Cancelled() }
            // The last packet can run past the window (300 rows for 295); trim to it.
            let rows = min(pixels.count / (width * channels), expectedRows)
            pixels.removeSubrange((rows * width * channels)...)
            if !verbose { say("\rScanning… 100%") }
            log("scan finished: \(packets) packets, \(width) x \(rows) px")
            return ScanImage(width: width, height: rows, channels: channels, dpi: Int(req.dpi), pixels: pixels)
        case 0x04:
            jobOpen = false
            if cancelling { log("scanner aborted the job after cancel"); throw Cancelled() }
            throw ProbeError(description: "the scanner aborted the scan")
        default:
            if !body.isEmpty { log("        body:\n" + hex(body.prefix(64))) }
        }
    }
}

// MARK: - Output

import CoreGraphics
import ImageIO

enum Mode: String { case color, gray, bw }
enum Format: String { case pdf, png, jpg }

/// Black & white the way HP's driver does it: scan grey, threshold on the host.
func threshold(_ img: ScanImage, at level: UInt8 = 128) -> (bits: Data, bytesPerRow: Int) {
    let bpr = (img.width + 7) / 8
    var out = Data(count: bpr * img.height)
    img.pixels.withUnsafeBytes { (src: UnsafeRawBufferPointer) in
        out.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) in
            for y in 0..<img.height {
                for x in 0..<img.width where src[y * img.width + x] >= level {
                    dst[y * bpr + x / 8] |= UInt8(0x80 >> (x % 8))      // 1 = white in DeviceGray
                }
            }
        }
    }
    return (out, bpr)
}

func makeCGImage(_ img: ScanImage, mode: Mode) throws -> CGImage {
    let gray = CGColorSpaceCreateDeviceGray()
    let made: CGImage?
    if mode == .bw {
        let (bits, bpr) = threshold(img)
        made = CGImage(width: img.width, height: img.height, bitsPerComponent: 1, bitsPerPixel: 1, bytesPerRow: bpr,
                       space: gray, bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.none.rawValue),
                       provider: CGDataProvider(data: bits as CFData)!, decode: nil, shouldInterpolate: false, intent: .defaultIntent)
    } else {
        made = CGImage(width: img.width, height: img.height, bitsPerComponent: 8, bitsPerPixel: 8 * img.channels,
                       bytesPerRow: img.width * img.channels,
                       space: img.channels == 1 ? gray : CGColorSpace(name: CGColorSpace.sRGB)!,
                       bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.none.rawValue),
                       provider: CGDataProvider(data: img.pixels as CFData)!, decode: nil, shouldInterpolate: false, intent: .defaultIntent)
    }
    guard let cg = made else { throw ProbeError(description: "could not build the image (\(img.width) x \(img.height))") }
    return cg
}

func encode(_ cg: CGImage, type: String, dpi: Int, quality: Double = 0.9) throws -> Data {
    let out = NSMutableData()
    guard let dst = CGImageDestinationCreateWithData(out as CFMutableData, type as CFString, 1, nil) else {
        throw ProbeError(description: "no \(type) encoder")
    }
    let props: [CFString: Any] = [kCGImagePropertyDPIWidth: dpi, kCGImagePropertyDPIHeight: dpi,
                                  kCGImageDestinationLossyCompressionQuality: quality]
    CGImageDestinationAddImage(dst, cg, props as CFDictionary)
    guard CGImageDestinationFinalize(dst) else { throw ProbeError(description: "\(type) encoding failed") }
    return out as Data
}

func save(_ img: ScanImage, mode: Mode, format: Format, to url: URL) throws {
    let cg = try makeCGImage(img, mode: mode)
    switch format {
    case .png: try encode(cg, type: "public.png", dpi: img.dpi).write(to: url)
    case .jpg:
        guard mode != .bw else { throw ProbeError(description: "use png or pdf for black & white") }
        try encode(cg, type: "public.jpeg", dpi: img.dpi).write(to: url)
    case .pdf:
        // Colour/grey pages are embedded as JPEG (CoreGraphics passes the DCT data
        // through), black & white as a 1-bit image.
        var page = CGImage?.none
        if mode == .bw { page = cg } else {
            let jpeg = try encode(cg, type: "public.jpeg", dpi: img.dpi, quality: 0.85)
            if let src = CGImageSourceCreateWithData(jpeg as CFData, nil) { page = CGImageSourceCreateImageAtIndex(src, 0, nil) }
        }
        var box = CGRect(x: 0, y: 0, width: Double(img.width) * 72 / Double(img.dpi), height: Double(img.height) * 72 / Double(img.dpi))
        let info: [CFString: Any] = [kCGPDFContextCreator: "m1132scan", kCGPDFContextTitle: url.deletingPathExtension().lastPathComponent]
        guard let image = page, let ctx = CGContext(url as CFURL, mediaBox: &box, info as CFDictionary) else {
            throw ProbeError(description: "could not create \(url.path)")
        }
        ctx.beginPDFPage(nil)
        ctx.interpolationQuality = .none
        ctx.draw(image, in: box)
        ctx.endPDFPage()
        ctx.closePDF()
    }
}

// MARK: - Command line

let usage = """
usage: m1132scan [options]

Scans one page on an HP LaserJet Professional M1132 MFP and saves it to ~/Downloads.

  --size a4|letter|max|WxHmm   area from the top-left corner of the glass (default a4;
                               max = whole glass, 8.17 x 11.22 in; e.g. 100x150mm)
  --offset XxYmm               start the area this far from the top-left corner
  --mode color|gray|bw         default color
  --dpi 150|300|600|1200       default 300
  --format pdf|png|jpg         default pdf (or taken from -o's extension)
  -o FILE                      output file (default ~/Downloads/Scan <date> at <time>.<format>)
  --verbose                    print the USB protocol trace
  --raw DIR                    also save the raw packet stream to DIR/packets.bin
  --cancel-after SECONDS       testing: cancel the scan after this long
  probe                        lock the scanner, print its settings, unlock (no scan)

Ctrl-C cancels a running scan cleanly. A4 is 11.69 in long but the glass is 11.22 in,
so A4 scans stop at the end of the glass.
"""

func hundredths(mm: Double) -> UInt32 { UInt32((mm / 25.4 * 100).rounded()) }

func parseMM(_ s: String) -> (Double, Double)? {
    let t = s.lowercased().replacingOccurrences(of: "mm", with: "")
    let p = t.split(separator: "x").compactMap { Double($0) }
    return p.count == 2 && p[0] >= 0 && p[1] >= 0 ? (p[0], p[1]) : nil
}

func main() throws {
    var args = Array(CommandLine.arguments.dropFirst())
    if args.first == "probe" { verbose = true; try probe(); return }
    if args.first == "scan" { args.removeFirst() }

    var req = ScanRequest()
    var mode = Mode.color
    var format: Format?
    var output: URL?
    var i = 0
    func value() throws -> String {
        i += 1
        guard i < args.count else { throw ProbeError(description: "\(args[i - 1]) needs a value\n\n" + usage) }
        return args[i]
    }
    while i < args.count {
        switch args[i] {
        case "-h", "--help": print(usage); return
        case "--size":
            let v = try value().lowercased()
            switch v {
            case "a4": (req.width, req.height) = (827, 1169)
            case "letter": (req.width, req.height) = (850, 1100)
            case "max", "full": (req.width, req.height) = (850, 1500)
            default:
                guard let (w, h) = parseMM(v), w > 0, h > 0 else { throw ProbeError(description: "bad --size \(v); use a4, letter, max or WxHmm") }
                (req.width, req.height) = (hundredths(mm: w), hundredths(mm: h))
            }
        case "--offset":
            let v = try value()
            guard let (x, y) = parseMM(v) else { throw ProbeError(description: "bad --offset \(v); use XxYmm, e.g. 20x30mm") }
            (req.left, req.top) = (hundredths(mm: x), hundredths(mm: y))
        case "--mode":
            let v = try value().lowercased()
            guard let m = Mode(rawValue: v == "grey" ? "gray" : v) else { throw ProbeError(description: "bad --mode \(v); use color, gray or bw") }
            mode = m
        case "--dpi":
            let v = try value()
            guard let d = UInt32(v), [150, 300, 600, 1200].contains(d) else { throw ProbeError(description: "bad --dpi \(v); use 150, 300, 600 or 1200") }
            req.dpi = d
        case "--format":
            let v = try value().lowercased()
            guard let f = Format(rawValue: v == "jpeg" ? "jpg" : v) else { throw ProbeError(description: "bad --format \(v); use pdf, png or jpg") }
            format = f
        case "-o", "--output": output = URL(fileURLWithPath: (try value() as NSString).expandingTildeInPath)
        case "--verbose", "-v": verbose = true
        case "--raw": req.rawDir = URL(fileURLWithPath: (try value() as NSString).expandingTildeInPath)
        case "--cancel-after":
            let v = try value()
            guard let t = Double(v), t >= 0 else { throw ProbeError(description: "bad --cancel-after \(v)") }
            req.cancelAfter = t
        default: throw ProbeError(description: "unknown option \(args[i])\n\n" + usage)
        }
        i += 1
    }
    req.gray = mode != .color
    if format == nil, let ext = output?.pathExtension.lowercased() { format = Format(rawValue: ext == "jpeg" ? "jpg" : ext) }
    let fmt = format ?? .pdf
    if fmt == .jpg && mode == .bw { throw ProbeError(description: "use png or pdf for black & white") }
    let dest = output ?? {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd 'at' HH.mm.ss"
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Downloads/Scan \(f.string(from: Date())).\(fmt.rawValue)")
    }()

    signal(SIGINT, SIG_IGN)
    sigint.setEventHandler { cancelRequested = true }
    sigint.resume()

    let shownW = min(req.width, 850 - min(req.left, 850)), shownH = min(req.height, glassBottom - min(req.top, glassBottom))
    say("Scanning \(mode.rawValue), \(req.dpi) dpi, \(String(format: "%.2f x %.2f in", Double(shownW) / 100, Double(shownH) / 100))…"
        + (shownH < req.height ? " (the glass ends at 11.22 in)" : ""))
    let t0 = Date()
    let img = try performScan(req)
    try save(img, mode: mode, format: fmt, to: dest)
    say(String(format: "Saved %@ (%d x %d px, %.1f s)", dest.path, img.width, img.height, Date().timeIntervalSince(t0)))
}

do { try main() }
catch is Cancelled { say("\nCancelled. The scanner was stopped and unlocked."); exit(130) }
catch { say("\nError: \(error)"); exit(1) }
