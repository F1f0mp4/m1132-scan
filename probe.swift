// First-contact probe for the HP LaserJet Professional M1132 MFP scanner.
// Sends only: 0x15, 0x00 Lock, 0x06 GetScanJobSettings, 0x01 Unlock.
// No StartScan, so the lamp and motor are never used. See PROTOCOL.md.
//
// Build: swiftc -O -framework IOUSBHost -o probe probe.swift

import Foundation
import IOKit
import IOUSBHost

let vendorID = 0x03F0, productID = 0x042A
let magic: UInt32 = 0x4153_5001

func log(_ s: String) { print(s); fflush(stdout) }
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

let fields = ["Gamma", "Brightness", "Contrast", "Resolution",
              "XYScale.x_num", "XYScale.x_den", "XYScale.y_num", "XYScale.y_den",
              "Sharp", "Smooth", "BitsPerPixel", "reserved1", "reserved2", "reserved3", "reserved4",
              "DataType", "window.top", "window.left", "window.bottom", "window.right",
              "Scannable.top", "Scannable.left", "Scannable.bottom", "Scannable.right", "ColorType"]

func run() throws {
    let s = try Scanner()
    var locked = false
    defer {
        if locked {
            do { try s.write(header(0x01), label: "0x01 Unlock"); _ = try s.readReply("Unlock") }
            catch { log("unlock failed: \(error)") }
        }
    }

    // Step 1: 0x15, which HP sends without reading a reply.
    try s.write(header(0x15), label: "0x15 (pre-lock, unknown)")
    let extra = try s.drain(timeout: 1.5)
    log(extra.isEmpty ? "← nothing came back after 0x15 within 1.5 s" : "← \(extra.count) bytes after 0x15:\n" + hex(extra))
    if !extra.isEmpty { s.pending = extra.count >= 32 ? Data(extra.dropFirst(32)) : Data() }

    // Step 2: Lock, retried like HP does (status must become 0).
    for attempt in 1...10 {
        try s.write(header(0x00), label: "0x00 Lock (attempt \(attempt))")
        let r = try s.readReply("Lock")
        if r.magic == magic && r.msg == 0x00 && r.status == 0 { locked = true; break }
        Thread.sleep(forTimeInterval: 1)
    }
    guard locked else { throw ProbeError(description: "scanner did not grant the lock") }
    log("lock granted")

    // Step 3: GetScanJobSettings.
    try s.write(header(0x06), label: "0x06 GetScanJobSettings")
    let r = try s.readReply("GetScanJobSettings")
    guard r.magic == magic, r.msg == 0x06, r.length > 0, r.length <= 4096 else {
        throw ProbeError(description: "unexpected GetScanJobSettings reply")
    }
    let payload = try s.read(Int(r.length))
    log("← settings payload (\(payload.count) bytes)\n" + hex(payload))
    for (i, name) in fields.enumerated() where (i + 1) * 4 <= payload.count {
        let v = be32(payload, i * 4)
        log(String(format: "   0x%02x  %-17@ %11d  (0x%08x)", i * 4, name as NSString, Int32(bitPattern: v), v))
    }
    let left = try s.drain(timeout: 0.5)
    if !left.isEmpty { log("note: \(left.count) unexpected extra bytes after settings:\n" + hex(left)) }
}

do { try run(); log("done") }
catch { log("ERROR: \(error)"); exit(1) }
