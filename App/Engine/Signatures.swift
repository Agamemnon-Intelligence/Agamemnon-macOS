import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// A SHA-256 digest stored as four big-endian words, so 1M+ hashes fit in ~37 MB
/// and can be binary-searched.
struct Hash256: Hashable, Comparable {
    let a: UInt64
    let b: UInt64
    let c: UInt64
    let d: UInt64

    init(a: UInt64, b: UInt64, c: UInt64, d: UInt64) {
        self.a = a; self.b = b; self.c = c; self.d = d
    }

    init?(bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        func word(_ i: Int) -> UInt64 {
            var v: UInt64 = 0
            for j in 0..<8 { v = (v << 8) | UInt64(bytes[i * 8 + j]) }
            return v
        }
        self.init(a: word(0), b: word(1), c: word(2), d: word(3))
    }

    /// Parses 64 hex characters starting at `offset` in a UTF-8 buffer.
    init?(hexBytes p: UnsafeBufferPointer<UInt8>, offset: Int) {
        guard offset + 64 <= p.count else { return nil }
        var words: (UInt64, UInt64, UInt64, UInt64) = (0, 0, 0, 0)
        for w in 0..<4 {
            var v: UInt64 = 0
            for i in 0..<16 {
                guard let n = Hash256.nibble(p[offset + w * 16 + i]) else { return nil }
                v = (v << 4) | UInt64(n)
            }
            switch w {
            case 0: words.0 = v
            case 1: words.1 = v
            case 2: words.2 = v
            default: words.3 = v
            }
        }
        self.init(a: words.0, b: words.1, c: words.2, d: words.3)
    }

    init?(hex: String) {
        let bytes = Array(hex.utf8)
        guard bytes.count == 64 else { return nil }
        let parsed: Hash256? = bytes.withUnsafeBufferPointer { Hash256(hexBytes: $0, offset: 0) }
        guard let parsed else { return nil }
        self = parsed
    }

    static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 48...57: return c - 48      // 0-9
        case 97...102: return c - 87     // a-f
        case 65...70: return c - 55      // A-F
        default: return nil
        }
    }

    var hex: String {
        [a, b, c, d].map { word -> String in
            let s = String(word, radix: 16)
            return String(repeating: "0", count: 16 - s.count) + s
        }.joined()
    }

    static func < (l: Hash256, r: Hash256) -> Bool {
        if l.a != r.a { return l.a < r.a }
        if l.b != r.b { return l.b < r.b }
        if l.c != r.c { return l.c < r.c }
        return l.d < r.d
    }
}

enum FileHasher {
    /// Streams the file through SHA-256 in 1 MB chunks.
    static func sha256(of url: URL) throws -> Hash256 {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = try handle.read(upToCount: 1 << 20) ?? Data()
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        let digest = Array(hasher.finalize())
        return Hash256(bytes: digest)!
    }
}

/// The EICAR anti-virus test file, so users can safely check that detection works.
enum Eicar {
    static let signature = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    static let sha256 = Hash256(hex: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")!

    static func matches(_ data: Data) -> Bool {
        guard data.count >= 68, data.count <= 256 else { return false }
        let text = String(decoding: data, as: UTF8.self)
        return text.hasPrefix(signature)
    }
}

/// Thread-safe, read-mostly set of known-malware SHA-256 hashes.
final class SignatureStore {
    static let shared = SignatureStore()

    private let lock = NSLock()
    private var hashes: [Hash256] = []

    /// Hashes that always ship with the app.
    static let builtIn: [Hash256: String] = [
        Eicar.sha256: "EICAR-Test-File",
    ]

    static var databaseURL: URL { AppPaths.signatures.appendingPathComponent("malwarebazaar-sha256.bin") }

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return hashes.count
    }

    /// Returns a threat name if the hash is known.
    func lookup(_ hash: Hash256) -> String? {
        if let name = SignatureStore.builtIn[hash] { return name }
        lock.lock(); defer { lock.unlock() }
        var lo = 0
        var hi = hashes.count - 1
        while lo <= hi {
            let mid = (lo + hi) >> 1
            let v = hashes[mid]
            if v == hash { return "Known malware (MalwareBazaar)" }
            if v < hash { lo = mid + 1 } else { hi = mid - 1 }
        }
        return nil
    }

    func snapshot() -> [Hash256] {
        lock.lock(); defer { lock.unlock() }
        return hashes
    }

    /// `sorted` must be sorted and de-duplicated.
    func replace(with sorted: [Hash256]) {
        lock.lock()
        hashes = sorted
        lock.unlock()
    }

    @discardableResult
    func loadFromDisk() -> Int {
        guard let loaded = try? SignatureStore.read(from: SignatureStore.databaseURL) else { return 0 }
        replace(with: loaded)
        return loaded.count
    }

    // MARK: - Binary format: N × 32 raw bytes, sorted.

    static func read(from url: URL) throws -> [Hash256] {
        let data = try Data(contentsOf: url, options: .alwaysMapped)
        let n = data.count / 32
        var result: [Hash256] = []
        result.reserveCapacity(n)
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            for i in 0..<n {
                let base = i * 32
                let a = UInt64(bigEndian: raw.loadUnaligned(fromByteOffset: base, as: UInt64.self))
                let b = UInt64(bigEndian: raw.loadUnaligned(fromByteOffset: base + 8, as: UInt64.self))
                let c = UInt64(bigEndian: raw.loadUnaligned(fromByteOffset: base + 16, as: UInt64.self))
                let d = UInt64(bigEndian: raw.loadUnaligned(fromByteOffset: base + 24, as: UInt64.self))
                result.append(Hash256(a: a, b: b, c: c, d: d))
            }
        }
        return result
    }

    static func write(_ hashes: [Hash256], to url: URL) throws {
        var out = Data(count: hashes.count * 32)
        out.withUnsafeMutableBytes { (raw: UnsafeMutableRawBufferPointer) in
            for (i, h) in hashes.enumerated() {
                let base = i * 32
                raw.storeBytes(of: h.a.bigEndian, toByteOffset: base, as: UInt64.self)
                raw.storeBytes(of: h.b.bigEndian, toByteOffset: base + 8, as: UInt64.self)
                raw.storeBytes(of: h.c.bigEndian, toByteOffset: base + 16, as: UInt64.self)
                raw.storeBytes(of: h.d.bigEndian, toByteOffset: base + 24, as: UInt64.self)
            }
        }
        try out.write(to: url, options: .atomic)
    }

    /// Extracts every 64-hex-character line from a MalwareBazaar text export.
    static func parseHashList(_ data: Data) -> [Hash256] {
        var result: [Hash256] = []
        result.reserveCapacity(data.count / 65)
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let p = raw.bindMemory(to: UInt8.self)
            var lineStart = 0
            let n = p.count
            var i = 0
            while i <= n {
                if i == n || p[i] == 0x0A {
                    var lineEnd = i
                    if lineEnd > lineStart, p[lineEnd - 1] == 0x0D { lineEnd -= 1 }
                    // Skip quotes some CSV exports wrap around values.
                    var s = lineStart
                    while s < lineEnd, p[s] == 0x22 || p[s] == 0x20 { s += 1 }
                    if lineEnd - s >= 64, p[s] != 0x23, let h = Hash256(hexBytes: p, offset: s) {
                        result.append(h)
                    }
                    lineStart = i + 1
                }
                i += 1
            }
        }
        return result
    }

    static func sortedUnique(_ input: [Hash256]) -> [Hash256] {
        let sorted = input.sorted()
        var out: [Hash256] = []
        out.reserveCapacity(sorted.count)
        for h in sorted where out.last != h { out.append(h) }
        return out
    }
}
