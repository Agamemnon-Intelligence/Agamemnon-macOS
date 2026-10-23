import Foundation

/// Undoes the tricks Mac malware scripts use to hide their real commands from simple string
/// matching, so the pattern rules can see them:
/// - strings split up and glued back together (`"cu" & "rl"`, `'os' + 'ascript'`),
/// - base64 blobs (also reversed, and gzip-compressed inside base64),
/// - long hex strings, `\xNN` / `\NNN` escapes and `%NN` URL escapes,
/// - character-code lists (`String.fromCharCode(99,117,…)`, `chr(99)+chr(117)`,
///   AppleScript `ASCII character 99`, `character id {99, 117}`).
///
/// Only decodes; never runs anything. Output is lower-case ASCII-ish text meant to be
/// appended to the script for matching. Results that don't look like text are dropped, so
/// random data (hashes, images in data: URLs) can't feed the rules garbage.
enum Deobfuscator {
    static let maxLevels = 3
    static let maxOutputBytes = 8 * 1024 * 1024

    /// Everything decoded from `data` (already lower-cased or not), joined by newlines.
    /// Empty when nothing was hidden.
    static func reveal(_ data: Data) -> Data {
        var output = Data()
        var queue: [(Data, Int)] = [(data, 0)]
        var seen = Set<Int>()
        while let (current, level) = queue.popLast() {
            for piece in decodeOnce(current) {
                guard output.count + piece.count < maxOutputBytes else { return output }
                let key = piece.hashValue
                guard !seen.contains(key) else { continue }
                seen.insert(key)
                output.append(0x0A)
                output.append(piece)
                if level + 1 < maxLevels { queue.append((piece, level + 1)) }
            }
        }
        return output
    }

    // MARK: - One pass

    private static func decodeOnce(_ data: Data) -> [Data] {
        var out: [Data] = []
        if let joined = joinConcatenations(data) { out.append(joined) }
        out.append(contentsOf: base64Blobs(data))
        out.append(contentsOf: hexBlobs(data))
        if let escaped = unescape(data) { out.append(escaped) }
        out.append(contentsOf: charCodeLists(data))
        return out.filter(isMostlyText).map(lowercased)
    }

    /// `"cu" & "rl"` → `"curl"`. Handles AppleScript `&`, JavaScript/Python `+`, PHP/Perl `.`,
    /// and shell's adjacent quoting (`'cu''rl'`, `"cu""rl"`).
    private static let concatenation = try! NSRegularExpression(
        pattern: #"(["'])\s*(?:&|\+|\.)?\s*\1"#)

    private static func joinConcatenations(_ data: Data) -> Data? {
        guard data.count <= 4 * 1024 * 1024 else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        let range = NSRange(text.startIndex..., in: text)
        let matches = concatenation.numberOfMatches(in: text, range: range)
        // A couple of these is normal code; malware splits dozens of words.
        guard matches >= 6 else { return nil }
        let joined = concatenation.stringByReplacingMatches(in: text, range: range, withTemplate: "")
        return Data(joined.utf8)
    }

    // MARK: Base64

    private static let base64Run = try! NSRegularExpression(pattern: #"[A-Za-z0-9+/]{40,}={0,2}"#)

    private static func base64Blobs(_ data: Data) -> [Data] {
        let text = String(decoding: data, as: UTF8.self)
        var out: [Data] = []
        let range = NSRange(text.startIndex..., in: text)
        for m in base64Run.matches(in: text, range: range).prefix(200) {
            guard let r = Range(m.range, in: text) else { continue }
            var blob = String(text[r])
            // Pure hex is handled by hexBlobs; letters-only words are identifiers.
            if blob.allSatisfy(\.isHexDigit) { continue }
            while blob.count % 4 != 0 { blob += "=" }
            for candidate in [blob, String(blob.reversed())] {
                guard var decoded = Data(base64Encoded: candidate) else { continue }
                if let inflated = gunzip(decoded) { decoded = inflated }
                if isMostlyText(decoded) { out.append(decoded); break }
            }
        }
        return out
    }

    /// gzip → raw DEFLATE via NSData's zlib decompressor (which is raw DEFLATE on Apple platforms).
    private static func gunzip(_ data: Data) -> Data? {
        guard data.count > 18, data[data.startIndex] == 0x1f, data[data.startIndex + 1] == 0x8b,
              data[data.startIndex + 2] == 0x08 else { return nil }
        let flags = data[data.startIndex + 3]
        var offset = 10
        let bytes = [UInt8](data)
        if flags & 0x04 != 0, bytes.count > offset + 2 {             // FEXTRA
            offset += 2 + Int(bytes[offset]) + Int(bytes[offset + 1]) << 8
        }
        if flags & 0x08 != 0 { while offset < bytes.count, bytes[offset] != 0 { offset += 1 }; offset += 1 }  // FNAME
        if flags & 0x10 != 0 { while offset < bytes.count, bytes[offset] != 0 { offset += 1 }; offset += 1 }  // FCOMMENT
        if flags & 0x02 != 0 { offset += 2 }                                                                  // FHCRC
        guard offset < bytes.count - 8 else { return nil }
        let body = Data(bytes[offset..<(bytes.count - 8)])
        guard let out = try? (body as NSData).decompressed(using: .zlib) as Data, out.count < maxOutputBytes else { return nil }
        return out
    }

    // MARK: Hex

    private static let hexRun = try! NSRegularExpression(pattern: #"(?:[0-9a-fA-F]{2}){24,}"#)

    private static func hexBlobs(_ data: Data) -> [Data] {
        let text = String(decoding: data, as: UTF8.self)
        var out: [Data] = []
        let range = NSRange(text.startIndex..., in: text)
        for m in hexRun.matches(in: text, range: range).prefix(200) {
            guard let r = Range(m.range, in: text) else { continue }
            let hex = Array(text[r].utf8)
            var bytes = [UInt8]()
            bytes.reserveCapacity(hex.count / 2)
            var i = 0
            while i + 1 < hex.count {
                guard let hi = Hash256.nibble(hex[i]), let lo = Hash256.nibble(hex[i + 1]) else { break }
                bytes.append(hi << 4 | lo)
                i += 2
            }
            let decoded = Data(bytes)
            if isMostlyText(decoded) { out.append(decoded) }
        }
        return out
    }

    // MARK: Escapes

    private static let escapeRun = try! NSRegularExpression(
        pattern: #"(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}|%[0-9a-fA-F]{2}|\\u00[0-9a-fA-F]{2}){8,}"#)

    private static func unescape(_ data: Data) -> Data? {
        let text = String(decoding: data, as: UTF8.self)
        let range = NSRange(text.startIndex..., in: text)
        let matches = escapeRun.matches(in: text, range: range)
        guard !matches.isEmpty else { return nil }
        var out = Data()
        for m in matches.prefix(500) {
            guard let r = Range(m.range, in: text) else { continue }
            let run = Array(text[r].utf8)
            var i = 0
            while i < run.count {
                if run[i] == 0x5C, i + 3 < run.count, run[i + 1] == 0x78,                       // \xNN
                   let hi = Hash256.nibble(run[i + 2]), let lo = Hash256.nibble(run[i + 3]) {
                    out.append(hi << 4 | lo); i += 4
                } else if run[i] == 0x5C, i + 5 < run.count, run[i + 1] == 0x75,                // \u00NN
                          let hi = Hash256.nibble(run[i + 4]), let lo = Hash256.nibble(run[i + 5]) {
                    out.append(hi << 4 | lo); i += 6
                } else if run[i] == 0x5C, i + 3 < run.count,                                     // \NNN octal
                          (0x30...0x37).contains(run[i + 1]), (0x30...0x37).contains(run[i + 2]), (0x30...0x37).contains(run[i + 3]) {
                    out.append((run[i + 1] - 0x30) << 6 | (run[i + 2] - 0x30) << 3 | (run[i + 3] - 0x30)); i += 4
                } else if run[i] == 0x25, i + 2 < run.count,                                     // %NN
                          let hi = Hash256.nibble(run[i + 1]), let lo = Hash256.nibble(run[i + 2]) {
                    out.append(hi << 4 | lo); i += 3
                } else { i += 1 }
            }
            out.append(0x20)
        }
        return out.isEmpty ? nil : out
    }

    // MARK: Character codes

    private static let charCodeCalls = try! NSRegularExpression(
        pattern: #"(?:fromcharcode|character id|chr|ascii character|chararray|\[char\])\s*\(?\s*\{?\s*\d{2,3}"#,
        options: [.caseInsensitive])
    private static let numbers = try! NSRegularExpression(pattern: #"\b\d{2,3}\b"#)

    /// Pulls every 2–3 digit number in the neighbourhood of character-code calls and keeps
    /// the printable ones, in order.
    private static func charCodeLists(_ data: Data) -> [Data] {
        let text = String(decoding: data, as: UTF8.self)
        let range = NSRange(text.startIndex..., in: text)
        let calls = charCodeCalls.matches(in: text, range: range)
        guard calls.count >= 1 else { return [] }
        var out: [Data] = []
        // Group nearby calls: one list per stretch of code.
        var start = calls[0].range.location
        var end = start
        func flush() {
            let span = NSRange(location: start, length: min(end + 4000, (text as NSString).length) - start)
            var bytes = [UInt8]()
            for m in numbers.matches(in: text, range: span) {
                guard let r = Range(m.range, in: text), let v = Int(text[r]) else { continue }
                if (9...126).contains(v) { bytes.append(UInt8(v)) }
            }
            if bytes.count >= 8 { out.append(Data(bytes)) }
        }
        for call in calls.dropFirst() {
            if call.range.location - end > 4000 { flush(); start = call.range.location }
            end = call.range.location
        }
        flush()
        return out
    }

    // MARK: - Helpers

    /// At least 85% printable ASCII or whitespace, and long enough to matter.
    static func isMostlyText(_ data: Data) -> Bool {
        guard data.count >= 8 else { return false }
        let sample = data.prefix(4096)
        var printable = 0
        for b in sample where (b >= 0x20 && b < 0x7F) || b == 0x09 || b == 0x0A || b == 0x0D { printable += 1 }
        return printable * 100 >= sample.count * 85
    }

    private static func lowercased(_ data: Data) -> Data {
        var copy = data
        copy.withUnsafeMutableBytes { buffer in
            for i in buffer.indices where buffer[i] >= 65 && buffer[i] <= 90 { buffer[i] += 32 }
        }
        return copy
    }
}
