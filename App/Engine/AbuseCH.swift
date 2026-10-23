import Foundation
import Security

/// abuse.ch (MalwareBazaar, URLhaus) stopped serving its lists without an account in
/// October 2026: the old keyless links answer "410 Gone". Every download now needs a free
/// Auth-Key (https://auth.abuse.ch), placed in the link itself. The key is the user's, so it's
/// kept in their login keychain rather than in Agamemnon's settings file.
enum AbuseCH {
    private static let service = "com.mirazbakis.Agamemnon.abusech"
    private static let account = "Auth-Key"

    /// Where users get a key (free; sign in with GitHub, Google, LinkedIn or X).
    static let signUpURL = URL(string: "https://auth.abuse.ch/")!

    static var authKey: String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let key = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !key.isEmpty else { return nil }
        return key
    }

    static var hasKey: Bool { authKey != nil }

    /// Saves (or, with an empty string, removes) the key.
    @discardableResult
    static func setAuthKey(_ key: String) -> Bool {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(base as CFDictionary)
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return true }
        // Keys are plain letters and digits; anything else would break the link.
        guard trimmed.allSatisfy({ $0.isLetter || $0.isNumber }), trimmed.count <= 128 else { return false }
        var add = base
        add[kSecValueData as String] = Data(trimmed.utf8)
        add[kSecAttrLabel as String] = "Agamemnon abuse.ch Auth-Key"
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    enum Feed {
        case malwareBazaar, urlhaus

        var host: String {
            switch self {
            case .malwareBazaar: return "mb-api.abuse.ch"
            case .urlhaus: return "urlhaus-api.abuse.ch"
            }
        }
    }

    /// `https://<feed>/v2/files/exports/<key>/<file>`
    static func exportURL(_ feed: Feed, _ file: String, key: String) -> URL? {
        URL(string: "https://\(feed.host)/v2/files/exports/\(key)/\(file)")
    }

    enum Failure: LocalizedError {
        case noKey
        case rejectedKey
        case notFound

        var errorDescription: String? {
            switch self {
            case .noKey: return "abuse.ch now needs a free Auth-Key. Add yours in Settings ▸ Malware signatures."
            case .rejectedKey: return "abuse.ch didn't accept the Auth-Key. Check it at auth.abuse.ch."
            case .notFound: return "abuse.ch doesn't offer that list any more."
            }
        }
    }

    /// Downloads one export. 401/403 means a bad key; 404 means that file name doesn't exist.
    static func fetch(_ feed: Feed, _ file: String, timeout: TimeInterval = 300) async throws -> Data {
        guard let key = authKey else { throw Failure.noKey }
        guard let url = exportURL(feed, file, key: key) else { throw Failure.rejectedKey }
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        request.setValue("Agamemnon/3.1 (macOS antivirus)", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse {
            switch http.statusCode {
            case 200..<300: return data
            case 401, 403: throw Failure.rejectedKey
            case 404, 410: throw Failure.notFound
            default: throw SignatureManager.UpdateError.http(http.statusCode)
            }
        }
        return data
    }

    /// Unpacks a ZIP export into memory (the first .txt or .csv file inside).
    static func unzipFirstList(_ zip: Data) throws -> Data {
        let dir = AppPaths.newScratchDirectory("abusech")
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("export.zip")
        try zip.write(to: file)
        let r = Shell.run("/usr/bin/unzip", ["-o", "-q", file.path, "-d", dir.path], timeout: 300)
        guard r.status == 0 else { throw SignatureManager.UpdateError.unzip(r.stderr) }
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        guard let list = files.first(where: { ["txt", "csv"].contains($0.pathExtension.lowercased()) }) else {
            throw SignatureManager.UpdateError.unzip("no hash list inside")
        }
        return try Data(contentsOf: list)
    }

    /// Splits one CSV line into fields (handles quotes and doubled quotes).
    static func csvFields(_ line: Substring) -> [String] {
        var fields: [String] = []
        var current = ""
        var quoted = false
        var iterator = line.makeIterator()
        while let c = iterator.next() {
            if quoted {
                if c == "\"" {
                    if let next = iterator.next() {
                        if next == "\"" { current.append("\"") } else {
                            quoted = false
                            if next == "," { fields.append(current); current = "" } else { current.append(next) }
                        }
                    } else { quoted = false }
                } else { current.append(c) }
            } else if c == "\"" {
                quoted = true
            } else if c == "," {
                fields.append(current); current = ""
            } else {
                current.append(c)
            }
        }
        fields.append(current)
        return fields.map { $0.trimmingCharacters(in: .whitespaces) }
    }
}

/// Live lookups of a file's SHA-256 in MalwareBazaar's database (the "cloud" check). Catches
/// samples reported in the last hours, before they reach the downloadable lists. Only the
/// fingerprint is sent, never the file, and only for programs nobody vouches for.
enum CloudLookup {
    private static let lock = NSLock()
    private static var cache: [String: String?] = [:]
    private static var recent: [Date] = []

    static var isEnabled: Bool { Prefs.bool(Prefs.cloudLookup) && AbuseCH.hasKey }

    /// The malware family name if MalwareBazaar knows this hash, nil if it doesn't (or the check
    /// couldn't run). Results are cached; at most 60 lookups a minute.
    static func lookup(sha256 hex: String) async -> String? {
        guard isEnabled, let key = AbuseCH.authKey else { return nil }
        switch reserve(hex) {
        case .cached(let value): return value
        case .rateLimited: return nil
        case .go: break
        }

        var request = URLRequest(url: URL(string: "https://mb-api.abuse.ch/api/v1/")!)
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue(key, forHTTPHeaderField: "Auth-Key")
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("Agamemnon/3.1 (macOS antivirus)", forHTTPHeaderField: "User-Agent")
        request.httpBody = Data("query=get_info&hash=\(hex)".utf8)
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let status = json["query_status"] as? String else { return nil }
        var result: String?
        if status == "ok", let first = (json["data"] as? [[String: Any]])?.first {
            let family = (first["signature"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "malware"
            result = "Known malware: \(family) (MalwareBazaar live)"
        } else if status != "hash_not_found" {
            return nil   // errors aren't cached
        }
        store(hex, result)
        return result
    }

    private enum Reservation { case cached(String?), rateLimited, go }

    /// Cache check and rate limit, in one locked step (synchronous, so it's safe to lock).
    private static func reserve(_ hex: String) -> Reservation {
        lock.lock(); defer { lock.unlock() }
        if let cached = cache[hex] { return .cached(cached) }
        recent = recent.filter { Date().timeIntervalSince($0) < 60 }
        guard recent.count < 60 else { return .rateLimited }
        recent.append(Date())
        return .go
    }

    private static func store(_ hex: String, _ result: String?) {
        lock.lock(); defer { lock.unlock() }
        if cache.count > 5000 { cache.removeAll() }
        cache[hex] = result
    }
}
