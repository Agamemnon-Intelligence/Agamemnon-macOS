import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// URLhaus by abuse.ch: links that are spreading malware right now (CC0). Downloaded from a
/// keyless mirror, or from abuse.ch itself when the user has added an Auth-Key (`AbuseCH`).
/// Agamemnon keeps the "online" list (about 25,000 links) on disk and in memory, and uses it
/// to judge where a download came from and what download tools are fetching.
final class URLhausStore {
    static let shared = URLhausStore()

    static var cacheURL: URL { AppPaths.signatures.appendingPathComponent("urlhaus-online.txt") }

    enum Match {
        /// This exact link is listed.
        case url(String)
        /// The site (a bare IP address, or a host that isn't shared hosting) serves listed links.
        case host(String)
    }

    private let lock = NSLock()
    private var urls: Set<String> = []
    private var hosts: Set<String> = []

    var count: Int { lock.lock(); defer { lock.unlock() }; return urls.count }

    /// Big shared sites where one bad link says nothing about the rest of the site.
    static let sharedHosts: [String] = [
        "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "google.com", "googleusercontent.com",
        "googleapis.com", "dropbox.com", "dropboxusercontent.com", "discord.com", "discordapp.com", "discordapp.net",
        "mediafire.com", "onedrive.live.com", "1drv.ms", "sharepoint.com", "amazonaws.com", "cloudfront.net",
        "azureedge.net", "blob.core.windows.net", "web.app", "firebaseapp.com", "pages.dev", "workers.dev",
        "vercel.app", "netlify.app", "herokuapp.com", "glitch.me", "telegram.org", "t.me", "mega.nz", "box.com",
        "wetransfer.com", "sourceforge.net", "archive.org", "apple.com", "icloud.com", "microsoft.com",
        "cdn.discordapp.com", "ngrok.io", "ngrok-free.app", "duckdns.org", "000webhostapp.com", "weebly.com",
        "wixsite.com", "blogspot.com", "wordpress.com", "r2.dev", "gofile.io", "transfer.sh", "pastebin.com",
    ]

    /// Lower-cased scheme-less form used for matching: host lower-cased, path kept as is,
    /// no trailing slash.
    static func normalize(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, !s.hasPrefix("#") else { return nil }
        if let range = s.range(of: "://") { s = String(s[range.upperBound...]) }
        guard !s.isEmpty else { return nil }
        let slash = s.firstIndex(of: "/") ?? s.endIndex
        var host = s[..<slash].lowercased()
        if host.hasPrefix("www.") { host.removeFirst(4) }
        var rest = String(s[slash...])
        if let hash = rest.firstIndex(of: "#") { rest = String(rest[..<hash]) }
        while rest.hasSuffix("/") { rest.removeLast() }
        return host + rest
    }

    static func host(of normalized: String) -> String {
        var host = String(normalized.prefix { $0 != "/" })
        if let colon = host.lastIndex(of: ":"), !host.contains("]") { host = String(host[..<colon]) }
        return host
    }

    static func isIPAddress(_ host: String) -> Bool {
        let parts = host.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { UInt8($0) != nil }
    }

    static func isShared(_ host: String) -> Bool {
        sharedHosts.contains { host == $0 || host.hasSuffix("." + $0) }
    }

    func replace(with list: [String]) {
        var newURLs = Set<String>()
        var newHosts = Set<String>()
        for line in list {
            guard let n = URLhausStore.normalize(line) else { continue }
            newURLs.insert(n)
            let host = URLhausStore.host(of: n)
            if !URLhausStore.isShared(host) { newHosts.insert(host) }
        }
        lock.lock()
        urls = newURLs
        hosts = newHosts
        lock.unlock()
    }

    @discardableResult
    func loadFromDisk() -> Int {
        guard let text = try? String(contentsOf: URLhausStore.cacheURL, encoding: .utf8) else { return 0 }
        replace(with: text.components(separatedBy: .newlines))
        return count
    }

    func lookup(_ raw: String) -> Match? {
        guard let n = URLhausStore.normalize(raw) else { return nil }
        let host = URLhausStore.host(of: n)
        lock.lock(); defer { lock.unlock() }
        if urls.contains(n) { return .url(raw) }
        if hosts.contains(host) { return .host(host) }
        return nil
    }

    private static let linkPattern = try! NSRegularExpression(pattern: #"https?://[^\s'"`<>|;)]+"#, options: [.caseInsensitive])

    /// The first link in a command line that's an exact URLhaus hit, or on a dedicated malware host.
    func firstListedURL(in text: String) -> String? {
        guard count > 0 else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        for m in URLhausStore.linkPattern.matches(in: text, range: range) {
            guard let r = Range(m.range, in: text) else { continue }
            let link = String(text[r])
            switch lookup(link) {
            case .url: return link
            case .host(let host) where URLhausStore.isIPAddress(host): return link
            default: continue
            }
        }
        return nil
    }

    // MARK: - Where a download came from

    /// The "Where from" links browsers record on downloads (read straight from the extended
    /// attribute, so it works even when Spotlight hasn't indexed the file).
    static func whereFroms(_ url: URL) -> [String] {
        let name = "com.apple.metadata:kMDItemWhereFroms"
        let size = getxattr(url.path, name, nil, 0, 0, 0)
        guard size > 0 else { return [] }
        var data = Data(count: size)
        let read = data.withUnsafeMutableBytes { getxattr(url.path, name, $0.baseAddress, size, 0, 0) }
        guard read > 0,
              let list = try? PropertyListSerialization.propertyList(from: data.prefix(read), format: nil) as? [String] else { return [] }
        return list
    }

    /// Judges a downloaded item by where it came from.
    func assessDownload(_ url: URL) -> Detection? {
        guard count > 0 else { return nil }
        for source in URLhausStore.whereFroms(url) {
            switch lookup(source) {
            case .url:
                return Detection(fileURL: url, innerPath: nil, threatName: "Downloaded from a known malware link (URLhaus)",
                                 engine: "URLhaus", level: .malicious)
            case .host(let host):
                let dedicated = URLhausStore.isIPAddress(host)
                return Detection(fileURL: url, innerPath: nil,
                                 threatName: dedicated ? "Downloaded from a known malware server (URLhaus)"
                                                       : "Downloaded from a site that's spreading malware (URLhaus)",
                                 engine: "URLhaus", level: dedicated ? .malicious : .suspicious)
            case nil:
                continue
            }
        }
        return nil
    }

    // MARK: - Updating

    /// Keyless mirrors of URLhaus's online list (malware-filter by curbengh, CC0/MIT), in
    /// uBlock format: `||host/path^$all` for links, a bare host or IP for whole sites.
    static let mirrors = [
        "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt",
        "https://curbengh.github.io/malware-filter/urlhaus-filter-online.txt",
        "https://malware-filter.pages.dev/urlhaus-filter-online.txt",
    ]

    /// Downloads the list: URLhaus's own export with an abuse.ch key, otherwise a keyless mirror.
    static func download() async throws -> [String] {
        var lines: [String] = []
        if AbuseCH.hasKey, let data = try? await AbuseCH.fetch(.urlhaus, "recent.csv", timeout: 180) {
            lines = parseExport(data)
        }
        if lines.count <= 500 {
            for mirror in mirrors {
                var request = URLRequest(url: URL(string: mirror)!)
                request.timeoutInterval = 120
                request.setValue("Agamemnon/3.1 (macOS antivirus)", forHTTPHeaderField: "User-Agent")
                guard let (data, response) = try? await URLSession.shared.data(for: request),
                      (response as? HTTPURLResponse)?.statusCode == 200 else { continue }
                lines = parseFilterList(data)
                if lines.count > 500 { break }
            }
        }
        guard lines.count > 500 else { throw SignatureManager.UpdateError.suspiciousList }
        try lines.joined(separator: "\n").write(to: cacheURL, atomically: true, encoding: .utf8)
        return lines
    }

    /// uBlock-format list → "host/path" or "host" lines (comments and options removed).
    static func parseFilterList(_ data: Data) -> [String] {
        let text = String(decoding: data, as: UTF8.self)
        var out: [String] = []
        for raw in text.split(whereSeparator: \.isNewline) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("!") || line.hasPrefix("#") { continue }
            if line.hasPrefix("||") { line.removeFirst(2) }
            if let caret = line.firstIndex(of: "^") { line = String(line[..<caret]) }
            if let dollar = line.firstIndex(of: "$") { line = String(line[..<dollar]) }
            if !line.isEmpty { out.append(line) }
        }
        return out
    }

    static func parseExport(_ data: Data) -> [String] {
        let text = String(decoding: data, as: UTF8.self)
        var links: [String] = []
        for line in text.split(whereSeparator: \.isNewline) where !line.hasPrefix("#") {
            // Plain-text exports are one link per line.
            if line.hasPrefix("http://") || line.hasPrefix("https://") { links.append(String(line)); continue }
            let fields = AbuseCH.csvFields(line)
            guard let link = fields.first(where: { $0.hasPrefix("http://") || $0.hasPrefix("https://") }) else { continue }
            if fields.contains(where: { $0.lowercased() == "offline" }) { continue }
            links.append(link)
        }
        return links
    }
}
