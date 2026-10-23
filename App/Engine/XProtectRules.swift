import Foundation

/// Apple's own malware rules, as an extra engine. macOS ships them with XProtect (YARA rules
/// for programs in XProtect.yara and for scripts in XPScripts.yr) and keeps them up to date in
/// the background, but only checks files when they're opened. Agamemnon runs the same rules
/// over whole folders with the open-source `yara` tool (Homebrew), so malware sitting in an
/// archive, on a USB drive or in a folder nobody opened is found too.
final class XProtectRules {
    static let shared = XProtectRules()

    /// Newer rules arrive over iCloud into /var/protected; the system copy is the fallback.
    static let bundles = [
        "/var/protected/xprotect/XProtect.bundle",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
    ]

    var yaraPath: String? { Shell.which("yara") }
    var yaracPath: String? { Shell.which("yarac") }
    var isInstalled: Bool { yaraPath != nil }

    /// The rule files of the newest XProtect bundle on this Mac.
    var ruleFiles: [String] {
        let best = XProtectRules.bundles
            .filter { FileManager.default.fileExists(atPath: $0 + "/Contents/Resources/XProtect.yara") }
            .max { XProtectRules.version(of: $0) < XProtectRules.version(of: $1) }
        guard let best else { return [] }
        return ["XProtect.yara", "XPScripts.yr"]
            .map { best + "/Contents/Resources/" + $0 }
            .filter { FileManager.default.fileExists(atPath: $0) }
    }

    var isReady: Bool { isInstalled && !ruleFiles.isEmpty }

    static func version(of bundle: String) -> Int {
        let info = NSDictionary(contentsOfFile: bundle + "/Contents/Info.plist")
        return Int(info?["CFBundleShortVersionString"] as? String ?? "") ?? 0
    }

    var rulesVersion: Int? {
        guard let file = ruleFiles.first else { return nil }
        let bundle = (file as NSString).deletingLastPathComponent
            .replacingOccurrences(of: "/Contents/Resources", with: "")
        return XProtectRules.version(of: bundle)
    }

    var ruleCount: Int {
        ruleFiles.reduce(0) { total, file in
            let text = (try? String(contentsOfFile: file, encoding: .utf8)) ?? ""
            return total + text.components(separatedBy: "\nrule ").count - 1 + (text.hasPrefix("rule ") ? 1 : 0)
        }
    }

    // MARK: - Compiled rules

    private let compileLock = NSLock()

    private var compiledURL: URL { AppPaths.directory("XProtect").appendingPathComponent("xprotect.yarc") }

    /// Compiles the rules once per XProtect update (loading 600 rules from source on every run
    /// costs a fraction of a second each time). Falls back to source rules if yarac fails.
    private func ruleArguments() -> [String] {
        let files = ruleFiles
        guard let yarac = yaracPath, !files.isEmpty else { return files }
        compileLock.lock(); defer { compileLock.unlock() }
        let stamp = files.compactMap { (try? FileManager.default.attributesOfItem(atPath: $0))?[.modificationDate] as? Date }.max()
        let compiled = (try? FileManager.default.attributesOfItem(atPath: compiledURL.path))?[.modificationDate] as? Date
        if let compiled, let stamp, compiled >= stamp { return ["-C", compiledURL.path] }
        let r = Shell.run(yarac, ["-w"] + files + [compiledURL.path], timeout: 120)
        if r.succeeded, FileManager.default.fileExists(atPath: compiledURL.path) { return ["-C", compiledURL.path] }
        return files
    }

    // MARK: - Scanning

    struct Hit {
        let path: String
        let name: String
        let level: ThreatLevel
    }

    /// Scans a list of files.
    func scan(files: [String], register: (LineProcess) -> Void = { _ in }) -> [Hit] {
        guard !files.isEmpty else { return [] }
        let list = AppPaths.newScratchDirectory("yara").appendingPathComponent("files.txt")
        defer { try? FileManager.default.removeItem(at: list.deletingLastPathComponent()) }
        guard (try? files.joined(separator: "\n").write(to: list, atomically: true, encoding: .utf8)) != nil else { return [] }
        return run(["--scan-list", list.path], register: register)
    }

    /// Scans a folder recursively (used for unpacked archives and disk images).
    func scan(folder: String, register: (LineProcess) -> Void = { _ in }) -> [Hit] {
        run(["-r", folder], register: register)
    }

    private static let line = try! NSRegularExpression(pattern: #"^(\S+)(?: \[(.*)\])? (/.*)$"#)
    private static let description = try! NSRegularExpression(pattern: #"description="([^"]*)""#)

    private func run(_ target: [String], register: (LineProcess) -> Void) -> [Hit] {
        guard let yara = yaraPath else { return [] }
        let rules = ruleArguments()
        guard !rules.isEmpty else { return [] }
        let threads = max(2, min(8, ProcessInfo.processInfo.activeProcessorCount))
        let args = ["-w", "-N", "-m", "-p", "\(threads)", "-z", "\(256 * 1024 * 1024)", "-a", "60"] + rules + target
        let lock = NSLock()
        var hits: [Hit] = []
        let process = LineProcess(yara, args) { text in
            let range = NSRange(text.startIndex..., in: text)
            guard let m = XProtectRules.line.firstMatch(in: text, range: range),
                  let ruleRange = Range(m.range(at: 1), in: text),
                  let pathRange = Range(m.range(at: 3), in: text) else { return }
            let rule = String(text[ruleRange])
            var name = rule
            if let metaRange = Range(m.range(at: 2), in: text) {
                let meta = String(text[metaRange])
                if let d = XProtectRules.description.firstMatch(in: meta, range: NSRange(meta.startIndex..., in: meta)),
                   let r = Range(d.range(at: 1), in: meta), !meta[r].isEmpty {
                    name = String(meta[r])
                }
            }
            let upper = name.uppercased()
            // Adware and unwanted programs are warnings; everything else Apple calls malware.
            let level: ThreatLevel = upper.contains("ADWARE") || upper.contains("PUA") || upper.contains("PUP") ? .suspicious : .malicious
            lock.lock()
            hits.append(Hit(path: String(text[pathRange]), name: "XProtect: " + name, level: level))
            lock.unlock()
        }
        do { try process.start() } catch { return [] }
        register(process)
        process.waitUntilExit()
        lock.lock(); defer { lock.unlock() }
        return hits
    }

    // MARK: - Installing

    /// `brew install yara` (only with Homebrew; yara has no signed macOS installer).
    func install() -> String? {
        guard let brew = Shell.which("brew") else {
            return "Apple's rules need the free yara tool, which installs with Homebrew (brew.sh)."
        }
        let r = Shell.run(brew, ["install", "yara"], timeout: 1200,
                          environment: ["HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_INSTALL_CLEANUP": "1", "HOMEBREW_NO_ENV_HINTS": "1"])
        if isInstalled { return nil }
        return "Homebrew couldn't install yara: " + String((r.stderr + r.stdout).suffix(200))
    }
}
