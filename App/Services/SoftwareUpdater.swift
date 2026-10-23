import Foundation
import Combine
import AppKit

/// Software updater: outdated apps are one of the main ways in, because attackers use the
/// security holes that updates fix. Finds out-of-date software without installing anything:
///
/// - apps that update themselves with Sparkle (most apps from outside the App Store): their
///   update feed (`SUFeedURL` in the app's Info.plist) is read and compared with the installed
///   version;
/// - Homebrew formulae and apps (`brew outdated`);
/// - macOS updates (`softwareupdate --list`).
///
/// Updating stays with the user: "Open" starts the app (which offers its own update), and
/// Homebrew items get the exact command.
@MainActor
final class SoftwareUpdater: ObservableObject {
    struct Outdated: Identifiable, Hashable {
        enum Source: String, Hashable { case app = "App", homebrew = "Homebrew", macOS = "macOS" }
        var id: String { source.rawValue + name }
        let name: String
        let installed: String
        let available: String
        let source: Source
        let path: String?
    }

    @Published private(set) var outdated: [Outdated] = []
    @Published private(set) var checkedApps = 0
    @Published private(set) var lastRun: Date?
    @Published private(set) var isRunning = false

    private var timer: Timer?

    func start() {
        // Weekly, a few minutes after launch.
        timer = Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.runIfDue() }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 240) { [weak self] in self?.runIfDue() }
    }

    private func runIfDue() {
        let last = UserDefaults.standard.object(forKey: "softwareUpdater.lastRun") as? Date
        if let last, Date().timeIntervalSince(last) < 7 * 86400 { return }
        run()
    }

    func run() {
        guard !isRunning else { return }
        isRunning = true
        Task {
            let apps = await SoftwareUpdater.checkApps()
            let brew = await Task.detached(priority: .utility) { SoftwareUpdater.checkHomebrew() }.value
            let system = await Task.detached(priority: .utility) { SoftwareUpdater.checkMacOS() }.value
            let previous = Set(self.outdated.map(\.id))
            self.outdated = (system + apps.items + brew).sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            self.checkedApps = apps.checked
            self.lastRun = Date()
            UserDefaults.standard.set(Date(), forKey: "softwareUpdater.lastRun")
            self.isRunning = false
            let new = self.outdated.filter { !previous.contains($0.id) }
            if !new.isEmpty {
                ActivityLog.shared.add(.update, "\(self.outdated.count) app\(self.outdated.count == 1 ? "" : "s") need updating",
                                       new.prefix(4).map(\.name).joined(separator: ", "))
                Notifier.post("Updates available", "\(new.prefix(3).map(\.name).joined(separator: ", "))\(new.count > 3 ? " and more" : "") have security updates waiting. See Security Checkup in Agamemnon.")
            }
        }
    }

    func open(_ item: Outdated) {
        if let path = item.path { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }
        if item.source == .macOS, let url = URL(string: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: - Sparkle apps

    nonisolated static func appFolders() -> [URL] {
        [URL(fileURLWithPath: "/Applications"), AppPaths.home.appendingPathComponent("Applications")]
    }

    nonisolated static func installedApps() -> [URL] {
        var out: [URL] = []
        for folder in appFolders() {
            let items = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? []
            for item in items {
                if item.pathExtension == "app" { out.append(item); continue }
                // One level of folders ("Utilities", "Microsoft Office"…).
                let inner = (try? FileManager.default.contentsOfDirectory(at: item, includingPropertiesForKeys: nil)) ?? []
                out += inner.filter { $0.pathExtension == "app" }
            }
        }
        return out
    }

    private static func checkApps() async -> (items: [Outdated], checked: Int) {
        var feeds: [(URL, String, String, String, URL)] = []   // app, name, short version, build, feed
        for app in installedApps() {
            guard let info = NSDictionary(contentsOf: app.appendingPathComponent("Contents/Info.plist")) as? [String: Any],
                  let feed = (info["SUFeedURL"] as? String).flatMap(URL.init(string:)), feed.scheme == "https" else { continue }
            let name = info["CFBundleDisplayName"] as? String ?? info["CFBundleName"] as? String ?? app.deletingPathExtension().lastPathComponent
            feeds.append((app, name, info["CFBundleShortVersionString"] as? String ?? "", info["CFBundleVersion"] as? String ?? "", feed))
        }
        var results: [Outdated] = []
        await withTaskGroup(of: Outdated?.self) { group in
            for (app, name, short, build, feed) in feeds {
                group.addTask {
                    guard let latest = await latestVersion(feed) else { return nil }
                    // Sparkle compares the build number (sparkle:version) first.
                    let newer: Bool
                    if let latestBuild = latest.build, !build.isEmpty {
                        newer = compare(latestBuild, build) == .orderedDescending
                    } else if let latestShort = latest.short, !short.isEmpty {
                        newer = compare(latestShort, short) == .orderedDescending
                    } else {
                        newer = false
                    }
                    guard newer else { return nil }
                    return Outdated(name: name, installed: short.isEmpty ? build : short,
                                    available: latest.short ?? latest.build ?? "newer", source: .app, path: app.path)
                }
            }
            for await item in group { if let item { results.append(item) } }
        }
        return (results, feeds.count)
    }

    nonisolated private static let shortAttr = try! NSRegularExpression(pattern: #"sparkle:shortVersionString\s*=\s*"([^"]+)"|<sparkle:shortVersionString>([^<]+)<"#)
    nonisolated private static let buildAttr = try! NSRegularExpression(pattern: #"sparkle:version\s*=\s*"([^"]+)"|<sparkle:version>([^<]+)<"#)

    /// The newest version an appcast offers (the highest one, whatever order it's listed in).
    nonisolated static func latestVersion(_ feed: URL) async -> (short: String?, build: String?)? {
        var request = URLRequest(url: feed)
        request.timeoutInterval = 20
        request.setValue("Agamemnon/3.1 (macOS antivirus; update check)", forHTTPHeaderField: "User-Agent")
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200, data.count < 8 * 1024 * 1024 else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        // Each <item> is one release; skip betas and items for newer macOS versions than this one.
        var best: (short: String?, build: String?)?
        for item in text.components(separatedBy: "<item").dropFirst() {
            let lower = item.lowercased()
            if lower.contains("<sparkle:channel>") { continue }
            if let min = firstMatch(#"<sparkle:minimumSystemVersion>([^<]+)<"#, in: item),
               compare(min, systemVersion) == .orderedDescending {
                continue
            }
            let short = groupValue(shortAttr, item)
            let build = groupValue(buildAttr, item)
            guard short != nil || build != nil else { continue }
            if let current = best {
                let a = build ?? short ?? "0", b = current.build ?? current.short ?? "0"
                if compare(a, b) == .orderedDescending { best = (short, build) }
            } else {
                best = (short, build)
            }
        }
        return best
    }

    nonisolated static var systemVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }

    nonisolated private static func groupValue(_ regex: NSRegularExpression, _ text: String) -> String? {
        guard let m = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) else { return nil }
        for i in 1..<m.numberOfRanges {
            if let r = Range(m.range(at: i), in: text) { return String(text[r]).trimmingCharacters(in: .whitespaces) }
        }
        return nil
    }

    nonisolated private static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        return groupValue(regex, text)
    }

    /// Compares dotted version strings numerically ("1.10" > "1.9"); letters are ignored.
    nonisolated static func compare(_ a: String, _ b: String) -> ComparisonResult {
        func parts(_ s: String) -> [Int] {
            s.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0.prefix(9)) }
        }
        let x = parts(a), y = parts(b)
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0, r = i < y.count ? y[i] : 0
            if l != r { return l < r ? .orderedAscending : .orderedDescending }
        }
        return .orderedSame
    }

    // MARK: - Homebrew and macOS

    nonisolated static func checkHomebrew() -> [Outdated] {
        guard let brew = Shell.which("brew") else { return [] }
        let r = Shell.run(brew, ["outdated", "--json=v2"], timeout: 120,
                          environment: ["HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ENV_HINTS": "1"])
        guard let json = try? JSONSerialization.jsonObject(with: Data(r.stdout.utf8)) as? [String: Any] else { return [] }
        var out: [Outdated] = []
        for key in ["formulae", "casks"] {
            for item in json[key] as? [[String: Any]] ?? [] {
                guard let name = item["name"] as? String else { continue }
                let installed = (item["installed_versions"] as? [String])?.last ?? (item["installed_versions"] as? String) ?? "?"
                out.append(Outdated(name: name, installed: installed, available: item["current_version"] as? String ?? "newer",
                                    source: .homebrew, path: nil))
            }
        }
        return out
    }

    nonisolated static func checkMacOS() -> [Outdated] {
        let r = Shell.run("/usr/sbin/softwareupdate", ["--list"], timeout: 180)
        var out: [Outdated] = []
        for line in r.stdout.components(separatedBy: .newlines) where line.contains("Title:") {
            let fields = line.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            let title = fields.first { $0.hasPrefix("Title:") }?.dropFirst(6).trimmingCharacters(in: .whitespaces) ?? "macOS update"
            let version = fields.first { $0.hasPrefix("Version:") }?.dropFirst(8).trimmingCharacters(in: .whitespaces) ?? ""
            out.append(Outdated(name: title, installed: ProcessInfo.processInfo.operatingSystemVersionString,
                                available: version, source: .macOS, path: nil))
        }
        return out
    }
}
