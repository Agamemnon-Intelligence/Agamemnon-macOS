import Foundation
import Combine
import AppKit

/// Browser protection against adware (Adload, Bundlore, Pirrit, Shlayer's payloads):
/// - Chrome, Brave, Edge, Vivaldi, Arc, Opera and Chromium extensions installed outside the
///   official store that can read every website or change the search engine,
/// - apps that force-install extensions behind your back ("External Extensions"),
/// - configuration profiles and Firefox policies that take control of the browser on a Mac
///   that isn't managed by a company,
/// - Safari extensions that come inside unsigned apps living in hidden or temporary folders.
///
/// Findings are warnings with Remove and Trust buttons. Only extensions containing known
/// malware (hash list or a malicious pattern rule) are moved to quarantine automatically.
@MainActor
final class BrowserGuard: ObservableObject {
    struct Finding: Identifiable, Hashable {
        var id: String { key }
        /// Stable identity, used for Trust and to notify only once.
        let key: String
        let browser: String
        let name: String
        let path: String?
        let reason: String
        let level: ThreatLevel
        /// What the Remove button does: move `path` to quarantine, or open Device Management.
        let removable: Bool
        var outcome: String?
    }

    @Published private(set) var findings: [Finding] = []
    @Published private(set) var extensionsChecked = 0
    @Published private(set) var lastRun: Date?
    @Published private(set) var isRunning = false

    private let vault: QuarantineVault
    private var watcher: FolderWatcher?
    private var timer: Timer?
    private var pendingRun: DispatchWorkItem?
    private let queue = DispatchQueue(label: "agamemnon.browser", qos: .utility)
    private let notifiedKey = "browser.notified"

    init(vault: QuarantineVault) {
        self.vault = vault
    }

    func applyPreference() {
        if Prefs.bool(Prefs.browserProtection) { start() } else { stop() }
    }

    func start() {
        guard !isRunning else { return }
        isRunning = true
        let paths = BrowserGuard.watchedFolders().filter { FileManager.default.fileExists(atPath: $0) }
        let watcher = FolderWatcher(paths: paths, latency: 2.0) { [weak self] _ in
            Task { @MainActor in self?.scheduleRun() }
        }
        if watcher.start() { self.watcher = watcher }
        timer = Timer.scheduledTimer(withTimeInterval: 30 * 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.run() }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self] in
            Task { @MainActor in self?.run() }
        }
    }

    func stop() {
        watcher?.stop()
        watcher = nil
        timer?.invalidate()
        timer = nil
        isRunning = false
    }

    private func scheduleRun() {
        pendingRun?.cancel()
        let work = DispatchWorkItem { [weak self] in Task { @MainActor in self?.run() } }
        pendingRun = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 3, execute: work)
    }

    func run() {
        let trusted = Set(UserDefaults.standard.stringArray(forKey: Prefs.trustedExtensions) ?? [])
        queue.async { [weak self] in
            let (found, count) = BrowserGuard.check()
            Task { @MainActor in self?.finish(found.filter { !trusted.contains($0.key) }, checked: count) }
        }
    }

    private func finish(_ found: [Finding], checked: Int) {
        lastRun = Date()
        extensionsChecked = checked
        var notified = Set(UserDefaults.standard.stringArray(forKey: notifiedKey) ?? [])
        var result: [Finding] = []
        for var finding in found {
            if finding.level == .malicious, finding.removable, Prefs.bool(Prefs.autoQuarantine) {
                finding.outcome = removeItem(finding)
            }
            result.append(finding)
        }
        findings = result

        let fresh = result.filter { !notified.contains($0.key) }
        if let first = fresh.first {
            let malicious = fresh.contains { $0.level == .malicious }
            Notifier.post(malicious ? "Malicious browser extension removed" : "Check your browser",
                          fresh.count == 1 ? "\(first.browser): \(first.name). \(first.reason)."
                                           : "\(fresh.count) things are changing or reading your browsers. Review them in Agamemnon.",
                          critical: malicious)
            for f in fresh {
                notified.insert(f.key)
                ActivityLog.shared.add(f.level == .malicious ? .threat : .info, "\(f.browser): \(f.name)", f.reason)
            }
            UserDefaults.standard.set(Array(notified), forKey: notifiedKey)
        }
    }

    // MARK: - Actions

    func remove(_ finding: Finding) {
        let outcome: String
        if finding.removable {
            outcome = removeItem(finding)
        } else {
            BrowserGuard.openDeviceManagement()
            outcome = "Remove it in System Settings › Device Management"
        }
        if let index = findings.firstIndex(where: { $0.key == finding.key }) { findings[index].outcome = outcome }
    }

    func trust(_ finding: Finding) {
        var list = UserDefaults.standard.stringArray(forKey: Prefs.trustedExtensions) ?? []
        if !list.contains(finding.key) { list.append(finding.key) }
        UserDefaults.standard.set(list, forKey: Prefs.trustedExtensions)
        findings.removeAll { $0.key == finding.key }
    }

    private func removeItem(_ finding: Finding) -> String {
        guard let path = finding.path, FileManager.default.fileExists(atPath: path) else { return "Already gone" }
        let detection = Detection(fileURL: URL(fileURLWithPath: path), innerPath: nil,
                                  threatName: "Browser: \(finding.reason)", engine: "Browser protection", level: finding.level)
        do {
            try vault.quarantine(detection)
            return "Moved to quarantine. Restart \(finding.browser) to finish"
        } catch {
            return error.localizedDescription
        }
    }

    static func openDeviceManagement() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Profiles-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: - Checking (off the main actor)

    /// Chromium-based browsers: display name → folder in ~/Library/Application Support.
    nonisolated static let chromiumBrowsers: [(String, String)] = [
        ("Chrome", "Google/Chrome"), ("Brave", "BraveSoftware/Brave-Browser"), ("Edge", "Microsoft Edge"),
        ("Vivaldi", "Vivaldi"), ("Arc", "Arc/User Data"), ("Opera", "com.operasoftware.Opera"), ("Chromium", "Chromium"),
    ]

    /// Update URLs of the official extension stores.
    nonisolated static let storeUpdateHosts = [
        "clients2.google.com/service/update2/crx", "edge.microsoft.com/extensionwebstorebase",
        "extension-updates.opera.com", "updates.vivaldi.com", "clients2.googleusercontent.com",
    ]

    nonisolated static let majorSearchHosts = [
        "google.", "bing.com", "duckduckgo.com", "yahoo.", "ecosia.org", "search.brave.com", "startpage.com",
        "qwant.com", "kagi.com", "yandex.", "baidu.com", "naver.com", "perplexity.ai", "you.com", "chatgpt.com",
    ]

    nonisolated static let broadHosts: Set<String> = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/"]
    nonisolated static let riskyPermissions: Set<String> = ["webRequest", "webRequestBlocking", "proxy", "debugger",
                                                            "nativeMessaging", "declarativeNetRequestWithHostAccess"]

    nonisolated static func appSupport(_ sub: String) -> String {
        AppPaths.home.appendingPathComponent("Library/Application Support/" + sub).path
    }

    nonisolated static func profileFolders(_ root: String) -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: root)) ?? []
        // Opera keeps a single profile in the root folder itself.
        var result = names.filter { $0 == "Default" || $0.hasPrefix("Profile ") }.map { root + "/" + $0 }
        if FileManager.default.fileExists(atPath: root + "/Extensions") { result.append(root) }
        return result
    }

    nonisolated static func watchedFolders() -> [String] {
        var folders: [String] = []
        for (_, sub) in chromiumBrowsers {
            let root = appSupport(sub)
            folders.append(contentsOf: profileFolders(root).map { $0 + "/Extensions" })
            folders.append(root + "/External Extensions")
        }
        folders.append("/Library/Application Support/Google/Chrome/External Extensions")
        folders.append("/Library/Managed Preferences")
        return folders
    }

    nonisolated static func check() -> ([Finding], Int) {
        var findings: [Finding] = []
        var count = 0
        for (browser, sub) in chromiumBrowsers {
            let root = appSupport(sub)
            for profile in profileFolders(root) {
                let (f, n) = checkChromiumExtensions(browser: browser, folder: profile + "/Extensions")
                findings += f
                count += n
            }
            findings += checkExternalExtensions(browser: browser, folder: root + "/External Extensions")
        }
        findings += checkExternalExtensions(browser: "Chrome", folder: "/Library/Application Support/Google/Chrome/External Extensions")
        let managed = isCompanyManaged()
        if !managed {
            findings += checkPolicies()
            findings += checkFirefoxPolicies()
        }
        let (safari, safariCount) = checkSafari()
        findings += safari
        count += safariCount
        findings.sort { ($0.level == .malicious ? 0 : 1) < ($1.level == .malicious ? 0 : 1) }
        return (findings, count)
    }

    nonisolated static func checkChromiumExtensions(browser: String, folder: String) -> ([Finding], Int) {
        var findings: [Finding] = []
        let ids = ((try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? []).filter { $0.count == 32 }
        for id in ids {
            let extFolder = folder + "/" + id
            let versions = ((try? FileManager.default.contentsOfDirectory(atPath: extFolder)) ?? []).filter { !$0.hasPrefix(".") }
            guard let version = versions.sorted().last else { continue }
            let dir = extFolder + "/" + version
            guard let data = FileManager.default.contents(atPath: dir + "/manifest.json"),
                  let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            let name = displayName(manifest, dir: dir) ?? id
            let key = "\(browser)|\(id)"

            // Known malware inside the extension.
            if let hit = scanFiles(dir) {
                findings.append(Finding(key: key, browser: browser, name: name, path: extFolder,
                                        reason: "Contains \(hit)", level: .malicious, removable: true))
                continue
            }

            let updateURL = (manifest["update_url"] as? String ?? "").lowercased()
            let fromStore = storeUpdateHosts.contains { updateURL.contains($0) }
            let permissions = ((manifest["permissions"] as? [Any]) ?? []).compactMap { $0 as? String }
                + ((manifest["host_permissions"] as? [Any]) ?? []).compactMap { $0 as? String }
            let contentMatches = ((manifest["content_scripts"] as? [[String: Any]]) ?? [])
                .flatMap { ($0["matches"] as? [String]) ?? [] }
            let readsEverything = !broadHosts.isDisjoint(with: permissions + contentMatches)
            let risky = !riskyPermissions.isDisjoint(with: permissions)

            let overrides = manifest["chrome_settings_overrides"] as? [String: Any]
            let search = (overrides?["search_provider"] as? [String: Any])?["search_url"] as? String
            let searchHost = search.flatMap { URL(string: $0.replacingOccurrences(of: "{searchTerms}", with: "x"))?.host?.lowercased() }
            let hijacksSearch = searchHost.map { host in !majorSearchHosts.contains { host.contains($0) } } ?? false
            let changesHome = overrides?["homepage"] != nil || overrides?["startup_pages"] != nil

            if hijacksSearch {
                findings.append(Finding(key: key, browser: browser, name: name, path: extFolder,
                                        reason: "Changes your search engine to \(searchHost ?? "another site")",
                                        level: .suspicious, removable: true))
            } else if !fromStore && (readsEverything || risky || changesHome) {
                findings.append(Finding(key: key, browser: browser, name: name, path: extFolder,
                                        reason: changesHome ? "Installed outside the store and changes your home page"
                                                            : "Installed outside the store and can read and change every website",
                                        level: .suspicious, removable: true))
            }
        }
        return (findings, ids.count)
    }

    /// Hash list and pattern rules on an extension's scripts (small files only).
    nonisolated static func scanFiles(_ dir: String) -> String? {
        guard let enumerator = FileManager.default.enumerator(atPath: dir) else { return nil }
        var checked = 0
        while let rel = enumerator.nextObject() as? String, checked < 400 {
            let url = URL(fileURLWithPath: dir + "/" + rel)
            guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size > 0, size < 8 * 1024 * 1024 else { continue }
            checked += 1
            if let hit = KnownMalware.lookup(url), hit.level == .malicious {
                return hit.name
            }
            if ["js", "mjs", "cjs"].contains(url.pathExtension.lowercased()),
               let hit = PatternRules.assess(url, size: Int64(size), outer: url, inner: nil, container: nil), hit.level == .malicious {
                return hit.threatName
            }
        }
        return nil
    }

    nonisolated static func displayName(_ manifest: [String: Any], dir: String) -> String? {
        guard let raw = manifest["name"] as? String else { return nil }
        guard raw.hasPrefix("__MSG_"), raw.hasSuffix("__") else { return raw }
        let msgKey = String(raw.dropFirst(6).dropLast(2))
        let locale = manifest["default_locale"] as? String ?? "en"
        for loc in [locale, "en", "en_US"] {
            if let data = FileManager.default.contents(atPath: "\(dir)/_locales/\(loc)/messages.json"),
               let messages = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                let match = messages.first { $0.key.lowercased() == msgKey.lowercased() }?.value as? [String: Any]
                if let text = match?["message"] as? String { return text }
            }
        }
        return nil
    }

    /// Apps can drop a JSON file here to make Chrome install an extension. Pointing at the
    /// official store is how some legitimate apps add their extension; a local .crx file isn't.
    nonisolated static func checkExternalExtensions(browser: String, folder: String) -> [Finding] {
        var findings: [Finding] = []
        for name in (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? [] where name.hasSuffix(".json") {
            let path = folder + "/" + name
            guard let data = FileManager.default.contents(atPath: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            let update = (json["external_update_url"] as? String ?? "").lowercased()
            if storeUpdateHosts.contains(where: { update.contains($0) }) { continue }
            findings.append(Finding(key: "\(browser)|external|\(name)", browser: browser,
                                    name: (name as NSString).deletingPathExtension,
                                    path: path, reason: "Another program installs this extension behind your back",
                                    level: .suspicious, removable: true))
        }
        return findings
    }

    /// MDM-enrolled Macs get browser policies from their company, which isn't adware.
    nonisolated static func isCompanyManaged() -> Bool {
        let r = Shell.run("/usr/bin/profiles", ["status", "-type", "enrollment"], timeout: 15)
        return r.stdout.lowercased().contains("mdm enrollment: yes")
    }

    /// Browser policies installed with a configuration profile (Adload, Pirrit and others do this).
    nonisolated static func checkPolicies() -> [Finding] {
        let domains: [(String, String)] = [("Chrome", "com.google.Chrome"), ("Brave", "com.brave.Browser"),
                                           ("Edge", "com.microsoft.Edge"), ("Safari", "com.apple.Safari")]
        let keys = ["ExtensionInstallForcelist", "ExtensionSettings", "HomepageLocation", "DefaultSearchProviderSearchURL",
                    "DefaultSearchProviderEnabled", "RestoreOnStartupURLs", "ProxyServer", "ProxyPacUrl", "NewTabPageLocation",
                    "HomePage", "NewWindowBehavior"]
        let base = "/Library/Managed Preferences"
        let folders = [base, base + "/" + NSUserName()]
        var findings: [Finding] = []
        for folder in folders {
            for (browser, domain) in domains {
                let path = "\(folder)/\(domain).plist"
                guard let dict = NSDictionary(contentsOfFile: path) as? [String: Any] else { continue }
                let set = keys.filter { dict[$0] != nil }
                guard !set.isEmpty else { continue }
                findings.append(Finding(key: "\(browser)|policy|\(path)", browser: browser, name: "Configuration profile",
                                        path: nil,
                                        reason: "A profile controls \(browser)'s \(describe(set)) on a Mac no company manages",
                                        level: .suspicious, removable: false))
            }
        }
        return findings
    }

    nonisolated static func describe(_ keys: [String]) -> String {
        if keys.contains(where: { $0.hasPrefix("Extension") }) { return "extensions" }
        if keys.contains(where: { $0.contains("Search") }) { return "search engine" }
        if keys.contains(where: { $0.hasPrefix("Proxy") }) { return "proxy (all your traffic)" }
        return "home page"
    }

    /// Firefox reads policies.json from inside the app; adware writes extensions and search settings there.
    nonisolated static func checkFirefoxPolicies() -> [Finding] {
        let path = "/Applications/Firefox.app/Contents/Resources/distribution/policies.json"
        guard let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let policies = json["policies"] as? [String: Any] else { return [] }
        let set = ["Extensions", "ExtensionSettings", "SearchEngines", "Homepage", "Proxy"].filter { policies[$0] != nil }
        guard !set.isEmpty else { return [] }
        return [Finding(key: "Firefox|policies", browser: "Firefox", name: "policies.json", path: path,
                        reason: "A file inside Firefox controls its \(describe(set))", level: .suspicious, removable: true)]
    }

    /// Safari extensions come inside apps. Adware ships them in unsigned apps hidden away in
    /// Application Support or temporary folders.
    nonisolated static func checkSafari() -> ([Finding], Int) {
        var findings: [Finding] = []
        var count = 0
        for point in ["com.apple.Safari.web-extension", "com.apple.Safari.extension", "com.apple.Safari.content-blocker"] {
            let r = Shell.run("/usr/bin/pluginkit", ["-mAvvv", "-p", point], timeout: 20)
            for line in r.stdout.components(separatedBy: .newlines) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard trimmed.hasPrefix("Path = ") else { continue }
                count += 1
                let path = String(trimmed.dropFirst(7))
                guard let range = path.range(of: ".app/") else { continue }
                let app = String(path[..<range.lowerBound]) + ".app"
                if BehaviorRules.isSystemPath(app) || app.hasPrefix("/Applications/") || app.hasPrefix(AppPaths.home.path + "/Applications/") { continue }
                let identity = CodeIdentity.of(app)
                guard identity.isUnvouched || StartupSweep.isHiddenOrTemporary(app) else { continue }
                findings.append(Finding(key: "Safari|\(app)", browser: "Safari", name: (app as NSString).lastPathComponent,
                                        path: app,
                                        reason: identity.isUnvouched ? "Extension inside an unsigned app outside Applications"
                                                                     : "Extension inside an app hidden outside Applications",
                                        level: .suspicious, removable: true))
            }
        }
        return (findings, count)
    }
}
