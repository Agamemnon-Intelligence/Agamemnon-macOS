import Foundation
import Combine

// MARK: - Administrator access monitor

/// Watches the macOS authorization daemon (authd) in the system log and warns
/// when an app asks for administrator rights — for example to install a
/// helper tool, change system settings or modify protected files.
@MainActor
final class AdminWatcher: ObservableObject {
    struct Request: Identifiable, Hashable {
        let id = UUID()
        let date: Date
        let requester: String
        let rights: [String]
        var outcome: String?

        var appName: String {
            if let range = requester.range(of: ".app/") ?? requester.range(of: ".app", options: .backwards) {
                let app = String(requester[..<range.lowerBound])
                return (app as NSString).lastPathComponent
            }
            return (requester as NSString).lastPathComponent
        }
    }

    @Published private(set) var isRunning = false
    @Published private(set) var requests: [Request] = []
    @Published private(set) var problem: String?

    private var process: LineProcess?
    private var restartWork: DispatchWorkItem?
    private var lastAlert: [String: Date] = [:]
    private var wantsRunning = false

    /// Rights that mean "this app wants admin-level control".
    private static let watchedRightPrefixes = [
        "system.privilege.admin", "system.install", "com.apple.ServiceManagement",
        "system.preferences", "system.services", "config.modify", "system.privilege.taskport",
        "system.csfde", "system.keychain.modify", "com.apple.security.sudo", "system.sharepoints",
        "system.identity.write",
    ]

    private static let evaluates = try! NSRegularExpression(
        pattern: #"Process (.+?) \(PID (\d+)\) evaluates \d+ rights? with flags ([0-9a-fA-F]+)[^:]*: \((.*)\)"#)
    private static let outcome = try! NSRegularExpression(
        pattern: #"(Succeeded authorizing|Failed to authorize) right '([^']+)' by client '[^']*' \[\d+\] for authorization created by '([^']+)'"#)

    func applyPreference() {
        if Prefs.bool(Prefs.adminAlerts) { start() } else { stop() }
    }

    func start() {
        wantsRunning = true
        guard process == nil else { return }
        let proc = LineProcess("/usr/bin/log", [
            "stream", "--style", "ndjson", "--level", "info",
            "--predicate", "process == \"authd\" AND (eventMessage CONTAINS \"evaluates\" OR eventMessage CONTAINS \"authoriz\")",
        ]) { [weak self] line in
            Task { @MainActor in self?.handle(line) }
        }
        do {
            try proc.start()
        } catch {
            problem = "Couldn't read the system log: \(error.localizedDescription)"
            return
        }
        process = proc
        isRunning = true
        problem = nil
        // Watch for the stream ending (e.g. not an admin account) and restart it.
        DispatchQueue.global(qos: .utility).async { [weak self] in
            proc.waitUntilExit()
            let err = proc.errorOutput
            Task { @MainActor in self?.streamEnded(err) }
        }
    }

    func stop() {
        wantsRunning = false
        restartWork?.cancel()
        process?.terminate()
        process = nil
        isRunning = false
    }

    private func streamEnded(_ error: String) {
        process = nil
        isRunning = false
        guard wantsRunning else { return }
        let trimmed = error.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().contains("must be admin") {
            problem = "Admin alerts need an administrator account."
            return
        }
        if !trimmed.isEmpty { problem = String(trimmed.prefix(200)) }
        let work = DispatchWorkItem { [weak self] in
            Task { @MainActor in
                guard let self, self.wantsRunning else { return }
                self.start()
            }
        }
        restartWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 10, execute: work)
    }

    private func handle(_ line: String) {
        guard line.hasPrefix("{"),
              let data = line.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let message = json["eventMessage"] as? String else { return }
        let range = NSRange(message.startIndex..., in: message)

        if let m = AdminWatcher.evaluates.firstMatch(in: message, range: range),
           let requesterRange = Range(m.range(at: 1), in: message),
           let flagsRange = Range(m.range(at: 3), in: message),
           let rightsRange = Range(m.range(at: 4), in: message) {
            let requester = String(message[requesterRange])
            let flags = UInt32(message[flagsRange], radix: 16) ?? 0
            let rights = message[rightsRange]
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: " '\"")) }
                .filter { !$0.isEmpty }
            // 0x1 = interaction allowed, 0x2 = extend rights → a password prompt can appear.
            guard flags & 0x3 == 0x3 else { return }
            let interesting = rights.filter { r in AdminWatcher.watchedRightPrefixes.contains { r.hasPrefix($0) } }
            guard !interesting.isEmpty else { return }
            report(requester: requester, rights: interesting)
            return
        }

        if let m = AdminWatcher.outcome.firstMatch(in: message, range: range),
           let kindRange = Range(m.range(at: 1), in: message),
           let rightRange = Range(m.range(at: 2), in: message),
           let creatorRange = Range(m.range(at: 3), in: message) {
            let succeeded = message[kindRange].hasPrefix("Succeeded")
            let right = String(message[rightRange])
            let creator = String(message[creatorRange])
            if let index = requests.firstIndex(where: { $0.requester == creator && $0.rights.contains(right) && $0.outcome == nil }) {
                requests[index].outcome = succeeded ? "Allowed" : "Denied"
            }
        }
    }

    private func report(requester: String, rights: [String]) {
        if Privileged.isPrompting { return }
        if let own = Bundle.main.executablePath, requester == own { return }
        let key = requester + "|" + rights.joined(separator: ",")
        if let last = lastAlert[key], Date().timeIntervalSince(last) < 30 { return }
        lastAlert[key] = Date()

        let request = Request(date: Date(), requester: requester, rights: rights, outcome: nil)
        requests.insert(request, at: 0)
        if requests.count > 50 { requests.removeLast(requests.count - 50) }

        let what = AdminWatcher.describe(rights)
        Notifier.post("\(request.appName) wants administrator access",
                      "It's asking to \(what). Only enter your password if you started this yourself.",
                      critical: true)
        ActivityLog.shared.add(.admin, "\(request.appName) asked for administrator access", requester)
    }

    static func describe(_ rights: [String]) -> String {
        let r = rights.first ?? ""
        if r.hasPrefix("system.install") { return "install software" }
        if r.hasPrefix("com.apple.ServiceManagement") { return "install a background helper" }
        if r.hasPrefix("system.preferences") { return "change system settings" }
        if r.hasPrefix("system.privilege.taskport") { return "control other apps" }
        if r.hasPrefix("system.keychain") { return "change a keychain" }
        if r.hasPrefix("system.services") || r.hasPrefix("system.identity") { return "change users or directory settings" }
        return "make changes as an administrator"
    }
}

// MARK: - Background item monitor

/// Watches LaunchAgents / LaunchDaemons folders, where malware installs itself
/// to start automatically. New items are reported and the program they launch is scanned.
@MainActor
final class BackgroundItemWatcher: ObservableObject {
    struct Item: Identifiable, Hashable {
        let id = UUID()
        let date: Date
        let plistPath: String
        let label: String
        let program: String?
        var verdict: String
    }

    @Published private(set) var isRunning = false
    @Published private(set) var items: [Item] = []

    private var watcher: FolderWatcher?
    private var known: [String: Date] = [:]
    private let vault: QuarantineVault
    private let queue = DispatchQueue(label: "agamemnon.background-items", qos: .utility)

    static var folders: [String] {
        [
            AppPaths.home.appendingPathComponent("Library/LaunchAgents").path,
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
        ]
    }

    /// Other places that make code run automatically. Anything new here is reported and scanned.
    static var pluginFolders: [String] {
        [
            "/Library/StartupItems",
            "/Library/Security/SecurityAgentPlugins",     // runs inside the login window
            "/Library/DirectoryServices/PlugIns",
            "/Library/PrivilegedHelperTools",
            AppPaths.home.appendingPathComponent("Library/Scripts/Folder Action Scripts").path,
            AppPaths.home.appendingPathComponent("Library/Spotlight").path,
            AppPaths.home.appendingPathComponent("Library/QuickLook").path,
        ]
    }

    /// Files run by every new Terminal window or shell.
    nonisolated static var shellProfiles: [String] {
        [".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".profile", ".bash_login",
         ".config/fish/config.fish"].map { AppPaths.home.appendingPathComponent($0).path } + ["/etc/zshrc", "/etc/profile", "/etc/zprofile"]
    }

    /// Our own helper (Settings ▸ Self-protection) isn't reported.
    nonisolated static let ownLabels: Set<String> = ["com.mirazbakis.Agamemnon.Helper"]

    init(vault: QuarantineVault) {
        self.vault = vault
    }

    func applyPreference() {
        if Prefs.bool(Prefs.backgroundItemAlerts) { start() } else { stop() }
    }

    func start() {
        guard !isRunning else { return }
        let paths = (BackgroundItemWatcher.folders + BackgroundItemWatcher.pluginFolders)
            .filter { FileManager.default.fileExists(atPath: $0) }
        known = [:]
        for folder in paths { snapshot(folder) }
        let watcher = FolderWatcher(paths: paths, latency: 1.0) { [weak self] changed in
            Task { @MainActor in self?.handle(changed) }
        }
        guard watcher.start() else { return }
        self.watcher = watcher
        isRunning = true
        profileState = BackgroundItemWatcher.readProfiles()
        cronState = BackgroundItemWatcher.readCrontab()
        loginHook = BackgroundItemWatcher.readLoginHook()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 20, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    func stop() {
        watcher?.stop()
        watcher = nil
        pollTimer?.invalidate()
        pollTimer = nil
        isRunning = false
    }

    // MARK: Shell profiles, cron and login hooks (polled; they're single files)

    private var pollTimer: Timer?
    private var profileState: [String: String] = [:]
    private var cronState = ""
    private var loginHook = ""

    nonisolated static func readProfiles() -> [String: String] {
        var out: [String: String] = [:]
        for path in shellProfiles {
            if let text = try? String(contentsOfFile: path, encoding: .utf8) { out[path] = text }
        }
        return out
    }

    nonisolated static func readCrontab() -> String {
        Shell.run("/usr/bin/crontab", ["-l"], timeout: 10).stdout
    }

    nonisolated static func readLoginHook() -> String {
        let prefs = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.loginwindow.plist")
        return [prefs?["LoginHook"], prefs?["LogoutHook"]].compactMap { $0 as? String }.joined(separator: "\n")
    }

    /// Lines a shell profile should never contain.
    nonisolated private static let profileDangers: [(NSRegularExpression, String)] = [
        (try! NSRegularExpression(pattern: #"(curl|wget)\b[^\n]*\|\s*(ba|z)?sh\b"#, options: .caseInsensitive), "downloads and runs code every time you open Terminal"),
        (try! NSRegularExpression(pattern: #"base64\s+(-d|-D|--decode)"#, options: .caseInsensitive), "decodes a hidden command"),
        (try! NSRegularExpression(pattern: #"DYLD_INSERT_LIBRARIES"#), "injects code into every program started from Terminal"),
        (try! NSRegularExpression(pattern: #"alias\s+sudo="#), "replaces sudo (a trick to capture your password)"),
        (try! NSRegularExpression(pattern: #"nohup\s+[^\n]*(/tmp/|/Users/Shared/|/\.[a-z])"#, options: .caseInsensitive), "starts a hidden background program"),
        (try! NSRegularExpression(pattern: #"osascript\s+-e"#), "runs AppleScript"),
    ]

    nonisolated static func dangers(in added: String) -> [String] {
        let range = NSRange(added.startIndex..., in: added)
        return profileDangers.filter { $0.0.firstMatch(in: added, range: range) != nil }.map(\.1)
    }

    private func poll() {
        let profiles = BackgroundItemWatcher.readProfiles()
        for (path, text) in profiles where profileState[path] != text {
            let before = Set((profileState[path] ?? "").components(separatedBy: .newlines))
            let added = text.components(separatedBy: .newlines).filter { !before.contains($0) }.joined(separator: "\n")
            let found = BackgroundItemWatcher.dangers(in: added)
            if !found.isEmpty {
                report(label: (path as NSString).lastPathComponent, path: path, program: nil,
                       verdict: "Suspicious: it " + found.joined(separator: ", "), critical: true)
            }
        }
        profileState = profiles

        let cron = BackgroundItemWatcher.readCrontab()
        if cron != cronState {
            let before = Set(cronState.components(separatedBy: .newlines))
            let added = cron.components(separatedBy: .newlines).filter { !$0.isEmpty && !$0.hasPrefix("#") && !before.contains($0) }
            if !added.isEmpty {
                let found = BackgroundItemWatcher.dangers(in: added.joined(separator: "\n"))
                report(label: "Scheduled task (cron)", path: "crontab", program: added.first,
                       verdict: found.isEmpty ? "New scheduled task" : "Suspicious: it " + found.joined(separator: ", "),
                       critical: !found.isEmpty)
            }
            cronState = cron
        }

        let hook = BackgroundItemWatcher.readLoginHook()
        if hook != loginHook, !hook.isEmpty {
            report(label: "Login hook", path: "/Library/Preferences/com.apple.loginwindow.plist", program: hook,
                   verdict: "Runs as root every time someone logs in. Rarely used by real apps.", critical: true)
        }
        loginHook = hook
    }

    private func report(label: String, path: String, program: String?, verdict: String, critical: Bool) {
        items.insert(Item(date: Date(), plistPath: path, label: label, program: program, verdict: verdict), at: 0)
        if items.count > 50 { items.removeLast(items.count - 50) }
        ActivityLog.shared.add(critical ? .threat : .background, "\(label) changed", verdict)
        Notifier.post(critical ? "Suspicious startup change: \(label)" : "\(label) changed", verdict, critical: critical)
    }

    private func modificationDate(_ path: String) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
    }

    private func snapshot(_ folder: String) {
        let everything = BackgroundItemWatcher.pluginFolders.contains(folder)
        for name in (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? [] where everything || name.hasSuffix(".plist") {
            let path = folder + "/" + name
            known[path] = modificationDate(path) ?? Date()
        }
    }

    private func handle(_ paths: [String]) {
        // Plug-ins, helper tools and startup items: anything new at the top of those folders.
        for path in Set(paths) {
            let parent = (path as NSString).deletingLastPathComponent
            guard BackgroundItemWatcher.pluginFolders.contains(parent), known[path] == nil,
                  FileManager.default.fileExists(atPath: path) else { continue }
            known[path] = Date()
            let name = (path as NSString).lastPathComponent
            if name.hasPrefix(".") || BackgroundItemWatcher.ownLabels.contains(name) { continue }
            inspect(path, isNew: true, plugin: true)
        }
        for path in Set(paths) where path.hasSuffix(".plist") {
            guard BackgroundItemWatcher.folders.contains((path as NSString).deletingLastPathComponent) else { continue }
            guard let modified = modificationDate(path) else { known[path] = nil; continue }
            if let previous = known[path], previous >= modified { continue }
            let isNew = known[path] == nil
            known[path] = modified
            inspect(path, isNew: isNew)
        }
    }

    /// Launch item settings that real apps don't use.
    nonisolated static func oddities(_ dict: [String: Any], program: String?) -> [String] {
        var out: [String] = []
        let env = dict["EnvironmentVariables"] as? [String: Any] ?? [:]
        if env.keys.contains(where: { $0.hasPrefix("DYLD_") }) { out.append("injects code into another program (DYLD)") }
        let args = ((dict["ProgramArguments"] as? [String]) ?? []).joined(separator: " ").lowercased()
        if let program, BehaviorRules.isOddLocation(program) { out.append("runs a program from a hidden or temporary folder") }
        if args.contains("curl ") || args.contains("wget ") { out.append("downloads something each time it starts") }
        if args.contains("base64") || args.contains("osascript -e") || args.contains(" -c \"") && args.contains("http") {
            out.append("runs a hidden command")
        }
        if let program, ["sh", "bash", "zsh", "python3", "osascript"].contains((program as NSString).lastPathComponent),
           args.contains("/tmp/") || args.contains("/users/shared/") {
            out.append("runs a script from a shared or temporary folder")
        }
        return out
    }

    private func inspect(_ path: String, isNew: Bool, plugin: Bool = false) {
        let dict = NSDictionary(contentsOfFile: path) as? [String: Any] ?? [:]
        let label = dict["Label"] as? String ?? (path as NSString).lastPathComponent
        if BackgroundItemWatcher.ownLabels.contains(label) { return }
        let program = plugin ? path : ((dict["Program"] as? String) ?? (dict["ProgramArguments"] as? [String])?.first)
        let odd = plugin ? [] : BackgroundItemWatcher.oddities(dict, program: program)
        if !odd.isEmpty {
            Notifier.post("Suspicious background item: \(label)", "It " + odd.joined(separator: ", ") + ".", critical: true)
            ActivityLog.shared.add(.threat, "Suspicious background item: \(label)", odd.joined(separator: ", "))
        }
        let item = Item(date: Date(), plistPath: path, label: label, program: program,
                        verdict: odd.isEmpty ? "Checking…" : "Suspicious: it " + odd.joined(separator: ", "))
        items.insert(item, at: 0)
        if items.count > 50 { items.removeLast(items.count - 50) }

        let verb = isNew ? "added" : "changed"
        ActivityLog.shared.add(.background, "Background item \(verb): \(label)", program ?? path)
        Notifier.post("A background item was \(verb)",
                      "“\(label)” will run automatically\(program.map { ": \(($0 as NSString).lastPathComponent)" } ?? ""). If you didn't just install something, check it in Agamemnon.")

        var roots = [URL(fileURLWithPath: path)]
        if let program, FileManager.default.fileExists(atPath: program) { roots.append(URL(fileURLWithPath: program)) }
        var options = ScanController.options(for: .custom)
        options.useClamAV = false
        let id = item.id
        let scanOptions = options
        let scanRoots = roots
        queue.async { [weak self] in
            let result = ScanEngine().run(roots: scanRoots, options: scanOptions) { _ in }
            Task { @MainActor in
                guard let self else { return }
                var verdict = odd.isEmpty ? "No known threats" : "Suspicious: it " + odd.joined(separator: ", ")
                if let threat = result.detections.first(where: { $0.level != .suspicious }) {
                    if (try? self.vault.quarantine(threat)) != nil {
                        verdict = "Quarantined: \(threat.threatName)"
                    } else {
                        verdict = "Threat: \(threat.threatName)"
                    }
                    Notifier.post("Malware tried to start automatically", "\(label): \(threat.threatName)", critical: true)
                }
                if let index = self.items.firstIndex(where: { $0.id == id }) {
                    self.items[index].verdict = verdict
                }
            }
        }
    }
}
