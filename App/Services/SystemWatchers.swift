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

    init(vault: QuarantineVault) {
        self.vault = vault
    }

    func applyPreference() {
        if Prefs.bool(Prefs.backgroundItemAlerts) { start() } else { stop() }
    }

    func start() {
        guard !isRunning else { return }
        let paths = BackgroundItemWatcher.folders.filter { FileManager.default.fileExists(atPath: $0) }
        known = [:]
        for folder in paths { snapshot(folder) }
        let watcher = FolderWatcher(paths: paths, latency: 1.0) { [weak self] changed in
            Task { @MainActor in self?.handle(changed) }
        }
        guard watcher.start() else { return }
        self.watcher = watcher
        isRunning = true
    }

    func stop() {
        watcher?.stop()
        watcher = nil
        isRunning = false
    }

    private func modificationDate(_ path: String) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
    }

    private func snapshot(_ folder: String) {
        for name in (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? [] where name.hasSuffix(".plist") {
            let path = folder + "/" + name
            known[path] = modificationDate(path) ?? Date()
        }
    }

    private func handle(_ paths: [String]) {
        for path in Set(paths) where path.hasSuffix(".plist") {
            guard BackgroundItemWatcher.folders.contains((path as NSString).deletingLastPathComponent) else { continue }
            guard let modified = modificationDate(path) else { known[path] = nil; continue }
            if let previous = known[path], previous >= modified { continue }
            let isNew = known[path] == nil
            known[path] = modified
            inspect(path, isNew: isNew)
        }
    }

    private func inspect(_ path: String, isNew: Bool) {
        let dict = NSDictionary(contentsOfFile: path) as? [String: Any] ?? [:]
        let label = dict["Label"] as? String ?? (path as NSString).lastPathComponent
        let program = (dict["Program"] as? String) ?? (dict["ProgramArguments"] as? [String])?.first
        let item = Item(date: Date(), plistPath: path, label: label, program: program, verdict: "Checking…")
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
                var verdict = "No known threats"
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
