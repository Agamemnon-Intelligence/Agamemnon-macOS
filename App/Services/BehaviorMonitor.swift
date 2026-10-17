import Foundation
import Combine
import Darwin

/// Behaviour protection: watches programs as they start and recognises what infostealers,
/// backdoors and miners do once they run (see `BehaviorRules`). It also checks each new
/// program's file against the malware hash list.
///
/// Without Apple's Endpoint Security entitlement this can't block a program before it
/// starts; it looks at new processes about once a second and reacts right after.
///
/// Safety rules (so protection never turns on the user):
/// - Only **high-confidence** findings are acted on automatically, and only when
///   "Stop dangerous programs automatically" is on. Everything else is just an alert.
/// - Programs that are part of macOS, signed by Apple, or signed with a Developer ID are
///   never stopped or quarantined automatically. The only exception is the one short-lived
///   instance of a system tool (osascript, curl, security, dscl…) caught doing the malicious
///   thing itself, which is harmless to stop.
/// - Package-manager installs (Homebrew, nvm, pyenv…), interpreters, and anything the user
///   trusted are never quarantined.
/// - Files are moved to the quarantine vault, never deleted, so everything can be restored.
@MainActor
final class BehaviorMonitor: ObservableObject {
    struct Alert: Identifiable, Hashable {
        let id = UUID()
        let date = Date()
        let finding: BehaviorFinding
        let pid: pid_t
        let processName: String
        let path: String
        let commandLine: String
        /// The program held responsible (the process itself or the unsigned parent that started it).
        let culpritPath: String?
        var outcome: String
        var handled: Bool
    }

    @Published private(set) var isRunning = false
    @Published private(set) var alerts: [Alert] = []
    @Published private(set) var processesChecked = 0

    private let vault: QuarantineVault
    private var worker: BehaviorWorker?
    private var lastNotified: [String: Date] = [:]

    init(vault: QuarantineVault) {
        self.vault = vault
    }

    func applyPreference() {
        if Prefs.bool(Prefs.behaviorProtection) { start() } else { stop() }
    }

    func start() {
        guard worker == nil else { return }
        let worker = BehaviorWorker { [weak self] report in
            Task { @MainActor in self?.handle(report) }
        } progress: { [weak self] count in
            Task { @MainActor in self?.processesChecked = count }
        }
        worker.start()
        self.worker = worker
        isRunning = true
    }

    func stop() {
        worker?.stop()
        worker = nil
        isRunning = false
    }

    // MARK: - Responding

    private func handle(_ report: BehaviorWorker.Report) {
        let p = report.process
        if isTrusted(p.path) || (report.culprit.map(isTrusted) ?? false) { return }

        var alert = Alert(finding: report.finding, pid: p.pid, processName: p.name, path: p.path,
                          commandLine: p.commandLine, culpritPath: report.culprit,
                          outcome: "Warning only", handled: false)

        if report.finding.confidence == .high && Prefs.bool(Prefs.behaviorAutoStop) {
            alert.outcome = respond(to: report)
            alert.handled = true
        }

        if alert.handled {
            // Earlier warnings about the same program are settled by this action too.
            let culprit = report.culprit ?? p.path
            for index in alerts.indices where !alerts[index].handled && (alerts[index].culpritPath ?? alerts[index].path) == culprit {
                alerts[index].outcome = alert.outcome
                alerts[index].handled = true
            }
        }
        alerts.insert(alert, at: 0)
        if alerts.count > 60 { alerts.removeLast(alerts.count - 60) }

        let key = report.finding.rule + "|" + (report.culprit ?? p.path)
        if let last = lastNotified[key], Date().timeIntervalSince(last) < 600 { return }
        lastNotified[key] = Date()

        let who = report.culprit.map { ($0 as NSString).lastPathComponent } ?? p.name
        if alert.handled {
            Notifier.post("Agamemnon stopped \(report.finding.title.lowercased())",
                          "\(who): \(alert.outcome). You can undo this from Quarantine.", critical: true)
            ActivityLog.shared.add(.threat, "Stopped: \(report.finding.title)", "\(who) · \(alert.outcome)")
        } else {
            Notifier.post(report.finding.title,
                          "\(who): \(report.finding.explanation) Check it in Agamemnon.",
                          critical: report.finding.confidence == .high)
            ActivityLog.shared.add(.behavior, report.finding.title, "\(who) · \(p.path)")
        }
    }

    /// Stops the process (and the unsigned program behind it) and quarantines that program.
    private func respond(to report: BehaviorWorker.Report) -> String {
        var done: [String] = []
        let p = report.process

        if BehaviorMonitor.mayStop(p) {
            kill(p.pid, SIGKILL)
            done.append("stopped \(p.name)")
        }

        if let culpritPath = report.culprit, let culpritPID = report.culpritPID, culpritPID != p.pid,
           BehaviorMonitor.mayQuarantine(culpritPath) {
            kill(culpritPID, SIGKILL)
            done.append("stopped \((culpritPath as NSString).lastPathComponent)")
        }

        if let culpritPath = report.culprit, BehaviorMonitor.mayQuarantine(culpritPath) {
            let target = BehaviorMonitor.quarantineTarget(for: culpritPath)
            let detection = Detection(fileURL: URL(fileURLWithPath: target), innerPath: nil,
                                      threatName: "Behavior: \(report.finding.title)",
                                      engine: "Behavior", level: .malicious)
            if !vault.contains(path: target), (try? vault.quarantine(detection)) != nil {
                done.append("quarantined \((target as NSString).lastPathComponent)")
            }
        }

        if done.isEmpty { return "Couldn't act safely, so it was only reported" }
        return done.joined(separator: ", ").capitalizedFirst
    }

    /// Manual "Stop" button.
    func stopProcess(_ alert: Alert) {
        guard let p = ProcessList.info(alert.pid), p.path == alert.path, BehaviorMonitor.mayStop(p, manual: true) else {
            update(alert.id, outcome: "Already stopped")
            return
        }
        kill(p.pid, SIGKILL)
        update(alert.id, outcome: "Stopped by you")
    }

    /// Manual "Quarantine" button.
    func quarantine(_ alert: Alert) {
        let path = alert.culpritPath ?? alert.path
        guard BehaviorMonitor.mayQuarantine(path) else {
            update(alert.id, outcome: "This program is part of macOS or signed, so Agamemnon won't move it")
            return
        }
        if let p = ProcessList.info(alert.pid), p.path == alert.path, BehaviorMonitor.mayStop(p, manual: true) {
            kill(p.pid, SIGKILL)
        }
        let target = BehaviorMonitor.quarantineTarget(for: path)
        let detection = Detection(fileURL: URL(fileURLWithPath: target), innerPath: nil,
                                  threatName: "Behavior: \(alert.finding.title)", engine: "Behavior", level: .malicious)
        do {
            try vault.quarantine(detection)
            update(alert.id, outcome: "Quarantined by you")
        } catch {
            update(alert.id, outcome: error.localizedDescription)
        }
    }

    /// "Trust" button: never alert about this program again.
    func trust(_ alert: Alert) {
        var list = UserDefaults.standard.stringArray(forKey: Prefs.trustedPrograms) ?? []
        let path = alert.culpritPath ?? alert.path
        if !list.contains(path) { list.append(path) }
        UserDefaults.standard.set(list, forKey: Prefs.trustedPrograms)
        alerts.removeAll { ($0.culpritPath ?? $0.path) == path }
        ActivityLog.shared.add(.info, "Trusted \((path as NSString).lastPathComponent)", path)
    }

    func clearAlerts() { alerts.removeAll() }

    private func update(_ id: UUID, outcome: String) {
        guard let index = alerts.firstIndex(where: { $0.id == id }) else { return }
        alerts[index].outcome = outcome
        alerts[index].handled = true
    }

    private func isTrusted(_ path: String) -> Bool {
        let list = UserDefaults.standard.stringArray(forKey: Prefs.trustedPrograms) ?? []
        return list.contains { path == $0 || path.hasPrefix($0 + "/") }
    }

    // MARK: - Guardrails

    /// System tools that malware drives. Stopping one running instance of these is harmless.
    nonisolated static let stoppableTools: Set<String> = [
        "osascript", "curl", "wget", "security", "dscl", "base64", "ditto", "nc",
        "python", "python3", "node", "perl", "ruby",
    ]

    /// Interpreters and shells: never quarantined, because they're shared by everything.
    nonisolated static let interpreters: Set<String> = [
        "sh", "bash", "zsh", "dash", "fish", "osascript", "python", "python3", "node", "perl", "ruby",
        "java", "deno", "bun", "php", "tclsh", "pwsh",
    ]

    nonisolated static func mayStop(_ p: RunningProcess, manual: Bool = false) -> Bool {
        guard p.pid > 1, p.pid != getpid(), p.uid == getuid() else { return false }
        if p.path.hasPrefix(Bundle.main.bundlePath) { return false }
        let base = p.name.lowercased()
        if stoppableTools.contains(base) || base.hasPrefix("python") { return true }
        if BehaviorRules.isSystemPath(p.path) { return false }
        let identity = CodeIdentity.of(p.path)
        if identity.signer == .apple { return false }
        if manual { return true }
        return identity.isUnvouched && !BehaviorRules.isPackageManaged(p.path)
    }

    nonisolated static func mayQuarantine(_ path: String) -> Bool {
        if BehaviorRules.isSystemPath(path) || BehaviorRules.isPackageManaged(path) { return false }
        if path.hasPrefix(Bundle.main.bundlePath) || path.hasPrefix(AppPaths.support.path) { return false }
        let base = (path as NSString).lastPathComponent.lowercased()
        if interpreters.contains(base) || base.hasPrefix("python") { return false }
        return CodeIdentity.of(path).isUnvouched
    }

    /// For a program inside an app bundle, quarantine the whole app.
    nonisolated static func quarantineTarget(for path: String) -> String {
        if let range = path.range(of: ".app/Contents/") {
            return String(path[..<range.lowerBound]) + ".app"
        }
        return path
    }
}

/// Runs off the main actor: lists processes about once a second and checks new ones.
final class BehaviorWorker {
    struct Report {
        let process: RunningProcess
        let finding: BehaviorFinding
        /// Path and PID of the unsigned program responsible, if there is one.
        let culprit: String?
        let culpritPID: pid_t?
    }

    private let queue = DispatchQueue(label: "agamemnon.behavior", qos: .utility)
    private var timer: DispatchSourceTimer?
    private let onReport: (Report) -> Void
    private let onProgress: (Int) -> Void

    // Only touched on `queue`.
    private var seen: Set<String> = []
    private var hashChecked: Set<String> = []
    private var reported: Set<String> = []
    private var cpuSamples: [String: (Date, Double)] = [:]
    private var busySince: [String: Date] = [:]
    private var checked = 0
    private var ticks = 0

    init(onReport: @escaping (Report) -> Void, progress: @escaping (Int) -> Void) {
        self.onReport = onReport
        self.onProgress = progress
    }

    func start() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1.0, leeway: .milliseconds(200))
        timer.setEventHandler { [weak self] in self?.tick() }
        timer.resume()
        self.timer = timer
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    private func tick() {
        ticks += 1
        let pids = ProcessList.allPIDs()
        var alive: Set<String> = []
        var current: [RunningProcess] = []

        for pid in pids {
            guard let p = ProcessList.info(pid) else { continue }
            alive.insert(p.key)
            current.append(p)
            if seen.contains(p.key) { continue }
            seen.insert(p.key)
            checked += 1
            inspect(p)
        }
        seen.formIntersection(alive)
        if ticks % 30 == 0 { checkCPU(current) }
        if ticks % 5 == 0 { onProgress(checked) }
    }

    private func inspect(_ p: RunningProcess) {
        if p.pid == getpid() { return }
        if p.uid != getuid() && p.uid != 0 { return }

        // 1. Known malware file (hash list), for programs outside macOS itself.
        if !BehaviorRules.isSystemPath(p.path), !hashChecked.contains(p.path) {
            hashChecked.insert(p.path)
            let size = ((try? FileManager.default.attributesOfItem(atPath: p.path))?[.size] as? NSNumber)?.int64Value ?? 0
            if size > 0, size < 256 * 1024 * 1024,
               let hash = try? FileHasher.sha256(of: URL(fileURLWithPath: p.path)),
               let name = SignatureStore.shared.lookup(hash), !name.hasPrefix("EICAR") {
                let finding = BehaviorFinding(rule: "known-malware", title: "Known malware is running",
                                              explanation: "This program matches a known malware sample (\(name)).",
                                              families: name, confidence: .high)
                emit(p, finding, culprit: (p.path, p.pid))
                return
            }
        }

        // 2. Behaviour rules.
        let ancestors = ProcessList.ancestors(of: p)
        guard let finding = BehaviorRules.evaluate(p, ancestors: ancestors) else { return }
        emit(p, finding, culprit: responsible(for: p, ancestors: ancestors))
    }

    /// The nearest unsigned, user-installed program in the chain (the process itself or a parent).
    private func responsible(for p: RunningProcess, ancestors: [RunningProcess]) -> (String, pid_t)? {
        for candidate in [p] + ancestors {
            if BehaviorRules.isUserLandUnvouched(candidate),
               !BehaviorMonitor.interpreters.contains(candidate.name.lowercased()) {
                return (candidate.path, candidate.pid)
            }
        }
        return nil
    }

    private func emit(_ p: RunningProcess, _ finding: BehaviorFinding, culprit: (String, pid_t)?) {
        let key = finding.rule + "|" + p.key
        guard !reported.contains(key) else { return }
        reported.insert(key)
        if reported.count > 5000 { reported.removeAll() }
        onReport(Report(process: p, finding: finding, culprit: culprit?.0, culpritPID: culprit?.1))
    }

    /// Cryptojacking: an unsigned program keeping a CPU core busy for 10 minutes.
    private func checkCPU(_ processes: [RunningProcess]) {
        let now = Date()
        var stillBusy: Set<String> = []
        for p in processes where p.uid == getuid() && BehaviorRules.isUserLandUnvouched(p) {
            guard let cpu = ProcessList.cpuSeconds(p.pid) else { continue }
            defer { cpuSamples[p.key] = (now, cpu) }
            guard let (then, before) = cpuSamples[p.key] else { continue }
            let elapsed = now.timeIntervalSince(then)
            guard elapsed > 1 else { continue }
            if (cpu - before) / elapsed > 0.85 {
                stillBusy.insert(p.key)
                let since = busySince[p.key] ?? now
                busySince[p.key] = since
                if now.timeIntervalSince(since) >= 600 {
                    let finding = BehaviorFinding(
                        rule: "cpu-hog",
                        title: "Unsigned program using lots of processor",
                        explanation: "An unsigned program has kept your processor busy for over 10 minutes. Hidden cryptocurrency miners do this.",
                        families: "CoinMiner", confidence: .medium)
                    emit(p, finding, culprit: (p.path, p.pid))
                }
            }
        }
        for key in busySince.keys where !stillBusy.contains(key) { busySince[key] = nil }
        let alive = Set(processes.map(\.key))
        cpuSamples = cpuSamples.filter { alive.contains($0.key) }
    }
}
