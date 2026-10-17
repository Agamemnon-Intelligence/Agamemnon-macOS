import Foundation
import Combine
import Darwin

/// Checks everything that's already set up to start automatically (LaunchAgents,
/// LaunchDaemons and the user's crontab). `BackgroundItemWatcher` only sees new items;
/// this catches backdoors that were installed before Agamemnon was, or while it was off.
///
/// Known malware (hash list or a malicious pattern rule) is quarantined when "Quarantine
/// threats automatically" is on. Everything else is only reported, with Quarantine and
/// Trust buttons, because odd-looking startup items can be legitimate.
@MainActor
final class StartupSweep: ObservableObject {
    struct Finding: Identifiable, Hashable {
        let id = UUID()
        let plistPath: String
        let label: String
        let program: String?
        let reason: String
        let level: ThreatLevel
        var outcome: String?
    }

    @Published private(set) var findings: [Finding] = []
    @Published private(set) var lastRun: Date?
    @Published private(set) var isRunning = false
    @Published private(set) var itemsChecked = 0

    private let vault: QuarantineVault
    private var timer: Timer?
    private let queue = DispatchQueue(label: "agamemnon.startup-sweep", qos: .utility)

    init(vault: QuarantineVault) {
        self.vault = vault
    }

    func applyPreference() {
        timer?.invalidate()
        timer = nil
        guard Prefs.bool(Prefs.startupSweep) else { return }
        // Shortly after launch, then every 6 hours.
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in
            Task { @MainActor in if self?.lastRun == nil { self?.run() } }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.run() }
        }
    }

    nonisolated static var folders: [String] {
        [AppPaths.home.appendingPathComponent("Library/LaunchAgents").path, "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    }

    func run() {
        guard !isRunning else { return }
        isRunning = true
        let trusted = Set(UserDefaults.standard.stringArray(forKey: Prefs.trustedPrograms) ?? [])
        queue.async { [weak self] in
            let (results, count) = StartupSweep.sweep(trusted: trusted)
            Task { @MainActor in self?.finish(results, checked: count) }
        }
    }

    private func finish(_ results: [Finding], checked: Int) {
        isRunning = false
        lastRun = Date()
        itemsChecked = checked
        let previous = Set(findings.map { $0.plistPath + "|" + $0.reason })
        var updated: [Finding] = []
        for var finding in results {
            if finding.level == .malicious, Prefs.bool(Prefs.autoQuarantine) {
                finding.outcome = quarantineItem(finding)
            }
            updated.append(finding)
        }
        findings = updated

        let fresh = updated.filter { !previous.contains($0.plistPath + "|" + $0.reason) }
        if let worst = fresh.first(where: { $0.level == .malicious }) ?? fresh.first {
            let critical = worst.level == .malicious
            Notifier.post(critical ? "Malware was set to start automatically" : "A startup item needs a look",
                          "\(worst.label): \(worst.reason)\(worst.outcome.map { ". \($0)." } ?? ".")", critical: critical)
        }
        ActivityLog.shared.add(fresh.contains { $0.level == .malicious } ? .threat : .background,
                               "Checked \(checked) startup items",
                               updated.isEmpty ? "Nothing suspicious" : "\(updated.count) need attention")
    }

    // MARK: - Actions

    func quarantine(_ finding: Finding) {
        let outcome = quarantineItem(finding)
        if let index = findings.firstIndex(where: { $0.id == finding.id }) { findings[index].outcome = outcome }
    }

    func trust(_ finding: Finding) {
        var list = UserDefaults.standard.stringArray(forKey: Prefs.trustedPrograms) ?? []
        if !list.contains(finding.plistPath) { list.append(finding.plistPath) }
        UserDefaults.standard.set(list, forKey: Prefs.trustedPrograms)
        findings.removeAll { $0.id == finding.id }
    }

    /// Stops the program, then moves it and its startup item to quarantine.
    private func quarantineItem(_ finding: Finding) -> String {
        var done: [String] = []
        if let program = finding.program, BehaviorMonitor.mayQuarantine(program) {
            for pid in ProcessList.allPIDs() {
                if let p = ProcessList.info(pid), p.path == program, BehaviorMonitor.mayStop(p, manual: true) {
                    kill(pid, SIGKILL)
                }
            }
            let target = BehaviorMonitor.quarantineTarget(for: program)
            let detection = Detection(fileURL: URL(fileURLWithPath: target), innerPath: nil,
                                      threatName: "Startup item: \(finding.reason)", engine: "Startup check", level: finding.level)
            if vault.contains(path: target) || (try? vault.quarantine(detection)) != nil { done.append("program quarantined") }
        }
        // The plist itself, so it can't start anything again. Apple's own items are never touched.
        if !finding.plistPath.hasPrefix("/System/"), FileManager.default.fileExists(atPath: finding.plistPath) {
            let detection = Detection(fileURL: URL(fileURLWithPath: finding.plistPath), innerPath: nil,
                                      threatName: "Startup item: \(finding.reason)", engine: "Startup check", level: finding.level)
            if (try? vault.quarantine(detection)) != nil { done.append("startup item removed") }
        }
        return done.isEmpty ? "Couldn't move it safely" : done.joined(separator: ", ").capitalizedFirst
    }

    // MARK: - Checking (off the main actor)

    nonisolated static func sweep(trusted: Set<String>) -> ([Finding], Int) {
        var findings: [Finding] = []
        var checked = 0
        for folder in folders {
            for name in (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? [] where name.hasSuffix(".plist") {
                let path = folder + "/" + name
                checked += 1
                if trusted.contains(path) { continue }
                if let finding = inspect(plist: path), !(finding.program.map(trusted.contains) ?? false) {
                    findings.append(finding)
                }
            }
        }
        findings.append(contentsOf: inspectCrontab())
        checked += 1
        findings.sort { ($0.level == .malicious ? 0 : 1) < ($1.level == .malicious ? 0 : 1) }
        return (findings, checked)
    }

    nonisolated static func inspect(plist path: String) -> Finding? {
        guard let dict = NSDictionary(contentsOfFile: path) as? [String: Any] else { return nil }
        let label = dict["Label"] as? String ?? (path as NSString).lastPathComponent
        let args = dict["ProgramArguments"] as? [String] ?? []
        let program = (dict["Program"] as? String) ?? args.first
        guard let program, !program.isEmpty else { return nil }
        let commandText = ([program] + args.dropFirst()).joined(separator: " ").lowercased()

        func finding(_ reason: String, _ level: ThreatLevel, _ prog: String? = program) -> Finding {
            Finding(plistPath: path, label: label, program: prog, reason: reason, level: level)
        }

        // The file that really runs: the program, or the script an interpreter is given.
        let base = (program as NSString).lastPathComponent.lowercased()
        let isInterpreter = BehaviorMonitor.interpreters.contains(base) || base.hasPrefix("python")
        let scriptArg = isInterpreter ? args.dropFirst().first { $0.hasPrefix("/") && FileManager.default.fileExists(atPath: $0) } : nil
        let target = scriptArg ?? program
        let exists = FileManager.default.fileExists(atPath: target)

        // 1. Known malware file.
        if exists, !BehaviorRules.isSystemPath(target), let size = fileSize(target), size > 0, size < 256 * 1024 * 1024,
           let hit = KnownMalware.lookup(URL(fileURLWithPath: target)), hit.level != .test {
            return finding("Known malware (\(hit.name))", hit.level, target)
        }

        // 2. Pattern rules.
        if exists, let size = fileSize(target),
           let hit = PatternRules.assess(URL(fileURLWithPath: target), size: size, outer: URL(fileURLWithPath: target), inner: nil, container: nil) {
            return finding("Matches \(hit.threatName)", hit.level, target)
        }

        // 3. Downloads and runs code every time it starts.
        if isInterpreter, commandText.contains(" -c"),
           ["curl ", "wget ", "base64 -d", "base64 --decode", "/dev/tcp/"].contains(where: { commandText.contains($0) }) {
            return finding("Downloads or decodes code and runs it every time it starts", .suspicious)
        }

        guard exists, !BehaviorRules.isSystemPath(target) else { return nil }
        let identity = CodeIdentity.of(BehaviorMonitor.quarantineTarget(for: target))

        // 4. Pretends to be part of macOS.
        if label.lowercased().hasPrefix("com.apple."), identity.signer != .apple, !BehaviorRules.isPackageManaged(target) {
            return finding("Calls itself “\(label)” but isn't from Apple",
                           identity.isUnvouched && !isInterpreter ? .malicious : .suspicious, target)
        }

        // 5. Unsigned program living somewhere programs don't.
        if identity.isUnvouched, !BehaviorRules.isPackageManaged(target), isHiddenOrTemporary(target) {
            return finding("Unsigned program in a hidden or temporary folder", .suspicious, target)
        }
        return nil
    }

    nonisolated static func isHiddenOrTemporary(_ path: String) -> Bool {
        if BehaviorRules.isOddLocation(path) || path.hasPrefix("/private/var/folders/") { return true }
        let home = AppPaths.home.path + "/"
        guard path.hasPrefix(home) else { return false }
        // Any hidden folder in the path below the home folder (~/.helper/agent, ~/Library/Application Support/.x/…).
        return path.dropFirst(home.count).split(separator: "/").dropLast().contains { $0.hasPrefix(".") }
    }

    nonisolated static func inspectCrontab() -> [Finding] {
        let result = Shell.run("/usr/bin/crontab", ["-l"], timeout: 10)
        guard result.succeeded else { return [] }
        var findings: [Finding] = []
        for line in result.stdout.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            let lower = trimmed.lowercased()
            let downloads = ["curl ", "wget "].contains { lower.contains($0) } && ["| sh", "|sh", "| bash", "|bash", "| zsh"].contains { lower.contains($0) }
            let shell = lower.contains("/dev/tcp/") || lower.contains("base64 -d") || lower.contains("base64 --decode")
            let hidden = lower.contains("/tmp/") || lower.contains("/users/shared/")
            if downloads || shell || (hidden && (lower.contains("curl") || lower.contains("chmod"))) {
                findings.append(Finding(plistPath: "crontab", label: "Scheduled task (crontab)", program: nil,
                                        reason: "Runs “\(String(trimmed.prefix(80)))” on a schedule", level: .suspicious))
            }
        }
        return findings
    }

    nonisolated private static func fileSize(_ path: String) -> Int64? {
        ((try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? NSNumber)?.int64Value
    }
}
