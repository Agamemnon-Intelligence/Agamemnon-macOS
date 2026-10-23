import Foundation
import Combine
import AppKit
import ServiceManagement

/// Keeps Agamemnon itself from being switched off by malware.
///
/// - **Protection helper** (optional, needs an admin password once): a root background
///   service that restarts Agamemnon if something kills it, checks the app hasn't been
///   modified, and, with Full Disk Access, streams Apple's Endpoint Security events: every new
///   program the moment it starts, and unknown programs opening passwords, browser data,
///   wallets, notes or SSH keys. See Helper/main.swift.
/// - **Settings lock**: protection switches, exclusions and trusted programs can only be
///   changed from Agamemnon's own window. Changes made behind its back (`defaults write` by a
///   script) are put back and reported.
/// - **Normal quit marker**, so the helper can tell quitting Agamemnon apart from killing it.
@MainActor
final class SelfProtection: ObservableObject {
    nonisolated static let label = "com.mirazbakis.Agamemnon.Helper"
    nonisolated static let helperPath = "/Library/PrivilegedHelperTools/com.mirazbakis.Agamemnon.Helper"
    nonisolated static let plistPath = "/Library/LaunchDaemons/com.mirazbakis.Agamemnon.Helper.plist"
    nonisolated static let stateDir = "/Library/Application Support/Agamemnon/Helper"
    nonisolated static var quitMarker: URL { AppPaths.support.appendingPathComponent(".quit") }
    /// Must match `helperBuild` in Helper/main.swift.
    nonisolated static let expectedHelperBuild = 4

    enum HelperState: Equatable {
        case notInstalled, needsApproval, starting, running(liveEvents: String), stopped
    }

    @Published private(set) var helperState: HelperState = .notInstalled
    @Published private(set) var helperVersion: String?
    @Published private(set) var busy = false
    @Published var message: String?
    @Published private(set) var tamperEvents: [String] = []

    private let behavior: BehaviorMonitor
    private let onAccess: OnAccessScanner
    private var tail: LineProcess?
    private var statusTimer: Timer?
    private var settingsTimer: Timer?
    private var lockedSnapshot: [String: Any] = [:]
    private var lastHelperAlert = Date.distantPast
    private var restartedOldHelper = false
    @Published private(set) var eventsPerMinute: [String: Int] = [:]

    init(behavior: BehaviorMonitor, onAccess: OnAccessScanner) {
        self.behavior = behavior
        self.onAccess = onAccess
    }

    func start() {
        try? FileManager.default.removeItem(at: SelfProtection.quitMarker)
        if CommandLine.arguments.contains("--watchdog") {
            ActivityLog.shared.add(.threat, "Agamemnon was stopped by something and restarted",
                                   "It closed without being quit. The protection helper started it again.")
        }
        refreshStatus()
        startTail()
        autoInstall()
        statusTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
        lockedSnapshot = SelfProtection.readLocked()
        settingsTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkSettings() }
        }
    }

    /// Called when the user quits Agamemnon normally.
    nonisolated static func markQuit() {
        FileManager.default.createFile(atPath: quitMarker.path, contents: Data())
    }

    // MARK: - Helper status

    /// Installed the classic way (admin password), or registered with SMAppService.
    var helperInstalled: Bool {
        FileManager.default.fileExists(atPath: SelfProtection.plistPath) || smStatus == .enabled
    }

    /// The SMAppService registration (macOS 13+): the helper runs from inside Agamemnon.app,
    /// and the user approves it with one switch in System Settings ▸ Login Items.
    private var service: SMAppService { SMAppService.daemon(plistName: SelfProtection.label + ".plist") }
    private var smStatus: SMAppService.Status { service.status }

    /// The helper's program, wherever it's installed.
    var helperProgramPath: String {
        FileManager.default.fileExists(atPath: SelfProtection.plistPath)
            ? SelfProtection.helperPath
            : Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/AgamemnonHelper").path
    }

    /// Sets the helper up without being asked, once: SMAppService first (no password, one
    /// switch to approve); if macOS refuses (ad-hoc builds), the classic install with a password.
    private func autoInstall() {
        if helperInstalled { UserDefaults.standard.set(true, forKey: Prefs.helperWanted) }
        // macOS stops the helper when Agamemnon.app is replaced (an update): register it again.
        // The user approved it before, so this needs no password and no new approval.
        if UserDefaults.standard.bool(forKey: Prefs.helperWanted), !helperInstalled, smStatus != .requiresApproval {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in self?.installHelper(allowPassword: false) }
            return
        }
        guard !helperInstalled, !UserDefaults.standard.bool(forKey: Prefs.helperAutoInstallTried) else {
            if smStatus == .requiresApproval { helperState = .needsApproval }
            return
        }
        UserDefaults.standard.set(true, forKey: Prefs.helperAutoInstallTried)
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in self?.installHelper() }
    }

    func refreshStatus() {
        if smStatus == .requiresApproval, !FileManager.default.fileExists(atPath: SelfProtection.plistPath) {
            helperState = .needsApproval
            return
        }
        guard helperInstalled else { helperState = .notInstalled; return }
        guard let data = FileManager.default.contents(atPath: SelfProtection.stateDir + "/status.json"),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let updated = json["updated"] as? Double else {
            helperState = .starting
            return
        }
        helperVersion = json["version"] as? String
        eventsPerMinute = json["eventsPerMinute"] as? [String: Int] ?? [:]
        if Date().timeIntervalSince1970 - updated < 45 {
            restartOldHelperIfNeeded(build: json["build"] as? Int ?? 1)
            helperState = .running(liveEvents: json["eslogger"] as? String ?? "starting")
            if tail == nil { startTail() }
        } else {
            helperState = .stopped
            if Date().timeIntervalSince(lastHelperAlert) > 3600 {
                lastHelperAlert = Date()
                Notifier.post("Agamemnon's protection helper isn't running",
                              "Something stopped it. Reinstall it from Real-Time Protection ▸ Self-protection.", critical: true)
                ActivityLog.shared.add(.threat, "Protection helper stopped", "It hasn't reported in for over 45 seconds")
            }
        }
    }

    /// An older helper keeps running after Agamemnon is updated (newer helpers restart
    /// themselves). Re-registering with SMAppService replaces it with the bundled one.
    private func restartOldHelperIfNeeded(build: Int) {
        guard build < SelfProtection.expectedHelperBuild, !restartedOldHelper, smStatus == .enabled,
              !FileManager.default.fileExists(atPath: SelfProtection.plistPath) else { return }
        restartedOldHelper = true
        Task.detached {
            let service = SMAppService.daemon(plistName: SelfProtection.label + ".plist")
            try? await service.unregister()
            try? service.register()
            await MainActor.run {
                ActivityLog.shared.add(.update, "Protection helper updated", "Restarted with the version inside this Agamemnon")
                if service.status == .requiresApproval { self.helperState = .needsApproval }
            }
        }
    }

    // MARK: - Install / remove

    /// `allowPassword: false` only tries the no-password route (used automatically at launch).
    func installHelper(allowPassword: Bool = true) {
        guard !busy else { return }
        // The modern way: no password, approved with a switch in Login Items.
        do {
            try service.register()
            if smStatus == .requiresApproval {
                helperState = .needsApproval
                message = "Turn on “Agamemnon” under Allow in the Background in System Settings ▸ General ▸ Login Items to start the helper."
                Notifier.post("Allow Agamemnon's protection helper", "Turn on Agamemnon in System Settings ▸ General ▸ Login Items ▸ Allow in the Background.")
                SMAppService.openSystemSettingsLoginItems()
            } else {
                helperState = .starting
                message = "Helper installed. For live monitoring, give Agamemnon's helper Full Disk Access."
                UserDefaults.standard.set(true, forKey: Prefs.helperWanted)
                ActivityLog.shared.add(.update, "Protection helper installed", "Registered with macOS (SMAppService)")
                DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in self?.refreshStatus() }
            }
            return
        } catch {
            // Falls through to the classic install below. The reason is logged so it can be fixed.
            let ns = error as NSError
            ActivityLog.shared.add(.info, "macOS didn't accept the helper registration, using the classic install",
                                   "\(ns.domain) \(ns.code): \(ns.localizedDescription) · status \(smStatus.rawValue)")
        }
        guard allowPassword else {
            helperState = .notInstalled
            return
        }
        installClassic()
    }

    private func installClassic() {
        let bundled = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/AgamemnonHelper").path
        guard FileManager.default.isExecutableFile(atPath: bundled) else {
            message = "This build doesn't include the helper."
            return
        }
        let plist: [String: Any] = [
            "Label": SelfProtection.label,
            "ProgramArguments": [SelfProtection.helperPath, "--app", Bundle.main.bundlePath],
            "RunAtLoad": true,
            "KeepAlive": true,
            "ProcessType": "Interactive",
            "AssociatedBundleIdentifiers": [CodeIdentity.ownBundleID],
        ]
        let tempPlist = AppPaths.newScratchDirectory("helper").appendingPathComponent("helper.plist")
        guard let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
              (try? data.write(to: tempPlist)) != nil else {
            message = "Couldn't prepare the helper."
            return
        }
        let q = Shell.quote
        let script = [
            "/bin/launchctl bootout system/\(SelfProtection.label) 2>/dev/null; true",
            "/bin/mkdir -p /Library/PrivilegedHelperTools \(q(SelfProtection.stateDir))",
            "/bin/cp -f \(q(bundled)) \(q(SelfProtection.helperPath))",
            "/usr/sbin/chown root:wheel \(q(SelfProtection.helperPath))",
            "/bin/chmod 755 \(q(SelfProtection.helperPath))",
            "/bin/cp -f \(q(tempPlist.path)) \(q(SelfProtection.plistPath))",
            "/usr/sbin/chown root:wheel \(q(SelfProtection.plistPath))",
            "/bin/chmod 644 \(q(SelfProtection.plistPath))",
            "/usr/sbin/chown -R root:wheel \(q("/Library/Application Support/Agamemnon"))",
            "/bin/chmod 755 \(q("/Library/Application Support/Agamemnon")) \(q(SelfProtection.stateDir))",
            "/bin/launchctl bootstrap system \(q(SelfProtection.plistPath))",
        ].joined(separator: " && ")
        busy = true
        defer {
            busy = false
            try? FileManager.default.removeItem(at: tempPlist.deletingLastPathComponent())
        }
        do {
            try Privileged.run(script, prompt: "Agamemnon is installing its protection helper, which keeps it running and watches for stealers.")
            UserDefaults.standard.set(true, forKey: Prefs.helperWanted)
            message = "Helper installed. For live file monitoring, give “com.mirazbakis.Agamemnon.Helper” Full Disk Access."
            ActivityLog.shared.add(.update, "Protection helper installed", SelfProtection.helperPath)
            helperState = .starting
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in self?.refreshStatus() }
        } catch Privileged.Failure.cancelled {
            message = nil
        } catch {
            message = "The helper wasn't installed: \(error.localizedDescription)"
        }
    }

    func removeHelper() {
        guard !busy else { return }
        UserDefaults.standard.set(false, forKey: Prefs.helperWanted)
        if smStatus == .enabled || smStatus == .requiresApproval {
            try? service.unregister()
            tail?.terminate()
            tail = nil
            helperState = .notInstalled
            message = "Helper removed."
            ActivityLog.shared.add(.info, "Protection helper removed")
            if !FileManager.default.fileExists(atPath: SelfProtection.plistPath) { return }
        }
        busy = true
        defer { busy = false }
        let q = Shell.quote
        let script = [
            "/bin/launchctl bootout system/\(SelfProtection.label) 2>/dev/null; true",
            "/bin/rm -f \(q(SelfProtection.plistPath)) \(q(SelfProtection.helperPath))",
            "/bin/rm -rf \(q(SelfProtection.stateDir))",
        ].joined(separator: " && ")
        do {
            try Privileged.run(script, prompt: "Agamemnon is removing its protection helper.")
            tail?.terminate()
            tail = nil
            helperState = .notInstalled
            message = "Helper removed."
            ActivityLog.shared.add(.info, "Protection helper removed")
        } catch Privileged.Failure.cancelled {
        } catch {
            message = error.localizedDescription
        }
    }

    /// Shows the helper in Finder and opens Full Disk Access, so it can be dragged in.
    func openFullDiskAccessForHelper() {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: helperProgramPath)])
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: - Helper reports

    private func startTail() {
        let events = SelfProtection.stateDir + "/events.ndjson"
        guard tail == nil, FileManager.default.fileExists(atPath: SelfProtection.stateDir) else { return }
        let process = LineProcess("/usr/bin/tail", ["-n", "0", "-F", events]) { [weak self] line in
            guard let data = line.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
            Task { @MainActor in self?.handle(json) }
        }
        do { try process.start(); tail = process } catch { tail = nil }
    }

    private func handle(_ event: [String: Any]) {
        let type = event["type"] as? String ?? ""
        switch type {
        case "exec":
            if let pid = event["pid"] as? Int { behavior.checkNow(pid_t(pid)) }
        case "new-file":
            if let path = event["path"] as? String { onAccess.fileWritten(path) }
        case "sensitive-open":
            guard let pid = event["pid"] as? Int, let category = event["category"] as? String,
                  let file = event["file"] as? String, let path = event["path"] as? String else { return }
            behavior.sensitiveAccess(pid: pid_t(pid), ppid: pid_t(event["ppid"] as? Int ?? 0), path: path,
                                     category: category, file: file,
                                     systemTool: (event["signer"] as? String) == "system-tool")
        case "relaunched":
            record("Agamemnon was killed and restarted by its helper")
            Notifier.post("Something tried to stop Agamemnon",
                          "Agamemnon was closed without being quit. Its helper started it again.", critical: true)
        case "watchdog-gave-up":
            record("Agamemnon keeps being stopped")
        case "app-modified":
            record("Agamemnon.app was modified on disk")
            Notifier.post("Agamemnon was modified", "Its app no longer matches its signature. Download it again from the official page.", critical: true)
        case "login-item":
            let item = (event["executable"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? (event["item"] as? String ?? "")
            let by = (event["by"] as? String).map { ($0 as NSString).lastPathComponent } ?? "an app"
            ActivityLog.shared.add(.background, "New login item or launch agent", "\(item) · added by \(by)")
        case "xprotect":
            let name = event["malware"] as? String ?? "malware"
            ActivityLog.shared.add(.threat, "macOS XProtect found \(name)", event["path"] as? String ?? "")
            Notifier.post("macOS blocked malware", "XProtect detected \(name).", critical: true)
        case "privacy-change":
            let service = (event["service"] as? String ?? "").replacingOccurrences(of: "kTCCService", with: "")
            let by = (event["by"] as? String).map { ($0 as NSString).lastPathComponent } ?? "an unsigned program"
            ActivityLog.shared.add(.threat, "Unsigned program changed privacy permissions", "\(service) · by \(by)")
            Notifier.post("Privacy permission changed", "\(by) changed the \(service) permission. Check System Settings ▸ Privacy & Security.", critical: true)
        default:
            break
        }
    }

    private func record(_ text: String) {
        tamperEvents.insert("\(Date().formatted(date: .omitted, time: .shortened)) · \(text)", at: 0)
        if tamperEvents.count > 20 { tamperEvents.removeLast() }
        ActivityLog.shared.add(.threat, text)
    }

    // MARK: - Settings lock

    /// Settings malware would want changed. They only change from Agamemnon's own window.
    nonisolated static let lockedKeys = [
        Prefs.downloadProtection, Prefs.behaviorProtection, Prefs.behaviorAutoStop, Prefs.autoQuarantine,
        Prefs.patternRules, Prefs.ransomwareShield, Prefs.browserProtection, Prefs.startupSweep,
        Prefs.backgroundItemAlerts, Prefs.usbProtection, Prefs.clipboardGuard, Prefs.useXProtect,
        Prefs.exclusions, Prefs.trustedPrograms, Prefs.ransomwareFolders, Prefs.notifications,
        Prefs.onAccessScan, Prefs.cloudLookup,
    ]

    nonisolated static func readLocked() -> [String: Any] {
        var out: [String: Any] = [:]
        for key in lockedKeys { out[key] = UserDefaults.standard.object(forKey: key) ?? NSNull() }
        return out
    }

    /// True while the user could be changing settings in Agamemnon's own window or menu.
    private var userIsInApp: Bool { NSApp.isActive || NSApp.keyWindow != nil || NSApp.windows.contains { $0.isKeyWindow } }

    private func checkSettings() {
        let current = SelfProtection.readLocked()
        let changed = SelfProtection.lockedKeys.filter { !SelfProtection.equal(current[$0], lockedSnapshot[$0]) }
        guard !changed.isEmpty else { return }
        if userIsInApp || !Prefs.bool(Prefs.settingsLock) {
            lockedSnapshot = current
            return
        }
        // Changed from outside: put it back.
        for key in changed {
            let old = lockedSnapshot[key]
            if old == nil || old is NSNull { UserDefaults.standard.removeObject(forKey: key) } else { UserDefaults.standard.set(old, forKey: key) }
        }
        AppModel.shared.preferencesChanged()
        record("Blocked a change to Agamemnon's settings from outside the app (\(changed.joined(separator: ", ")))")
        Notifier.post("Agamemnon kept its settings", "Something tried to change Agamemnon's protection settings without using the app. The change was undone.", critical: true)
    }

    nonisolated private static func equal(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x as NSObject, y as NSObject): return x.isEqual(y)
        default: return false
        }
    }
}
