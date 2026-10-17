import Foundation
import Combine
import AppKit

/// A quick check of the macOS settings that matter most for security, each with a button to
/// the right System Settings page. Read-only: Agamemnon never changes these itself.
@MainActor
final class SecurityCheckup: ObservableObject {
    struct Item: Identifiable, Hashable {
        enum State: Hashable { case good, warning, bad }
        let id: String
        let title: String
        let detail: String
        let state: State
        /// System Settings page that fixes it.
        let settingsURL: String?
    }

    @Published private(set) var items: [Item] = []
    @Published private(set) var lastRun: Date?
    @Published private(set) var isRunning = false

    var score: (good: Int, total: Int) { (items.filter { $0.state == .good }.count, items.count) }

    func run() {
        guard !isRunning else { return }
        isRunning = true
        Task {
            let result = await Task.detached(priority: .utility) { SecurityCheckup.check() }.value
            self.items = result
            self.lastRun = Date()
            self.isRunning = false
        }
    }

    func open(_ item: Item) {
        guard let raw = item.settingsURL, let url = URL(string: raw) else { return }
        NSWorkspace.shared.open(url)
    }

    // MARK: - Checks (off the main actor)

    nonisolated private static func output(_ path: String, _ args: [String]) -> String? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }
        let r = Shell.run(path, args, timeout: 20)
        let text = (r.stdout + r.stderr).lowercased()
        return text.isEmpty ? nil : text
    }

    nonisolated private static func softwareUpdatePref(_ key: String) -> Bool {
        let dict = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.SoftwareUpdate.plist") as? [String: Any]
        // Missing means macOS's default, which is on.
        return (dict?[key] as? Bool) ?? ((dict?[key] as? NSNumber)?.boolValue ?? true)
    }

    nonisolated static func check() -> [Item] {
        var items: [Item] = []

        // macOS version: Apple fully patches only the newest three releases.
        let major = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        let version = ProcessInfo.processInfo.operatingSystemVersionString
        items.append(Item(id: "macos", title: "macOS is supported",
                          detail: major >= 15 ? "\(version) still gets Apple's security fixes."
                                              : "\(version) no longer gets all of Apple's security fixes. Update macOS if your Mac supports it.",
                          state: major >= 15 ? .good : .bad,
                          settingsURL: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"))

        let security = softwareUpdatePref("CriticalUpdateInstall") && softwareUpdatePref("ConfigDataInstall")
        items.append(Item(id: "updates", title: "Automatic security updates",
                          detail: security ? "Security responses and XProtect malware definitions install by themselves."
                                           : "Turn on “Install Security Responses and system files” so XProtect stays current.",
                          state: security ? .good : .bad,
                          settingsURL: "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"))

        if let fv = output("/usr/bin/fdesetup", ["status"]) {
            let on = fv.contains("filevault is on")
            items.append(Item(id: "filevault", title: "FileVault disk encryption",
                              detail: on ? "Your disk is encrypted, so nobody can read it if your Mac is lost or stolen."
                                         : "Your disk isn't encrypted. Anyone with your Mac can read your files.",
                              state: on ? .good : .bad,
                              settingsURL: "x-apple.systempreferences:com.apple.preference.security?FileVault"))
        }

        if let fw = output("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]) {
            let on = fw.contains("enabled") || fw.contains("state = 1") || fw.contains("state = 2")
            items.append(Item(id: "firewall", title: "Firewall",
                              detail: on ? "Incoming connections to apps are controlled."
                                         : "Off. Turn it on to block unwanted incoming connections, especially on public Wi-Fi.",
                              state: on ? .good : .warning,
                              settingsURL: "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall"))
        }

        if let gk = output("/usr/sbin/spctl", ["--status"]) {
            let on = gk.contains("assessments enabled")
            items.append(Item(id: "gatekeeper", title: "Gatekeeper",
                              detail: on ? "macOS checks apps before they open for the first time."
                                         : "Off. Any app can run without being checked. Malware installers often ask you to turn this off.",
                              state: on ? .good : .bad,
                              settingsURL: "x-apple.systempreferences:com.apple.preference.security?General"))
        }

        if let sip = output("/usr/bin/csrutil", ["status"]) {
            let on = sip.contains("status: enabled")
            items.append(Item(id: "sip", title: "System Integrity Protection",
                              detail: on ? "macOS's own files are protected from changes."
                                         : "Off. Malware could change macOS itself. Turn it back on from Recovery mode.",
                              state: on ? .good : .bad, settingsURL: nil))
        }

        let loginwindow = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.loginwindow.plist") as? [String: Any]
        let autoLogin = loginwindow?["autoLoginUser"] != nil
        items.append(Item(id: "autologin", title: "Password at login",
                          detail: autoLogin ? "Your Mac logs in automatically, so anyone who turns it on gets in."
                                            : "Your Mac asks for a password when it starts.",
                          state: autoLogin ? .bad : .good,
                          settingsURL: "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension"))

        let ssh = Shell.run("/bin/launchctl", ["print", "system/com.openssh.sshd"], timeout: 10).status == 0
        items.append(Item(id: "ssh", title: "Remote Login (SSH)",
                          detail: ssh ? "On. Other computers can log in to your Mac over the network. Turn it off if you don't use it."
                                      : "Off. Nobody can log in to your Mac remotely.",
                          state: ssh ? .warning : .good,
                          settingsURL: "x-apple.systempreferences:com.apple.Sharing-Settings.extension"))

        if let tm = output("/usr/bin/tmutil", ["destinationinfo"]) {
            let none = tm.contains("no destinations")
            items.append(Item(id: "backup", title: "Time Machine backup",
                              detail: none ? "No backup is set up. A backup is the surest way back from ransomware or a dead disk."
                                           : "Your Mac is backed up with Time Machine.",
                              state: none ? .warning : .good,
                              settingsURL: "x-apple.systempreferences:com.apple.Time-Machine-Settings.extension"))
        }

        return items
    }
}
