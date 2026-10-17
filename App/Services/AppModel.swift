import Foundation
import Combine
import SwiftUI
import AppKit

/// Owns every service and decides the overall protection status.
@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()

    let activity = ActivityLog.shared
    let signatures: SignatureManager
    let vault: QuarantineVault
    let scanner: ScanController
    let downloads: DownloadGuard
    let admin: AdminWatcher
    let backgroundItems: BackgroundItemWatcher
    let behavior: BehaviorMonitor
    let dns: DNSManager
    let scheduler: ScanScheduler
    let startupSweep: StartupSweep
    let browser: BrowserGuard
    let ransomware: RansomwareShield
    let checkup: SecurityCheckup

    @Published private(set) var clamAVInstalled = false
    @Published private(set) var clamAVReady = false
    @Published private(set) var clamAVVersion: String?
    @Published private(set) var clamAVUpdating = false
    @Published var clamAVMessage: String?
    @Published private(set) var hasFullDiskAccess = true
    @Published private(set) var clamAVInstalling = false

    private var bag = Set<AnyCancellable>()
    private var started = false

    private init() {
        Prefs.registerDefaults()
        signatures = SignatureManager()
        vault = QuarantineVault()
        scanner = ScanController(quarantine: vault)
        downloads = DownloadGuard(vault: vault)
        admin = AdminWatcher()
        backgroundItems = BackgroundItemWatcher(vault: vault)
        behavior = BehaviorMonitor(vault: vault)
        dns = DNSManager()
        scheduler = ScanScheduler(scanner: scanner)
        startupSweep = StartupSweep(vault: vault)
        browser = BrowserGuard(vault: vault)
        ransomware = RansomwareShield(vault: vault)
        checkup = SecurityCheckup()

        // Re-publish child changes so the menu bar icon and overview stay current.
        let children: [AnyPublisher<Void, Never>] = [
            signatures.objectWillChange.map { _ in () }.eraseToAnyPublisher(),
            vault.objectWillChange.map { _ in () }.eraseToAnyPublisher(),
            scanner.objectWillChange.map { _ in () }.eraseToAnyPublisher(),
            downloads.objectWillChange.map { _ in () }.eraseToAnyPublisher(),
            dns.objectWillChange.map { _ in () }.eraseToAnyPublisher(),
            behavior.objectWillChange.map { _ in () }.eraseToAnyPublisher(),
            ransomware.objectWillChange.map { _ in () }.eraseToAnyPublisher(),
        ]
        for publisher in children {
            publisher
                .receive(on: RunLoop.main)
                .sink { [weak self] in self?.objectWillChange.send() }
                .store(in: &bag)
        }
    }

    func start() {
        guard !started else { return }
        started = true
        AppPaths.cleanScratch()
        Notifier.requestAuthorization()
        signatures.start()
        downloads.applyPreference()
        admin.applyPreference()
        backgroundItems.applyPreference()
        behavior.applyPreference()
        scheduler.start()
        dns.refreshStatus()
        refreshEnvironment()
        startupSweep.applyPreference()
        browser.applyPreference()
        ransomware.applyPreference()
        checkup.run()
        // Set up ClamAV once, automatically, if it isn't there yet.
        DispatchQueue.main.asyncAfter(deadline: .now() + 45) { [weak self] in
            Task { @MainActor in self?.autoInstallClamAVIfNeeded() }
        }
    }

    private func autoInstallClamAVIfNeeded() {
        // Installed but without signatures (for example, the first download was interrupted).
        if ClamAV.shared.isInstalled {
            if !ClamAV.shared.hasDatabase { updateClamAV() }
            return
        }
        guard Prefs.bool(Prefs.autoInstallClamAV), !Prefs.bool(Prefs.clamAVAutoInstallTried) else { return }
        UserDefaults.standard.set(true, forKey: Prefs.clamAVAutoInstallTried)
        installClamAV()
    }

    /// Installs ClamAV (Homebrew if present, otherwise Cisco's signed installer), then its signatures.
    func installClamAV() {
        guard !clamAVInstalling else { return }
        clamAVInstalling = true
        clamAVMessage = "Installing ClamAV, a free second antivirus engine…"
        Task {
            let step = await ClamAV.shared.prepareInstall()
            switch step {
            case .done:
                break
            case .needsPassword(let pkg):
                self.clamAVMessage = "Installing ClamAV… macOS will ask for your password."
                do {
                    try Privileged.run("/usr/sbin/installer -pkg \(Shell.quote(pkg.path)) -target /",
                                       prompt: "Agamemnon is installing ClamAV, a free second antivirus engine by Cisco.")
                } catch {
                    self.clamAVMessage = "ClamAV wasn't installed: \(error.localizedDescription)"
                }
                try? FileManager.default.removeItem(at: pkg.deletingLastPathComponent())
            case .failed(let message):
                self.clamAVMessage = message
            }
            self.clamAVInstalling = false
            if ClamAV.shared.isInstalled {
                UserDefaults.standard.set(true, forKey: Prefs.useClamAV)
                ActivityLog.shared.add(.update, "ClamAV installed", "Downloading its signatures next")
                self.refreshEnvironment()
                self.updateClamAV()
            }
        }
    }

    /// Re-applies toggles from Settings.
    func preferencesChanged() {
        downloads.applyPreference()
        admin.applyPreference()
        backgroundItems.applyPreference()
        behavior.applyPreference()
        startupSweep.applyPreference()
        browser.applyPreference()
        ransomware.applyPreference()
    }

    func refreshEnvironment() {
        Task {
            let info = await Task.detached(priority: .utility) { () -> (Bool, Bool, String?, Bool) in
                let clam = ClamAV.shared
                let fda = AppModel.checkFullDiskAccess()
                return (clam.isInstalled, clam.isReady, clam.isInstalled ? clam.version : nil, fda)
            }.value
            self.clamAVInstalled = info.0
            self.clamAVReady = info.1
            self.clamAVVersion = info.2
            self.hasFullDiskAccess = info.3
        }
    }

    nonisolated static func checkFullDiskAccess() -> Bool {
        let probes = [
            "/Library/Application Support/com.apple.TCC/TCC.db",
            AppPaths.home.appendingPathComponent("Library/Safari/Bookmarks.plist").path,
        ]
        for path in probes where FileManager.default.fileExists(atPath: path) {
            if let handle = FileHandle(forReadingAtPath: path) {
                try? handle.close()
                return true
            }
            return false
        }
        return true
    }

    func openFullDiskAccessSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    func updateClamAV() {
        guard !clamAVUpdating else { return }
        clamAVUpdating = true
        clamAVMessage = "Downloading ClamAV signatures… (first time ≈ 300 MB)"
        Task {
            let result = await Task.detached(priority: .utility) { ClamAV.shared.updateDatabase() }.value
            self.clamAVUpdating = false
            if result.succeeded {
                self.clamAVMessage = "ClamAV signatures are up to date."
                ActivityLog.shared.add(.update, "ClamAV signatures updated")
            } else {
                let text = (result.stdout + "\n" + result.stderr).trimmingCharacters(in: .whitespacesAndNewlines)
                self.clamAVMessage = "ClamAV update failed: " + String(text.suffix(240))
            }
            self.refreshEnvironment()
        }
    }

    // MARK: - Overall status

    enum Status {
        case protected, attention, scanning, threats

        var title: String {
            switch self {
            case .protected: return "Your Mac is protected"
            case .attention: return "Protection needs attention"
            case .scanning: return "Scanning…"
            case .threats: return "Threats need your attention"
            }
        }

        var symbol: String {
            switch self {
            case .protected: return "checkmark.shield.fill"
            case .attention: return "exclamationmark.shield.fill"
            case .scanning: return "shield.lefthalf.filled"
            case .threats: return "xmark.shield.fill"
            }
        }
    }

    var status: Status {
        if !scanner.detections.filter({ $0.level != .test }).isEmpty { return .threats }
        if scanner.isScanning { return .scanning }
        if signatures.count == 0 || !downloads.isRunning || !behavior.isRunning { return .attention }
        return .protected
    }

    var menuBarSymbol: String {
        switch status {
        case .protected: return "checkmark.shield"
        case .attention: return "exclamationmark.shield"
        case .scanning: return "shield.lefthalf.filled"
        case .threats: return "xmark.shield.fill"
        }
    }

    var attentionReasons: [String] {
        var reasons: [String] = []
        if signatures.count == 0 { reasons.append(signatures.isUpdating ? "Downloading malware signatures…" : "Malware signatures haven't been downloaded yet.") }
        if !downloads.isRunning { reasons.append("Download protection is off.") }
        if !behavior.isRunning { reasons.append("Behaviour protection is off.") }
        return reasons
    }
}
