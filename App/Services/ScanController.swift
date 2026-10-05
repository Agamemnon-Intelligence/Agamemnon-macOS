import Foundation
import Combine

/// Runs Quick / Full / Custom scans for the UI and the scheduler.
@MainActor
final class ScanController: ObservableObject {
    @Published private(set) var isScanning = false
    @Published private(set) var kind: ScanKind?
    @Published private(set) var phase = ""
    @Published private(set) var filesScanned = 0
    @Published private(set) var archivesOpened = 0
    @Published private(set) var currentPath = ""
    @Published private(set) var startedAt: Date?
    /// Threats from the current or last scan that are still on disk.
    @Published var detections: [Detection] = []
    @Published private(set) var skippedArchives: [String] = []
    @Published private(set) var lastSummary: ScanSummary?
    @Published private(set) var clamAVNote: String?

    private var engine: ScanEngine?
    private let vault: QuarantineVault
    private let summaryKey = "scan.lastSummary"

    init(quarantine: QuarantineVault) {
        self.vault = quarantine
        if let data = UserDefaults.standard.data(forKey: summaryKey),
           let summary = try? JSONDecoder().decode(ScanSummary.self, from: data) {
            lastSummary = summary
        }
    }

    // MARK: - Targets

    static func quickTargets() -> [URL] {
        let home = AppPaths.home
        let candidates = [
            home.appendingPathComponent("Downloads"),
            home.appendingPathComponent("Desktop"),
            URL(fileURLWithPath: "/Applications"),
            home.appendingPathComponent("Applications"),
            home.appendingPathComponent("Library/LaunchAgents"),
            URL(fileURLWithPath: "/Library/LaunchAgents"),
            URL(fileURLWithPath: "/Library/LaunchDaemons"),
            URL(fileURLWithPath: "/Library/StartupItems"),
            URL(fileURLWithPath: "/Library/PrivilegedHelperTools"),
            URL(fileURLWithPath: "/Users/Shared"),
            URL(fileURLWithPath: "/private/tmp"),
        ]
        return candidates.filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    static func fullTargets() -> [URL] { [URL(fileURLWithPath: "/")] }

    static func options(for kind: ScanKind) -> ScanEngine.Options {
        var o = ScanEngine.Options()
        o.scanArchives = Prefs.bool(Prefs.scanArchives)
        o.useClamAV = Prefs.bool(Prefs.useClamAV)
        o.exclusions = Prefs.exclusionList
        if kind == .full { o.exclusions += ScanEngine.fullScanExclusions }
        o.gatekeeperCheck = kind == .download
        return o
    }

    // MARK: - Running

    func start(_ kind: ScanKind, targets custom: [URL] = [], scheduled: Bool = false) {
        guard !isScanning else { return }
        let targets: [URL]
        switch kind {
        case .quick: targets = ScanController.quickTargets()
        case .full: targets = ScanController.fullTargets()
        case .custom, .download: targets = custom
        }
        guard !targets.isEmpty else { return }

        let engine = ScanEngine()
        self.engine = engine
        self.kind = kind
        isScanning = true
        phase = "Starting"
        filesScanned = 0
        archivesOpened = 0
        currentPath = ""
        detections = []
        skippedArchives = []
        clamAVNote = nil
        let started = Date()
        startedAt = started
        let options = ScanController.options(for: kind)

        Thread.detachNewThread { [weak self] in
            let result = engine.run(roots: targets, options: options) { snapshot in
                Task { @MainActor in
                    guard let self, self.engine === engine else { return }
                    self.phase = snapshot.phase
                    self.filesScanned = snapshot.filesScanned
                    self.archivesOpened = snapshot.archivesOpened
                    self.currentPath = snapshot.currentPath
                    self.detections = snapshot.detections
                }
            }
            Task { @MainActor in
                self?.finish(result, kind: kind, started: started, scheduled: scheduled)
            }
        }
    }

    func cancel() {
        engine?.cancel()
        phase = "Stopping…"
    }

    private func finish(_ result: ScanResult, kind: ScanKind, started: Date, scheduled: Bool) {
        engine = nil
        isScanning = false
        filesScanned = result.filesScanned
        archivesOpened = result.archivesOpened
        detections = result.detections
        skippedArchives = result.skippedArchives
        clamAVNote = result.clamAVError
        currentPath = ""
        phase = result.cancelled ? "Stopped" : "Finished"

        var quarantined = 0
        if Prefs.bool(Prefs.autoQuarantine) {
            for detection in result.detections where detection.level != .suspicious {
                if (try? vault.quarantine(detection)) != nil {
                    quarantined += 1
                    detections.removeAll { $0.fileURL == detection.fileURL }
                }
            }
        }

        let summary = ScanSummary(kind: kind, started: started, finished: Date(),
                                  filesScanned: result.filesScanned, archivesOpened: result.archivesOpened,
                                  detections: result.detections.count, quarantined: quarantined,
                                  cancelled: result.cancelled, scheduled: scheduled)
        lastSummary = summary
        if let data = try? JSONEncoder().encode(summary) {
            UserDefaults.standard.set(data, forKey: summaryKey)
        }

        let found = result.detections.count
        let title = result.cancelled ? "\(kind.title) stopped" : "\(kind.title) finished"
        let detail = "\(result.filesScanned.formatted()) files · " +
            (found == 0 ? "no threats" : "\(found) threat\(found == 1 ? "" : "s") found, \(quarantined) quarantined")
        ActivityLog.shared.add(found > 0 ? .threat : .scan, title, detail)
        if found > 0 {
            Notifier.post("Agamemnon found \(found) threat\(found == 1 ? "" : "s")", detail, critical: true)
        } else if scheduled {
            Notifier.post(title, detail)
        }
    }

    // MARK: - Acting on results

    func quarantine(_ detection: Detection) {
        do {
            try vault.quarantine(detection)
            detections.removeAll { $0.fileURL == detection.fileURL }
        } catch {
            vault.lastError = error.localizedDescription
        }
    }

    func quarantineAll() {
        for d in detections where vault.contains(path: d.fileURL.path) == false { quarantine(d) }
    }

    func ignore(_ detection: Detection) {
        detections.removeAll { $0.id == detection.id }
    }
}
