import Foundation
import Combine

/// Watches the Downloads folder (and any extra folders the user adds). When a
/// download finishes, it's scanned right away — including inside archives,
/// installers and disk images — and quarantined if it's dangerous.
@MainActor
final class DownloadGuard: ObservableObject {
    struct Event: Identifiable, Hashable {
        enum Verdict: Hashable { case checking, clean, suspicious(String), quarantined(String), threat(String), skipped(String) }
        let id = UUID()
        let name: String
        let path: String
        var date = Date()
        var verdict: Verdict
    }

    @Published private(set) var isRunning = false
    @Published private(set) var events: [Event] = []
    @Published private(set) var folders: [URL] = []

    private let vault: QuarantineVault
    private var watcher: FolderWatcher?
    private var timer: Timer?
    /// top-level item path → time of its last file-system event
    private var pending: [String: Date] = [:]
    /// path → (size, modification date) of the last scan, to avoid re-scanning
    private var scanned: [String: String] = [:]
    private var scanning: Set<String> = []
    private let queue = DispatchQueue(label: "agamemnon.downloads", qos: .utility)

    /// Suffixes browsers use while a download is still in progress.
    private static let partialSuffixes = [".download", ".crdownload", ".part", ".partial", ".opdownload", ".tmp", ".icloud", ".aria2"]

    init(vault: QuarantineVault) {
        self.vault = vault
        loadFolders()
    }

    static var defaultFolder: URL { AppPaths.home.appendingPathComponent("Downloads", isDirectory: true) }

    private func loadFolders() {
        let extra = (UserDefaults.standard.stringArray(forKey: Prefs.watchedFolders) ?? []).map { URL(fileURLWithPath: $0) }
        folders = [DownloadGuard.defaultFolder] + extra.filter { $0.path != DownloadGuard.defaultFolder.path }
    }

    func addFolder(_ url: URL) {
        var extra = UserDefaults.standard.stringArray(forKey: Prefs.watchedFolders) ?? []
        guard !extra.contains(url.path), url.path != DownloadGuard.defaultFolder.path else { return }
        extra.append(url.path)
        UserDefaults.standard.set(extra, forKey: Prefs.watchedFolders)
        loadFolders()
        restart()
    }

    func removeFolder(_ url: URL) {
        var extra = UserDefaults.standard.stringArray(forKey: Prefs.watchedFolders) ?? []
        extra.removeAll { $0 == url.path }
        UserDefaults.standard.set(extra, forKey: Prefs.watchedFolders)
        loadFolders()
        restart()
    }

    func applyPreference() {
        if Prefs.bool(Prefs.downloadProtection) { start() } else { stop() }
    }

    func start() {
        guard !isRunning else { return }
        let paths = folders.map(\.path).filter { FileManager.default.fileExists(atPath: $0) }
        let watcher = FolderWatcher(paths: paths, latency: 0.3) { [weak self] changed in
            Task { @MainActor in self?.handle(changed) }
        }
        guard watcher.start() else { return }
        self.watcher = watcher
        isRunning = true
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
    }

    func stop() {
        watcher?.stop()
        watcher = nil
        timer?.invalidate()
        timer = nil
        pending.removeAll()
        isRunning = false
    }

    private func restart() {
        guard isRunning else { return }
        stop()
        start()
    }

    // MARK: - Events

    /// Maps any changed path to the top-level item inside a watched folder.
    private func topLevelItem(for path: String) -> String? {
        for folder in folders {
            let root = folder.path
            guard path.hasPrefix(root + "/") else { continue }
            let rest = path.dropFirst(root.count + 1)
            guard let first = rest.split(separator: "/", maxSplits: 1).first else { return nil }
            return root + "/" + first
        }
        return nil
    }

    private func handle(_ paths: [String]) {
        let now = Date()
        for path in paths {
            guard let item = topLevelItem(for: path) else { continue }
            let name = (item as NSString).lastPathComponent
            if name.hasPrefix(".") { continue }
            let lower = name.lowercased()
            if DownloadGuard.partialSuffixes.contains(where: { lower.hasSuffix($0) }) { continue }
            pending[item] = now
        }
    }

    /// Scans items that have been quiet for 2 seconds (the download is complete).
    private func tick() {
        let now = Date()
        for (path, last) in pending where now.timeIntervalSince(last) >= 2 {
            pending[path] = nil
            guard !scanning.contains(path) else { pending[path] = now; continue }
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else { continue }
            let fingerprint = "\((attrs[.size] as? NSNumber)?.int64Value ?? 0)-\((attrs[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0)"
            if scanned[path] == fingerprint { continue }
            scanned[path] = fingerprint
            scan(URL(fileURLWithPath: path))
        }
    }

    private func scan(_ url: URL) {
        scanning.insert(url.path)
        let event = Event(name: url.lastPathComponent, path: url.path, verdict: .checking)
        events.insert(event, at: 0)
        if events.count > 50 { events.removeLast(events.count - 50) }

        var options = ScanController.options(for: .download)
        // Per-file ClamAV runs are slow to start; only use it for archives/installers.
        options.useClamAV = options.useClamAV && ArchiveInspector.kind(of: url) != nil
        let scanOptions = options
        queue.async { [weak self] in
            let result = ScanEngine().run(roots: [url], options: scanOptions) { _ in }
            Task { @MainActor in self?.finish(event.id, url: url, result: result) }
        }
    }

    private func finish(_ id: UUID, url: URL, result: ScanResult) {
        scanning.remove(url.path)
        let verdict: Event.Verdict
        let malicious = result.detections.filter { $0.level != .suspicious }
        let suspicious = result.detections.filter { $0.level == .suspicious }

        if let threat = malicious.first {
            do {
                try vault.quarantine(threat)
                verdict = .quarantined(threat.threatName)
                Notifier.post("Dangerous download quarantined",
                              "“\(url.lastPathComponent)” contains \(threat.threatName). Agamemnon moved it to quarantine.",
                              critical: true)
                ActivityLog.shared.add(.threat, "Blocked download \(url.lastPathComponent)", threat.threatName)
            } catch {
                verdict = .threat(threat.threatName)
                Notifier.post("Dangerous download", "“\(url.lastPathComponent)” contains \(threat.threatName). Don't open it.", critical: true)
                ActivityLog.shared.add(.threat, "Dangerous download \(url.lastPathComponent)", error.localizedDescription)
            }
        } else if let warning = suspicious.first {
            if Prefs.bool(Prefs.quarantineUnnotarized), (try? vault.quarantine(warning)) != nil {
                verdict = .quarantined(warning.threatName)
                Notifier.post("Unverified app quarantined", "“\(url.lastPathComponent)”: \(warning.threatName).")
            } else {
                verdict = .suspicious(warning.threatName)
                Notifier.post("Be careful with this download", "“\(url.lastPathComponent)”: \(warning.threatName). Only open it if you trust where it came from.")
            }
            ActivityLog.shared.add(.download, "Checked \(url.lastPathComponent)", warning.threatName)
        } else if let skip = result.skippedArchives.first {
            verdict = .skipped(skip.components(separatedBy: ": ").last ?? skip)
            ActivityLog.shared.add(.download, "Checked \(url.lastPathComponent)", "Couldn't look inside: \(skip)")
        } else {
            verdict = .clean
            ActivityLog.shared.add(.download, "Checked \(url.lastPathComponent)", "No threats · \(result.filesScanned) file\(result.filesScanned == 1 ? "" : "s")")
        }
        if let index = events.firstIndex(where: { $0.id == id }) {
            events[index].verdict = verdict
        }
    }
}
