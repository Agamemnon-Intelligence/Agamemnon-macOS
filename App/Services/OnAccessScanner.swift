import Foundation
import Combine

/// On-access scanning: every program, script, installer or archive written anywhere on the Mac
/// (not just Downloads) is checked within a second or two, the way commercial antivirus does.
/// The protection helper sees the writes through Endpoint Security (`eslogger` close events)
/// and reports them; this collects them for a moment and runs the scan engine on the batch:
/// hash lists, pattern rules, program analysis, Apple's XProtect rules, archive contents, and,
/// for unsigned programs, the MalwareBazaar cloud check.
///
/// Needs the protection helper with Full Disk Access. Without it, download protection still
/// covers the download folders.
@MainActor
final class OnAccessScanner: ObservableObject {
    struct Finding: Identifiable, Hashable {
        let id = UUID()
        let date = Date()
        let path: String
        let threat: String
        let outcome: String
    }

    @Published private(set) var filesChecked = 0
    @Published private(set) var findings: [Finding] = []

    private let vault: QuarantineVault
    private var pending: Set<String> = []
    private var flushScheduled = false
    private var scanning = false
    private let queue = DispatchQueue(label: "agamemnon.on-access", qos: .userInitiated)

    init(vault: QuarantineVault) {
        self.vault = vault
    }

    /// A file was just written (from the helper).
    func fileWritten(_ path: String) {
        guard Prefs.bool(Prefs.onAccessScan) else { return }
        if ScanEngine.alwaysExcluded.contains(where: { path.hasPrefix($0) }) { return }
        if Prefs.exclusionList.contains(where: { path == $0 || path.hasPrefix($0 + "/") }) { return }
        if pending.count < 2000 { pending.insert(path) }
        guard !flushScheduled else { return }
        flushScheduled = true
        // Wait a moment so a whole app or archive being copied is checked as one batch.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in self?.flush() }
    }

    private func flush() {
        flushScheduled = false
        guard !pending.isEmpty else { return }
        if scanning {
            // finished() picks the rest up.
            return
        }
        // Programs inside an app are checked as the whole app.
        let roots = Set(pending.map { BehaviorMonitor.quarantineTarget(for: $0) })
            .filter { FileManager.default.fileExists(atPath: $0) }
            .map { URL(fileURLWithPath: $0) }
        pending.removeAll()
        guard !roots.isEmpty else { return }
        scanning = true
        var options = ScanController.options(for: .custom)
        options.useClamAV = false            // ClamAV loads its whole database per run; too slow here
        options.appSignatureCheck = false
        queue.async { [weak self] in
            let result = ScanEngine().run(roots: roots, options: options) { _ in }
            let found = DetectionBox(result.detections)
            // Cloud check for unsigned programs the local engines didn't flag.
            let group = DispatchGroup()
            for root in roots where CloudLookup.isEnabled && !result.detections.contains(where: { $0.fileURL == root }) {
                let target = root.pathExtension == "app"
                    ? (Bundle(url: root)?.executableURL ?? root) : root
                let size = ((try? FileManager.default.attributesOfItem(atPath: target.path))?[.size] as? NSNumber)?.int64Value ?? 0
                guard PatternRules.kind(of: target, size: size) == .program,
                      CodeIdentity.of(root.path).isUnvouched,
                      let sha = try? FileHasher.sha256(of: target).hex else { continue }
                group.enter()
                Task {
                    if let name = await CloudLookup.lookup(sha256: sha) {
                        found.append(Detection(fileURL: root, innerPath: nil, threatName: name, engine: "MalwareBazaar", level: .malicious))
                    }
                    group.leave()
                }
            }
            group.wait()
            let detections = found.items
            Task { @MainActor in self?.finished(detections, checked: result.filesScanned) }
        }
    }

    private func finished(_ detections: [Detection], checked: Int) {
        scanning = false
        filesChecked += checked
        for d in detections {
            var outcome = "Reported"
            if d.level == .malicious, Prefs.bool(Prefs.autoQuarantine) {
                outcome = (try? vault.quarantine(d)) != nil ? "Quarantined" : "Couldn't quarantine"
            }
            findings.insert(Finding(path: d.displayPath, threat: d.threatName, outcome: outcome), at: 0)
            if findings.count > 30 { findings.removeLast() }
            ActivityLog.shared.add(.threat, "\(d.threatName) written to disk", "\(d.displayPath) · \(outcome)")
            Notifier.post(d.level == .malicious ? "Malware blocked as it was saved" : "Suspicious file saved",
                          "\(d.fileName): \(d.threatName). \(outcome).", critical: d.level == .malicious)
        }
        if !pending.isEmpty { flush() }
    }
}

/// Detections collected from several threads.
private final class DetectionBox: @unchecked Sendable {
    private let lock = NSLock()
    private var list: [Detection]
    init(_ list: [Detection]) { self.list = list }
    func append(_ d: Detection) { lock.lock(); list.append(d); lock.unlock() }
    var items: [Detection] { lock.lock(); defer { lock.unlock() }; return list }
}
