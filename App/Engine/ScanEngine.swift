import Foundation

/// Walks files, hashes them against the signature database, looks inside
/// archives / installers / disk images, optionally asks Gatekeeper about apps,
/// and finally hands the same paths to ClamAV when it's installed.
///
/// `run` is synchronous; call it from a background thread.
final class ScanEngine {
    struct Options {
        var scanArchives = true
        var useClamAV = true
        var gatekeeperCheck = false
        var exclusions: [String] = []
        /// Files bigger than this aren't hashed (malware samples are rarely huge).
        var maxHashBytes: Int64 = 1024 * 1024 * 1024
    }

    /// Paths that are never scanned.
    static var alwaysExcluded: [String] {
        [
            AppPaths.quarantine.path,
            AppPaths.scratch.path,
            AppPaths.clamav.path,
            AppPaths.signatures.path,
        ]
    }

    /// System paths skipped by a full scan (sealed system volume, devices, VM swap,
    /// other volumes).
    static let fullScanExclusions = [
        "/System", "/dev", "/Volumes", "/private/var/vm", "/cores", "/net", "/home",
        "/private/var/db/uuidtext", "/private/var/db/diagnostics",
    ]

    private let signatures: SignatureStore
    private let archives = ArchiveInspector()
    private let cancelLock = NSLock()
    private var cancelled = false
    private var clamProcess: LineProcess?

    // Per-run state (only touched from the scanning thread).
    private var options = Options()
    private var excluded: [String] = []
    private var detections: [Detection] = []
    private var files = 0
    private var archivesOpened = 0
    private var skipped: [String] = []
    private var phase = "Scanning"
    private var lastReport = Date.distantPast
    private var progress: (ScanSnapshot) -> Void = { _ in }

    init(signatures: SignatureStore = .shared) {
        self.signatures = signatures
    }

    var isCancelled: Bool {
        cancelLock.lock(); defer { cancelLock.unlock() }
        return cancelled
    }

    func cancel() {
        cancelLock.lock()
        cancelled = true
        let clam = clamProcess
        cancelLock.unlock()
        clam?.terminate()
    }

    func run(roots: [URL], options: Options, progress: @escaping (ScanSnapshot) -> Void) -> ScanResult {
        self.options = options
        self.progress = progress
        self.excluded = (options.exclusions + ScanEngine.alwaysExcluded).map { ScanEngine.normalize($0) }
        detections = []
        files = 0
        archivesOpened = 0
        skipped = []

        // 1. Built-in engine.
        phase = "Checking files"
        for root in roots where !isCancelled {
            walk(root.resolvingSymlinksInPath(), depth: 0, container: nil, extractionRoot: nil, innerBase: nil)
        }

        // 2. ClamAV, if installed and enabled.
        var clamError: String?
        if options.useClamAV, ClamAV.shared.isReady, !isCancelled {
            phase = "ClamAV deep scan"
            report(force: true, path: "Loading ClamAV signatures…")
            let paths = roots.map { $0.resolvingSymlinksInPath().path }
            let result = ClamAV.shared.scan(
                paths: paths,
                exclusions: excluded,
                onFile: { [weak self] path in self?.report(force: true, path: path) },
                register: { [weak self] process in
                    guard let self else { return }
                    self.cancelLock.lock(); self.clamProcess = process; self.cancelLock.unlock()
                    if self.isCancelled { process.terminate() }
                })
            cancelLock.lock(); clamProcess = nil; cancelLock.unlock()
            if !isCancelled { clamError = result.error }
            for (path, name) in result.hits {
                let url = URL(fileURLWithPath: path)
                if detections.contains(where: { $0.fileURL.path == url.path }) { continue }
                let lower = name.lowercased()
                let level: ThreatLevel = lower.contains("eicar") ? .test : (lower.hasPrefix("pua.") ? .suspicious : .malicious)
                detections.append(Detection(fileURL: url, innerPath: nil, threatName: name, engine: "ClamAV", level: level))
            }
        }

        report(force: true, path: "")
        return ScanResult(detections: detections,
                          filesScanned: files,
                          archivesOpened: archivesOpened,
                          skippedArchives: skipped,
                          cancelled: isCancelled,
                          clamAVError: clamError)
    }

    // MARK: - Walking

    private static func normalize(_ path: String) -> String {
        // Resolve /var → /private/var etc. so exclusions match enumerated paths.
        var p = URL(fileURLWithPath: (path as NSString).expandingTildeInPath).resolvingSymlinksInPath().path
        while p.count > 1 && p.hasSuffix("/") { p.removeLast() }
        return p
    }

    private func isExcluded(_ path: String) -> Bool {
        for ex in excluded where path == ex || path.hasPrefix(ex == "/" ? "/" : ex + "/") {
            return true
        }
        return false
    }

    private func walk(_ root: URL, depth: Int, container: URL?, extractionRoot: URL?, innerBase: String?) {
        if isCancelled { return }
        if container == nil && isExcluded(root.path) { return }

        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDir) else { return }
        if !isDir.boolValue {
            let size = (try? root.resourceValues(forKeys: [.fileSizeKey]).fileSize).map { Int64($0) } ?? 0
            scanFile(root, size: size, depth: depth, container: container, extractionRoot: extractionRoot, innerBase: innerBase)
            return
        }
        if options.gatekeeperCheck { checkBundle(root, container: container, extractionRoot: extractionRoot, innerBase: innerBase) }

        let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey, .isDirectoryKey, .fileSizeKey]
        guard let enumerator = FileManager.default.enumerator(at: root,
                                                              includingPropertiesForKeys: keys,
                                                              options: [],
                                                              errorHandler: { _, _ in true }) else { return }
        let keySet = Set(keys)
        for case let url as URL in enumerator {
            if isCancelled { return }
            if container == nil && isExcluded(url.path) {
                enumerator.skipDescendants()
                continue
            }
            guard let values = try? url.resourceValues(forKeys: keySet) else { continue }
            if values.isSymbolicLink == true { continue }
            if values.isDirectory == true {
                if options.gatekeeperCheck, depth <= 1 {
                    checkBundle(url, container: container, extractionRoot: extractionRoot, innerBase: innerBase)
                }
                continue
            }
            if values.isRegularFile == true {
                scanFile(url, size: Int64(values.fileSize ?? 0), depth: depth,
                         container: container, extractionRoot: extractionRoot, innerBase: innerBase)
            }
        }
    }

    private func innerPath(of url: URL, extractionRoot: URL?, innerBase: String?) -> String? {
        guard let extractionRoot else { return innerBase }
        var relative = url.path
        if relative.hasPrefix(extractionRoot.path) {
            relative = String(relative.dropFirst(extractionRoot.path.count))
            while relative.hasPrefix("/") { relative.removeFirst() }
        }
        if let innerBase { return relative.isEmpty ? innerBase : "\(innerBase) ▸ \(relative)" }
        return relative.isEmpty ? nil : relative
    }

    private func scanFile(_ url: URL, size: Int64, depth: Int, container: URL?, extractionRoot: URL?, innerBase: String?) {
        files += 1
        report(force: false, path: container.map { "\($0.lastPathComponent) ▸ \(url.lastPathComponent)" } ?? url.path)
        guard size > 0 else { return }

        let outer = container ?? url
        let inner = innerPath(of: url, extractionRoot: extractionRoot, innerBase: innerBase)

        // EICAR test string (also catches EICAR with trailing whitespace).
        if size <= 256, let data = try? Data(contentsOf: url), Eicar.matches(data) {
            add(Detection(fileURL: outer, innerPath: inner, threatName: "EICAR-Test-File",
                          engine: "Agamemnon", level: .test, sha256: nil))
            return
        }

        if size <= options.maxHashBytes, let hash = try? FileHasher.sha256(of: url) {
            if let name = signatures.lookup(hash) {
                let level: ThreatLevel = name.hasPrefix("EICAR") ? .test : .malicious
                add(Detection(fileURL: outer, innerPath: inner, threatName: name,
                              engine: "Agamemnon", level: level, sha256: hash.hex))
                return
            }
        }

        if options.gatekeeperCheck, depth <= 1, ["pkg", "mpkg"].contains(url.pathExtension.lowercased()) {
            checkBundle(url, container: container, extractionRoot: extractionRoot, innerBase: innerBase)
        }

        guard options.scanArchives,
              depth < ArchiveInspector.maxDepth,
              let kind = ArchiveInspector.kind(of: url) else { return }

        archivesOpened += 1
        let previousPhase = phase
        phase = "Looking inside \(url.lastPathComponent)"
        report(force: true, path: url.path)
        let nestedBase = container == nil ? nil : inner
        let outcome = archives.open(url, kind: kind) { contents in
            walk(contents, depth: depth + 1, container: outer, extractionRoot: contents, innerBase: nestedBase)
        }
        phase = previousPhase
        if case .skipped(let reason) = outcome {
            skipped.append("\(inner ?? url.path): \(reason)")
        }
    }

    /// Gatekeeper check for .app bundles and installer packages.
    private func checkBundle(_ url: URL, container: URL?, extractionRoot: URL?, innerBase: String?) {
        guard ["app", "pkg", "mpkg"].contains(url.pathExtension.lowercased()) else { return }
        guard let verdict = Gatekeeper.assess(url), !verdict.accepted else { return }
        let outer = container ?? url
        let inner = innerPath(of: url, extractionRoot: extractionRoot, innerBase: innerBase)
        if detections.contains(where: { $0.fileURL == outer && $0.innerPath == inner }) { return }
        let level: ThreatLevel = verdict.reason.contains("revoked") ? .malicious : .suspicious
        add(Detection(fileURL: outer, innerPath: inner, threatName: verdict.reason,
                      engine: "Gatekeeper", level: level))
    }

    private func add(_ detection: Detection) {
        detections.append(detection)
        report(force: true, path: detection.displayPath)
    }

    private func report(force: Bool, path: String) {
        let now = Date()
        guard force || now.timeIntervalSince(lastReport) > 0.08 else { return }
        lastReport = now
        progress(ScanSnapshot(phase: phase, filesScanned: files, archivesOpened: archivesOpened,
                              currentPath: path, detections: detections))
    }
}
