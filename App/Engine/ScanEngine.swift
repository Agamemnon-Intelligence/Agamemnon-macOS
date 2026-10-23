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
        /// Ask Gatekeeper about apps on disk, and flag apps changed after they were signed.
        var appSignatureCheck = false
        /// Agamemnon's built-in pattern rules for scripts and unsigned programs.
        var patternRules = true
        /// Apple's XProtect YARA rules, run with yara when it's installed.
        var useXProtect = true
        /// Only look at files that can run or carry something that runs (programs, scripts,
        /// apps, installers, archives, disk images). Used for USB drives full of photos.
        var riskyOnly = false
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
    /// Programs and scripts seen by this run, for Apple's XProtect rules at the end.
    private let candidateLock = NSLock()
    private var xprotectCandidates: [String] = []

    // Per-run state (only touched from the scanning thread).
    private var options = Options()
    private var excluded: [String] = []
    private var detections: [Detection] = []
    private var files = 0
    private var archivesOpened = 0
    private var skipped: [String] = []
    private var phase = "Scanning"
    private var lastReport = Date.distantPast
    /// Log lines not yet handed to the UI. Capped, so a stalled UI can't grow it forever.
    private var pendingLog: [ScanLogEntry] = []
    static let maxPendingLog = 5_000
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
        pendingLog = []
        xprotectCandidates = []

        // 1. Built-in engine.
        phase = "Checking files"
        log(.info, "Scanning \(roots.map(\.path).joined(separator: ", "))")
        for root in roots where !isCancelled {
            walk(root.resolvingSymlinksInPath(), depth: 0, container: nil, extractionRoot: nil, innerBase: nil)
        }

        // 2. ClamAV, if installed and enabled.
        var clamError: String?
        if options.useClamAV, ClamAV.shared.isReady, !isCancelled {
            phase = "ClamAV deep scan"
            log(.info, "Starting ClamAV deep scan")
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
                log(.threat, "\(name) · ClamAV · \(path)")
            }
            if let clamError { log(.skipped, "ClamAV: \(clamError)") }
        }

        // 3. Apple's XProtect rules over every program and script found.
        if options.useXProtect, XProtectRules.shared.isReady, !isCancelled {
            candidateLock.lock(); let files = xprotectCandidates; candidateLock.unlock()
            if !files.isEmpty {
                phase = "Apple XProtect rules"
                log(.info, "Checking \(files.count.formatted()) programs and scripts with Apple's XProtect rules")
                report(force: true, path: "")
                let hits = XProtectRules.shared.scan(files: files, register: registerExternal)
                for hit in hits where !detections.contains(where: { $0.fileURL.path == hit.path }) {
                    add(Detection(fileURL: URL(fileURLWithPath: hit.path), innerPath: nil, threatName: hit.name,
                                  engine: "XProtect", level: hit.level))
                }
            }
        }

        log(.info, isCancelled ? "Stopped after \(files.formatted()) files" : "Finished: \(files.formatted()) files, \(archivesOpened.formatted()) archives, \(detections.count) threat\(detections.count == 1 ? "" : "s")")

        report(force: true, path: "")
        return ScanResult(detections: detections,
                          filesScanned: files,
                          archivesOpened: archivesOpened,
                          skippedArchives: skipped,
                          cancelled: isCancelled,
                          clamAVError: clamError)
    }

    // MARK: - Walking

    /// Lets `cancel()` stop a helper tool (yara) that's running.
    private func registerExternal(_ process: LineProcess) {
        cancelLock.lock(); clamProcess = process; let stop = cancelled; cancelLock.unlock()
        if stop { process.terminate() }
    }

    /// Files a USB-drive check looks at when `riskyOnly` is set.
    static let riskyExtensions: Set<String> = [
        "app", "pkg", "mpkg", "dmg", "iso", "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "xar",
        "command", "tool", "terminal", "sh", "zsh", "bash", "py", "js", "jar", "scpt", "applescript",
        "workflow", "action", "dylib", "so", "bundle", "plugin", "kext", "pl", "rb", "php", "docm", "xlsm",
        "pptm", "doc", "xls", "pdf", "lnk", "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "hta", "inetloc", "fileloc",
    ]

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

    /// A file or folder that only exists in the cloud (the "dataless" flag set by iCloud Drive
    /// and File Provider apps). Checked with lstat, which never triggers a download.
    static func isCloudPlaceholder(_ path: String) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0 else { return false }
        return st.st_flags & UInt32(SF_DATALESS) != 0
    }

    private func walk(_ root: URL, depth: Int, container: URL?, extractionRoot: URL?, innerBase: String?) {
        if isCancelled { return }
        if ScanEngine.isCloudPlaceholder(root.path) { return }
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
        // Regular files are checked in batches across all cores; everything else stays in order.
        var batch: [(URL, Int64)] = []
        defer { if !isCancelled { scanBatch(batch, depth: depth, container: container, extractionRoot: extractionRoot, innerBase: innerBase) } }
        for case let url as URL in enumerator {
            if isCancelled { return }
            if container == nil && isExcluded(url.path) {
                enumerator.skipDescendants()
                continue
            }
            // iCloud Drive / Google Drive items that aren't downloaded: reading them would make
            // macOS fetch them from the cloud (and can hang waiting for the network).
            if ScanEngine.isCloudPlaceholder(url.path) {
                enumerator.skipDescendants()
                continue
            }
            guard let values = try? url.resourceValues(forKeys: keySet) else { continue }
            if values.isSymbolicLink == true { continue }
            if values.isDirectory == true {
                if options.gatekeeperCheck, depth <= 1 {
                    checkBundle(url, container: container, extractionRoot: extractionRoot, innerBase: innerBase)
                } else if options.appSignatureCheck, container == nil {
                    checkAppSignature(url)
                }
                continue
            }
            if values.isRegularFile == true {
                batch.append((url, Int64(values.fileSize ?? 0)))
                if batch.count >= ScanEngine.batchSize {
                    scanBatch(batch, depth: depth, container: container, extractionRoot: extractionRoot, innerBase: innerBase)
                    batch.removeAll(keepingCapacity: true)
                }
            }
        }
    }

    static let batchSize = 64

    /// Hashes and pattern-checks a batch of files in parallel, then records the results and
    /// opens archives one at a time, in order, on this thread.
    private func scanBatch(_ batch: [(URL, Int64)], depth: Int, container: URL?, extractionRoot: URL?, innerBase: String?) {
        guard !batch.isEmpty else { return }
        var verdicts = [Detection?](repeating: nil, count: batch.count)
        verdicts.withUnsafeMutableBufferPointer { out in
            let out = out
            DispatchQueue.concurrentPerform(iterations: batch.count) { i in
                if isCancelled { return }
                // Free each file's temporary buffers straight away (a full scan visits
                // hundreds of thousands of files).
                autoreleasepool {
                    let (url, size) = batch[i]
                    let inner = innerPath(of: url, extractionRoot: extractionRoot, innerBase: innerBase)
                    out[i] = inspect(url, size: size, outer: container ?? url, inner: inner, container: container)
                }
            }
        }
        for (i, item) in batch.enumerated() {
            if isCancelled { return }
            autoreleasepool {
                scanFile(item.0, size: item.1, depth: depth, container: container,
                         extractionRoot: extractionRoot, innerBase: innerBase, verdict: .some(verdicts[i]))
            }
        }
    }

    private func innerPath(of url: URL, extractionRoot: URL?, innerBase: String?) -> String? {
        guard let extractionRoot else { return innerBase }
        var relative = url.path
        // The temp folder is under /var, which is a link to /private/var, so a file's path
        // may use either spelling.
        let prefixes = [extractionRoot.path, extractionRoot.resolvingSymlinksInPath().path,
                        "/private" + extractionRoot.path]
        if let prefix = prefixes.first(where: { relative.hasPrefix($0 + "/") || relative == $0 }) {
            relative = String(relative.dropFirst(prefix.count))
            while relative.hasPrefix("/") { relative.removeFirst() }
        }
        if let innerBase { return relative.isEmpty ? innerBase : "\(innerBase) ▸ \(relative)" }
        return relative.isEmpty ? nil : relative
    }

    /// The EICAR, hash-list and pattern checks for one file. Safe to call from several threads.
    private func inspect(_ url: URL, size: Int64, outer: URL, inner: String?, container: URL?) -> Detection? {
        guard size > 0 else { return nil }
        let kind = PatternRules.kind(of: url, size: size)
        if options.riskyOnly, kind == nil, !ScanEngine.riskyExtensions.contains(url.pathExtension.lowercased()) {
            return nil
        }
        if container == nil, kind != nil, options.useXProtect {
            candidateLock.lock(); xprotectCandidates.append(url.path); candidateLock.unlock()
        }
        // EICAR test string (also catches EICAR with trailing whitespace).
        if size <= 256, let data = try? Data(contentsOf: url), Eicar.matches(data) {
            return Detection(fileURL: outer, innerPath: inner, threatName: "EICAR-Test-File",
                             engine: "Agamemnon", level: .test, sha256: nil)
        }
        if size <= options.maxHashBytes, let hit = KnownMalware.lookup(url) {
            return Detection(fileURL: outer, innerPath: inner, threatName: hit.name,
                             engine: hit.name.contains("VirusShare") ? "VirusShare" : "Agamemnon",
                             level: hit.level, sha256: hit.sha256)
        }
        if options.patternRules {
            return PatternRules.assess(url, size: size, outer: outer, inner: inner, container: container)
        }
        return nil
    }

    /// `verdict` is the result of `inspect` when it already ran (in a batch); nil runs it here.
    private func scanFile(_ url: URL, size: Int64, depth: Int, container: URL?, extractionRoot: URL?, innerBase: String?,
                          verdict: Detection?? = nil) {
        files += 1
        let shown = container.map { "\($0.lastPathComponent) ▸ \(url.lastPathComponent)" } ?? url.path
        log(.file, shown)
        report(force: false, path: shown)
        guard size > 0 else { return }

        let outer = container ?? url
        let inner = innerPath(of: url, extractionRoot: extractionRoot, innerBase: innerBase)

        if let hit = verdict ?? inspect(url, size: size, outer: outer, inner: inner, container: container) {
            add(hit)
            return
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
        log(.archive, "Opening \(inner ?? url.path)")
        report(force: true, path: url.path)
        let nestedBase = container == nil ? nil : inner
        let outcome = archives.open(url, kind: kind) { contents in
            walk(contents, depth: depth + 1, container: outer, extractionRoot: contents, innerBase: nestedBase)
            // Apple's rules over what was inside, before the scratch copy is cleaned up.
            if options.useXProtect, XProtectRules.shared.isReady, !isCancelled,
               !detections.contains(where: { $0.fileURL == outer }) {
                for hit in XProtectRules.shared.scan(folder: contents.path, register: registerExternal) {
                    let inside = innerPath(of: URL(fileURLWithPath: hit.path), extractionRoot: contents, innerBase: nestedBase)
                    add(Detection(fileURL: outer, innerPath: inside, threatName: hit.name, engine: "XProtect", level: hit.level))
                    break
                }
            }
        }
        phase = previousPhase
        if case .skipped(let reason) = outcome {
            skipped.append("\(inner ?? url.path): \(reason)")
            log(.skipped, "Couldn't open \(inner ?? url.path): \(reason)")
        }
    }

    /// Gatekeeper check for .app bundles and installer packages.
    private func checkBundle(_ url: URL, container: URL?, extractionRoot: URL?, innerBase: String?) {
        guard ["app", "pkg", "mpkg"].contains(url.pathExtension.lowercased()) else { return }
        // Agamemnon's own (ad-hoc signed) builds aren't notarized; don't warn about ourselves.
        if CodeIdentity.isGenuineAgamemnon(url, download: container) { return }
        guard let verdict = Gatekeeper.assess(url), !verdict.accepted else { return }
        let outer = container ?? url
        let inner = innerPath(of: url, extractionRoot: extractionRoot, innerBase: innerBase)
        if detections.contains(where: { $0.fileURL == outer && $0.innerPath == inner }) { return }
        let level: ThreatLevel = verdict.reason.contains("revoked") ? .malicious : .suspicious
        add(Detection(fileURL: outer, innerPath: inner, threatName: verdict.reason,
                      engine: "Gatekeeper", level: level))
    }

    /// Apps on disk (not inside another app): flags ones Apple has revoked, and ones whose
    /// signature no longer matches their contents (changed after signing, as cracked apps are).
    private func checkAppSignature(_ url: URL) {
        guard url.pathExtension.lowercased() == "app",
              !url.deletingLastPathComponent().path.contains(".app/"),
              !BehaviorRules.isSystemPath(url.path + "/"),
              // Xcode, simulators and package managers: big, Apple- or tool-built, and slow to verify.
              !BehaviorRules.isPackageManaged(url.path + "/"),
              !CodeIdentity.isGenuineAgamemnon(url, download: nil) else { return }
        let identity = CodeIdentity.of(url.path)
        switch identity.signer {
        case .apple, .adHoc:
            return
        case .developer:
            // Gatekeeper knows about revoked certificates and notarization tickets.
            guard let verdict = Gatekeeper.assess(url), verdict.reason.contains("revoked") else { return }
            add(Detection(fileURL: url, innerPath: nil, threatName: verdict.reason, engine: "Gatekeeper", level: .malicious))
        case .unsigned:
            // Only a real "contents don't match the seal" error counts; reading errors, privacy
            // blocks and never-signed apps don't. Then Apple's own codesign tool has to agree,
            // so a quirk of the Security framework can never flag a normal app.
            let seal = url.appendingPathComponent("Contents/_CodeSignature/CodeResources").path
            guard FileManager.default.fileExists(atPath: seal), identity.looksTampered,
                  ScanEngine.codesignConfirmsTampering(url) else { return }
            add(Detection(fileURL: url, innerPath: nil, threatName: "App was changed after it was signed",
                          engine: "Agamemnon", level: .suspicious))
        }
    }

    /// Asks `codesign` (the tool macOS itself trusts) whether the app's seal is broken.
    static func codesignConfirmsTampering(_ url: URL) -> Bool {
        let r = Shell.run("/usr/bin/codesign", ["--verify", "--deep", "--strict", url.path], timeout: 120)
        if r.timedOut { return false }
        guard r.status != 0 else { return false }
        let text = r.stderr.lowercased()
        return text.contains("a sealed resource is missing or invalid")
            || text.contains("file added") || text.contains("file modified") || text.contains("file missing")
            || text.contains("invalid signature (code or signature have been modified)")
            || text.contains("main executable failed strict validation")
    }

    private func add(_ detection: Detection) {
        detections.append(detection)
        log(.threat, "\(detection.threatName) · \(detection.engine) · \(detection.displayPath)")
        report(force: true, path: detection.displayPath)
    }

    private func log(_ kind: ScanLogEntry.Kind, _ text: String) {
        if pendingLog.count >= ScanEngine.maxPendingLog { pendingLog.removeFirst(pendingLog.count / 2) }
        pendingLog.append(ScanLogEntry(kind: kind, text: text))
    }

    private func report(force: Bool, path: String) {
        let now = Date()
        guard force || now.timeIntervalSince(lastReport) > 0.08 else { return }
        lastReport = now
        progress(ScanSnapshot(phase: phase, filesScanned: files, archivesOpened: archivesOpened,
                              currentPath: path, detections: detections, newLog: pendingLog))
        pendingLog.removeAll(keepingCapacity: true)
    }
}
