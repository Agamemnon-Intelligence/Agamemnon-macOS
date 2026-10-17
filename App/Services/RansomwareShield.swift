import Foundation
import Combine
import Darwin

/// Ransomware shield for the folders that matter most (Documents, Desktop, Pictures, plus any
/// the user adds).
///
/// Without Apple's Endpoint Security entitlement Agamemnon can't block a write before it
/// happens, so the shield recognises an encryption burst as it starts:
/// 1. lots of files in protected folders change within a few seconds, and
/// 2. sampled files no longer match their type (a .jpg that isn't a JPEG any more, a .txt full
///    of random bytes), files get a new unknown extension (photo.jpg.locked), or ransom notes
///    appear.
/// It then finds the program doing the writing (disk-write counters and open files), stops it
/// and quarantines it if nobody has signed it. Signed programs are only reported.
@MainActor
final class RansomwareShield: ObservableObject {
    struct Incident: Identifiable, Hashable {
        let id = UUID()
        let date = Date()
        let summary: String
        let culprit: String?
        var outcome: String
    }

    @Published private(set) var isRunning = false
    @Published private(set) var incidents: [Incident] = []
    @Published private(set) var folders: [URL] = []

    private let vault: QuarantineVault
    private var watcher: FolderWatcher?
    private var timer: Timer?
    /// Recently changed files (path → time).
    private var recent: [String: Date] = [:]
    private var lastIncident = Date.distantPast
    private var analysing = false
    private let queue = DispatchQueue(label: "agamemnon.ransomware", qos: .userInitiated)

    init(vault: QuarantineVault) {
        self.vault = vault
        loadFolders()
    }

    nonisolated static var defaultFolders: [URL] {
        ["Documents", "Desktop", "Pictures"].map { AppPaths.home.appendingPathComponent($0, isDirectory: true) }
    }

    private func loadFolders() {
        let extra = (UserDefaults.standard.stringArray(forKey: Prefs.ransomwareFolders) ?? []).map { URL(fileURLWithPath: $0) }
        folders = RansomwareShield.defaultFolders + extra.filter { url in !RansomwareShield.defaultFolders.contains(url) }
    }

    func addFolder(_ url: URL) {
        var extra = UserDefaults.standard.stringArray(forKey: Prefs.ransomwareFolders) ?? []
        guard !extra.contains(url.path), !RansomwareShield.defaultFolders.contains(url) else { return }
        extra.append(url.path)
        UserDefaults.standard.set(extra, forKey: Prefs.ransomwareFolders)
        loadFolders()
        restart()
    }

    func removeFolder(_ url: URL) {
        var extra = UserDefaults.standard.stringArray(forKey: Prefs.ransomwareFolders) ?? []
        extra.removeAll { $0 == url.path }
        UserDefaults.standard.set(extra, forKey: Prefs.ransomwareFolders)
        loadFolders()
        restart()
    }

    func applyPreference() {
        if Prefs.bool(Prefs.ransomwareShield) { start() } else { stop() }
    }

    func start() {
        guard !isRunning else { return }
        let paths = folders.map(\.path).filter { FileManager.default.fileExists(atPath: $0) }
        let watcher = FolderWatcher(paths: paths, latency: 0.5) { [weak self] changed in
            Task { @MainActor in self?.record(changed) }
        }
        guard watcher.start() else { return }
        self.watcher = watcher
        isRunning = true
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.evaluate() }
        }
    }

    func stop() {
        watcher?.stop()
        watcher = nil
        timer?.invalidate()
        timer = nil
        recent.removeAll()
        isRunning = false
    }

    private func restart() {
        guard isRunning else { return }
        stop()
        start()
    }

    func clearIncidents() { incidents.removeAll() }

    // MARK: - Watching

    /// How many changed files within `window` seconds count as a burst.
    nonisolated static let burstFiles = 25
    nonisolated static let window: TimeInterval = 15

    private func record(_ paths: [String]) {
        let now = Date()
        for path in paths {
            let name = (path as NSString).lastPathComponent
            if name.hasPrefix(".") || name.hasPrefix("~$") { continue }
            recent[path] = now
        }
    }

    private func evaluate() {
        let cutoff = Date().addingTimeInterval(-RansomwareShield.window)
        recent = recent.filter { $0.value >= cutoff }
        guard !analysing, recent.count >= RansomwareShield.burstFiles,
              Date().timeIntervalSince(lastIncident) > 120 else { return }
        analysing = true
        let paths = Array(recent.keys)
        let roots = folders.map(\.path)
        queue.async { [weak self] in
            let verdict = RansomwareShield.analyse(paths)
            let culprits = verdict == nil ? [] : RansomwareShield.findWriters(in: roots)
            Task { @MainActor in self?.conclude(verdict, culprits: culprits) }
        }
    }

    private func conclude(_ verdict: String?, culprits: [RunningProcess]) {
        analysing = false
        guard let verdict else { return }
        lastIncident = Date()
        recent.removeAll()

        var outcome = "Reported"
        var culpritPath: String?
        let autoStop = Prefs.bool(Prefs.behaviorAutoStop)
        var stopped: [String] = []
        for p in culprits {
            culpritPath = culpritPath ?? p.path
            guard autoStop, CodeIdentity.of(p.path).isUnvouched, BehaviorMonitor.mayStop(p) else { continue }
            kill(p.pid, SIGKILL)
            stopped.append(p.name)
            let target = BehaviorMonitor.quarantineTarget(for: p.path)
            if BehaviorMonitor.mayQuarantine(p.path), !vault.contains(path: target) {
                let detection = Detection(fileURL: URL(fileURLWithPath: target), innerPath: nil,
                                          threatName: "Ransomware behaviour", engine: "Ransomware shield", level: .malicious)
                _ = try? vault.quarantine(detection)
            }
        }
        if !stopped.isEmpty {
            outcome = "Stopped and quarantined " + stopped.joined(separator: ", ")
        } else if let culpritPath {
            outcome = "Likely cause: \((culpritPath as NSString).lastPathComponent). It's signed, so Agamemnon didn't stop it"
        } else {
            outcome = "Couldn't tell which program did it"
        }

        incidents.insert(Incident(summary: verdict, culprit: culpritPath, outcome: outcome), at: 0)
        if incidents.count > 20 { incidents.removeLast(incidents.count - 20) }
        Notifier.post("Possible ransomware attack", "\(verdict). \(outcome). If you have a Time Machine backup, don't delete it.", critical: true)
        ActivityLog.shared.add(.threat, "Ransomware shield: \(verdict)", outcome)
    }

    // MARK: - Analysis (off the main actor)

    nonisolated static let ransomNotes = ["readme_decrypt", "how_to_decrypt", "how_to_recover", "decrypt_instructions",
                                          "restore_files", "recover_files", "how_to_restore", "_readme.txt", "read_me_now",
                                          "your_files_are_encrypted", "files_encrypted", "decrypt-files", "!!!"]

    /// File types whose first bytes we can check.
    nonisolated static func signatureMatches(_ ext: String, _ head: [UInt8]) -> Bool? {
        func starts(_ bytes: [UInt8]) -> Bool { head.count >= bytes.count && Array(head.prefix(bytes.count)) == bytes }
        func ftyp() -> Bool { head.count >= 8 && Array(head[4..<8]) == Array("ftyp".utf8) }
        switch ext {
        case "jpg", "jpeg": return starts([0xFF, 0xD8, 0xFF])
        case "png": return starts([0x89, 0x50, 0x4E, 0x47])
        case "gif": return starts(Array("GIF8".utf8))
        case "pdf": return starts(Array("%PDF".utf8))
        case "zip", "docx", "xlsx", "pptx", "odt", "ods", "epub": return starts([0x50, 0x4B])
        case "doc", "xls", "ppt": return starts([0xD0, 0xCF, 0x11, 0xE0])
        case "heic", "heif", "mp4", "m4a", "mov", "m4v": return ftyp() || starts([0, 0, 0])
        case "mp3": return starts(Array("ID3".utf8)) || starts([0xFF, 0xFB]) || starts([0xFF, 0xF3])
        case "rtf": return starts(Array("{\\rtf".utf8))
        case "txt", "md", "csv", "json", "html", "xml", "swift", "py", "js":
            // Text must be valid UTF-8 (encrypted data almost never is) with few control characters.
            let sample = Array(head.prefix(512))
            guard !sample.isEmpty else { return true }
            // The sample may end in the middle of a multi-byte character.
            let valid = (0...3).contains { cut in String(bytes: sample.dropLast(cut), encoding: .utf8) != nil }
            let control = sample.filter { $0 < 32 && $0 != 9 && $0 != 10 && $0 != 13 }.count
            return valid && Double(control) / Double(sample.count) < 0.05
        default: return nil
        }
    }

    nonisolated static let knownExtensions: Set<String> = ["jpg", "jpeg", "png", "gif", "pdf", "zip", "docx", "xlsx", "pptx",
        "doc", "xls", "ppt", "heic", "heif", "mp4", "m4a", "mov", "m4v", "mp3", "rtf", "txt", "md", "csv", "json", "pages",
        "numbers", "key", "psd", "raw", "cr2", "nef", "dng", "tiff", "tif", "odt", "ods", "epub", "html", "xml", "wav"]

    /// Returns a description if the burst looks like encryption, nil otherwise.
    nonisolated static func analyse(_ paths: [String]) -> String? {
        let fm = FileManager.default
        var checked = 0, broken = 0
        var newExtensions: [String: Int] = [:]
        var notes = 0

        for path in paths {
            let name = (path as NSString).lastPathComponent.lowercased()
            if ransomNotes.contains(where: { name.contains($0) }) && fm.fileExists(atPath: path) { notes += 1 }

            // photo.jpg.locked: a known extension followed by an unknown one.
            let parts = name.split(separator: ".")
            if parts.count >= 3, knownExtensions.contains(String(parts[parts.count - 2])),
               !knownExtensions.contains(String(parts.last!)), fm.fileExists(atPath: path) {
                newExtensions[String(parts.last!), default: 0] += 1
            }

            guard checked < 40, let ext = parts.count >= 2 ? String(parts.last!) : nil,
                  let handle = FileHandle(forReadingAtPath: path) else { continue }
            let head = [UInt8]((try? handle.read(upToCount: 512)) ?? Data())
            try? handle.close()
            guard !head.isEmpty, let ok = signatureMatches(ext, head) else { continue }
            checked += 1
            if !ok { broken += 1 }
        }

        if let (ext, count) = newExtensions.max(by: { $0.value < $1.value }), count >= 10 {
            return "\(count) files were renamed to .\(ext)"
        }
        if checked >= 8, Double(broken) / Double(checked) >= 0.6 {
            return "\(broken) of \(checked) recently changed files no longer open as what they claim to be"
        }
        if notes >= 2, broken >= 3 {
            return "Ransom notes appeared while files were being scrambled"
        }
        return nil
    }

    /// User programs that are writing to disk heavily or have files open in the protected folders.
    nonisolated static func findWriters(in roots: [String]) -> [RunningProcess] {
        let me = getpid(), uid = getuid()
        var first: [pid_t: UInt64?] = [:]
        let candidates = ProcessList.allPIDs().compactMap { ProcessList.info($0) }.filter {
            $0.uid == uid && $0.pid != me && !BehaviorRules.isSystemPath($0.path)
                && !$0.path.hasPrefix(Bundle.main.bundlePath)
        }
        for p in candidates { first[p.pid] = bytesWritten(p.pid) }
        Thread.sleep(forTimeInterval: 1.5)
        var scored: [(RunningProcess, UInt64)] = []
        for p in candidates {
            guard let before = first[p.pid] ?? nil, let after = bytesWritten(p.pid) else { continue }
            let delta = after >= before ? after - before : 0
            let touches = hasOpenFile(p.pid, under: roots)
            // Even slow ransomware writes tens of kilobytes a second; idle programs write next to nothing.
            if delta > 32 * 1024 || touches {
                scored.append((p, touches ? delta + (1 << 40) : delta))
            }
        }
        // Signed-by-Apple programs (Finder, Photos, cloud sync) aren't culprits we'd act on.
        return scored.sorted { $0.1 > $1.1 }.map(\.0)
            .filter { CodeIdentity.of(BehaviorMonitor.quarantineTarget(for: $0.path)).signer != .apple }
            .prefix(3).map { $0 }
    }

    /// Bytes the program has asked to write so far (counted per write, before the disk cache
    /// flushes them, so it reacts straight away).
    nonisolated static func bytesWritten(_ pid: pid_t) -> UInt64? {
        var info = rusage_info_v4()
        let ok = withUnsafeMutablePointer(to: &info) { ptr in
            ptr.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
        }
        return ok == 0 ? info.ri_logical_writes : nil
    }

    nonisolated static func hasOpenFile(_ pid: pid_t, under roots: [String]) -> Bool {
        let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard size > 0 else { return false }
        let count = Int(size) / MemoryLayout<proc_fdinfo>.stride
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: count)
        let filled = fds.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, size) }
        guard filled > 0 else { return false }
        for fd in fds.prefix(Int(filled) / MemoryLayout<proc_fdinfo>.stride) where fd.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
            var vnode = vnode_fdinfowithpath()
            let r = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &vnode, Int32(MemoryLayout<vnode_fdinfowithpath>.size))
            guard r > 0 else { continue }
            let path = withUnsafeBytes(of: vnode.pvip.vip_path) { raw in
                String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
            }
            if roots.contains(where: { path.hasPrefix($0 + "/") }) { return true }
        }
        return false
    }
}
