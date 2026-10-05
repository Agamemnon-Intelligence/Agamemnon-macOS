import Foundation

/// Optional second engine. If ClamAV is installed (`brew install clamav`),
/// Agamemnon keeps its own signature folder up to date with freshclam and
/// runs clamscan after its built-in checks.
final class ClamAV {
    static let shared = ClamAV()

    var clamscanPath: String? { Shell.which("clamscan") }
    var freshclamPath: String? { Shell.which("freshclam") }
    var isInstalled: Bool { clamscanPath != nil }

    /// Agamemnon's own database folder.
    var ownDatabaseDir: URL { AppPaths.clamav }

    /// Databases set up by Homebrew / MacPorts, used if ours is empty.
    private let systemDatabaseDirs = [
        "/opt/homebrew/var/lib/clamav",
        "/usr/local/var/lib/clamav",
        "/opt/local/share/clamav",
        "/var/lib/clamav",
    ]

    private static func hasSignatures(_ dir: String) -> Bool {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return false }
        return files.contains { $0.hasSuffix(".cvd") || $0.hasSuffix(".cld") }
    }

    /// The database folder clamscan should use, if any has signatures.
    var databaseDir: String? {
        if ClamAV.hasSignatures(ownDatabaseDir.path) { return ownDatabaseDir.path }
        return systemDatabaseDirs.first(where: ClamAV.hasSignatures)
    }

    var hasDatabase: Bool { databaseDir != nil }
    var isReady: Bool { isInstalled && hasDatabase }

    var version: String? {
        guard let path = clamscanPath else { return nil }
        let r = Shell.run(path, ["--version"], timeout: 15)
        let v = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return v.isEmpty ? nil : v
    }

    var databaseDate: Date? {
        guard let dir = databaseDir,
              let files = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return nil }
        return files
            .filter { $0.hasSuffix(".cvd") || $0.hasSuffix(".cld") }
            .compactMap { try? FileManager.default.attributesOfItem(atPath: dir + "/" + $0)[.modificationDate] as? Date }
            .max()
    }

    /// Downloads / refreshes the ClamAV signatures into Agamemnon's folder.
    func updateDatabase() -> ShellResult {
        guard let freshclam = freshclamPath else {
            return ShellResult(status: -1, stdout: "", stderr: "freshclam isn't installed. Run: brew install clamav", timedOut: false)
        }
        // freshclam insists on a config file; a one-line one is enough.
        let conf = ownDatabaseDir.appendingPathComponent("freshclam.conf")
        let text = "# Written by Agamemnon\nDatabaseMirror database.clamav.net\n"
        try? text.write(to: conf, atomically: true, encoding: .utf8)
        return Shell.run(freshclam,
                         ["--config-file=\(conf.path)", "--datadir=\(ownDatabaseDir.path)", "--stdout"],
                         timeout: 1200)
    }

    /// Runs clamscan over `paths`. Returns (file path, signature name) pairs.
    /// `register` receives the running process so the caller can cancel it.
    func scan(paths: [String],
              exclusions: [String],
              onFile: @escaping (String) -> Void,
              register: (LineProcess) -> Void) -> (hits: [(String, String)], error: String?) {
        guard let clamscan = clamscanPath, let db = databaseDir else { return ([], "ClamAV isn't ready") }
        var args = [
            "--recursive", "--infected", "--no-summary", "--stdout",
            "--database=\(db)",
            "--scan-archive=yes",
            "--max-filesize=500M", "--max-scansize=1000M",
            "--max-recursion=8", "--max-files=50000",
            "--follow-dir-symlinks=0", "--follow-file-symlinks=0",
        ]
        for ex in exclusions {
            args.append("--exclude-dir=^" + NSRegularExpression.escapedPattern(for: ex))
        }
        args.append(contentsOf: paths)

        let lock = NSLock()
        var hits: [(String, String)] = []
        let process = LineProcess(clamscan, args) { line in
            guard line.hasSuffix(" FOUND") else { return }
            let body = String(line.dropLast(" FOUND".count))
            guard let sep = body.range(of: ": ", options: .backwards) else { return }
            let path = String(body[..<sep.lowerBound])
            let name = String(body[sep.upperBound...])
            lock.lock(); hits.append((path, name)); lock.unlock()
            onFile(path)
        }
        do {
            try process.start()
        } catch {
            return ([], error.localizedDescription)
        }
        register(process)
        process.waitUntilExit()
        let status = process.process.terminationStatus
        lock.lock(); let result = hits; lock.unlock()
        // clamscan exits 0 (clean) or 1 (found something); 2 means an error.
        if status == 2 && result.isEmpty {
            let err = process.errorOutput.trimmingCharacters(in: .whitespacesAndNewlines)
            return (result, err.isEmpty ? "ClamAV reported an error" : String(err.suffix(300)))
        }
        return (result, nil)
    }
}
