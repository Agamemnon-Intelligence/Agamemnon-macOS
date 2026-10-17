import Foundation

/// Optional second engine. If ClamAV is installed (`brew install clamav`),
/// Agamemnon keeps its own signature folder up to date with freshclam and
/// runs clamscan after its built-in checks.
final class ClamAV {
    static let shared = ClamAV()

    /// Where Cisco's official macOS installer puts the tools.
    static let pkgBinDir = "/usr/local/clamav/bin"

    var clamscanPath: String? { Shell.which("clamscan") ?? ClamAV.tool("clamscan") }
    var freshclamPath: String? { Shell.which("freshclam") ?? ClamAV.tool("freshclam") }

    private static func tool(_ name: String) -> String? {
        let path = pkgBinDir + "/" + name
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }
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

    // MARK: - Installing

    enum InstallStep {
        /// Installed with Homebrew; nothing else to do.
        case done
        /// Cisco's signed installer is downloaded and verified; it needs an admin password.
        case needsPassword(pkg: URL)
        case failed(String)
    }

    /// Installs ClamAV without asking anything if Homebrew is there; otherwise downloads and
    /// verifies Cisco's official signed installer package.
    func prepareInstall() async -> InstallStep {
        if let brew = Shell.which("brew") {
            let r = Shell.run(brew, ["install", "clamav"], timeout: 1800,
                              environment: ["HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_INSTALL_CLEANUP": "1",
                                            "HOMEBREW_NO_ENV_HINTS": "1"])
            if isInstalled { return .done }
            return .failed("Homebrew couldn't install ClamAV: " + String((r.stderr + r.stdout).suffix(200)))
        }
        do {
            let pkg = try await ClamAV.downloadOfficialPackage()
            return .needsPassword(pkg: pkg)
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    struct InstallError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// Finds the newest macOS package on ClamAV's GitHub releases, downloads it and checks
    /// that it's signed by Cisco with an Apple Developer ID.
    static func downloadOfficialPackage() async throws -> URL {
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest")!)
        request.setValue("Agamemnon/1.0 (macOS antivirus)", forHTTPHeaderField: "User-Agent")
        let (data, _) = try await URLSession.shared.data(for: request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let assets = json["assets"] as? [[String: Any]],
              let asset = assets.first(where: { ($0["name"] as? String ?? "").hasSuffix(".macos.universal.pkg") }),
              let link = asset["browser_download_url"] as? String,
              link.hasPrefix("https://github.com/Cisco-Talos/clamav/releases/download/"),
              let url = URL(string: link) else {
            throw InstallError(message: "Couldn't find ClamAV's macOS installer.")
        }
        var download = URLRequest(url: url)
        download.timeoutInterval = 900
        let (tmp, _) = try await URLSession.shared.download(for: download)
        let dir = AppPaths.newScratchDirectory("clamav-install")
        let pkg = dir.appendingPathComponent(url.lastPathComponent)
        try FileManager.default.moveItem(at: tmp, to: pkg)

        let check = Shell.run("/usr/sbin/pkgutil", ["--check-signature", pkg.path], timeout: 60)
        let text = check.stdout.lowercased()
        // Cisco's Apple team ID, so a package signed by anyone else is refused.
        guard check.succeeded, text.contains("developer id installer: cisco (de8y96k9qp)"),
              text.contains("signed by a developer certificate issued by apple") else {
            try? FileManager.default.removeItem(at: dir)
            throw InstallError(message: "The ClamAV installer wasn't signed by Cisco, so it wasn't used.")
        }
        return pkg
    }

    /// Downloads / refreshes the ClamAV signatures into Agamemnon's folder.
    func updateDatabase() -> ShellResult {
        guard let freshclam = freshclamPath else {
            return ShellResult(status: -1, stdout: "", stderr: "ClamAV isn't installed yet.", timedOut: false)
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
