import Foundation
import Combine
import AppKit

/// Keeps Agamemnon itself up to date. Once a day it asks GitHub for the newest release of
/// Agamemnon-Intelligence/Agamemnon-macOS (pre-releases and the nightly build are ignored).
/// When there's a newer version it offers it; "Update" then:
///
/// 1. downloads the release's DMG from github.com/Agamemnon-Intelligence/Agamemnon-macOS only;
/// 2. mounts it read-only and checks the app inside: bundle ID, a newer version, a valid
///    signature (`codesign --verify --deep --strict`), and, when this copy is signed by a
///    developer team, the same team (so a lookalike can't replace Agamemnon);
/// 3. moves the current app to the Trash (it can be put back), copies the new one in its
///    place and reopens it.
@MainActor
final class AgamemnonUpdater: ObservableObject {
    struct Release: Equatable {
        let version: String
        let notes: String
        let dmg: URL
        let page: URL
    }

    enum State: Equatable {
        case idle, checking, upToDate, available(Release), downloading, installing, failed(String)
    }

    @Published private(set) var state: State = .idle
    @Published private(set) var lastChecked: Date?

    nonisolated static let latestAPI = URL(string: "https://api.github.com/repos/Agamemnon-Intelligence/Agamemnon-macOS/releases/latest")!
    nonisolated static let downloadPrefix = "https://github.com/Agamemnon-Intelligence/Agamemnon-macOS/releases/download/"

    var currentVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0" }

    var available: Release? {
        if case .available(let release) = state { return release }
        return nil
    }

    private var timer: Timer?
    private var notified: String?

    func start() {
        lastChecked = UserDefaults.standard.object(forKey: "agamemnonUpdater.lastChecked") as? Date
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in self?.check(quietly: true) }
        timer = Timer.scheduledTimer(withTimeInterval: 6 * 3600, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.check(quietly: true) }
        }
    }

    func check(quietly: Bool = false) {
        if case .downloading = state { return }
        if case .installing = state { return }
        if quietly, let last = lastChecked, Date().timeIntervalSince(last) < 20 * 3600, available == nil { return }
        state = .checking
        Task {
            do {
                let release = try await AgamemnonUpdater.fetchLatest()
                let now = Date()
                self.lastChecked = now
                UserDefaults.standard.set(now, forKey: "agamemnonUpdater.lastChecked")
                if let release, SoftwareUpdater.compare(release.version, self.currentVersion) == .orderedDescending {
                    self.state = .available(release)
                    if self.notified != release.version {
                        self.notified = release.version
                        Notifier.post("Agamemnon \(release.version) is available",
                                      "You have \(self.currentVersion). Open Agamemnon to update; it takes a few seconds.")
                        ActivityLog.shared.add(.update, "Agamemnon \(release.version) is available", "Installed: \(self.currentVersion)")
                    }
                } else {
                    self.state = .upToDate
                }
            } catch {
                self.state = quietly ? .idle : .failed("Couldn't check for updates: \(error.localizedDescription)")
            }
        }
    }

    nonisolated static func fetchLatest() async throws -> Release? {
        var request = URLRequest(url: latestAPI)
        request.timeoutInterval = 30
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Agamemnon/3.1 (macOS antivirus; update check)", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              json["prerelease"] as? Bool != true, json["draft"] as? Bool != true,
              let tag = json["tag_name"] as? String,
              let assets = json["assets"] as? [[String: Any]],
              let link = assets.compactMap({ $0["browser_download_url"] as? String })
                  .first(where: { $0.hasPrefix(downloadPrefix) && $0.lowercased().hasSuffix(".dmg") }),
              let dmg = URL(string: link) else { return nil }
        let version = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        let page = URL(string: json["html_url"] as? String ?? "") ?? URL(string: "https://github.com/Agamemnon-Intelligence/Agamemnon-macOS/releases")!
        return Release(version: version, notes: String((json["body"] as? String ?? "").prefix(1200)), dmg: dmg, page: page)
    }

    // MARK: - Installing

    enum UpdateError: LocalizedError {
        case message(String)
        var errorDescription: String? { if case .message(let m) = self { return m }; return nil }
    }

    func install() {
        guard let release = available else { return }
        state = .downloading
        let current = Bundle.main.bundleURL
        let currentVersion = self.currentVersion
        Task {
            do {
                let staged = try await AgamemnonUpdater.downloadAndVerify(release, currentVersion: currentVersion)
                self.state = .installing
                try self.replace(current, with: staged)
            } catch {
                self.state = .failed(error.localizedDescription)
                ActivityLog.shared.add(.info, "Agamemnon update failed", error.localizedDescription)
            }
        }
    }

    nonisolated static func downloadAndVerify(_ release: Release, currentVersion: String) async throws -> URL {
        guard release.dmg.absoluteString.hasPrefix(downloadPrefix) else { throw UpdateError.message("The update didn't come from Agamemnon's release page.") }
        var request = URLRequest(url: release.dmg)
        request.timeoutInterval = 600
        let (tmp, response) = try await URLSession.shared.download(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UpdateError.message("The download failed.") }
        let dir = AppPaths.newScratchDirectory("agamemnon-update")
        let dmg = dir.appendingPathComponent("Agamemnon.dmg")
        try FileManager.default.moveItem(at: tmp, to: dmg)

        let mount = dir.appendingPathComponent("mount")
        try FileManager.default.createDirectory(at: mount, withIntermediateDirectories: true)
        let attach = Shell.run("/usr/bin/hdiutil", ["attach", dmg.path, "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount.path], timeout: 120)
        guard attach.succeeded else { throw UpdateError.message("Couldn't open the update: \(attach.stderr.prefix(160))") }
        defer { Shell.run("/usr/bin/hdiutil", ["detach", mount.path, "-force"], timeout: 60) }

        guard let app = (try? FileManager.default.contentsOfDirectory(at: mount, includingPropertiesForKeys: nil))?
            .first(where: { $0.pathExtension == "app" }) else { throw UpdateError.message("The update doesn't contain Agamemnon.app.") }
        let info = NSDictionary(contentsOf: app.appendingPathComponent("Contents/Info.plist")) as? [String: Any] ?? [:]
        guard info["CFBundleIdentifier"] as? String == CodeIdentity.ownBundleID else { throw UpdateError.message("The update isn't Agamemnon.") }
        let newVersion = info["CFBundleShortVersionString"] as? String ?? "0"
        guard SoftwareUpdater.compare(newVersion, currentVersion) == .orderedDescending else {
            throw UpdateError.message("The download is version \(newVersion), which isn't newer.")
        }
        let verify = Shell.run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path], timeout: 120)
        guard verify.status == 0 else { throw UpdateError.message("The update's signature is broken, so it wasn't installed.") }
        // A copy signed by a developer team only accepts updates from that same team.
        if let team = CodeIdentity.running.teamID {
            guard CodeIdentity.of(app.path).teamID == team else {
                throw UpdateError.message("The update is signed by someone else, so it wasn't installed.")
            }
        }
        let staged = dir.appendingPathComponent("Agamemnon.app")
        let copy = Shell.run("/usr/bin/ditto", [app.path, staged.path], timeout: 300)
        guard copy.succeeded else { throw UpdateError.message("Couldn't unpack the update.") }
        Shell.run("/usr/bin/xattr", ["-dr", "com.apple.quarantine", staged.path], timeout: 30)
        return staged
    }

    /// Swaps the app on disk and reopens it.
    private func replace(_ current: URL, with staged: URL) throws {
        let fm = FileManager.default
        let folder = current.deletingLastPathComponent()
        if fm.isWritableFile(atPath: folder.path) {
            var trashed: NSURL?
            try fm.trashItem(at: current, resultingItemURL: &trashed)
            do {
                try fm.copyItem(at: staged, to: current)
            } catch {
                // Put the old version back.
                if let trashed = trashed as URL? { try? fm.moveItem(at: trashed, to: current) }
                throw error
            }
        } else {
            let q = Shell.quote
            try Privileged.run("/bin/rm -rf \(q(current.path)) && /usr/bin/ditto \(q(staged.path)) \(q(current.path))",
                               prompt: "Agamemnon is installing its update.")
        }
        ActivityLog.shared.add(.update, "Agamemnon updated", "Reopening the new version")
        // Normal quit (so the protection helper doesn't treat it as an attack), then reopen.
        SelfProtection.markQuit()
        let relaunch = Process()
        relaunch.executableURL = URL(fileURLWithPath: "/bin/sh")
        relaunch.arguments = ["-c", "sleep 2; /usr/bin/open \"$0\"", current.path]
        try relaunch.run()
        NSApp.terminate(nil)
    }
}
