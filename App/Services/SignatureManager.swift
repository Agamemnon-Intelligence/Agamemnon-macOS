import Foundation
import Combine
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Keeps the MalwareBazaar hash list (abuse.ch, CC0) on disk and in memory.
/// First update downloads the full list (~45 MB zip, 1M+ hashes); later
/// updates merge the last 48 hours. A fresh full download happens weekly.
@MainActor
final class SignatureManager: ObservableObject {
    nonisolated static let fullURL = URL(string: "https://bazaar.abuse.ch/export/txt/sha256/full/")!
    nonisolated static let recentURL = URL(string: "https://bazaar.abuse.ch/export/txt/sha256/recent/")!

    @Published private(set) var count = 0
    @Published private(set) var lastUpdated: Date?
    @Published private(set) var isUpdating = false
    @Published private(set) var status = ""
    @Published private(set) var lastError: String?

    private let store = SignatureStore.shared
    private let lastUpdatedKey = "signatures.lastUpdated"
    private let lastFullKey = "signatures.lastFull"
    private var timer: Timer?

    init() {
        lastUpdated = UserDefaults.standard.object(forKey: lastUpdatedKey) as? Date
    }

    var totalCount: Int { count + SignatureStore.builtIn.count }

    func start() {
        Task {
            let store = self.store
            let loaded = await Task.detached(priority: .userInitiated) { store.loadFromDisk() }.value
            self.count = loaded
            self.autoUpdateIfNeeded()
        }
        timer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.autoUpdateIfNeeded() }
        }
    }

    private func autoUpdateIfNeeded() {
        guard Prefs.bool(Prefs.autoUpdateSignatures) || count == 0 else { return }
        if let last = lastUpdated, Date().timeIntervalSince(last) < 12 * 3600, count > 0 { return }
        update()
    }

    func update(forceFull: Bool = false) {
        guard !isUpdating else { return }
        isUpdating = true
        lastError = nil
        let lastFull = UserDefaults.standard.object(forKey: lastFullKey) as? Date
        let needFull = forceFull || count == 0 || lastFull == nil || Date().timeIntervalSince(lastFull!) > 7 * 86400
        status = needFull ? "Downloading the full malware list…" : "Downloading new malware hashes…"
        let store = self.store

        Task {
            do {
                let merged: [Hash256]
                if needFull {
                    let full = try await SignatureManager.downloadFull()
                    self.status = "Adding the newest hashes…"
                    let recent = (try? await SignatureManager.downloadRecent()) ?? []
                    merged = await Task.detached(priority: .utility) { SignatureStore.sortedUnique(full + recent) }.value
                } else {
                    let recent = try await SignatureManager.downloadRecent()
                    merged = await Task.detached(priority: .utility) {
                        SignatureStore.sortedUnique(store.snapshot() + recent)
                    }.value
                }
                guard merged.count > 1000 else { throw UpdateError.suspiciousList }
                self.status = "Saving…"
                try await Task.detached(priority: .utility) {
                    try SignatureStore.write(merged, to: SignatureStore.databaseURL)
                    store.replace(with: merged)
                }.value
                let added = merged.count - self.count
                self.count = merged.count
                let now = Date()
                self.lastUpdated = now
                UserDefaults.standard.set(now, forKey: self.lastUpdatedKey)
                if needFull { UserDefaults.standard.set(now, forKey: self.lastFullKey) }
                self.status = ""
                ActivityLog.shared.add(.update, "Malware signatures updated",
                                       added > 0 ? "\(added.formatted()) new · \(merged.count.formatted()) total" : "\(merged.count.formatted()) known threats")
            } catch {
                self.lastError = error.localizedDescription
                self.status = ""
            }
            self.isUpdating = false
        }
    }

    enum UpdateError: LocalizedError {
        case http(Int)
        case unzip(String)
        case suspiciousList

        var errorDescription: String? {
            switch self {
            case .http(let code): return "The signature server answered with HTTP \(code). Try again later."
            case .unzip(let msg): return "Couldn't unpack the signature list: \(msg)"
            case .suspiciousList: return "The downloaded list looked incomplete, so it wasn't used."
            }
        }
    }

    nonisolated private static func check(_ response: URLResponse) throws {
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw UpdateError.http(http.statusCode)
        }
    }

    nonisolated static func downloadRecent() async throws -> [Hash256] {
        var request = URLRequest(url: recentURL)
        request.setValue("Agamemnon/1.0 (macOS antivirus)", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        try check(response)
        return SignatureStore.parseHashList(data)
    }

    nonisolated static func downloadFull() async throws -> [Hash256] {
        var request = URLRequest(url: fullURL)
        request.timeoutInterval = 600
        request.setValue("Agamemnon/1.0 (macOS antivirus)", forHTTPHeaderField: "User-Agent")
        let (tmp, response) = try await URLSession.shared.download(for: request)
        try check(response)
        let dir = AppPaths.newScratchDirectory("signatures")
        defer { try? FileManager.default.removeItem(at: dir) }
        let zip = dir.appendingPathComponent("full.zip")
        try FileManager.default.moveItem(at: tmp, to: zip)
        let unzip = Shell.run("/usr/bin/unzip", ["-o", "-q", zip.path, "-d", dir.path], timeout: 300)
        guard unzip.status == 0 else { throw UpdateError.unzip(unzip.stderr) }
        let files = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        guard let txt = files.first(where: { $0.pathExtension.lowercased() == "txt" }) else {
            throw UpdateError.unzip("no hash list inside")
        }
        let data = try Data(contentsOf: txt)
        return SignatureStore.parseHashList(data)
    }
}
