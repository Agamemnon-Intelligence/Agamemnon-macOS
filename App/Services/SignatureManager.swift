import Foundation
import Combine
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Keeps the known-malware SHA-256 list on disk and in memory. Every 6 hours it merges in a
/// keyless, hourly-updated list of fresh malware hashes (see `downloadKeyless`); with an
/// abuse.ch Auth-Key, MalwareBazaar's own 48-hour export (and a weekly full dump) too.
@MainActor
final class SignatureManager: ObservableObject {
    nonisolated static let fullURL = URL(string: "https://bazaar.abuse.ch/export/txt/sha256/full/")!
    nonisolated static let recentURL = URL(string: "https://bazaar.abuse.ch/export/txt/sha256/recent/")!

    @Published private(set) var count = 0
    @Published private(set) var lastUpdated: Date?
    @Published private(set) var isUpdating = false
    @Published private(set) var status = ""
    @Published private(set) var lastError: String?
    @Published private(set) var urlhausCount = 0
    @Published private(set) var urlhausUpdated: Date?
    @Published private(set) var virusShareCount = VirusShareStore.shared.count
    @Published private(set) var virusShareStatus = ""
    @Published private(set) var virusShareUpdating = false

    private let urlhausUpdatedKey = "urlhaus.lastUpdated"
    private var urlhausUpdating = false

    private let store = SignatureStore.shared
    private let lastUpdatedKey = "signatures.lastUpdated"
    private let lastFullKey = "signatures.lastFull"
    private var timer: Timer?

    init() {
        lastUpdated = UserDefaults.standard.object(forKey: lastUpdatedKey) as? Date
        urlhausUpdated = UserDefaults.standard.object(forKey: urlhausUpdatedKey) as? Date
    }

    var totalCount: Int { count + SignatureStore.builtIn.count + virusShareCount }

    func start() {
        Task {
            let store = self.store
            let loaded = await Task.detached(priority: .userInitiated) { store.loadFromDisk() }.value
            self.count = loaded
            if store.tamperedOnDisk {
                Notifier.post("Agamemnon's malware list was changed",
                              "Something other than Agamemnon edited its signature database. It's being downloaded again.", critical: true)
                ActivityLog.shared.add(.threat, "Signature database was changed outside Agamemnon", SignatureStore.databaseURL.path)
                UserDefaults.standard.removeObject(forKey: self.lastUpdatedKey)
                self.lastUpdated = nil
            }
            self.urlhausCount = await Task.detached(priority: .utility) { URLhausStore.shared.loadFromDisk() }.value
            self.autoUpdateIfNeeded()
        }
        timer = Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.autoUpdateIfNeeded() }
        }
    }

    private func autoUpdateIfNeeded() {
        updateURLhausIfNeeded()
        updateVirusShareIfNeeded()
        guard Prefs.bool(Prefs.autoUpdateSignatures) || count == 0 else { return }
        // The keyless list is refreshed hourly upstream; checking every 6 hours is plenty.
        if let last = lastUpdated, Date().timeIntervalSince(last) < 6 * 3600, count > 0 { return }
        update()
    }

    func update(forceFull: Bool = false) {
        guard !isUpdating else { return }
        isUpdating = true
        lastError = nil
        let lastFull = UserDefaults.standard.object(forKey: lastFullKey) as? Date
        let needFull = AbuseCH.hasKey && (forceFull || count == 0 || lastFull == nil || Date().timeIntervalSince(lastFull!) > 7 * 86400)
        status = needFull ? "Downloading the full malware list…" : "Downloading new malware hashes…"
        let store = self.store

        Task {
            do {
                let merged: [Hash256]
                // Keyless: an hourly list of fresh malware hashes (MalwareBazaar's last 120 days,
                // URLhaus payloads, AlienVault OTX). With an abuse.ch key, MalwareBazaar's own
                // feed is added on top. New hashes are merged into the list already on disk.
                var recent = (try? await SignatureManager.downloadKeyless()) ?? []
                var keyed: Error?
                let full: [Hash256]? = needFull ? (try? await SignatureManager.downloadFull()) : nil
                if AbuseCH.hasKey {
                    do { recent += try await SignatureManager.downloadRecent() } catch { keyed = error }
                }
                if recent.isEmpty && full == nil { throw keyed ?? UpdateError.http(0) }
                self.status = "Adding the newest hashes…"
                if let full {
                    merged = await Task.detached(priority: .utility) { SignatureStore.sortedUnique(full + recent) }.value
                } else {
                    let fresh = recent
                    merged = await Task.detached(priority: .utility) {
                        SignatureStore.sortedUnique(store.snapshot() + fresh)
                    }.value
                }
                if let keyed { self.lastError = "MalwareBazaar: \(keyed.localizedDescription) The keyless list was still updated." }
                // A 48-hour export alone is a few hundred hashes; only a full list replaces everything.
                guard merged.count > 1000 || (full == nil && merged.count >= self.count) else { throw UpdateError.suspiciousList }
                self.status = "Saving…"
                try await Task.detached(priority: .utility) {
                    try SignatureStore.write(merged, to: SignatureStore.databaseURL)
                    store.replace(with: merged)
                }.value
                let added = merged.count - self.count
                await Task.detached(priority: .utility) { SignatureStore.recordIntegrity() }.value
                self.count = merged.count
                let now = Date()
                self.lastUpdated = now
                UserDefaults.standard.set(now, forKey: self.lastUpdatedKey)
                if full != nil { UserDefaults.standard.set(now, forKey: self.lastFullKey) }
                self.status = ""
                if keyed == nil { self.lastError = nil }
                ActivityLog.shared.add(.update, "Malware signatures updated",
                                       added > 0 ? "\(added.formatted()) new · \(merged.count.formatted()) total" : "\(merged.count.formatted()) known threats")
            } catch {
                self.lastError = error.localizedDescription
                self.status = ""
            }
            self.isUpdating = false
        }
    }

    // MARK: - VirusShare (MD5 lists)

    private func updateVirusShareIfNeeded() {
        guard Prefs.bool(Prefs.virusShare), !virusShareUpdating else { return }
        let store = VirusShareStore.shared
        // Keep going until the first download is complete; after that, look for new lists weekly.
        if let last = store.state.lastChecked, Date().timeIntervalSince(last) < 7 * 86400, store.count > 0 { return }
        updateVirusShare()
    }

    func updateVirusShare() {
        guard !virusShareUpdating else { return }
        virusShareUpdating = true
        virusShareStatus = "Downloading VirusShare's malware lists…"
        let before = VirusShareStore.shared.count
        Task {
            do {
                let result = try await VirusShareStore.shared.update(progress: { done, next in
                    Task { @MainActor in
                        self.virusShareStatus = "Downloading VirusShare's malware lists… \(next) of about 500"
                        self.virusShareCount = VirusShareStore.shared.count
                    }
                }, shouldStop: { !Prefs.bool(Prefs.virusShare) })
                self.virusShareCount = result.total
                self.virusShareStatus = ""
                if result.total > before {
                    ActivityLog.shared.add(.update, "VirusShare hashes updated",
                                           "\((result.total - before).formatted()) new · \(result.total.formatted()) total")
                }
            } catch {
                self.virusShareStatus = "VirusShare download paused: \(error.localizedDescription) It will continue later."
            }
            self.virusShareCount = VirusShareStore.shared.count
            self.virusShareUpdating = false
        }
    }

    // MARK: - URLhaus (malware links)

    private func updateURLhausIfNeeded() {
        guard Prefs.bool(Prefs.urlhausProtection), !urlhausUpdating else { return }
        if let last = urlhausUpdated, Date().timeIntervalSince(last) < 6 * 3600, urlhausCount > 0 { return }
        updateURLhaus()
    }

    func updateURLhaus() {
        guard !urlhausUpdating else { return }
        urlhausUpdating = true
        Task {
            do {
                let lines = try await URLhausStore.download()
                let count = await Task.detached(priority: .utility) { () -> Int in
                    URLhausStore.shared.replace(with: lines)
                    return URLhausStore.shared.count
                }.value
                self.urlhausCount = count
                let now = Date()
                self.urlhausUpdated = now
                UserDefaults.standard.set(now, forKey: self.urlhausUpdatedKey)
                ActivityLog.shared.add(.update, "Malware link list updated", "\(count.formatted()) live malware links from URLhaus")
            } catch {
                ActivityLog.shared.add(.info, "Couldn't update the malware link list", error.localizedDescription)
            }
            self.urlhausUpdating = false
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

    /// Keyless hash list (github.com/romainmarcoux/malicious-hash, MIT): fresh malware SHA-256s
    /// gathered hourly from MalwareBazaar, URLhaus payloads and AlienVault OTX. Split into files
    /// of up to 131,072 hashes (-aa, -ab…); all of them are read.
    nonisolated static let keylessBase = "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-"

    nonisolated static func downloadKeyless() async throws -> [Hash256] {
        var all: [Hash256] = []
        for suffix in ["aa", "ab", "ac", "ad", "ae", "af"] {
            var request = URLRequest(url: URL(string: keylessBase + suffix + ".txt")!)
            request.timeoutInterval = 120
            request.setValue("Agamemnon/3.1 (macOS antivirus)", forHTTPHeaderField: "User-Agent")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { break }
            all += SignatureStore.parseHashList(data)
        }
        guard all.count > 500 else { throw UpdateError.suspiciousList }
        return all
    }

    /// Last 48 hours of new samples (the export abuse.ch documents).
    nonisolated static func downloadRecent() async throws -> [Hash256] {
        let data = try await AbuseCH.fetch(.malwareBazaar, "recent.csv")
        return SignatureStore.parseHashList(data)
    }

    /// The complete list. abuse.ch only shows the full-dump file names to signed-in users, so
    /// the known spellings are tried in turn; when none exists, the weekly refresh is skipped and
    /// the list keeps growing from the 48-hour exports instead (nothing already known is lost).
    nonisolated static let fullExportNames = ["full.zip", "full.csv.zip", "sha256_full.zip", "full_sha256.txt.zip", "full.txt.zip"]

    nonisolated static func downloadFull() async throws -> [Hash256] {
        for name in fullExportNames {
            do {
                let zip = try await AbuseCH.fetch(.malwareBazaar, name, timeout: 900)
                let list = try AbuseCH.unzipFirstList(zip)
                let hashes = SignatureStore.parseHashList(list)
                if hashes.count > 100_000 { return hashes }
            } catch AbuseCH.Failure.notFound {
                continue
            }
        }
        throw AbuseCH.Failure.notFound
    }
}
