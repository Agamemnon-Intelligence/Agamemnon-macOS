import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// VirusShare's free MD5 lists (about 42 million hashes of malware samples, published as
/// numbered text files at virusshare.com/hashes).
///
/// The hashes are kept on disk in 256 sorted files, one per first byte of the hash
/// (`Signatures/VirusShare/00.bin` … `ff.bin`, 16 bytes per hash). A lookup memory-maps one
/// small file and binary-searches it, so the ~680 MB list never has to be loaded into memory.
///
/// Downloading happens in the background, list by list, and resumes where it stopped. New
/// lists are appended to per-bucket `.new` files and sorted into the `.bin` files every
/// `finalizeEvery` lists, so protection grows while the first download is still running.
final class VirusShareStore {
    static let shared = VirusShareStore()

    static var folder: URL {
        let url = AppPaths.signatures.appendingPathComponent("VirusShare", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static func listURL(_ index: Int) -> URL {
        URL(string: String(format: "https://virusshare.com/hashfiles/VirusShare_%05d.md5", index))!
    }

    struct State: Codable {
        /// The next list to download.
        var nextIndex = 0
        /// Hashes in the sorted `.bin` files.
        var count = 0
        var lastChecked: Date?
    }

    private let lock = NSLock()
    private var cache: [Int: Data] = [:]
    private(set) var state = State()

    init() {
        if let data = try? Data(contentsOf: VirusShareStore.stateURL),
           let saved = try? JSONDecoder().decode(State.self, from: data) {
            state = saved
        }
    }

    static var stateURL: URL { folder.appendingPathComponent("state.json") }

    var count: Int { lock.lock(); defer { lock.unlock() }; return state.count }

    private func saveState() {
        if let data = try? JSONEncoder().encode(state) { try? data.write(to: VirusShareStore.stateURL, options: .atomic) }
    }

    private static func bucketURL(_ b: Int, ext: String) -> URL {
        folder.appendingPathComponent(String(format: "%02x.%@", b, ext))
    }

    // MARK: - Lookup

    func contains(_ md5: MD5Hash) -> Bool {
        let bucket = Int(md5.firstByte)
        lock.lock()
        var data = cache[bucket]
        if data == nil {
            data = try? Data(contentsOf: VirusShareStore.bucketURL(bucket, ext: "bin"), options: .alwaysMapped)
            cache[bucket] = data ?? Data()
        }
        lock.unlock()
        guard let data, data.count >= 16 else { return false }
        return data.withUnsafeBytes { raw -> Bool in
            let n = raw.count / 16
            var lo = 0, hi = n - 1
            while lo <= hi {
                let mid = (lo + hi) / 2
                let rec = VirusShareStore.read(raw, mid)
                if rec == md5 { return true }
                if rec < md5 { lo = mid + 1 } else { hi = mid - 1 }
            }
            return false
        }
    }

    private static func read(_ raw: UnsafeRawBufferPointer, _ i: Int) -> MD5Hash {
        let h = UInt64(bigEndian: raw.loadUnaligned(fromByteOffset: i * 16, as: UInt64.self))
        let l = UInt64(bigEndian: raw.loadUnaligned(fromByteOffset: i * 16 + 8, as: UInt64.self))
        return MD5Hash(hi: h, lo: l)
    }

    // MARK: - Updating

    static let finalizeEvery = 50

    struct UpdateResult {
        let listsDownloaded: Int
        let total: Int
    }

    /// Downloads every list from `state.nextIndex` until VirusShare has no more (HTTP 404).
    /// `progress` gets (lists done this run, next index). Stops early if `shouldStop` returns true.
    func update(progress: @escaping (Int, Int) -> Void, shouldStop: @escaping () -> Bool) async throws -> UpdateResult {
        var downloaded = 0
        var pending = 0
        var index = state.nextIndex
        while !shouldStop() {
            var request = URLRequest(url: VirusShareStore.listURL(index))
            request.timeoutInterval = 120
            request.setValue("Agamemnon/1.0 (macOS antivirus)", forHTTPHeaderField: "User-Agent")
            let (data, response) = try await URLSession.shared.data(for: request)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if status == 404 { break }
            guard (200..<300).contains(status) else { throw SignatureManager.UpdateError.http(status) }
            let hashes = VirusShareStore.parse(data)
            // A real list has tens of thousands of hashes; an HTML page or error has none.
            guard hashes.count > 1000 else { break }
            try VirusShareStore.append(hashes)
            index += 1
            downloaded += 1
            pending += 1
            setNextIndex(index)
            if pending >= VirusShareStore.finalizeEvery {
                try finalize()
                pending = 0
            }
            saveState()
            progress(downloaded, index)
            try? await Task.sleep(nanoseconds: 150_000_000)   // be gentle with a free service
        }
        if pending > 0 { try finalize() }
        markChecked()
        saveState()
        return UpdateResult(listsDownloaded: downloaded, total: count)
    }

    private func setNextIndex(_ index: Int) {
        lock.lock(); state.nextIndex = index; lock.unlock()
    }

    private func markChecked() {
        lock.lock(); state.lastChecked = Date(); lock.unlock()
    }

    static func parse(_ data: Data) -> [MD5Hash] {
        var result: [MD5Hash] = []
        result.reserveCapacity(data.count / 33)
        data.withUnsafeBytes { raw in
            let p = raw.bindMemory(to: UInt8.self)
            var i = 0
            while i < p.count {
                var end = i
                while end < p.count && p[end] != 10 { end += 1 }
                if end - i >= 32, p[i] != 35, let h = MD5Hash(hexBytes: p, offset: i) { result.append(h) }
                i = end + 1
            }
        }
        return result
    }

    /// Appends new hashes, unsorted, to each bucket's `.new` file.
    static func append(_ hashes: [MD5Hash]) throws {
        var buckets = [[UInt8]](repeating: [], count: 256)
        for h in hashes {
            var be = (h.hi.bigEndian, h.lo.bigEndian)
            withUnsafeBytes(of: &be) { buckets[Int(h.firstByte)].append(contentsOf: $0) }
        }
        for (b, bytes) in buckets.enumerated() where !bytes.isEmpty {
            let url = bucketURL(b, ext: "new")
            if !FileManager.default.fileExists(atPath: url.path) {
                FileManager.default.createFile(atPath: url.path, contents: nil)
            }
            let handle = try FileHandle(forWritingTo: url)
            try handle.seekToEnd()
            try handle.write(contentsOf: Data(bytes))
            try handle.close()
        }
    }

    /// Sorts each bucket's new hashes into its `.bin` file (removing duplicates).
    func finalize() throws {
        var total = 0
        for b in 0..<256 {
            let bin = VirusShareStore.bucketURL(b, ext: "bin")
            let new = VirusShareStore.bucketURL(b, ext: "new")
            let old = (try? Data(contentsOf: bin)) ?? Data()
            guard let added = try? Data(contentsOf: new), !added.isEmpty else {
                total += old.count / 16
                continue
            }
            var all: [MD5Hash] = []
            all.reserveCapacity((old.count + added.count) / 16)
            for chunk in [old, added] {
                chunk.withUnsafeBytes { raw in
                    for i in 0..<(raw.count / 16) { all.append(VirusShareStore.read(raw, i)) }
                }
            }
            all.sort()
            var out = [UInt8]()
            out.reserveCapacity(all.count * 16)
            var previous: MD5Hash?
            for h in all where h != previous {
                var be = (h.hi.bigEndian, h.lo.bigEndian)
                withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
                previous = h
            }
            try Data(out).write(to: bin, options: .atomic)
            try? FileManager.default.removeItem(at: new)
            total += out.count / 16
        }
        lock.lock()
        cache.removeAll()
        state.count = total
        lock.unlock()
        saveState()
    }
}
