import Foundation

/// Where Agamemnon keeps its data:
/// ~/Library/Application Support/Agamemnon/{Signatures,Quarantine,ClamAV,Profiles}
enum AppPaths {
    static let support: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
        let url = base.appendingPathComponent("Agamemnon", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    static func directory(_ name: String) -> URL {
        let url = support.appendingPathComponent(name, isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    static var signatures: URL { directory("Signatures") }
    static var quarantine: URL {
        let url = directory("Quarantine")
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }
    static var clamav: URL { directory("ClamAV") }
    static var profiles: URL { directory("Profiles") }

    /// Scratch space for unpacking archives and mounting disk images.
    static let scratch: URL = {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Agamemnon", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }()

    static func newScratchDirectory(_ prefix: String) -> URL {
        let url = scratch.appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// Removes leftovers from a previous run (e.g. after a crash).
    static func cleanScratch() {
        guard let items = try? FileManager.default.contentsOfDirectory(at: scratch, includingPropertiesForKeys: nil) else { return }
        for item in items {
            _ = Shell.run("/bin/chmod", ["-R", "u+rwX", item.path], timeout: 30)
            try? FileManager.default.removeItem(at: item)
        }
    }

    static var home: URL { FileManager.default.homeDirectoryForCurrentUser }
}
