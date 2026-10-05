import Foundation

/// Opens archives, installers and disk images so their contents can be scanned
/// before the user opens them. Uses only tools that ship with macOS:
///  - bsdtar (libarchive): ZIP, RAR, 7Z, TAR(.gz/.bz2/.xz), ISO, XAR, CAB, CPIO, JAR, IPA…
///  - hdiutil: DMG (mounted read-only, hidden from Finder)
///  - pkgutil: PKG / MPKG (fully expanded, including payloads)
final class ArchiveInspector {
    enum Kind: Equatable {
        case libarchive
        case diskImage
        case installer
    }

    enum Outcome: Equatable {
        case opened
        case skipped(String)
    }

    /// Nested archives are followed this deep (archive inside archive inside archive).
    static let maxDepth = 3
    /// Refuse to unpack more than this (zip-bomb protection).
    static let maxExpandedBytes: Int64 = 4 * 1024 * 1024 * 1024
    static let maxEntries = 100_000
    /// Disk images and installers bigger than this are skipped.
    static let maxContainerBytes: Int64 = 8 * 1024 * 1024 * 1024

    private static let libarchiveExtensions: Set<String> = [
        "zip", "jar", "war", "ear", "apk", "ipa", "xpi", "crx", "epub",
        "rar", "7z", "tar", "tgz", "tbz", "tbz2", "txz", "tlz",
        "iso", "xar", "cab", "cpio", "lha", "lzh", "ar", "deb", "rpm",
    ]
    private static let compoundSuffixes = [".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lz", ".tar.zst", ".tar.z"]

    static func kind(of url: URL) -> Kind? {
        let name = url.lastPathComponent.lowercased()
        let ext = url.pathExtension.lowercased()
        if ext == "dmg" || ext == "sparseimage" || ext == "cdr" { return .diskImage }
        if ext == "pkg" || ext == "mpkg" { return .installer }
        if libarchiveExtensions.contains(ext) { return .libarchive }
        if compoundSuffixes.contains(where: { name.hasSuffix($0) }) { return .libarchive }
        return sniff(url)
    }

    /// Recognises archives by their first bytes when the extension lies or is missing.
    private static func sniff(_ url: URL) -> Kind? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard let head = try? handle.read(upToCount: 8), head.count >= 4 else { return nil }
        let b = [UInt8](head)
        if b[0] == 0x50, b[1] == 0x4B, b[2] == 0x03, b[3] == 0x04 { return .libarchive }            // PK..
        if b[0] == 0x52, b[1] == 0x61, b[2] == 0x72, b[3] == 0x21 { return .libarchive }            // Rar!
        if b.count >= 6, b[0] == 0x37, b[1] == 0x7A, b[2] == 0xBC, b[3] == 0xAF, b[4] == 0x27, b[5] == 0x1C { return .libarchive } // 7z
        if b[0] == 0x78, b[1] == 0x61, b[2] == 0x72, b[3] == 0x21 { return .installer }             // xar! (flat pkg)
        return nil
    }

    /// Unpacks or mounts `url`, calls `body` with the folder holding its contents,
    /// then cleans up. `body` runs synchronously on the calling thread.
    func open(_ url: URL, kind: Kind, body: (URL) -> Void) -> Outcome {
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map { Int64($0) } ?? 0
        switch kind {
        case .libarchive:
            return openWithLibarchive(url, body: body)
        case .diskImage:
            if size > ArchiveInspector.maxContainerBytes { return .skipped("Disk image is too large to check") }
            return mountDiskImage(url, body: body)
        case .installer:
            if size > ArchiveInspector.maxContainerBytes { return .skipped("Installer is too large to check") }
            return expandInstaller(url, body: body)
        }
    }

    // MARK: - bsdtar

    private func openWithLibarchive(_ url: URL, body: (URL) -> Void) -> Outcome {
        // 1. List first so we know how big it would get.
        let listing = Shell.run("/usr/bin/bsdtar", ["-tvf", url.path], timeout: 180)
        if listing.timedOut { return .skipped("Took too long to read") }
        if listing.status != 0 && listing.stdout.isEmpty {
            let err = listing.stderr.lowercased()
            if err.contains("passphrase") || err.contains("encrypt") || err.contains("password") {
                return .skipped("Password-protected archive")
            }
            return .skipped("Couldn't open the archive")
        }
        var entries = 0
        var total: Int64 = 0
        for line in listing.stdout.split(separator: "\n", omittingEmptySubsequences: true) {
            entries += 1
            let fields = line.split(separator: " ", maxSplits: 8, omittingEmptySubsequences: true)
            if fields.count > 4, let size = Int64(fields[4]) { total += size }
        }
        if entries > ArchiveInspector.maxEntries { return .skipped("Too many files inside to check safely") }
        if total > ArchiveInspector.maxExpandedBytes { return .skipped("Would unpack to more than 4 GB (possible zip bomb)") }

        // 2. Extract into a private scratch folder. bsdtar refuses absolute paths and
        //    "../" entries by default, so nothing can escape the folder.
        let dest = AppPaths.newScratchDirectory("archive")
        defer { remove(dest) }
        let result = Shell.run("/usr/bin/bsdtar",
                               ["-xf", url.path, "-C", dest.path, "--no-same-owner", "--no-same-permissions"],
                               timeout: 900)
        if result.timedOut { return .skipped("Took too long to unpack") }
        makeReadable(dest)
        body(dest)
        if result.status != 0 {
            let err = result.stderr.lowercased()
            if err.contains("passphrase") || err.contains("encrypt") || err.contains("password") {
                return .skipped("Some files are password-protected")
            }
        }
        return .opened
    }

    // MARK: - hdiutil

    private func mountDiskImage(_ url: URL, body: (URL) -> Void) -> Outcome {
        // Never trigger a password prompt for encrypted images.
        let enc = Shell.run("/usr/bin/hdiutil", ["isencrypted", url.path], timeout: 30)
        if enc.stdout.contains("encrypted: YES") { return .skipped("Encrypted disk image") }

        let mountRoot = AppPaths.newScratchDirectory("dmg")
        defer { try? FileManager.default.removeItem(at: mountRoot) }
        let attach = Shell.run("/usr/bin/hdiutil",
                               ["attach", url.path, "-readonly", "-nobrowse", "-noautoopen", "-noverify",
                                "-mountrandom", mountRoot.path, "-plist"],
                               timeout: 180,
                               stdin: "Y\n")
        // Images with a licence agreement print it before the plist; skip to the XML.
        let xml = attach.stdout.range(of: "<?xml").map { String(attach.stdout[$0.lowerBound...]) } ?? attach.stdout
        guard attach.status == 0,
              let data = xml.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let entities = plist["system-entities"] as? [[String: Any]] else {
            return .skipped("Couldn't mount the disk image")
        }
        let mountPoints = entities.compactMap { $0["mount-point"] as? String }
        let devices = entities.compactMap { $0["dev-entry"] as? String }
        defer {
            // Detaching the whole-disk device unmounts every volume of the image.
            if let disk = devices.min(by: { $0.count < $1.count }) {
                let r = Shell.run("/usr/bin/hdiutil", ["detach", disk, "-quiet"], timeout: 60)
                if r.status != 0 { _ = Shell.run("/usr/bin/hdiutil", ["detach", disk, "-force", "-quiet"], timeout: 60) }
            }
        }
        if mountPoints.isEmpty { return .skipped("Disk image has no readable volume") }
        for mp in mountPoints { body(URL(fileURLWithPath: mp, isDirectory: true)) }
        return .opened
    }

    // MARK: - pkgutil

    private func expandInstaller(_ url: URL, body: (URL) -> Void) -> Outcome {
        let parent = AppPaths.newScratchDirectory("pkg")
        defer { remove(parent) }
        let dest = parent.appendingPathComponent("expanded", isDirectory: true)   // must not exist yet
        var r = Shell.run("/usr/sbin/pkgutil", ["--expand-full", url.path, dest.path], timeout: 900)
        if r.status != 0 {
            // Older or unusual packages: fall back to a plain expand (scripts + payload archives).
            try? FileManager.default.removeItem(at: dest)
            r = Shell.run("/usr/sbin/pkgutil", ["--expand", url.path, dest.path], timeout: 600)
        }
        if r.timedOut { return .skipped("Took too long to unpack the installer") }
        guard r.status == 0 else { return .skipped("Couldn't expand the installer") }
        makeReadable(dest)
        body(dest)
        return .opened
    }

    // MARK: - Helpers

    private func makeReadable(_ url: URL) {
        _ = Shell.run("/bin/chmod", ["-R", "u+rwX", url.path], timeout: 120)
    }

    private func remove(_ url: URL) {
        makeReadable(url)
        try? FileManager.default.removeItem(at: url)
    }
}
