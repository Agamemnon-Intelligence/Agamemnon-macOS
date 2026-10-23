import Foundation
import Security

/// Who signed a program, read with the Security framework (no tools launched).
struct CodeIdentity: Hashable {
    enum Signer: Hashable {
        /// Part of macOS, or signed by Apple.
        case apple
        /// Signed with a Developer ID or App Store certificate (has a team ID).
        case developer(team: String)
        /// Ad-hoc signed: no certificate, so nobody vouches for it.
        case adHoc
        /// No signature at all, or the signature is broken.
        case unsigned
    }

    let signer: Signer
    let identifier: String?
    /// The code directory hash: identical builds have the same one.
    let cdhash: Data?
    /// Why the signature check failed (`errSecSuccess` when it passed).
    var validationStatus: OSStatus = errSecSuccess

    /// Signature errors that mean the signed contents were changed afterwards (as opposed
    /// to "never signed", "can't read the file" or "macOS wouldn't let us look").
    static let tamperStatuses: Set<OSStatus> = [
        errSecCSSignatureFailed,    // -67061: the code itself doesn't match its signature
        errSecCSBadResource,        // -67054: a sealed file was changed
        errSecCSResourcesInvalid,   // -67055
        errSecCSResourcesNotFound,  // -67056: a sealed file was deleted
        errSecCSResourcesNotSealed, // -67057: files added that the seal doesn't cover
        errSecCSBadMainExecutable,  // -67010
        errSecCSInfoPlistFailed,    // -67030: Info.plist changed
    ]

    /// The seal is there but the contents no longer match it.
    var looksTampered: Bool { signer == .unsigned && CodeIdentity.tamperStatuses.contains(validationStatus) }

    /// Unsigned or ad-hoc: nobody vouches for this program.
    var isUnvouched: Bool {
        switch signer {
        case .adHoc, .unsigned: return true
        case .apple, .developer: return false
        }
    }

    var teamID: String? {
        if case .developer(let team) = signer { return team }
        return nil
    }

    private static let cacheLock = NSLock()
    private static var cache: [String: (Date?, CodeIdentity)] = [:]

    /// Reads (and caches by path + modification date) the signature of a file or bundle.
    static func of(_ path: String) -> CodeIdentity {
        let modified = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        cacheLock.lock()
        if let hit = cache[path], hit.0 == modified { cacheLock.unlock(); return hit.1 }
        cacheLock.unlock()

        let identity = read(path)
        cacheLock.lock()
        if cache.count > 4000 { cache.removeAll() }
        cache[path] = (modified, identity)
        cacheLock.unlock()
        return identity
    }

    private static func read(_ path: String) -> CodeIdentity {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return CodeIdentity(signer: .unsigned, identifier: nil, cdhash: nil)
        }
        // A missing or tampered signature fails this check. Some universal apps ship one slice
        // with a broken signature that macOS never runs, so the native slice gets a second try.
        var status = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), nil)
        if status != errSecSuccess {
            status = SecStaticCodeCheckValidity(code, [], nil)
        }
        guard status == errSecSuccess else {
            return CodeIdentity(signer: .unsigned, identifier: nil, cdhash: nil, validationStatus: status)
        }
        var infoRef: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef)
        let info = infoRef as? [String: Any] ?? [:]
        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        let cdhash = info[kSecCodeInfoUnique as String] as? Data

        if satisfies(code, "anchor apple") {
            return CodeIdentity(signer: .apple, identifier: identifier, cdhash: cdhash)
        }
        if let team = info[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty,
           satisfies(code, "anchor apple generic") {
            return CodeIdentity(signer: .developer(team: team), identifier: identifier, cdhash: cdhash)
        }
        return CodeIdentity(signer: .adHoc, identifier: identifier, cdhash: cdhash)
    }

    private static func satisfies(_ code: SecStaticCode, _ requirementText: String) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    // MARK: - Agamemnon's own builds

    static let ownBundleID = "com.mirazbakis.Agamemnon"

    /// Where official Agamemnon downloads come from.
    static let officialSources = [
        "github.com/agamemnon-intelligence/agamemnon-macos/",
        "athenesoftworks.com/",
    ]

    /// The signature of the copy of Agamemnon that's running now.
    static let running: CodeIdentity = of(Bundle.main.bundlePath)

    /// True when `appURL` is a genuine Agamemnon build, so Gatekeeper's warning about it
    /// (ad-hoc builds aren't notarized) can be skipped. Malware can copy our bundle ID,
    /// so the ID alone isn't enough. One of these must also hold:
    /// - it's byte-for-byte the build that's running (same code directory hash),
    /// - it's signed by the same Developer ID team as the running build, or
    /// - the download it came in was fetched from Agamemnon's official release page.
    /// Hash and ClamAV checks still run on it either way.
    static func isGenuineAgamemnon(_ appURL: URL, download: URL?) -> Bool {
        guard appURL.pathExtension.lowercased() == "app",
              Bundle(url: appURL)?.bundleIdentifier == ownBundleID else { return false }
        let candidate = of(appURL.path)
        guard candidate.identifier == ownBundleID, candidate.signer != .unsigned else { return false }
        if let hash = candidate.cdhash, hash == running.cdhash { return true }
        if let team = candidate.teamID, team == running.teamID { return true }
        if let download, cameFromOfficialSource(download) { return true }
        if cameFromOfficialSource(appURL) { return true }
        return false
    }

    /// Agamemnon's own executable or helper (also as a build product of Agamemnon's source).
    /// The identifier alone proves nothing (ad-hoc signatures can claim any name), so it must also
    /// be byte-identical to the running copy or signed by the same team.
    static func isOwnProgram(_ path: String, identity: CodeIdentity) -> Bool {
        // Building Agamemnon from source: Xcode's intermediate copies are unsigned, so they're
        // recognised by name and by sitting in Xcode's build folders.
        let ownNames: Set<String> = ["Agamemnon", "AgamemnonHelper", "Agamemnon.debug.dylib"]
        if ownNames.contains((path as NSString).lastPathComponent),
           path.contains("/Build/Intermediates.noindex/") || path.contains("/Build/Products/") {
            return true
        }
        guard let id = identity.identifier, id == ownBundleID || id == ownBundleID + ".Helper"
            || id == "Agamemnon" || id == "AgamemnonHelper" || id == "Agamemnon.debug" else { return false }
        if let team = identity.teamID, team == running.teamID { return true }
        if let hash = identity.cdhash, hash == running.cdhash { return true }
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/AgamemnonHelper").path
        if let hash = identity.cdhash, hash == of(helper).cdhash { return true }
        return false
    }

    /// Checks the "Where from" record browsers attach to downloads.
    static func cameFromOfficialSource(_ url: URL) -> Bool {
        guard let item = MDItemCreate(nil, url.path as CFString),
              let sources = MDItemCopyAttribute(item, kMDItemWhereFroms) as? [String] else { return false }
        return sources.contains { source in
            let lower = source.lowercased()
                .replacingOccurrences(of: "https://", with: "")
                .replacingOccurrences(of: "http://", with: "")
                .replacingOccurrences(of: "www.", with: "")
            return officialSources.contains { lower.hasPrefix($0) }
        }
    }
}
