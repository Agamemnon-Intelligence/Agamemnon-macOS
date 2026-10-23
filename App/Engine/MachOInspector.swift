import Foundation

/// Static analysis of Mac programs (Mach-O), without running them. Looks at what a program
/// is built to do (the system functions it imports, the libraries it links, tell-tale strings
/// and how it's packed) and scores the combination.
///
/// Only used for programs nobody vouches for (unsigned or ad-hoc signed, outside macOS and
/// package managers), the same guardrail as the pattern rules. A single capability is never
/// enough: screenshots, keychain access and networking are all normal on their own. It's the
/// combination stealers and spyware need (grab something private + hide + send it off) that
/// scores high.
enum MachOInspector {
    struct Report {
        var capabilities: [Capability: Int] = [:]
        var linksDylibs: [String] = []
        var hasCodeSignature = false
        var isPacked = false
        var architectures: [String] = []

        var score: Int { capabilities.values.reduce(0, +) }
        func has(_ c: Capability) -> Bool { capabilities[c] != nil }
    }

    enum Capability: String, CaseIterable {
        case keylogging = "records keystrokes"
        case screenCapture = "takes screenshots"
        case microphoneCamera = "uses the microphone or camera"
        case keychain = "reads saved passwords"
        case browserData = "reads browser passwords and cookies"
        case wallets = "looks for crypto wallets"
        case passwordPrompt = "shows a fake password prompt"
        case persistence = "starts itself automatically"
        case antiAnalysis = "hides from security tools"
        case vmCheck = "checks for virtual machines"
        case shellExecution = "runs shell commands"
        case networking = "talks to the internet"
        case gatekeeperBypass = "removes macOS's download warning"
        case privacyTamper = "edits the privacy database"
        case privilegeEscalation = "asks for root in an old, abused way"
        case packed = "is packed to hide its code"
        case systemInfo = "collects system information"
    }

    /// (needle, capability, weight). Needles are case-sensitive: symbol names as they appear in
    /// a program's import table, or literal strings.
    private static let indicators: [(String, Capability, Int)] = [
        ("_CGEventTapCreate", .keylogging, 3),
        ("_IOHIDManagerRegisterInputValueCallback", .keylogging, 3),
        ("addGlobalMonitorForEventsMatchingMask:handler:", .keylogging, 2),
        ("_CGWindowListCreateImage", .screenCapture, 2),
        ("_CGDisplayCreateImage", .screenCapture, 2),
        ("_CGDisplayStreamCreate", .screenCapture, 2),
        ("SCScreenshotManager", .screenCapture, 2),
        ("/usr/sbin/screencapture", .screenCapture, 2),
        ("AVCaptureDevice", .microphoneCamera, 1),
        ("_SecKeychainFindGenericPassword", .keychain, 2),
        ("_SecKeychainItemCopyContent", .keychain, 2),
        ("_SecKeychainCopySearchList", .keychain, 2),
        ("find-generic-password", .keychain, 3),
        ("dump-keychain", .keychain, 4),
        ("login.keychain-db", .keychain, 3),
        ("Login Data", .browserData, 2),
        ("Cookies.binarycookies", .browserData, 3),
        ("logins.json", .browserData, 2),
        ("key4.db", .browserData, 2),
        ("Chrome Safe Storage", .browserData, 3),
        ("Local Extension Settings", .wallets, 3),
        ("nkbihfbeogaeaoehlefnkodbefgpgknn", .wallets, 3),   // MetaMask's extension ID
        ("Exodus/exodus.wallet", .wallets, 3),
        ("wallet.dat", .wallets, 2),
        ("hidden answer", .passwordPrompt, 4),
        ("with hidden answer", .passwordPrompt, 4),
        ("Library/LaunchAgents", .persistence, 2),
        ("RunAtLoad", .persistence, 1),
        ("_SMLoginItemSetEnabled", .persistence, 1),
        ("_LSSharedFileListInsertItemURL", .persistence, 2),
        ("_ptrace", .antiAnalysis, 1),
        ("P_TRACED", .antiAnalysis, 1),
        ("_csops", .antiAnalysis, 1),
        ("VMware", .vmCheck, 1),
        ("VirtualBox", .vmCheck, 1),
        ("QEMU", .vmCheck, 1),
        ("system_profiler SPHardwareDataType", .vmCheck, 2),
        ("/bin/sh", .shellExecution, 1),
        ("/bin/bash", .shellExecution, 1),
        ("/usr/bin/osascript", .shellExecution, 2),
        ("_popen", .shellExecution, 1),
        ("_system", .shellExecution, 1),
        ("NSURLSession", .networking, 1),
        ("_curl_easy_perform", .networking, 1),
        ("/usr/bin/curl", .networking, 2),
        ("_connect", .networking, 1),
        ("api.telegram.org", .networking, 3),
        ("discord.com/api/webhooks", .networking, 3),
        ("com.apple.quarantine", .gatekeeperBypass, 2),
        ("_removexattr", .gatekeeperBypass, 1),
        ("spctl --master-disable", .gatekeeperBypass, 3),
        ("TCC.db", .privacyTamper, 3),
        ("_AuthorizationExecuteWithPrivileges", .privilegeEscalation, 2),
        ("IOPlatformSerialNumber", .systemInfo, 1),
        ("IOPlatformUUID", .systemInfo, 1),
    ]

    /// Reads a program file and reports what it can do. nil for files that aren't Mach-O.
    static func inspect(_ data: Data) -> Report? {
        guard data.count >= 32 else { return nil }
        var report = Report()
        guard let slices = sliceOffsets(data), !slices.isEmpty else { return nil }
        for (offset, size) in slices {
            parseLoadCommands(data, offset: offset, size: size, into: &report)
        }
        for (needle, capability, weight) in indicators where data.range(of: Data(needle.utf8)) != nil {
            report.capabilities[capability] = max(report.capabilities[capability] ?? 0, 0) + weight
        }
        // Caps per capability, so twenty screenshot functions don't add up to "spyware".
        for (k, v) in report.capabilities { report.capabilities[k] = min(v, 4) }
        // UPX and similar packers.
        if data.range(of: Data("UPX!".utf8)) != nil || data.range(of: Data("upxTEXT".utf8)) != nil
            || data.range(of: Data("__XHDR".utf8)) != nil {
            report.isPacked = true
            report.capabilities[.packed] = 4
        }
        return report
    }

    /// A finding for programs whose combination of capabilities looks like malware, or nil.
    static func verdict(_ report: Report) -> (name: String, level: ThreatLevel, reason: String)? {
        let steals = report.has(.keychain) || report.has(.browserData) || report.has(.wallets) || report.has(.passwordPrompt)
        let spies = report.has(.keylogging) || report.has(.screenCapture)
        let sends = report.has(.networking)
        let hides = report.has(.antiAnalysis) || report.has(.vmCheck) || report.has(.packed) || report.has(.gatekeeperBypass)
        let score = report.score

        let reasons = report.capabilities.keys.sorted { $0.rawValue < $1.rawValue }.map(\.rawValue)
        let reason = "It " + ListFormatter.localizedString(byJoining: reasons) + "."

        // Stealer: grabs secrets in two or more ways (or with a fake password prompt) and sends them.
        let stealKinds = [report.has(.keychain), report.has(.browserData), report.has(.wallets), report.has(.passwordPrompt)].filter { $0 }.count
        if sends && (stealKinds >= 2 || (report.has(.passwordPrompt) && stealKinds >= 1)) && score >= 10 {
            return ("MacOS.Heuristic.Stealer", .malicious, reason)
        }
        if report.has(.privacyTamper) && (spies || steals) && sends {
            return ("MacOS.Heuristic.Spyware", .malicious, reason)
        }
        if spies && sends && (report.has(.persistence) || hides) && score >= 9 {
            return ("MacOS.Heuristic.Spyware", .suspicious, reason)
        }
        if steals && sends && hides && score >= 9 {
            return ("MacOS.Heuristic.Stealer", .suspicious, reason)
        }
        if report.isPacked && (steals || spies || report.has(.persistence)) {
            return ("MacOS.Heuristic.PackedTrojan", .suspicious, reason)
        }
        return nil
    }

    // MARK: - Mach-O parsing

    /// (offset, size) of each architecture slice.
    private static func sliceOffsets(_ data: Data) -> [(Int, Int)]? {
        let magic = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        switch magic {
        case 0xfeedfacf, 0xfeedface, 0xcffaedfe, 0xcefaedfe:
            return [(0, data.count)]
        case 0xbebafeca, 0xcafebabe:   // fat, stored big-endian
            let count = Int(readBE32(data, 4))
            guard count > 0, count < 30 else { return nil }
            var slices: [(Int, Int)] = []
            for i in 0..<count {
                let base = 8 + i * 20
                guard base + 20 <= data.count else { break }
                let offset = Int(readBE32(data, base + 8))
                let size = Int(readBE32(data, base + 12))
                if offset > 0, offset + size <= data.count { slices.append((offset, size)) }
            }
            return slices
        default:
            return nil
        }
    }

    private static func readBE32(_ data: Data, _ at: Int) -> UInt32 {
        data.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: at, as: UInt32.self)) }
    }

    private static func readLE32(_ data: Data, _ at: Int) -> UInt32 {
        data.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(fromByteOffset: at, as: UInt32.self)) }
    }

    private static func parseLoadCommands(_ data: Data, offset: Int, size: Int, into report: inout Report) {
        guard offset + 32 <= data.count else { return }
        let magic = readLE32(data, offset)
        // Only little-endian (every Mac since Intel) is parsed.
        guard magic == 0xfeedfacf || magic == 0xfeedface else { return }
        let is64 = magic == 0xfeedfacf
        let cpu = readLE32(data, offset + 4)
        report.architectures.append(cpu == 0x0100000c ? "arm64" : cpu == 0x01000007 ? "x86_64" : "other")
        let ncmds = Int(readLE32(data, offset + 16))
        var cursor = offset + (is64 ? 32 : 28)
        let end = min(offset + size, data.count)
        for _ in 0..<min(ncmds, 512) {
            guard cursor + 8 <= end else { break }
            let cmd = readLE32(data, cursor)
            let cmdsize = Int(readLE32(data, cursor + 4))
            guard cmdsize >= 8, cursor + cmdsize <= end else { break }
            switch cmd {
            case 0x1d:   // LC_CODE_SIGNATURE
                report.hasCodeSignature = true
            case 0xc, 0x80000018, 0x1f, 0x80000023:   // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB
                let nameOffset = Int(readLE32(data, cursor + 8))
                if nameOffset < cmdsize {
                    let bytes = data[(cursor + nameOffset)..<(cursor + cmdsize)].prefix { $0 != 0 }
                    let name = String(decoding: bytes, as: UTF8.self)
                    if !report.linksDylibs.contains(name) { report.linksDylibs.append(name) }
                }
            default:
                break
            }
            cursor += cmdsize
        }
        // Frameworks that only make sense for specific capabilities.
        for lib in report.linksDylibs {
            if lib.contains("ScreenCaptureKit") { report.capabilities[.screenCapture] = max(report.capabilities[.screenCapture] ?? 0, 1) }
            if lib.contains("/AVFoundation.framework") { report.capabilities[.microphoneCamera] = max(report.capabilities[.microphoneCamera] ?? 0, 1) }
        }
    }
}
