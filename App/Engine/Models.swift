import Foundation

enum ThreatLevel: String, Codable, CaseIterable {
    case malicious
    case suspicious
    case test

    var label: String {
        switch self {
        case .malicious: return "Malware"
        case .suspicious: return "Suspicious"
        case .test: return "Test file"
        }
    }
}

/// Something a scan found.
struct Detection: Identifiable, Codable, Hashable {
    var id = UUID()
    /// The item on disk that gets quarantined (for archives, the archive itself).
    var fileURL: URL
    /// Where inside the archive / disk image the threat was found, if anywhere.
    var innerPath: String?
    var threatName: String
    /// "Agamemnon", "ClamAV" or "Gatekeeper".
    var engine: String
    var level: ThreatLevel
    var sha256: String?
    var date = Date()

    var fileName: String { fileURL.lastPathComponent }
    var displayPath: String {
        if let innerPath { return "\(fileURL.path) ▸ \(innerPath)" }
        return fileURL.path
    }
}

enum ScanKind: String, Codable, CaseIterable, Identifiable {
    case quick, full, custom, download

    var id: String { rawValue }

    var title: String {
        switch self {
        case .quick: return "Quick Scan"
        case .full: return "Full Scan"
        case .custom: return "Custom Scan"
        case .download: return "Download Check"
        }
    }

    var symbol: String {
        switch self {
        case .quick: return "bolt.shield"
        case .full: return "internaldrive"
        case .custom: return "folder.badge.gearshape"
        case .download: return "arrow.down.circle"
        }
    }

    var summary: String {
        switch self {
        case .quick: return "Downloads, Desktop, Applications and the places malware likes to start from."
        case .full: return "Every file on your startup disk. Takes a while."
        case .custom: return "Pick the files and folders to check."
        case .download: return "A single new download."
        }
    }
}

/// Saved result of a finished scan.
struct ScanSummary: Codable, Hashable {
    var kind: ScanKind
    var started: Date
    var finished: Date
    var filesScanned: Int
    var archivesOpened: Int
    var detections: Int
    var quarantined: Int
    var cancelled: Bool
    var scheduled: Bool

    var duration: TimeInterval { finished.timeIntervalSince(started) }
}

/// Live progress, sent from the scan thread to the UI.
struct ScanSnapshot {
    var phase: String
    var filesScanned: Int
    var archivesOpened: Int
    var currentPath: String
    var detections: [Detection]
}

/// Final result of ScanEngine.run.
struct ScanResult {
    var detections: [Detection]
    var filesScanned: Int
    var archivesOpened: Int
    var skippedArchives: [String]
    var cancelled: Bool
    var clamAVError: String?
}
