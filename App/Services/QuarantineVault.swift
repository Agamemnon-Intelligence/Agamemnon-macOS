import Foundation
import Combine

struct QuarantineItem: Identifiable, Codable, Hashable {
    let id: UUID
    let originalPath: String
    let innerPath: String?
    let threatName: String
    let engine: String
    let level: ThreatLevel
    let date: Date
    let sha256: String?
    let size: Int64
    let originalPermissions: Int?
    let isDirectory: Bool

    var name: String { (originalPath as NSString).lastPathComponent }
}

/// Moves threats into ~/Library/Application Support/Agamemnon/Quarantine, where they
/// can't run (execute bits removed, folder only readable by you). Items can be
/// restored to where they came from or deleted for good.
@MainActor
final class QuarantineVault: ObservableObject {
    @Published private(set) var items: [QuarantineItem] = []
    @Published var lastError: String?

    private let indexURL = AppPaths.quarantine.appendingPathComponent("index.json")

    init() {
        if let data = try? Data(contentsOf: indexURL),
           let decoded = try? JSONDecoder().decode([QuarantineItem].self, from: data) {
            items = decoded.sorted { $0.date > $1.date }
        }
    }

    private func folder(for id: UUID) -> URL {
        AppPaths.quarantine.appendingPathComponent(id.uuidString, isDirectory: true)
    }

    func storedURL(for item: QuarantineItem) -> URL {
        folder(for: item.id).appendingPathComponent(item.name)
    }

    func contains(path: String) -> Bool {
        items.contains { $0.originalPath == path }
    }

    // MARK: - Quarantine

    @discardableResult
    func quarantine(_ detection: Detection) throws -> QuarantineItem {
        let fm = FileManager.default
        let source = detection.fileURL
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: source.path, isDirectory: &isDir) else {
            throw VaultError.missing(source.lastPathComponent)
        }
        let attributes = try? fm.attributesOfItem(atPath: source.path)
        let perms = attributes?[.posixPermissions] as? Int
        let size = (attributes?[.size] as? NSNumber)?.int64Value ?? 0

        let item = QuarantineItem(id: UUID(),
                                  originalPath: source.path,
                                  innerPath: detection.innerPath,
                                  threatName: detection.threatName,
                                  engine: detection.engine,
                                  level: detection.level,
                                  date: Date(),
                                  sha256: detection.sha256,
                                  size: size,
                                  originalPermissions: perms,
                                  isDirectory: isDir.boolValue)
        let dir = folder(for: item.id)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let destination = storedURL(for: item)

        do {
            try fm.moveItem(at: source, to: destination)
        } catch {
            // Owned by root or another user (e.g. something in /Library/LaunchDaemons).
            let user = NSUserName()
            let command = "/bin/mv \(Shell.quote(source.path)) \(Shell.quote(destination.path)) && /usr/sbin/chown -R \(Shell.quote(user)) \(Shell.quote(destination.path))"
            do {
                try Privileged.run(command, prompt: "Agamemnon needs your password to quarantine “\(source.lastPathComponent)”.")
            } catch {
                try? fm.removeItem(at: dir)
                throw error
            }
        }

        // Make sure it can't be run from the vault.
        if !isDir.boolValue {
            try? fm.setAttributes([.posixPermissions: 0o400], ofItemAtPath: destination.path)
        }

        items.insert(item, at: 0)
        save()
        ActivityLog.shared.add(.quarantine, "Quarantined \(item.name)", detection.threatName)
        return item
    }

    // MARK: - Restore / delete

    @discardableResult
    func restore(_ item: QuarantineItem) throws -> URL {
        let fm = FileManager.default
        let stored = storedURL(for: item)
        guard fm.fileExists(atPath: stored.path) else { throw VaultError.missing(item.name) }

        var target = URL(fileURLWithPath: item.originalPath)
        try? fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        if fm.fileExists(atPath: target.path) {
            let base = target.deletingPathExtension().lastPathComponent
            let ext = target.pathExtension
            var n = 1
            repeat {
                let name = ext.isEmpty ? "\(base) (restored \(n))" : "\(base) (restored \(n)).\(ext)"
                target = target.deletingLastPathComponent().appendingPathComponent(name)
                n += 1
            } while fm.fileExists(atPath: target.path)
        }

        if let perms = item.originalPermissions, !item.isDirectory {
            try? fm.setAttributes([.posixPermissions: perms | 0o600], ofItemAtPath: stored.path)
        }
        do {
            try fm.moveItem(at: stored, to: target)
        } catch {
            let command = "/bin/mv \(Shell.quote(stored.path)) \(Shell.quote(target.path))"
            try Privileged.run(command, prompt: "Agamemnon needs your password to restore “\(item.name)”.")
        }
        if let perms = item.originalPermissions, !item.isDirectory {
            try? fm.setAttributes([.posixPermissions: perms], ofItemAtPath: target.path)
        }
        try? fm.removeItem(at: folder(for: item.id))
        items.removeAll { $0.id == item.id }
        save()
        ActivityLog.shared.add(.restore, "Restored \(item.name)", target.path)
        return target
    }

    func delete(_ item: QuarantineItem) throws {
        let dir = folder(for: item.id)
        _ = Shell.run("/bin/chmod", ["-R", "u+rwX", dir.path], timeout: 60)
        if FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.removeItem(at: dir)
        }
        items.removeAll { $0.id == item.id }
        save()
        ActivityLog.shared.add(.info, "Deleted \(item.name) for good", item.threatName)
    }

    func deleteAll() {
        for item in items { try? delete(item) }
    }

    private func save() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted]
        if let data = try? encoder.encode(items) {
            try? data.write(to: indexURL, options: .atomic)
        }
    }

    enum VaultError: LocalizedError {
        case missing(String)
        var errorDescription: String? {
            switch self {
            case .missing(let name): return "“\(name)” no longer exists."
            }
        }
    }
}
