import Foundation
import Combine
import UserNotifications

/// A short history of what Agamemnon did, shown on the Overview and Protection pages.
@MainActor
final class ActivityLog: ObservableObject {
    static let shared = ActivityLog()

    enum Kind: String, Codable {
        case scan, threat, quarantine, restore, download, admin, background, dns, update, info

        var symbol: String {
            switch self {
            case .scan: return "magnifyingglass"
            case .threat: return "exclamationmark.triangle.fill"
            case .quarantine: return "lock.shield.fill"
            case .restore: return "arrow.uturn.backward.circle"
            case .download: return "arrow.down.circle.fill"
            case .admin: return "person.badge.key.fill"
            case .background: return "gearshape.2.fill"
            case .dns: return "network.badge.shield.half.filled"
            case .update: return "arrow.triangle.2.circlepath"
            case .info: return "info.circle"
            }
        }
    }

    struct Entry: Identifiable, Codable, Hashable {
        var id = UUID()
        var date = Date()
        var kind: Kind
        var title: String
        var detail: String
    }

    @Published private(set) var entries: [Entry] = []
    private let url = AppPaths.support.appendingPathComponent("activity.json")

    private init() {
        if let data = try? Data(contentsOf: url),
           let decoded = try? JSONDecoder().decode([Entry].self, from: data) {
            entries = decoded
        }
    }

    func add(_ kind: Kind, _ title: String, _ detail: String = "") {
        entries.insert(Entry(kind: kind, title: title, detail: detail), at: 0)
        if entries.count > 300 { entries.removeLast(entries.count - 300) }
        save()
    }

    func clear() {
        entries.removeAll()
        save()
    }

    private func save() {
        if let data = try? JSONEncoder().encode(entries) {
            try? data.write(to: url, options: .atomic)
        }
    }
}

/// macOS notifications.
enum Notifier {
    static func requestAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func post(_ title: String, _ body: String, critical: Bool = false) {
        guard Prefs.bool(Prefs.notifications) else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = critical ? .defaultCritical : .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
