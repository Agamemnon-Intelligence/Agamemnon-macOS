import Foundation
import Combine
import ServiceManagement

/// Runs a Quick or Full scan daily or weekly while Agamemnon is running
/// (it stays in the menu bar, and can open at login). If the Mac was asleep
/// at the scheduled time, the scan runs as soon as it wakes.
@MainActor
final class ScanScheduler: ObservableObject {
    enum Frequency: String, CaseIterable, Identifiable {
        case daily, weekly
        var id: String { rawValue }
        var title: String { self == .daily ? "Every day" : "Every week" }
    }

    @Published var enabled: Bool { didSet { save() } }
    @Published var frequency: Frequency { didSet { save() } }
    /// 1 = Sunday … 7 = Saturday (Calendar weekday numbering).
    @Published var weekday: Int { didSet { save() } }
    @Published var time: Date { didSet { save() } }
    @Published var kind: ScanKind { didSet { save() } }
    @Published private(set) var lastRun: Date?
    @Published private(set) var launchAtLogin = false
    @Published var loginItemError: String?

    private let scanner: ScanController
    private var timer: Timer?
    private var loading = true
    private let d = UserDefaults.standard

    init(scanner: ScanController) {
        self.scanner = scanner
        let d = UserDefaults.standard
        enabled = d.bool(forKey: "schedule.enabled")
        frequency = Frequency(rawValue: d.string(forKey: "schedule.frequency") ?? "") ?? .weekly
        weekday = d.object(forKey: "schedule.weekday") as? Int ?? 1
        let defaultTime = Calendar.current.date(bySettingHour: 12, minute: 0, second: 0, of: Date()) ?? Date()
        time = d.object(forKey: "schedule.time") as? Date ?? defaultTime
        kind = ScanKind(rawValue: d.string(forKey: "schedule.kind") ?? "") ?? .quick
        lastRun = d.object(forKey: "schedule.lastRun") as? Date
        loading = false
        if d.object(forKey: "schedule.anchor") == nil { d.set(Date(), forKey: "schedule.anchor") }
        refreshLoginItem()
    }

    private func save() {
        guard !loading else { return }
        d.set(enabled, forKey: "schedule.enabled")
        d.set(frequency.rawValue, forKey: "schedule.frequency")
        d.set(weekday, forKey: "schedule.weekday")
        d.set(time, forKey: "schedule.time")
        d.set(kind.rawValue, forKey: "schedule.kind")
        // Changing the schedule shouldn't immediately fire a "missed" run.
        d.set(Date(), forKey: "schedule.anchor")
        objectWillChange.send()
    }

    var nextRun: Date? {
        guard enabled else { return nil }
        let anchor = d.object(forKey: "schedule.anchor") as? Date ?? Date()
        let base = max(anchor, lastRun ?? .distantPast)
        var components = Calendar.current.dateComponents([.hour, .minute], from: time)
        components.second = 0
        if frequency == .weekly { components.weekday = weekday }
        return Calendar.current.nextDate(after: base, matching: components, matchingPolicy: .nextTime)
    }

    func start() {
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.check() }
        }
        check()
    }

    private func check() {
        guard enabled, let next = nextRun, next <= Date(), !scanner.isScanning else { return }
        let now = Date()
        lastRun = now
        d.set(now, forKey: "schedule.lastRun")
        scanner.start(kind == .full ? .full : .quick, scheduled: true)
        ActivityLog.shared.add(.scan, "Scheduled \(kind.title.lowercased()) started")
    }

    // MARK: - Open at login

    func refreshLoginItem() {
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    func setLaunchAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            loginItemError = nil
        } catch {
            loginItemError = "macOS didn't allow it: \(error.localizedDescription). You can add Agamemnon in System Settings › General › Login Items."
        }
        refreshLoginItem()
    }
}
