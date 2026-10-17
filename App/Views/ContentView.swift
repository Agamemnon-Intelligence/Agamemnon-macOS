import SwiftUI

enum AppSection: String, CaseIterable, Identifiable {
    case overview, scan, quarantine, protection, checkup, dns, schedule, settings, about

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: return "Overview"
        case .scan: return "Scan"
        case .quarantine: return "Quarantine"
        case .protection: return "Real-Time Protection"
        case .checkup: return "Security Checkup"
        case .dns: return "Encrypted DNS"
        case .schedule: return "Scheduled Scans"
        case .settings: return "Settings"
        case .about: return "About"
        }
    }

    var symbol: String {
        switch self {
        case .overview: return "shield.lefthalf.filled"
        case .scan: return "magnifyingglass"
        case .quarantine: return "archivebox"
        case .protection: return "bolt.shield"
        case .checkup: return "checklist"
        case .dns: return "network.badge.shield.half.filled"
        case .schedule: return "calendar.badge.clock"
        case .settings: return "gearshape"
        case .about: return "info.circle"
        }
    }
}

/// Which page the main window shows (also driven from the menu bar).
@MainActor
final class Navigator: ObservableObject {
    static let shared = Navigator()
    @Published var section: AppSection = .overview
}

struct ContentView: View {
    @EnvironmentObject private var nav: Navigator
    @State private var columns = NavigationSplitViewVisibility.all

    var body: some View {
        NavigationSplitView(columnVisibility: $columns) {
            // The system sidebar: real Liquid Glass on macOS 26, a translucent sidebar before.
            Sidebar()
                .frame(minWidth: 232)
                .navigationSplitViewColumnWidth(min: 232, ideal: 240, max: 280)
                .hideSidebarToggle()
        } detail: {
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(AuroraBackground())
        }
        .navigationSplitViewStyle(.balanced)
    }

    @ViewBuilder
    private var detail: some View {
        switch nav.section {
        case .overview: OverviewView()
        case .scan: ScanView()
        case .quarantine: QuarantineView()
        case .protection: ProtectionView()
        case .checkup: SecurityCheckupView()
        case .dns: DNSView()
        case .schedule: ScheduleView()
        case .settings: SettingsView()
        case .about: AboutView()
        }
    }
}

private extension View {
    @ViewBuilder
    func hideSidebarToggle() -> some View {
        if #available(macOS 14.0, *) {
            self.toolbar(removing: .sidebarToggle)
        } else {
            self
        }
    }
}

struct Sidebar: View {
    @EnvironmentObject private var nav: Navigator
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var vault: QuarantineVault
    @EnvironmentObject private var scanner: ScanController

    private var selection: Binding<AppSection?> {
        Binding(get: { nav.section }, set: { if let value = $0 { nav.section = value } })
    }

    var body: some View {
        List(selection: selection) {
            Section {
                ForEach([AppSection.overview, .scan, .quarantine]) { row($0) }
            }
            Section("Protection") {
                ForEach([AppSection.protection, .checkup, .dns, .schedule]) { row($0) }
            }
            Section {
                ForEach([AppSection.settings, .about]) { row($0) }
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        // A dark wash under the system sidebar, so the desktop behind it doesn't lighten it.
        .background(Theme.sidebar.opacity(0.82).ignoresSafeArea())
        .safeAreaInset(edge: .top, spacing: 0) { header }
        .safeAreaInset(edge: .bottom, spacing: 0) { footer }
    }

    private func row(_ section: AppSection) -> some View {
        Label(section.title, systemImage: section.symbol)
            .font(.system(size: 13, weight: .medium))
            .badge(badge(for: section))
            .tag(section)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image("Emblem")
                .resizable()
                .scaledToFit()
                .frame(width: 34, height: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text("Agamemnon")
                    .font(.system(size: 15, weight: .bold, design: .rounded))
                    .foregroundStyle(Theme.text)
                HStack(spacing: 5) {
                    Circle().fill(statusColor).frame(width: 6, height: 6)
                    Text(statusLine)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(statusColor)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.top, 8)
        .padding(.bottom, 10)
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Free & open source · GPLv2")
            Text("by mirazbakis & mertyesileducation")
        }
        .font(.system(size: 10))
        .foregroundStyle(Theme.textTertiary)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
    }

    private var statusLine: String {
        switch model.status {
        case .protected: return "Protected"
        case .attention: return "Needs attention"
        case .scanning: return "Scanning…"
        case .threats: return "Threats found"
        }
    }

    private var statusColor: Color {
        switch model.status {
        case .protected: return Theme.success
        case .attention: return Theme.warning
        case .scanning: return Theme.accent
        case .threats: return Theme.danger
        }
    }

    private func badge(for section: AppSection) -> Int {
        switch section {
        case .quarantine: return vault.items.count
        case .scan: return scanner.isScanning ? 0 : scanner.detections.count
        default: return 0
        }
    }
}
