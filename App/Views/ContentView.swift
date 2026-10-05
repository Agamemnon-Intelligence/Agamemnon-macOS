import SwiftUI

enum AppSection: String, CaseIterable, Identifiable {
    case overview, scan, quarantine, protection, dns, schedule, settings, about

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: return "Overview"
        case .scan: return "Scan"
        case .quarantine: return "Quarantine"
        case .protection: return "Real-Time Protection"
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

    var body: some View {
        HStack(spacing: 0) {
            Sidebar()
                .frame(width: 228)
            Rectangle()
                .fill(Theme.stroke)
                .frame(width: 1)
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(Theme.midnight)
        .ignoresSafeArea()
    }

    @ViewBuilder
    private var detail: some View {
        switch nav.section {
        case .overview: OverviewView()
        case .scan: ScanView()
        case .quarantine: QuarantineView()
        case .protection: ProtectionView()
        case .dns: DNSView()
        case .schedule: ScheduleView()
        case .settings: SettingsView()
        case .about: AboutView()
        }
    }
}

struct Sidebar: View {
    @EnvironmentObject private var nav: Navigator
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var vault: QuarantineVault
    @EnvironmentObject private var scanner: ScanController

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image("Emblem")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 38, height: 38)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Agamemnon")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(Theme.text)
                    Text(statusLine)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(statusColor)
                }
            }
            .padding(.horizontal, 18)
            .padding(.top, 46)
            .padding(.bottom, 22)

            VStack(spacing: 2) {
                ForEach(AppSection.allCases) { section in
                    SidebarItem(section: section,
                                selected: nav.section == section,
                                badge: badge(for: section)) {
                        nav.section = section
                    }
                }
            }
            .padding(.horizontal, 10)

            Spacer()

            VStack(alignment: .leading, spacing: 3) {
                Text("Free & open source · GPLv2")
                Text("by mirazbakis & mertyesileducation")
            }
            .font(.system(size: 10))
            .foregroundStyle(Theme.textTertiary)
            .padding(18)
        }
        .frame(maxHeight: .infinity)
        .background(Theme.sidebar)
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

    private func badge(for section: AppSection) -> String? {
        switch section {
        case .quarantine: return vault.items.isEmpty ? nil : "\(vault.items.count)"
        case .scan:
            if scanner.isScanning { return "•" }
            return scanner.detections.isEmpty ? nil : "\(scanner.detections.count)"
        default: return nil
        }
    }
}

private struct SidebarItem: View {
    let section: AppSection
    let selected: Bool
    let badge: String?
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: section.symbol)
                    .font(.system(size: 13, weight: .semibold))
                    .frame(width: 20)
                    .foregroundStyle(selected ? Theme.accent : Theme.textSecondary)
                Text(section.title)
                    .font(.system(size: 13, weight: selected ? .semibold : .medium))
                    .foregroundStyle(selected ? Theme.text : Theme.textSecondary)
                Spacer()
                if let badge {
                    Text(badge)
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(section == .quarantine ? Theme.navyHover : Theme.danger))
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(selected ? Theme.navy.opacity(0.55) : (hovering ? Theme.card : Color.clear))
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
