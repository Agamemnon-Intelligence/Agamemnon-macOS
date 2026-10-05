import SwiftUI
import AppKit

/// The window that drops down from the menu bar shield icon.
struct MenuBarView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var scanner: ScanController
    @EnvironmentObject private var downloads: DownloadGuard
    @EnvironmentObject private var dns: DNSManager
    @EnvironmentObject private var vault: QuarantineVault
    @EnvironmentObject private var nav: Navigator
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image("Emblem").resizable().scaledToFit().frame(width: 34, height: 34)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Agamemnon").font(.system(size: 14, weight: .bold)).foregroundStyle(Theme.text)
                    Text(model.status.title).font(.system(size: 11, weight: .medium)).foregroundStyle(statusColor)
                }
                Spacer()
                Image(systemName: model.status.symbol).font(.system(size: 20)).foregroundStyle(statusColor)
            }

            if scanner.isScanning {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(scanner.kind?.title ?? "Scanning").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                        Spacer()
                        Text("\(scanner.filesScanned.formatted()) files").font(.system(size: 11).monospacedDigit()).foregroundStyle(Theme.textSecondary)
                    }
                    ProgressView().progressViewStyle(.linear).tint(Theme.accent)
                    Button("Stop Scan") { scanner.cancel() }.buttonStyle(NavyButtonStyle(kind: .destructive, compact: true))
                }
            } else {
                HStack(spacing: 8) {
                    Button { scanner.start(.quick) } label: { Label("Quick Scan", systemImage: "bolt.shield") }
                        .buttonStyle(NavyButtonStyle(kind: .primary, compact: true))
                    Button { open(.scan) } label: { Label("More…", systemImage: "magnifyingglass") }
                        .buttonStyle(.navyCompact)
                }
            }

            VStack(spacing: 8) {
                row("arrow.down.circle", "Download protection", downloads.isRunning ? "On" : "Off",
                    downloads.isRunning ? Theme.success : Theme.warning) { open(.protection) }
                row("network.badge.shield.half.filled", "Encrypted DNS", dns.activeDescription ?? "Off",
                    dns.activeVariantID != nil ? Theme.success : Theme.textSecondary) { open(.dns) }
                row("archivebox", "Quarantine", vault.items.isEmpty ? "Empty" : "\(vault.items.count)",
                    vault.items.isEmpty ? Theme.textSecondary : Theme.accent) { open(.quarantine) }
                if let last = scanner.lastSummary {
                    row("clock", "Last scan", last.finished.relative, Theme.textSecondary) { open(.scan) }
                }
            }

            Divider().overlay(Theme.stroke)

            HStack {
                Button("Open Agamemnon") { open(.overview) }.buttonStyle(.navyCompact)
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }.buttonStyle(.navyCompact)
            }
        }
        .padding(16)
        .frame(width: 320)
        .background(AuroraBackground())
    }

    private var statusColor: Color {
        switch model.status {
        case .protected: return Theme.success
        case .attention: return Theme.warning
        case .scanning: return Theme.accent
        case .threats: return Theme.danger
        }
    }

    private func row(_ symbol: String, _ title: String, _ value: String, _ color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Image(systemName: symbol).frame(width: 18).foregroundStyle(Theme.textSecondary)
                Text(title).font(.system(size: 12)).foregroundStyle(Theme.text)
                Spacer()
                Text(value).font(.system(size: 12, weight: .medium)).foregroundStyle(color).lineLimit(1)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func open(_ section: AppSection) {
        nav.section = section
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}
