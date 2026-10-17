import SwiftUI

struct OverviewView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var nav: Navigator
    @EnvironmentObject private var scanner: ScanController
    @EnvironmentObject private var signatures: SignatureManager
    @EnvironmentObject private var downloads: DownloadGuard
    @EnvironmentObject private var dns: DNSManager
    @EnvironmentObject private var vault: QuarantineVault
    @EnvironmentObject private var activity: ActivityLog
    @EnvironmentObject private var behavior: BehaviorMonitor
    @EnvironmentObject private var admin: AdminWatcher
    @EnvironmentObject private var backgroundItems: BackgroundItemWatcher

    var body: some View {
        Page {
            hero

            LazyVGrid(columns: [GridItem(.flexible(), spacing: 14), GridItem(.flexible(), spacing: 14)], spacing: 14) {
                StatCard(symbol: "shield.checkered", color: signatures.count > 0 ? Theme.success : Theme.warning,
                         title: "Malware signatures",
                         value: signatures.count > 0 ? signatures.totalCount.formatted() : (signatures.isUpdating ? "Downloading…" : "Not downloaded"),
                         detail: signatures.lastUpdated.map { "Updated \($0.relative)" } ?? "From MalwareBazaar") {
                    Button(signatures.isUpdating ? "Updating…" : "Update") { signatures.update() }
                        .buttonStyle(.navyCompact)
                        .disabled(signatures.isUpdating)
                }
                StatCard(symbol: "arrow.down.circle.fill", color: downloads.isRunning ? Theme.success : Theme.warning,
                         title: "Download protection",
                         value: downloads.isRunning ? "On" : "Off",
                         detail: downloads.isRunning ? "Watching \(downloads.folders.count) folder\(downloads.folders.count == 1 ? "" : "s")" : "New downloads aren't being checked") {
                    Button("Manage") { nav.section = .protection }.buttonStyle(.navyCompact)
                }
                StatCard(symbol: "network.badge.shield.half.filled", color: dns.activeVariantID != nil ? Theme.success : Theme.textSecondary,
                         title: "Encrypted DNS",
                         value: dns.activeDescription ?? "Off",
                         detail: dns.activeVariantID != nil ? "All lookups are encrypted" : "Pick a private DNS provider") {
                    Button(dns.activeVariantID != nil ? "Change" : "Turn On") { nav.section = .dns }.buttonStyle(.navyCompact)
                }
                StatCard(symbol: "archivebox.fill", color: vault.items.isEmpty ? Theme.textSecondary : Theme.accent,
                         title: "Quarantine",
                         value: vault.items.isEmpty ? "Empty" : "\(vault.items.count) item\(vault.items.count == 1 ? "" : "s")",
                         detail: "Threats are locked away here") {
                    Button("Open") { nav.section = .quarantine }.buttonStyle(.navyCompact)
                }
            }

            HStack(alignment: .top, spacing: 14) {
                lastScanCard
                engineCard
            }

            recentActivity
        }
    }

    // MARK: - Hero

    private var hero: some View {
        Card(padding: 26, tint: statusColor.opacity(0.10)) {
            VStack(alignment: .leading, spacing: 22) {
                HStack(spacing: 26) {
                    StatusRing(symbol: model.status.symbol, color: statusColor, spinning: model.status == .scanning)
                    VStack(alignment: .leading, spacing: 8) {
                        Text(model.status.title)
                            .font(.system(size: 26, weight: .bold, design: .rounded))
                            .foregroundStyle(Theme.text)
                        if model.status == .threats {
                            Text("The last scan found \(scanner.detections.count) item\(scanner.detections.count == 1 ? "" : "s") that still need a decision.")
                                .font(.system(size: 13)).foregroundStyle(Theme.textSecondary)
                        } else if model.status == .scanning {
                            Text("\(scanner.kind?.title ?? "Scan") · \(scanner.filesScanned.formatted()) files checked")
                                .font(.system(size: 13)).foregroundStyle(Theme.textSecondary)
                        } else if model.attentionReasons.isEmpty {
                            Text("Downloads, running programs and startup items are being watched, and your malware signatures are current.")
                                .font(.system(size: 13)).foregroundStyle(Theme.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        } else {
                            ForEach(model.attentionReasons, id: \.self) { reason in
                                Label(reason, systemImage: "exclamationmark.circle")
                                    .font(.system(size: 13)).foregroundStyle(Theme.warning)
                            }
                        }
                        HStack(spacing: 10) {
                            if scanner.isScanning || model.status == .threats {
                                Button("View Scan") { nav.section = .scan }.buttonStyle(.navy)
                            } else {
                                Button {
                                    scanner.start(.quick)
                                    nav.section = .scan
                                } label: { Label("Quick Scan", systemImage: "bolt.shield") }
                                    .buttonStyle(.navy)
                                Button {
                                    scanner.start(.full)
                                    nav.section = .scan
                                } label: { Label("Full Scan", systemImage: "internaldrive") }
                                    .buttonStyle(.navySecondary)
                            }
                        }
                        .glassGroup(spacing: 10)
                        .padding(.top, 6)
                    }
                    Spacer(minLength: 0)
                }

                Divider().overlay(Color.white.opacity(0.06))

                HStack(spacing: 10) {
                    LayerChip(symbol: "arrow.down.circle", title: "Downloads", on: downloads.isRunning)
                    LayerChip(symbol: "eye", title: "Behaviour", on: behavior.isRunning)
                    LayerChip(symbol: "gearshape.2", title: "Startup", on: backgroundItems.isRunning)
                    LayerChip(symbol: "person.badge.key", title: "Admin alerts", on: admin.isRunning)
                    LayerChip(symbol: "shield.checkered", title: "Signatures", on: signatures.count > 0)
                }
            }
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

    // MARK: - Cards

    private var lastScanCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "Last scan")
                if let s = scanner.lastSummary {
                    Text(s.kind.title + (s.cancelled ? " (stopped)" : ""))
                        .font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
                    Text("\(s.finished.relative) · \(s.filesScanned.formatted()) files · \(Duration.seconds(s.duration).formatted(.time(pattern: .hourMinuteSecond)))")
                        .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    if s.detections == 0 {
                        StatusPill(text: "No threats", color: Theme.success)
                    } else {
                        StatusPill(text: "\(s.detections) found · \(s.quarantined) quarantined", color: Theme.danger)
                    }
                } else {
                    Text("You haven't scanned yet")
                        .font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
                    Text("Run a Quick Scan to check the places malware usually hides.")
                        .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                }
            }
        }
    }

    private var engineCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "Scan engines")
                engineRow("Agamemnon engine", signatures.count > 0 ? "Ready" : "Waiting for signatures",
                          signatures.count > 0 ? Theme.success : Theme.warning)
                engineRow("VirusShare hashes", signatures.virusShareCount > 0 ? "\(signatures.virusShareCount.formatted())" : (signatures.virusShareUpdating ? "Downloading…" : "Waiting"),
                          signatures.virusShareCount > 0 ? Theme.success : Theme.textTertiary)
                engineRow("Pattern rules", Prefs.bool(Prefs.patternRules) ? "On" : "Off",
                          Prefs.bool(Prefs.patternRules) ? Theme.success : Theme.warning)
                engineRow("Malware site list (URLhaus)", signatures.urlhausCount > 0 ? "\(signatures.urlhausCount.formatted()) links" : "Waiting",
                          signatures.urlhausCount > 0 ? Theme.success : Theme.textTertiary)
                engineRow("ClamAV", model.clamAVReady ? "Ready" : (model.clamAVInstalling ? "Installing…" : (model.clamAVInstalled ? "Needs signatures" : "Not installed")),
                          model.clamAVReady ? Theme.success : Theme.textTertiary)
                engineRow("Archive & installer scanning", Prefs.bool(Prefs.scanArchives) ? "On" : "Off",
                          Prefs.bool(Prefs.scanArchives) ? Theme.success : Theme.warning)
            }
        }
    }

    private func engineRow(_ name: String, _ state: String, _ color: Color) -> some View {
        HStack {
            Text(name).font(.system(size: 13)).foregroundStyle(Theme.text)
            Spacer()
            StatusPill(text: state, color: color)
        }
    }

    private var recentActivity: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "Recent activity")
                if activity.entries.isEmpty {
                    Text("Nothing yet. Scans, blocked downloads and alerts will show up here.")
                        .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                }
                ForEach(activity.entries.prefix(7)) { entry in
                    ActivityRow(entry: entry)
                }
            }
        }
    }
}

struct StatCard<Accessory: View>: View {
    let symbol: String
    let color: Color
    let title: String
    let value: String
    let detail: String
    @ViewBuilder var accessory: () -> Accessory

    var body: some View {
        Card {
            HStack(alignment: .top, spacing: 14) {
                IconBadge(symbol: symbol, color: color, size: 38)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textSecondary)
                    Text(value).font(.system(size: 18, weight: .bold)).foregroundStyle(Theme.text)
                        .lineLimit(1).minimumScaleFactor(0.7)
                    Text(detail).font(.system(size: 11)).foregroundStyle(Theme.textTertiary).lineLimit(1)
                }
                Spacer(minLength: 8)
                accessory()
            }
        }
    }
}

struct ActivityRow: View {
    let entry: ActivityLog.Entry

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: entry.kind.symbol)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.title).font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.text)
                if !entry.detail.isEmpty {
                    Text(entry.detail).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                        .lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer()
            Text(entry.date.relative).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
        }
    }

    private var color: Color {
        switch entry.kind {
        case .threat: return Theme.danger
        case .quarantine, .admin, .background, .behavior: return Theme.warning
        case .scan, .update, .dns, .download: return Theme.accent
        case .restore, .info: return Theme.textSecondary
        }
    }
}

/// The big status indicator on the Overview page.
struct StatusRing: View {
    let symbol: String
    let color: Color
    var spinning = false
    @State private var angle = 0.0

    var body: some View {
        ZStack {
            Circle()
                .fill(RadialGradient(colors: [color.opacity(0.22), color.opacity(0.02)],
                                     center: .center, startRadius: 4, endRadius: 64))
            Circle()
                .stroke(color.opacity(0.14), lineWidth: 8)
            Circle()
                .trim(from: 0, to: spinning ? 0.3 : 1)
                .stroke(AngularGradient(colors: [color.opacity(0.35), color, color.opacity(0.35)], center: .center),
                        style: StrokeStyle(lineWidth: 8, lineCap: .round))
                .rotationEffect(.degrees(angle - 90))
            Image(systemName: symbol)
                .font(.system(size: 42, weight: .semibold))
                .foregroundStyle(color)
                .shadow(color: color.opacity(0.5), radius: 12)
        }
        .frame(width: 118, height: 118)
        .onAppear { spin(spinning) }
        .onChange(of: spinning) { spin($0) }
    }

    private func spin(_ on: Bool) {
        if on {
            withAnimation(.linear(duration: 1.2).repeatForever(autoreverses: false)) { angle = 360 }
        } else {
            withAnimation(.easeOut(duration: 0.3)) { angle = 0 }
        }
    }
}

/// One protection layer and whether it's on.
struct LayerChip: View {
    let symbol: String
    let title: String
    let on: Bool

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: symbol)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(on ? Theme.success : Theme.warning)
            Text(title)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Theme.text.opacity(0.9))
                .lineLimit(1)
            Spacer(minLength: 0)
            Image(systemName: on ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                .font(.system(size: 11))
                .foregroundStyle(on ? Theme.success : Theme.warning)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .frame(maxWidth: .infinity)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.white.opacity(0.04)))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color.white.opacity(0.06), lineWidth: 1))
    }
}
