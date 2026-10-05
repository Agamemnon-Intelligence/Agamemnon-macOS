import SwiftUI
import AppKit

struct ProtectionView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var downloads: DownloadGuard
    @EnvironmentObject private var admin: AdminWatcher
    @EnvironmentObject private var backgroundItems: BackgroundItemWatcher

    @AppStorage(Prefs.downloadProtection) private var downloadProtection = true
    @AppStorage(Prefs.adminAlerts) private var adminAlerts = true
    @AppStorage(Prefs.backgroundItemAlerts) private var backgroundItemAlerts = true
    @AppStorage(Prefs.quarantineUnnotarized) private var quarantineUnnotarized = false
    @State private var testMessage: String?

    var body: some View {
        Page {
            PageHeader(title: "Real-Time Protection",
                       subtitle: "Agamemnon keeps watch in the background while it's in your menu bar.")

            downloadsCard
            adminCard
            backgroundCard
            testCard
        }
        .onChange(of: downloadProtection) { _ in model.preferencesChanged() }
        .onChange(of: adminAlerts) { _ in model.preferencesChanged() }
        .onChange(of: backgroundItemAlerts) { _ in model.preferencesChanged() }
    }

    // MARK: - Downloads

    private var downloadsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "arrow.down.circle.fill", title: "Download protection",
                           detail: "Every new download is checked the moment it finishes, including inside ZIP, RAR, 7Z, DMG, PKG and ISO files. Dangerous files go straight to quarantine.",
                           color: downloads.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $downloadProtection).toggleStyle(.switch).labelsHidden()
                }
                SettingRow(symbol: "checkmark.seal", title: "Quarantine apps Apple hasn't verified",
                           detail: "Unsigned or un-notarized apps and installers are always flagged. Turn this on to quarantine them automatically too.",
                           color: Theme.accent) {
                    Toggle("", isOn: $quarantineUnnotarized).toggleStyle(.switch).labelsHidden()
                }

                Divider().overlay(Theme.stroke)
                HStack {
                    SectionTitle(text: "Watched folders")
                    Spacer()
                    Button("Add Folder…", action: addFolder).buttonStyle(.navyCompact)
                }
                ForEach(downloads.folders, id: \.self) { folder in
                    HStack {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: folder.path)).resizable().frame(width: 18, height: 18)
                        Text(folder.path).font(.system(size: 12)).foregroundStyle(Theme.text)
                        Spacer()
                        if folder != DownloadGuard.defaultFolder {
                            Button { downloads.removeFolder(folder) } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.plain).foregroundStyle(Theme.textSecondary)
                        }
                    }
                }

                if !downloads.events.isEmpty {
                    Divider().overlay(Theme.stroke)
                    SectionTitle(text: "Recent downloads")
                    ForEach(downloads.events.prefix(8)) { event in
                        HStack {
                            Text(event.name).font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.text)
                                .lineLimit(1).truncationMode(.middle)
                            Spacer()
                            verdictPill(event.verdict)
                            Text(event.date.relative).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                                .frame(width: 110, alignment: .trailing)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func verdictPill(_ verdict: DownloadGuard.Event.Verdict) -> some View {
        switch verdict {
        case .checking: StatusPill(text: "Checking…", color: Theme.accent)
        case .clean: StatusPill(text: "Safe", color: Theme.success)
        case .suspicious(let why): StatusPill(text: why, color: Theme.warning)
        case .quarantined(let what): StatusPill(text: "Quarantined · \(what)", color: Theme.danger)
        case .threat(let what): StatusPill(text: what, color: Theme.danger)
        case .skipped(let why): StatusPill(text: why, color: Theme.textSecondary)
        }
    }

    private func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Watch Folder"
        if panel.runModal() == .OK, let url = panel.url { downloads.addFolder(url) }
    }

    // MARK: - Admin

    private var adminCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "person.badge.key.fill", title: "Administrator access alerts",
                           detail: "Warns you when an app asks for your administrator password, so malware can't quietly get full control of your Mac.",
                           color: admin.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $adminAlerts).toggleStyle(.switch).labelsHidden()
                }
                if let problem = admin.problem {
                    Notice(symbol: "exclamationmark.triangle", text: problem)
                }
                if !admin.requests.isEmpty {
                    Divider().overlay(Theme.stroke)
                    SectionTitle(text: "Recent requests")
                    ForEach(admin.requests.prefix(6)) { request in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(request.appName).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                                Text(AdminWatcher.describe(request.rights).capitalizedFirst + " · " + request.requester)
                                    .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            if let outcome = request.outcome {
                                StatusPill(text: outcome, color: outcome == "Allowed" ? Theme.warning : Theme.textSecondary)
                            }
                            Text(request.date.relative).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Background items

    private var backgroundCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "gearshape.2.fill", title: "Background item alerts",
                           detail: "Tells you when something sets itself up to start automatically (LaunchAgents and LaunchDaemons) — a favourite trick of Mac malware — and scans it.",
                           color: backgroundItems.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $backgroundItemAlerts).toggleStyle(.switch).labelsHidden()
                }
                if !backgroundItems.items.isEmpty {
                    Divider().overlay(Theme.stroke)
                    ForEach(backgroundItems.items.prefix(6)) { item in
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.label).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                                Text(item.program ?? item.plistPath)
                                    .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            Text(item.verdict).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                            Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.plistPath)]) }
                                .buttonStyle(.navyCompact)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Test

    private var testCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                SettingRow(symbol: "testtube.2", title: "Test your protection",
                           detail: "Saves the harmless EICAR test file to your Downloads folder. Every antivirus detects it, so Agamemnon should quarantine it within a few seconds.") {
                    Button("Run Test", action: runTest).buttonStyle(.navySecondary)
                }
                if let testMessage {
                    Text(testMessage).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                }
            }
        }
    }

    private func runTest() {
        let url = DownloadGuard.defaultFolder.appendingPathComponent("eicar-test-\(Int(Date().timeIntervalSince1970)).com")
        do {
            try Eicar.signature.write(to: url, atomically: true, encoding: .ascii)
            testMessage = downloads.isRunning
                ? "Created \(url.lastPathComponent). Watch for the notification — it should land in Quarantine."
                : "Created \(url.lastPathComponent), but download protection is off. Turn it on, or scan your Downloads folder."
        } catch {
            testMessage = "Couldn't create the test file: \(error.localizedDescription)"
        }
    }
}

extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
