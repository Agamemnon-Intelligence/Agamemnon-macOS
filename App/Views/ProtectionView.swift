import SwiftUI
import AppKit

struct ProtectionView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var downloads: DownloadGuard
    @EnvironmentObject private var admin: AdminWatcher
    @EnvironmentObject private var backgroundItems: BackgroundItemWatcher
    @EnvironmentObject private var behavior: BehaviorMonitor

    @AppStorage(Prefs.downloadProtection) private var downloadProtection = true
    @AppStorage(Prefs.adminAlerts) private var adminAlerts = true
    @AppStorage(Prefs.backgroundItemAlerts) private var backgroundItemAlerts = true
    @AppStorage(Prefs.quarantineUnnotarized) private var quarantineUnnotarized = false
    @AppStorage(Prefs.behaviorProtection) private var behaviorProtection = true
    @AppStorage(Prefs.behaviorAutoStop) private var behaviorAutoStop = true
    @State private var trusted: [String] = UserDefaults.standard.stringArray(forKey: Prefs.trustedPrograms) ?? []
    @State private var testMessage: String?

    var body: some View {
        Page {
            PageHeader(title: "Real-Time Protection",
                       subtitle: "Agamemnon keeps watch in the background while it's in your menu bar.")

            behaviorCard
            RansomwareCard()
            downloadsCard
            BrowserCard()
            StartupSweepCard()
            adminCard
            backgroundCard
            testCard
        }
        .onChange(of: downloadProtection) { _ in model.preferencesChanged() }
        .onChange(of: adminAlerts) { _ in model.preferencesChanged() }
        .onChange(of: backgroundItemAlerts) { _ in model.preferencesChanged() }
        .onChange(of: behaviorProtection) { _ in model.preferencesChanged() }
    }

    // MARK: - Behaviour

    private var behaviorCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "eye.trianglebadge.exclamationmark", title: "Behaviour protection",
                           detail: "Watches programs as they run and recognises what stealers, backdoors, spyware and miners do: fake password prompts, stealing passwords, crypto wallets and browser data, secret screenshots, switching off macOS's download check, and downloading from known malware sites. New programs and scripts are also checked against the malware list and Agamemnon's pattern rules.",
                           color: behavior.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $behaviorProtection).toggleStyle(.switch).labelsHidden()
                }
                SettingRow(symbol: "hand.raised.fill", title: "Stop dangerous programs automatically",
                           detail: "Only for clear-cut cases. Agamemnon never stops or moves anything that's part of macOS or signed by a known developer, and stopped programs go to Quarantine, where you can restore them.",
                           color: Theme.accent) {
                    Toggle("", isOn: $behaviorAutoStop).toggleStyle(.switch).labelsHidden()
                }
                    .disabled(!behaviorProtection)

                if behavior.isRunning {
                    Text("\(behavior.processesChecked.formatted()) programs checked since Agamemnon started.")
                        .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                }

                if !behavior.alerts.isEmpty {
                    Divider().overlay(Theme.stroke)
                    HStack {
                        SectionTitle(text: "Recent alerts")
                        Spacer()
                        Button("Clear") { behavior.clearAlerts() }.buttonStyle(.navyCompact)
                    }
                    ForEach(behavior.alerts.prefix(8)) { alert in
                        BehaviorAlertRow(alert: alert)
                    }
                }

                if !trusted.isEmpty {
                    Divider().overlay(Theme.stroke)
                    SectionTitle(text: "Programs you trust")
                    ForEach(trusted, id: \.self) { path in
                        HStack {
                            Text(path).font(.system(size: 12)).foregroundStyle(Theme.text)
                                .lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Button { untrust(path) } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.plain).foregroundStyle(Theme.textSecondary)
                                .help("Stop trusting this program")
                        }
                    }
                }

                Notice(symbol: "info.circle",
                       text: "Agamemnon checks new programs about once a second, so it reacts just after something starts rather than before. Blocking programs before they run needs an Apple entitlement this version doesn't have.",
                       color: Theme.accent)
            }
        }
        .onReceive(behavior.$alerts) { _ in
            trusted = UserDefaults.standard.stringArray(forKey: Prefs.trustedPrograms) ?? []
        }
    }

    private func untrust(_ path: String) {
        trusted.removeAll { $0 == path }
        UserDefaults.standard.set(trusted, forKey: Prefs.trustedPrograms)
    }

    // MARK: - Downloads

    private var downloadsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "arrow.down.circle.fill", title: "Download protection",
                           detail: "Every new download is checked the moment it finishes, including inside ZIP, RAR, 7Z, DMG, PKG and ISO files, and against a live list of malware sites it may have come from. Dangerous files go straight to quarantine.",
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

private struct BehaviorAlertRow: View {
    let alert: BehaviorMonitor.Alert
    @EnvironmentObject private var behavior: BehaviorMonitor
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 12) {
                IconBadge(symbol: alert.finding.confidence == .high ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill",
                          color: alert.finding.confidence == .high ? Theme.danger : Theme.warning, size: 30)
                VStack(alignment: .leading, spacing: 3) {
                    Text(alert.finding.title).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                    Text(((alert.culpritPath ?? alert.path) as NSString).lastPathComponent + " · " + alert.outcome)
                        .font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                        .lineLimit(1).truncationMode(.middle)
                    Text("Seen in: \(alert.finding.families)")
                        .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                }
                Spacer()
                Text(alert.date.relative).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
            }
            if expanded {
                VStack(alignment: .leading, spacing: 4) {
                    Text(alert.finding.explanation)
                        .font(.system(size: 12)).foregroundStyle(Theme.text.opacity(0.9))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(alert.commandLine)
                        .font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.textSecondary)
                        .lineLimit(4).textSelection(.enabled)
                }
                .padding(.leading, 42)
            }
            HStack(spacing: 8) {
                Button(expanded ? "Less" : "Details") { withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() } }
                    .buttonStyle(.navyCompact)
                Spacer()
                if !alert.handled {
                    Button("Stop") { behavior.stopProcess(alert) }.buttonStyle(.navyCompact)
                    Button("Quarantine") { behavior.quarantine(alert) }
                        .buttonStyle(NavyButtonStyle(kind: .destructive, compact: true))
                }
                Button("Trust") { behavior.trust(alert) }.buttonStyle(.navyCompact)
                    .help("Never warn about this program again")
            }
            .padding(.leading, 42)
        }
        .padding(.vertical, 4)
    }
}
