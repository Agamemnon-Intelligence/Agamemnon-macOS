import SwiftUI
import AppKit

// Cards on the Real-Time Protection page for the ransomware shield, browser protection and
// the startup-item check.

struct RansomwareCard: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var shield: RansomwareShield
    @AppStorage(Prefs.ransomwareShield) private var enabled = true

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "lock.doc.fill", title: "Ransomware shield",
                           detail: "Watches your most important folders for a sudden burst of files being scrambled or renamed, then stops the unsigned program doing it and moves it to quarantine.",
                           color: shield.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $enabled).toggleStyle(.switch).labelsHidden()
                }
                Divider().overlay(Theme.stroke)
                HStack {
                    SectionTitle(text: "Protected folders")
                    Spacer()
                    Button("Add Folder…", action: addFolder).buttonStyle(.navyCompact)
                }
                ForEach(shield.folders, id: \.self) { folder in
                    HStack {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: folder.path)).resizable().frame(width: 18, height: 18)
                        Text(folder.path).font(.system(size: 12)).foregroundStyle(Theme.text)
                        Spacer()
                        if !RansomwareShield.defaultFolders.contains(folder) {
                            Button { shield.removeFolder(folder) } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.plain).foregroundStyle(Theme.textSecondary)
                        }
                    }
                }
                if !shield.incidents.isEmpty {
                    Divider().overlay(Theme.stroke)
                    HStack {
                        SectionTitle(text: "Incidents")
                        Spacer()
                        Button("Clear") { shield.clearIncidents() }.buttonStyle(.navyCompact)
                    }
                    ForEach(shield.incidents) { incident in
                        HStack(alignment: .top, spacing: 12) {
                            IconBadge(symbol: "exclamationmark.octagon.fill", color: Theme.danger, size: 30)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(incident.summary).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                                Text(incident.outcome).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                            }
                            Spacer()
                            Text(incident.date.relative).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                        }
                    }
                }
                Notice(symbol: "info.circle",
                       text: "The shield reacts within seconds of an attack starting, so a few files may already be affected. Keep a Time Machine backup to get those back.",
                       color: Theme.accent)
            }
        }
        .onChange(of: enabled) { _ in model.preferencesChanged() }
    }

    private func addFolder() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Protect Folder"
        if panel.runModal() == .OK, let url = panel.url { shield.addFolder(url) }
    }
}

struct BrowserCard: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var browser: BrowserGuard
    @AppStorage(Prefs.browserProtection) private var enabled = true

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "safari.fill", title: "Browser protection",
                           detail: "Finds adware in Safari, Chrome, Brave, Edge, Firefox, Arc, Opera and Vivaldi: extensions installed outside the store that can read every website, search-engine hijacks, and profiles that take over your browser.",
                           color: browser.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $enabled).toggleStyle(.switch).labelsHidden()
                }
                HStack {
                    if let last = browser.lastRun {
                        Text("\(browser.extensionsChecked) extensions checked \(last.relative).")
                            .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                    }
                    Spacer()
                    Button("Check Now") { browser.run() }.buttonStyle(.navyCompact).disabled(!enabled)
                }
                if browser.lastRun != nil, browser.findings.isEmpty {
                    StatusPill(text: "Your browsers look clean", color: Theme.success)
                }
                ForEach(browser.findings) { finding in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(alignment: .top, spacing: 12) {
                            IconBadge(symbol: finding.level == .malicious ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill",
                                      color: finding.level == .malicious ? Theme.danger : Theme.warning, size: 30)
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(finding.browser): \(finding.name)").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                                Text(finding.outcome ?? finding.reason).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                            }
                            Spacer()
                        }
                        HStack(spacing: 8) {
                            Spacer()
                            if let path = finding.path {
                                Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
                                    .buttonStyle(.navyCompact)
                            }
                            if finding.outcome == nil {
                                Button("Remove") { browser.remove(finding) }
                                    .buttonStyle(NavyButtonStyle(kind: .destructive, compact: true))
                            }
                            Button("Trust") { browser.trust(finding) }.buttonStyle(.navyCompact)
                        }
                        .padding(.leading, 42)
                    }
                }
            }
        }
        .onChange(of: enabled) { _ in model.preferencesChanged() }
    }
}

struct StartupSweepCard: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var sweep: StartupSweep
    @AppStorage(Prefs.startupSweep) private var enabled = true

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "power.circle.fill", title: "Startup items check",
                           detail: "Checks everything that starts automatically — including items installed before Agamemnon — for known malware, fake Apple items and unsigned programs hiding in odd folders. Runs every 6 hours.",
                           color: enabled ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $enabled).toggleStyle(.switch).labelsHidden()
                }
                HStack {
                    if let last = sweep.lastRun {
                        Text("\(sweep.itemsChecked) startup items checked \(last.relative).")
                            .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                    }
                    Spacer()
                    if sweep.isRunning { ProgressView().controlSize(.small) }
                    Button("Check Now") { sweep.run() }.buttonStyle(.navyCompact).disabled(sweep.isRunning)
                }
                if sweep.lastRun != nil, sweep.findings.isEmpty {
                    StatusPill(text: "Nothing suspicious starts with your Mac", color: Theme.success)
                }
                ForEach(sweep.findings) { finding in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(alignment: .top, spacing: 12) {
                            IconBadge(symbol: finding.level == .malicious ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill",
                                      color: finding.level == .malicious ? Theme.danger : Theme.warning, size: 30)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(finding.label).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                                Text(finding.outcome ?? finding.reason).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                                Text(finding.program ?? finding.plistPath).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                        }
                        HStack(spacing: 8) {
                            Spacer()
                            if finding.plistPath != "crontab" {
                                Button("Reveal") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: finding.plistPath)]) }
                                    .buttonStyle(.navyCompact)
                            }
                            if finding.outcome == nil, finding.plistPath != "crontab" {
                                Button("Quarantine") { sweep.quarantine(finding) }
                                    .buttonStyle(NavyButtonStyle(kind: .destructive, compact: true))
                            }
                            Button("Trust") { sweep.trust(finding) }.buttonStyle(.navyCompact)
                        }
                        .padding(.leading, 42)
                    }
                }
            }
        }
        .onChange(of: enabled) { _ in model.preferencesChanged() }
    }
}

// MARK: - Security Checkup page

struct SecurityCheckupView: View {
    @EnvironmentObject private var checkup: SecurityCheckup

    var body: some View {
        Page {
            PageHeader(title: "Security Checkup",
                       subtitle: "The macOS settings that matter most for keeping your Mac safe. Agamemnon only checks them; you stay in control.")

            Card {
                HStack(spacing: 14) {
                    IconBadge(symbol: summarySymbol, color: summaryColor, size: 44)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(checkup.items.isEmpty ? "Checking your Mac…" : "\(checkup.score.good) of \(checkup.score.total) look good")
                            .font(.system(size: 17, weight: .semibold)).foregroundStyle(Theme.text)
                        if let last = checkup.lastRun {
                            Text("Checked \(last.relative)").font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                        }
                    }
                    Spacer()
                    if checkup.isRunning { ProgressView().controlSize(.small) }
                    Button("Check Again") { checkup.run() }.buttonStyle(.navySecondary).disabled(checkup.isRunning)
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(checkup.items) { item in
                        HStack(alignment: .top, spacing: 12) {
                            IconBadge(symbol: symbol(item.state), color: color(item.state), size: 30)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.title).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                                Text(item.detail).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            if item.state != .good, item.settingsURL != nil {
                                Button("Fix…") { checkup.open(item) }.buttonStyle(.navyCompact)
                            }
                        }
                    }
                }
            }

            SoftwareUpdatesCard()
        }
        .onAppear { if checkup.items.isEmpty { checkup.run() } }
    }

    private var summarySymbol: String {
        checkup.items.contains { $0.state == .bad } ? "exclamationmark.shield.fill" : "checkmark.shield.fill"
    }

    private var summaryColor: Color {
        if checkup.items.contains(where: { $0.state == .bad }) { return Theme.danger }
        if checkup.items.contains(where: { $0.state == .warning }) { return Theme.warning }
        return Theme.success
    }

    private func symbol(_ state: SecurityCheckup.Item.State) -> String {
        switch state {
        case .good: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .bad: return "xmark.octagon.fill"
        }
    }

    private func color(_ state: SecurityCheckup.Item.State) -> Color {
        switch state {
        case .good: return Theme.success
        case .warning: return Theme.warning
        case .bad: return Theme.danger
        }
    }
}
