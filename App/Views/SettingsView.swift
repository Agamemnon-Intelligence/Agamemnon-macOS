import SwiftUI
import AppKit

struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var signatures: SignatureManager

    @AppStorage(Prefs.autoQuarantine) private var autoQuarantine = true
    @AppStorage(Prefs.scanArchives) private var scanArchives = true
    @AppStorage(Prefs.useClamAV) private var useClamAV = true
    @AppStorage(Prefs.autoUpdateSignatures) private var autoUpdate = true
    @AppStorage(Prefs.notifications) private var notifications = true
    @State private var exclusions: [String] = Prefs.exclusionList
    @State private var copied = false

    var body: some View {
        Page {
            PageHeader(title: "Settings", subtitle: "Fine-tune how Agamemnon scans and what it does with threats.")

            Card {
                VStack(alignment: .leading, spacing: 16) {
                    SectionTitle(text: "Scanning")
                    SettingRow(symbol: "lock.shield", title: "Quarantine threats automatically",
                               detail: "Known malware found by a scan goes straight to quarantine. Suspicious items always wait for you.") {
                        Toggle("", isOn: $autoQuarantine).toggleStyle(.switch).labelsHidden()
                    }
                    SettingRow(symbol: "doc.zipper", title: "Look inside archives and installers",
                               detail: "Opens ZIP, RAR, 7Z, TAR, ISO, DMG and PKG files (up to 3 levels deep) so threats can't hide inside.") {
                        Toggle("", isOn: $scanArchives).toggleStyle(.switch).labelsHidden()
                    }
                    SettingRow(symbol: "bell.badge", title: "Notifications",
                               detail: "Alerts for threats, blocked downloads and administrator requests.") {
                        Toggle("", isOn: $notifications).toggleStyle(.switch).labelsHidden()
                    }
                }
            }

            signaturesCard
            clamAVCard
            exclusionsCard

            Card {
                SettingRow(symbol: "externaldrive.badge.checkmark", title: "Full Disk Access",
                           detail: model.hasFullDiskAccess
                               ? "Granted. Agamemnon can scan every folder."
                               : "Not granted. Some protected folders (Mail, Messages, other apps' data) are skipped.",
                           color: model.hasFullDiskAccess ? Theme.success : Theme.warning) {
                    Button("Open Settings") { model.openFullDiskAccessSettings() }.buttonStyle(.navyCompact)
                }
            }
        }
        .onAppear { model.refreshEnvironment() }
    }

    // MARK: - Signatures

    private var signaturesCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SectionTitle(text: "Malware signatures")
                SettingRow(symbol: "shield.checkered", title: "\(signatures.totalCount.formatted()) known threats",
                           detail: signatures.lastUpdated.map { "Last updated \($0.formatted(date: .abbreviated, time: .shortened)). Source: MalwareBazaar by abuse.ch." }
                               ?? "Not downloaded yet. Source: MalwareBazaar by abuse.ch.",
                           color: signatures.count > 0 ? Theme.success : Theme.warning) {
                    HStack {
                        Button("Re-download") { signatures.update(forceFull: true) }
                            .buttonStyle(.navyCompact).disabled(signatures.isUpdating)
                        Button(signatures.isUpdating ? "Updating…" : "Update Now") { signatures.update() }
                            .buttonStyle(NavyButtonStyle(kind: .primary, compact: true))
                            .disabled(signatures.isUpdating)
                    }
                }
                if !signatures.status.isEmpty {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(signatures.status).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                }
                if let error = signatures.lastError {
                    Notice(symbol: "xmark.octagon", text: error, color: Theme.danger)
                }
                Toggle("Update automatically twice a day", isOn: $autoUpdate)
                    .toggleStyle(.checkbox)
                    .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
            }
        }
    }

    // MARK: - ClamAV

    private var clamAVCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SectionTitle(text: "ClamAV engine (optional)")
                SettingRow(symbol: "cpu", title: model.clamAVReady ? "ClamAV is ready" : (model.clamAVInstalled ? "ClamAV needs its signatures" : "ClamAV isn't installed"),
                           detail: model.clamAVVersion ?? "A free, open-source engine with millions of extra signatures, including document and script malware. Agamemnon uses it as a second opinion when it's installed.",
                           color: model.clamAVReady ? Theme.success : Theme.textSecondary) {
                    Toggle("", isOn: $useClamAV).toggleStyle(.switch).labelsHidden()
                        .disabled(!model.clamAVInstalled)
                }
                if model.clamAVInstalled {
                    HStack {
                        Button(model.clamAVUpdating ? "Updating…" : "Update ClamAV Signatures") { model.updateClamAV() }
                            .buttonStyle(.navySecondary)
                            .disabled(model.clamAVUpdating)
                        if model.clamAVUpdating { ProgressView().controlSize(.small) }
                    }
                } else {
                    HStack(spacing: 10) {
                        Text("brew install clamav")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(Theme.text)
                            .padding(.horizontal, 10).padding(.vertical, 6)
                            .background(RoundedRectangle(cornerRadius: 6).fill(Theme.midnight))
                            .textSelection(.enabled)
                        Button(copied ? "Copied" : "Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString("brew install clamav", forType: .string)
                            copied = true
                        }
                        .buttonStyle(.navyCompact)
                        Button("Check Again") { model.refreshEnvironment() }.buttonStyle(.navyCompact)
                        Link("Get Homebrew", destination: URL(string: "https://brew.sh")!)
                            .font(.system(size: 12))
                    }
                }
                if let message = model.clamAVMessage {
                    Text(message).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                }
            }
        }
    }

    // MARK: - Exclusions

    private var exclusionsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    SectionTitle(text: "Exclusions")
                    Spacer()
                    Button("Add…", action: addExclusion).buttonStyle(.navyCompact)
                }
                Text("Files and folders here are never scanned. Only exclude things you trust.")
                    .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                if exclusions.isEmpty {
                    Text("No exclusions").font(.system(size: 12)).foregroundStyle(Theme.textTertiary)
                }
                ForEach(exclusions, id: \.self) { path in
                    HStack {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable().frame(width: 18, height: 18)
                        Text(path).font(.system(size: 12)).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Button { remove(path) } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.plain).foregroundStyle(Theme.textSecondary)
                    }
                }
            }
        }
    }

    private func addExclusion() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Exclude"
        if panel.runModal() == .OK {
            for url in panel.urls where !exclusions.contains(url.path) { exclusions.append(url.path) }
            Prefs.exclusionList = exclusions
        }
    }

    private func remove(_ path: String) {
        exclusions.removeAll { $0 == path }
        Prefs.exclusionList = exclusions
    }
}
