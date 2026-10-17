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
    @AppStorage(Prefs.patternRules) private var patternRules = true
    @AppStorage(Prefs.urlhausProtection) private var urlhaus = true
    @AppStorage(Prefs.virusShare) private var virusShare = true
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
                    SettingRow(symbol: "text.magnifyingglass", title: "Pattern rules",
                               detail: "Recognises Mac stealers, backdoors, droppers and miners by their code, so new versions are caught even before anyone has listed them.") {
                        Toggle("", isOn: $patternRules).toggleStyle(.switch).labelsHidden()
                    }
                    SettingRow(symbol: "link.badge.plus", title: "Malware site list",
                               detail: urlhaus ? "\(signatures.urlhausCount.formatted()) live malware links from URLhaus by abuse.ch, updated every 6 hours. Used to judge downloads and stop programs fetching from them."
                                              : "Checks downloads against URLhaus, a public list of links spreading malware right now.") {
                        Toggle("", isOn: $urlhaus).toggleStyle(.switch).labelsHidden()
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
        .onChange(of: virusShare) { on in if on { signatures.updateVirusShare() } }
    }

    // MARK: - Signatures

    private var signaturesCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SectionTitle(text: "Malware signatures")
                SettingRow(symbol: "shield.checkered", title: "\(signatures.totalCount.formatted()) known threats",
                           detail: signatures.lastUpdated.map { "Last updated \($0.formatted(date: .abbreviated, time: .shortened)). Sources: MalwareBazaar by abuse.ch and VirusShare." }
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
                SettingRow(symbol: "square.stack.3d.down.right", title: "VirusShare hash lists",
                           detail: signatures.virusShareCount > 0
                               ? "\(signatures.virusShareCount.formatted()) extra malware fingerprints (MD5) from VirusShare.com, kept on disk and checked in the same pass as the others."
                               : "About 42 million extra malware fingerprints from VirusShare.com. The first download is about 1.4 GB and runs in the background.") {
                    Toggle("", isOn: $virusShare).toggleStyle(.switch).labelsHidden()
                }
                if !signatures.virusShareStatus.isEmpty {
                    HStack(spacing: 8) {
                        if signatures.virusShareUpdating { ProgressView().controlSize(.small) }
                        Text(signatures.virusShareStatus).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
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
                SectionTitle(text: "ClamAV engine")
                SettingRow(symbol: "cpu", title: model.clamAVReady ? "ClamAV is ready" : (model.clamAVInstalled ? "ClamAV needs its signatures" : "ClamAV isn't installed"),
                           detail: model.clamAVVersion ?? "A free, open-source engine by Cisco with millions of extra signatures, including document and script malware. Agamemnon installs it for you and uses it as a second opinion.",
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
                        Button(model.clamAVInstalling ? "Installing…" : "Install ClamAV") { model.installClamAV() }
                            .buttonStyle(NavyButtonStyle(kind: .primary, compact: false))
                            .disabled(model.clamAVInstalling)
                        if model.clamAVInstalling { ProgressView().controlSize(.small) }
                        Button("Check Again") { model.refreshEnvironment() }.buttonStyle(.navyCompact)
                    }
                    Text("Uses Homebrew if you have it. Otherwise Agamemnon downloads Cisco's official signed installer and asks for your password once.")
                        .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
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
