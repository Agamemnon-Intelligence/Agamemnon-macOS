import SwiftUI
import AppKit
import ServiceManagement

// Cards on the Real-Time Protection page for self-protection, USB protection and the
// paste-command guard.

struct SelfProtectionCard: View {
    @EnvironmentObject private var protection: SelfProtection
    @EnvironmentObject private var onAccess: OnAccessScanner
    @AppStorage(Prefs.settingsLock) private var settingsLock = true
    @AppStorage(Prefs.onAccessScan) private var onAccessScan = true
    @AppStorage(Prefs.cloudLookup) private var cloudLookup = true

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "lock.shield.fill", title: "Self-protection",
                           detail: helperDetail, color: helperColor) {
                    helperButton
                }
                if case .running(let live) = protection.helperState, live == "needs-full-disk-access" {
                    Notice(symbol: "exclamationmark.triangle",
                           text: "Live file monitoring needs Full Disk Access. Click Grant Access, drag “com.mirazbakis.Agamemnon.Helper” from the Finder window into the list and switch it on. If it still says this after a minute, also add /usr/bin/eslogger (press ⌘⇧G in the file picker and type the path).",
                           color: Theme.warning)
                    HStack {
                        Spacer()
                        Button("Grant Access") { protection.openFullDiskAccessForHelper() }.buttonStyle(.navyCompact)
                    }
                }
                SettingRow(symbol: "bolt.shield.fill", title: "Scan files as they're saved",
                           detail: liveRunning
                               ? "Every program, script, installer and archive saved anywhere on your Mac is checked within seconds. \(onAccess.filesChecked.formatted()) checked so far."
                               : "Every program, script, installer and archive saved anywhere on your Mac is checked within seconds. Needs the helper with Full Disk Access.",
                           color: liveRunning && onAccessScan ? Theme.success : Theme.textSecondary) {
                    Toggle("", isOn: $onAccessScan).toggleStyle(.switch).labelsHidden()
                }
                SettingRow(symbol: "icloud.and.arrow.down", title: "Cloud check",
                           detail: AbuseCH.hasKey
                               ? "Unsigned programs that run or are saved are looked up in MalwareBazaar's live database, which knows new malware hours before the downloadable lists. Only the file's fingerprint is sent, never the file."
                               : "Looks up unsigned programs in MalwareBazaar's live database (fingerprints only). This one needs the optional abuse.ch Auth-Key in Settings.",
                           color: cloudLookup && AbuseCH.hasKey ? Theme.success : Theme.textSecondary) {
                    Toggle("", isOn: $cloudLookup).toggleStyle(.switch).labelsHidden()
                }
                if !onAccess.findings.isEmpty {
                    ForEach(onAccess.findings.prefix(4)) { f in
                        HStack(alignment: .top) {
                            Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(Theme.danger)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(f.threat).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                                Text("\(f.outcome) · \(f.path)").font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                        }
                    }
                }
                SettingRow(symbol: "slider.horizontal.below.square.and.square.filled", title: "Lock Agamemnon's settings",
                           detail: "Protection switches, exclusions and trusted programs can only be changed here. If a script changes them behind Agamemnon's back, the change is undone and you're told.",
                           color: Theme.accent) {
                    Toggle("", isOn: $settingsLock).toggleStyle(.switch).labelsHidden()
                }
                if let message = protection.message {
                    Text(message).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                }
                if !protection.tamperEvents.isEmpty {
                    Divider().overlay(Theme.stroke)
                    SectionTitle(text: "Tamper attempts")
                    ForEach(protection.tamperEvents, id: \.self) { line in
                        Text(line).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    }
                }
            }
        }
    }

    private var liveRunning: Bool {
        if case .running(let live) = protection.helperState { return live == "running" }
        return false
    }

    private var helperDetail: String {
        let base = "A small background helper that runs as administrator. It restarts Agamemnon if malware kills it, checks Agamemnon hasn't been modified, and uses Apple's Endpoint Security to see new programs the instant they start and catch stealers opening your passwords, browser data and wallets."
        switch protection.helperState {
        case .notInstalled: return base
        case .needsApproval: return "Waiting for your OK: turn on Agamemnon in System Settings ▸ General ▸ Login Items ▸ Allow in the Background."
        case .starting: return "Starting the helper…"
        case .running(let live):
            switch live {
            case "running": return "Running. Agamemnon is guarded, and live file monitoring is on."
            case "needs-full-disk-access": return "Running and guarding Agamemnon. Live file monitoring is waiting for Full Disk Access."
            default: return "Running and guarding Agamemnon. Live file monitoring: \(live)."
            }
        case .stopped: return "The helper isn't responding. Something may have stopped it: reinstall it."
        }
    }

    private var helperColor: Color {
        switch protection.helperState {
        case .running(let live): return live == "running" ? Theme.success : Theme.warning
        case .stopped: return Theme.danger
        case .starting: return Theme.accent
        case .notInstalled: return Theme.textSecondary
        case .needsApproval: return Theme.warning
        }
    }

    @ViewBuilder private var helperButton: some View {
        switch protection.helperState {
        case .needsApproval:
            Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
                .buttonStyle(NavyButtonStyle(kind: .primary, compact: true))
        case .notInstalled, .stopped:
            Button(protection.busy ? "Installing…" : "Install Helper") { protection.installHelper() }
                .buttonStyle(NavyButtonStyle(kind: .primary, compact: true))
                .disabled(protection.busy)
        default:
            Button("Remove") { protection.removeHelper() }
                .buttonStyle(.navyCompact)
                .disabled(protection.busy)
        }
    }
}

struct USBCard: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var usb: USBGuard
    @AppStorage(Prefs.usbProtection) private var enabled = true
    @AppStorage(Prefs.usbAutoEject) private var autoEject = true

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "externaldrive.fill.badge.checkmark", title: "USB protection",
                           detail: "Checks every USB stick, SD card and external drive the moment it's connected: programs, scripts, apps, installers and archives, plus files disguised as documents. Also watches for BadUSB sticks that pretend to be a keyboard and type commands.",
                           color: usb.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $enabled).toggleStyle(.switch).labelsHidden()
                }
                SettingRow(symbol: "eject.fill", title: "Eject drives with malware",
                           detail: "After moving the malware to quarantine, the drive is ejected so nothing else on it gets opened by accident.",
                           color: Theme.accent) {
                    Toggle("", isOn: $autoEject).toggleStyle(.switch).labelsHidden()
                }
                .disabled(!enabled)
                if !usb.drives.isEmpty || !usb.keyboards.isEmpty {
                    Divider().overlay(Theme.stroke)
                    HStack {
                        SectionTitle(text: "Recently connected")
                        Spacer()
                        Button("Clear") { usb.clear() }.buttonStyle(.navyCompact)
                    }
                    ForEach(usb.keyboards.prefix(4)) { k in
                        row(symbol: "keyboard", title: k.name, detail: k.verdict, date: k.date,
                            color: k.dangerous ? Theme.danger : Theme.textSecondary)
                    }
                    ForEach(usb.drives.prefix(6)) { d in
                        HStack(alignment: .top) {
                            row(symbol: "externaldrive", title: d.name, detail: d.verdict, date: d.date,
                                color: d.threats > 0 ? Theme.danger : Theme.textSecondary)
                            if d.threats > 0, !d.ejected, FileManager.default.fileExists(atPath: d.path) {
                                Button("Eject") { usb.eject(d) }.buttonStyle(.navyCompact)
                            }
                        }
                    }
                }
            }
        }
        .onChange(of: enabled) { _ in model.preferencesChanged() }
    }

    private func row(symbol: String, title: String, detail: String, date: Date, color: Color) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol).foregroundStyle(color).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                Text(detail).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
            }
            Spacer()
            Text(date.relative).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
        }
    }
}

struct ClipboardCard: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var clipboard: ClipboardGuard
    @AppStorage(Prefs.clipboardGuard) private var enabled = true

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "doc.on.clipboard.fill", title: "Paste-command guard",
                           detail: "Fake “verify you're human” and “fix this error” pages trick people into pasting a malware installer into Terminal. Agamemnon warns you the moment you copy a command like that. Nothing you copy leaves your Mac.",
                           color: clipboard.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $enabled).toggleStyle(.switch).labelsHidden()
                }
                if clipboard.blockedByPrivacy {
                    Notice(symbol: "hand.raised", text: "macOS asks before apps read the clipboard, so this guard is paused. Allow Agamemnon to paste in System Settings ▸ Privacy & Security ▸ Paste from Other Apps.",
                           color: Theme.warning)
                }
                if !clipboard.warnings.isEmpty {
                    Divider().overlay(Theme.stroke)
                    HStack {
                        SectionTitle(text: "Warnings")
                        Spacer()
                        Button("Clear") { clipboard.clear() }.buttonStyle(.navyCompact)
                    }
                    ForEach(clipboard.warnings.prefix(5)) { w in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(w.reason.capitalizedFirst).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                            Text(w.preview).font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.textTertiary)
                                .lineLimit(2).truncationMode(.middle)
                        }
                    }
                }
            }
        }
        .onChange(of: enabled) { _ in model.preferencesChanged() }
    }
}

struct PrivacyCard: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var privacy: PrivacyMonitor
    @AppStorage(Prefs.cameraMicAlerts) private var enabled = true

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "video.badge.ellipsis", title: "Camera & microphone alerts",
                           detail: "Tells you whenever your camera or microphone switches on, and which app was in front, so spyware can't watch or listen quietly. Agamemnon never sees or hears anything itself.",
                           color: privacy.isRunning ? Theme.success : Theme.warning) {
                    Toggle("", isOn: $enabled).toggleStyle(.switch).labelsHidden()
                }
                if !privacy.events.isEmpty {
                    Divider().overlay(Theme.stroke)
                    HStack {
                        SectionTitle(text: "Recent use")
                        Spacer()
                        Button("Clear") { privacy.clear() }.buttonStyle(.navyCompact)
                    }
                    ForEach(privacy.events.prefix(6)) { e in
                        HStack {
                            Image(systemName: e.device == "Camera" ? "video.fill" : "mic.fill")
                                .foregroundStyle(e.ended == nil ? Theme.warning : Theme.textSecondary).frame(width: 18)
                            Text("\(e.device) · \(e.app)").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                            Spacer()
                            Text(e.ended == nil ? "On now" : e.date.relative).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                        }
                    }
                }
            }
        }
        .onChange(of: enabled) { _ in model.preferencesChanged() }
    }
}

struct SoftwareUpdatesCard: View {
    @EnvironmentObject private var updater: SoftwareUpdater

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                SettingRow(symbol: "arrow.down.app.fill",
                           title: updater.lastRun == nil ? "Software updates" : (updater.outdated.isEmpty ? "Your software is up to date" : "\(updater.outdated.count) update\(updater.outdated.count == 1 ? "" : "s") waiting"),
                           detail: updater.lastRun.map { "Checked \($0.relative): macOS, Homebrew and \(updater.checkedApps) apps that update themselves. Out-of-date apps are a common way in for malware." }
                               ?? "Finds out-of-date apps, Homebrew software and macOS updates. Attackers use the security holes that updates fix.",
                           color: updater.lastRun == nil ? Theme.textSecondary : (updater.outdated.isEmpty ? Theme.success : Theme.warning)) {
                    HStack {
                        if updater.isRunning { ProgressView().controlSize(.small) }
                        Button(updater.isRunning ? "Checking…" : "Check Now") { updater.run() }
                            .buttonStyle(.navyCompact).disabled(updater.isRunning)
                    }
                }
                ForEach(updater.outdated) { item in
                    HStack {
                        Image(systemName: item.source == .homebrew ? "mug" : (item.source == .macOS ? "apple.logo" : "app.badge"))
                            .foregroundStyle(Theme.warning).frame(width: 18)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.name).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                            Text(item.source == .homebrew ? "\(item.installed) → \(item.available) · run: brew upgrade \(item.name)"
                                                          : "\(item.installed) → \(item.available)")
                                .font(.system(size: 11)).foregroundStyle(Theme.textTertiary).textSelection(.enabled)
                        }
                        Spacer()
                        if item.source != .homebrew {
                            Button(item.source == .macOS ? "Update…" : "Open") { updater.open(item) }.buttonStyle(.navyCompact)
                        }
                    }
                }
            }
        }
    }
}

/// Shown at the top of the Overview when a newer Agamemnon is out.
struct AgamemnonUpdateBanner: View {
    @EnvironmentObject private var updater: AgamemnonUpdater

    var body: some View {
        switch updater.state {
        case .available(let release):
            Card {
                HStack(spacing: 14) {
                    IconBadge(symbol: "arrow.down.circle.fill", color: Theme.accent, size: 40)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Agamemnon \(release.version) is available").font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                        Text("You have \(updater.currentVersion). Updating takes a few seconds and keeps your settings, quarantine and signatures.")
                            .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    Button("What's New") { NSWorkspace.shared.open(release.page) }.buttonStyle(.navyCompact)
                    Button("Update Now") { updater.install() }.buttonStyle(NavyButtonStyle(kind: .primary, compact: true))
                }
            }
        case .downloading, .installing:
            Card {
                HStack(spacing: 12) {
                    ProgressView().controlSize(.small)
                    Text(updater.state == .downloading ? "Downloading and checking the update…" : "Installing the update…")
                        .font(.system(size: 13)).foregroundStyle(Theme.text)
                }
            }
        default:
            EmptyView()
        }
    }
}

struct AgamemnonUpdateCard: View {
    @EnvironmentObject private var updater: AgamemnonUpdater

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                SectionTitle(text: "Agamemnon updates")
                SettingRow(symbol: "arrow.triangle.2.circlepath.circle.fill", title: title, detail: detail, color: color) {
                    HStack {
                        if updater.state == .checking || updater.state == .downloading || updater.state == .installing {
                            ProgressView().controlSize(.small)
                        }
                        if updater.available != nil {
                            Button("Update Now") { updater.install() }.buttonStyle(NavyButtonStyle(kind: .primary, compact: true))
                        } else {
                            Button("Check Now") { updater.check() }.buttonStyle(.navyCompact)
                                .disabled(updater.state == .checking)
                        }
                    }
                }
            }
        }
    }

    private var title: String {
        switch updater.state {
        case .available(let r): return "Version \(r.version) is available"
        case .upToDate: return "Agamemnon \(updater.currentVersion) is up to date"
        case .checking: return "Checking for updates…"
        case .downloading: return "Downloading the update…"
        case .installing: return "Installing the update…"
        case .failed: return "Update problem"
        case .idle: return "Agamemnon \(updater.currentVersion)"
        }
    }

    private var detail: String {
        if case .failed(let message) = updater.state { return message }
        let checked = updater.lastChecked.map { " Last checked \($0.relative)." } ?? ""
        return "Agamemnon checks its official GitHub release page once a day and offers new versions here and in a notification. Updates are only installed after their signature is checked." + checked
    }

    private var color: Color {
        switch updater.state {
        case .available: return Theme.accent
        case .failed: return Theme.warning
        case .upToDate: return Theme.success
        default: return Theme.textSecondary
        }
    }
}
