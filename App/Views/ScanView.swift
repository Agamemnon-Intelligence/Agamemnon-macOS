import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct ScanView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var scanner: ScanController
    @EnvironmentObject private var vault: QuarantineVault
    @State private var customTargets: [URL] = []
    @State private var dropTargeted = false
    @State private var showSkipped = false

    var body: some View {
        Page {
            PageHeader(title: "Scan", subtitle: "Check your Mac for known malware, including inside archives, installers and disk images.")

            if !model.hasFullDiskAccess {
                HStack {
                    Notice(symbol: "lock.trianglebadge.exclamationmark",
                           text: "Give Agamemnon Full Disk Access so it can scan protected folders like Mail, Messages and other apps' data.")
                    Button("Open Settings") { model.openFullDiskAccessSettings() }.buttonStyle(.navyCompact)
                }
            }

            if scanner.isScanning {
                progressCard
            } else {
                HStack(alignment: .top, spacing: 14) {
                    scanCard(.quick)
                    scanCard(.full)
                }
                customCard
            }

            if let error = vault.lastError {
                Notice(symbol: "xmark.octagon", text: error, color: Theme.danger)
            }

            results
        }
    }

    // MARK: - Start cards

    private func scanCard(_ kind: ScanKind) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                IconBadge(symbol: kind.symbol, size: 40)
                Text(kind.title).font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.text)
                Text(kind.summary).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button("Start \(kind.title)") { scanner.start(kind) }
                    .buttonStyle(kind == .quick ? NavyButtonStyle() : NavyButtonStyle(kind: .secondary))
            }
            .frame(maxWidth: .infinity, minHeight: 170, alignment: .topLeading)
        }
    }

    private var customCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    IconBadge(symbol: ScanKind.custom.symbol, size: 40)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Custom Scan").font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.text)
                        Text("Drop files or folders here, or choose them.")
                            .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    Button("Choose…", action: choose).buttonStyle(.navySecondary)
                    Button("Scan") { scanner.start(.custom, targets: customTargets) }
                        .buttonStyle(.navy)
                        .disabled(customTargets.isEmpty)
                }

                ZStack {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6, 5]))
                        .foregroundStyle(dropTargeted ? Theme.accent : Theme.stroke)
                        .background(RoundedRectangle(cornerRadius: 12).fill(dropTargeted ? Theme.navy.opacity(0.25) : Color.clear))
                    if customTargets.isEmpty {
                        VStack(spacing: 6) {
                            Image(systemName: "tray.and.arrow.down").font(.system(size: 22)).foregroundStyle(Theme.textTertiary)
                            Text("Drop a ZIP, DMG, PKG, app or folder").font(.system(size: 12)).foregroundStyle(Theme.textTertiary)
                        }
                        .padding(22)
                    } else {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(customTargets, id: \.self) { url in
                                HStack {
                                    Image(nsImage: NSWorkspace.shared.icon(forFile: url.path))
                                        .resizable().frame(width: 18, height: 18)
                                    Text(url.path).font(.system(size: 12)).foregroundStyle(Theme.text)
                                        .lineLimit(1).truncationMode(.middle)
                                    Spacer()
                                    Button {
                                        customTargets.removeAll { $0 == url }
                                    } label: { Image(systemName: "xmark.circle.fill") }
                                        .buttonStyle(.plain).foregroundStyle(Theme.textTertiary)
                                }
                            }
                        }
                        .padding(14)
                    }
                }
                .frame(minHeight: 90)
                .onDrop(of: [UTType.fileURL], isTargeted: $dropTargeted) { providers in
                    for provider in providers {
                        _ = provider.loadObject(ofClass: URL.self) { url, _ in
                            guard let url else { return }
                            Task { @MainActor in
                                if !customTargets.contains(url) { customTargets.append(url) }
                            }
                        }
                    }
                    return true
                }
            }
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.treatsFilePackagesAsDirectories = false
        panel.prompt = "Choose"
        panel.message = "Choose files or folders to scan"
        if panel.runModal() == .OK {
            for url in panel.urls where !customTargets.contains(url) { customTargets.append(url) }
        }
    }

    // MARK: - Progress

    private var progressCard: some View {
        Card(padding: 22) {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    IconBadge(symbol: scanner.kind?.symbol ?? "magnifyingglass", size: 40)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(scanner.kind?.title ?? "Scanning")
                            .font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.text)
                        Text(scanner.phase).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                    Button("Stop") { scanner.cancel() }.buttonStyle(.navyDestructive)
                }
                ProgressView().progressViewStyle(.linear).tint(Theme.accent)
                HStack(spacing: 28) {
                    metric("Files checked", scanner.filesScanned.formatted())
                    metric("Archives opened", scanner.archivesOpened.formatted())
                    metric("Threats", "\(scanner.detections.count)", color: scanner.detections.isEmpty ? Theme.text : Theme.danger)
                    if let started = scanner.startedAt {
                        TimelineView(.periodic(from: started, by: 1)) { context in
                            metric("Elapsed", Duration.seconds(context.date.timeIntervalSince(started)).formatted(.time(pattern: .hourMinuteSecond)))
                        }
                    }
                }
                Text(scanner.currentPath)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Theme.textTertiary)
                    .lineLimit(1).truncationMode(.middle)
            }
        }
    }

    private func metric(_ title: String, _ value: String, color: Color = Theme.text) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).font(.system(size: 18, weight: .bold).monospacedDigit()).foregroundStyle(color)
            Text(title).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
        }
    }

    // MARK: - Results

    @ViewBuilder
    private var results: some View {
        if !scanner.detections.isEmpty {
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        SectionTitle(text: scanner.isScanning ? "Found so far" : "Needs your decision")
                        Spacer()
                        if !scanner.isScanning {
                            Button("Quarantine All") { scanner.quarantineAll() }.buttonStyle(.navy)
                        }
                    }
                    ForEach(scanner.detections) { detection in
                        DetectionRow(detection: detection, actionsEnabled: !scanner.isScanning)
                        if detection.id != scanner.detections.last?.id { Divider().overlay(Theme.stroke) }
                    }
                }
            }
        } else if !scanner.isScanning, let summary = scanner.lastSummary {
            Card {
                HStack(spacing: 14) {
                    IconBadge(symbol: summary.detections == 0 ? "checkmark.shield.fill" : "lock.shield.fill",
                              color: summary.detections == 0 ? Theme.success : Theme.accent, size: 40)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(summary.detections == 0 ? "No threats found" : "\(summary.quarantined) threat\(summary.quarantined == 1 ? "" : "s") moved to quarantine")
                            .font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
                        Text("\(summary.kind.title)\(summary.cancelled ? " (stopped)" : "") · \(summary.finished.relative) · \(summary.filesScanned.formatted()) files · \(summary.archivesOpened.formatted()) archives opened")
                            .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                }
            }
        }

        if let note = scanner.clamAVNote {
            Notice(symbol: "exclamationmark.triangle", text: "ClamAV: \(note)")
        }

        if !scanner.skippedArchives.isEmpty && !scanner.isScanning {
            Card {
                DisclosureGroup(isExpanded: $showSkipped) {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(scanner.skippedArchives, id: \.self) { item in
                            Text(item).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                                .lineLimit(2).truncationMode(.middle)
                        }
                    }
                    .padding(.top, 8)
                } label: {
                    Text("\(scanner.skippedArchives.count) archive\(scanner.skippedArchives.count == 1 ? "" : "s") couldn't be opened (password-protected, damaged or too large)")
                        .font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textSecondary)
                }
            }
        }
    }
}

struct DetectionRow: View {
    @EnvironmentObject private var scanner: ScanController
    let detection: Detection
    var actionsEnabled = true

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            IconBadge(symbol: detection.level == .suspicious ? "exclamationmark.triangle.fill" : "ladybug.fill",
                      color: Theme.color(for: detection.level))
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(detection.fileName).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                    StatusPill(text: detection.level.label, color: Theme.color(for: detection.level))
                }
                Text("\(detection.threatName) · found by \(detection.engine)")
                    .font(.system(size: 12)).foregroundStyle(Theme.color(for: detection.level))
                Text(detection.displayPath)
                    .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                    .lineLimit(2).truncationMode(.middle)
                    .textSelection(.enabled)
            }
            Spacer()
            if actionsEnabled {
                Button("Ignore") { scanner.ignore(detection) }.buttonStyle(.navyCompact)
                Button("Quarantine") { scanner.quarantine(detection) }
                    .buttonStyle(NavyButtonStyle(kind: .primary, compact: true))
            }
        }
    }
}
