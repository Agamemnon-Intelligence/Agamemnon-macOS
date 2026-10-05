import SwiftUI
import AppKit

struct QuarantineView: View {
    @EnvironmentObject private var vault: QuarantineVault
    @State private var confirmRestore: QuarantineItem?
    @State private var confirmDeleteAll = false
    @State private var message: String?

    var body: some View {
        Page {
            HStack(alignment: .bottom) {
                PageHeader(title: "Quarantine",
                           subtitle: "Threats are moved here and locked so they can't run. Restore anything you trust, or delete it for good.")
                if !vault.items.isEmpty {
                    Button("Delete All…") { confirmDeleteAll = true }.buttonStyle(.navyDestructive)
                }
            }

            if let message {
                Notice(symbol: "info.circle", text: message, color: Theme.accent)
            }
            if let error = vault.lastError {
                Notice(symbol: "xmark.octagon", text: error, color: Theme.danger)
            }

            if vault.items.isEmpty {
                Card(padding: 40) {
                    VStack(spacing: 10) {
                        Image(systemName: "archivebox")
                            .font(.system(size: 36)).foregroundStyle(Theme.textTertiary)
                        Text("Quarantine is empty").font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.text)
                        Text("When Agamemnon finds a threat, it'll be locked away here.")
                            .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                    .frame(maxWidth: .infinity)
                }
            } else {
                Card(padding: 0) {
                    VStack(spacing: 0) {
                        ForEach(vault.items) { item in
                            row(item)
                                .padding(16)
                            if item.id != vault.items.last?.id { Divider().overlay(Theme.stroke) }
                        }
                    }
                }
            }
        }
        .alert("Restore “\(confirmRestore?.name ?? "")”?", isPresented: Binding(
            get: { confirmRestore != nil },
            set: { if !$0 { confirmRestore = nil } })) {
            Button("Restore", role: .destructive) {
                if let item = confirmRestore { restore(item) }
                confirmRestore = nil
            }
            Button("Cancel", role: .cancel) { confirmRestore = nil }
        } message: {
            Text("It was flagged as \(confirmRestore?.threatName ?? "a threat"). Only restore it if you're sure it's safe.")
        }
        .alert("Delete everything in quarantine?", isPresented: $confirmDeleteAll) {
            Button("Delete All", role: .destructive) { vault.deleteAll() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This can't be undone.")
        }
    }

    private func row(_ item: QuarantineItem) -> some View {
        HStack(alignment: .top, spacing: 12) {
            IconBadge(symbol: item.isDirectory ? "app.badge" : "doc.badge.ellipsis",
                      color: Theme.color(for: item.level))
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(item.name).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                    StatusPill(text: item.level.label, color: Theme.color(for: item.level))
                }
                Text("\(item.threatName) · \(item.engine)")
                    .font(.system(size: 12)).foregroundStyle(Theme.color(for: item.level))
                Text(item.originalPath + (item.innerPath.map { " ▸ \($0)" } ?? ""))
                    .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                    .lineLimit(2).truncationMode(.middle)
                    .textSelection(.enabled)
                Text("\(item.date.formatted(date: .abbreviated, time: .shortened)) · \(item.size.fileSize)")
                    .font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
            }
            Spacer()
            Button("Restore…") { confirmRestore = item }.buttonStyle(.navyCompact)
            Button("Delete") {
                do { try vault.delete(item) } catch { message = error.localizedDescription }
            }
            .buttonStyle(NavyButtonStyle(kind: .destructive, compact: true))
        }
    }

    private func restore(_ item: QuarantineItem) {
        do {
            let url = try vault.restore(item)
            message = "Restored to \(url.path)."
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } catch {
            message = error.localizedDescription
        }
    }
}
