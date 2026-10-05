import SwiftUI

struct DNSView: View {
    @EnvironmentObject private var dns: DNSManager
    @State private var selectedVariant: [String: String] = [:]

    var body: some View {
        Page {
            PageHeader(title: "Encrypted DNS",
                       subtitle: "Hide the websites you visit from your network and internet provider, and block known malware and phishing domains.")

            statusCard

            LazyVGrid(columns: [GridItem(.flexible(), spacing: 14), GridItem(.flexible(), spacing: 14)], spacing: 14) {
                ForEach(DNSManager.providers) { provider in
                    providerCard(provider)
                }
            }

            Notice(symbol: "info.circle",
                   text: "macOS asks you to approve DNS changes yourself. After you click Turn On, System Settings opens: double-click “Agamemnon Encrypted DNS”, then click Install. A VPN that sets its own DNS takes priority while it's connected.",
                   color: Theme.accent)
        }
        .onAppear { dns.refreshStatus() }
    }

    private var statusCard: some View {
        Card {
            HStack(spacing: 14) {
                IconBadge(symbol: dns.activeVariantID != nil ? "lock.shield.fill" : "lock.open",
                          color: dns.activeVariantID != nil ? Theme.success : Theme.textSecondary, size: 44)
                VStack(alignment: .leading, spacing: 3) {
                    if let active = dns.activeDescription {
                        Text("Encrypted DNS is on").font(.system(size: 16, weight: .bold)).foregroundStyle(Theme.text)
                        Text(active).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    } else if let pending = DNSManager.variant(dns.pendingVariantID) {
                        Text("Waiting for your approval").font(.system(size: 16, weight: .bold)).foregroundStyle(Theme.text)
                        Text("Install the \(pending.0.name) profile in System Settings › General › Device Management.")
                            .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    } else {
                        Text("Encrypted DNS is off").font(.system(size: 16, weight: .bold)).foregroundStyle(Theme.text)
                        Text("Your Mac uses your network's DNS, which anyone on the network can read.")
                            .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    }
                    if let message = dns.message {
                        Text(message).font(.system(size: 12)).foregroundStyle(Theme.accent).padding(.top, 2)
                    }
                }
                Spacer()
                Button(dns.isChecking ? "Checking…" : "Check Again") { dns.refreshStatus() }
                    .buttonStyle(.navyCompact)
                    .disabled(dns.isChecking)
                if dns.pendingVariantID != nil && dns.activeVariantID == nil {
                    Button("Open Settings") { dns.openProfilesSettings() }.buttonStyle(.navyCompact)
                }
                if dns.activeVariantID != nil {
                    Button("Turn Off") { dns.remove() }
                        .buttonStyle(NavyButtonStyle(kind: .destructive, compact: true))
                }
            }
        }
    }

    private func providerCard(_ provider: DNSProvider) -> some View {
        let chosenID = selectedVariant[provider.id] ?? provider.variants.first?.id ?? ""
        let isActiveProvider = provider.variants.contains { $0.id == dns.activeVariantID }
        return Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    Text(provider.monogram)
                        .font(.system(size: 14, weight: .heavy, design: .rounded))
                        .foregroundStyle(.white)
                        .frame(width: 40, height: 40)
                        .background(Circle().fill(LinearGradient(colors: [Theme.navyHover, Theme.navy], startPoint: .top, endPoint: .bottom)))
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(provider.name).font(.system(size: 15, weight: .bold)).foregroundStyle(Theme.text)
                            if isActiveProvider { StatusPill(text: "Active", color: Theme.success) }
                        }
                        Text(provider.tagline).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                VStack(spacing: 6) {
                    ForEach(provider.variants) { variant in
                        Button {
                            selectedVariant[provider.id] = variant.id
                        } label: {
                            HStack(spacing: 10) {
                                Image(systemName: chosenID == variant.id ? "largecircle.fill.circle" : "circle")
                                    .foregroundStyle(chosenID == variant.id ? Theme.accent : Theme.textTertiary)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(variant.name).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                                    Text(variant.detail).font(.system(size: 11)).foregroundStyle(Theme.textTertiary)
                                }
                                Spacer()
                                if variant.blocksMalware {
                                    Image(systemName: "shield.checkered").foregroundStyle(Theme.success)
                                        .help("Blocks known malware and phishing domains")
                                }
                            }
                            .padding(8)
                            .background(RoundedRectangle(cornerRadius: 8).fill(chosenID == variant.id ? Theme.navy.opacity(0.35) : Color.clear))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                HStack {
                    Link("Website", destination: URL(string: provider.website)!)
                        .font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    Spacer()
                    Button(dns.activeVariantID == chosenID ? "Active" : "Turn On") {
                        if let variant = provider.variants.first(where: { $0.id == chosenID }) {
                            dns.install(provider, variant)
                        }
                    }
                    .buttonStyle(.navy)
                    .disabled(dns.activeVariantID == chosenID)
                }
            }
        }
    }
}
