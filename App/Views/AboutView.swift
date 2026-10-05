import SwiftUI

struct AboutView: View {
    private var version: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "Version \(v) (\(b))"
    }

    var body: some View {
        Page {
            Card(padding: 30) {
                VStack(spacing: 12) {
                    Image("Emblem")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 170, height: 170)
                        .shadow(color: Theme.gold.opacity(0.3), radius: 24)
                    Text("Agamemnon")
                        .font(.system(size: 30, weight: .bold, design: .serif))
                        .foregroundStyle(Theme.text)
                    Text("Free, open-source antivirus for Mac")
                        .font(.system(size: 14)).foregroundStyle(Theme.textSecondary)
                    HStack(spacing: 8) {
                        StatusPill(text: version, color: Theme.accent)
                        StatusPill(text: "GPLv2", color: Theme.gold)
                        StatusPill(text: "Windows version in development", color: Theme.textSecondary)
                    }
                }
                .frame(maxWidth: .infinity)
            }

            SectionTitle(text: "Created by")
            HStack(spacing: 14) {
                CreatorCard(username: "mirazbakis")
                CreatorCard(username: "mertyesileducation")
            }

            SectionTitle(text: "Built with")
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    credit("MalwareBazaar by abuse.ch", "Known-malware hash list (CC0)", "https://bazaar.abuse.ch")
                    credit("ClamAV", "Optional second engine, by Cisco Talos (GPLv2)", "https://www.clamav.net")
                    credit("libarchive, hdiutil & pkgutil", "Archive, disk image and installer unpacking (built into macOS)", "https://www.libarchive.org")
                    credit("Cloudflare, Quad9, Mullvad & AdGuard", "Encrypted DNS providers", "https://quad9.net")
                    credit("The Sacrifice of Iphigenia", "Giovanni Battista Tiepolo — the emblem's painting (public domain)", "https://en.wikipedia.org/wiki/Giovanni_Battista_Tiepolo")
                }
            }

            Card {
                VStack(alignment: .leading, spacing: 8) {
                    Text("License").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                    Text("Agamemnon is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License, version 2. It comes with ABSOLUTELY NO WARRANTY. No antivirus catches everything: keep macOS up to date and only install software you trust.")
                        .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 16) {
                        Link("Source code", destination: URL(string: "https://github.com/mirazbakis/Agamemnon")!)
                        Link("GNU GPL v2", destination: URL(string: "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html")!)
                    }
                    .font(.system(size: 12))
                }
            }
        }
    }

    private func credit(_ name: String, _ detail: String, _ url: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                Text(detail).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
            }
            Spacer()
            Link(destination: URL(string: url)!) {
                Image(systemName: "arrow.up.right.square").foregroundStyle(Theme.textSecondary)
            }
        }
    }
}

struct CreatorCard: View {
    let username: String

    var body: some View {
        Link(destination: URL(string: "https://github.com/\(username)")!) {
            Card {
                HStack(spacing: 14) {
                    AsyncImage(url: URL(string: "https://github.com/\(username).png?size=128")) { image in
                        image.resizable().scaledToFill()
                    } placeholder: {
                        Image(systemName: "person.crop.circle.fill")
                            .resizable().foregroundStyle(Theme.textTertiary)
                    }
                    .frame(width: 52, height: 52)
                    .clipShape(Circle())
                    .overlay(Circle().strokeBorder(Theme.gold.opacity(0.6), lineWidth: 1.5))
                    VStack(alignment: .leading, spacing: 3) {
                        Text(username).font(.system(size: 15, weight: .bold)).foregroundStyle(Theme.text)
                        Text("Creator · @\(username) on GitHub").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    Image(systemName: "arrow.up.right").foregroundStyle(Theme.textTertiary)
                }
            }
        }
        .buttonStyle(.plain)
    }
}
