import Foundation
import Combine
import AppKit

struct DNSVariant: Identifiable, Hashable {
    let id: String
    let name: String
    let detail: String
    let blocksMalware: Bool
    let serverURL: String
    let addresses: [String]
}

struct DNSProvider: Identifiable, Hashable {
    let id: String
    let name: String
    let tagline: String
    let website: String
    let monogram: String
    let variants: [DNSVariant]
}

/// Turns on encrypted DNS (DNS-over-HTTPS) for the whole Mac.
///
/// macOS only lets apps change system-wide DNS through a configuration profile
/// (or a Network Extension that needs a special Apple entitlement). Agamemnon
/// writes a signed-by-nobody, open-source `.mobileconfig`, opens it, and takes
/// the user to System Settings › Device Management to approve it. Every profile
/// uses the same identifier, so switching provider replaces the old one.
@MainActor
final class DNSManager: ObservableObject {
    static let profileIdentifier = "com.mirazbakis.agamemnon.dns"

    static let providers: [DNSProvider] = [
        DNSProvider(id: "cloudflare", name: "Cloudflare", tagline: "Fastest public resolver, strong privacy promises.",
                    website: "https://one.one.one.one", monogram: "CF", variants: [
            DNSVariant(id: "cloudflare-security", name: "Malware blocking", detail: "1.1.1.2 · blocks malware",
                       blocksMalware: true, serverURL: "https://security.cloudflare-dns.com/dns-query",
                       addresses: ["1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002"]),
            DNSVariant(id: "cloudflare-standard", name: "Standard", detail: "1.1.1.1 · no filtering",
                       blocksMalware: false, serverURL: "https://cloudflare-dns.com/dns-query",
                       addresses: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]),
        ]),
        DNSProvider(id: "quad9", name: "Quad9", tagline: "Swiss non-profit. Blocks malware and phishing by default.",
                    website: "https://quad9.net", monogram: "Q9", variants: [
            DNSVariant(id: "quad9-secure", name: "Malware blocking", detail: "9.9.9.9 · blocks malware & phishing",
                       blocksMalware: true, serverURL: "https://dns.quad9.net/dns-query",
                       addresses: ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"]),
            DNSVariant(id: "quad9-unsecured", name: "Unfiltered", detail: "9.9.9.10 · no filtering",
                       blocksMalware: false, serverURL: "https://dns10.quad9.net/dns-query",
                       addresses: ["9.9.9.10", "149.112.112.10", "2620:fe::10", "2620:fe::fe:10"]),
        ]),
        DNSProvider(id: "mullvad", name: "Mullvad", tagline: "No logs, no account. Run by the Mullvad VPN team.",
                    website: "https://mullvad.net/help/dns-over-https-and-dns-over-tls", monogram: "MV", variants: [
            DNSVariant(id: "mullvad-base", name: "Ads, trackers & malware", detail: "base.dns.mullvad.net",
                       blocksMalware: true, serverURL: "https://base.dns.mullvad.net/dns-query",
                       addresses: ["194.242.2.4", "2a07:e340::4"]),
            DNSVariant(id: "mullvad-standard", name: "Unfiltered", detail: "dns.mullvad.net · no filtering",
                       blocksMalware: false, serverURL: "https://dns.mullvad.net/dns-query",
                       addresses: ["194.242.2.2", "2a07:e340::2"]),
        ]),
        DNSProvider(id: "adguard", name: "AdGuard", tagline: "Blocks ads, trackers, malware and phishing sites.",
                    website: "https://adguard-dns.io/public-dns.html", monogram: "AG", variants: [
            DNSVariant(id: "adguard-default", name: "Ads, trackers & malware", detail: "94.140.14.14 · default filtering",
                       blocksMalware: true, serverURL: "https://dns.adguard-dns.com/dns-query",
                       addresses: ["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"]),
            DNSVariant(id: "adguard-unfiltered", name: "Unfiltered", detail: "94.140.14.140 · no filtering",
                       blocksMalware: false, serverURL: "https://unfiltered.adguard-dns.com/dns-query",
                       addresses: ["94.140.14.140", "94.140.14.141", "2a10:50c0::1:ff", "2a10:50c0::2:ff"]),
        ]),
    ]

    /// The variant whose profile is installed (detected), or nil.
    @Published private(set) var activeVariantID: String?
    /// The variant the user last asked to install (waiting for approval in System Settings).
    @Published private(set) var pendingVariantID: String?
    @Published private(set) var isChecking = false
    @Published var message: String?

    private let pendingKey = "dns.pending"
    private var pollTimer: Timer?
    private var pollTicks = 0

    init() {
        pendingVariantID = UserDefaults.standard.string(forKey: pendingKey)
    }

    static func variant(_ id: String?) -> (DNSProvider, DNSVariant)? {
        guard let id else { return nil }
        for p in providers { if let v = p.variants.first(where: { $0.id == id }) { return (p, v) } }
        return nil
    }

    var activeDescription: String? {
        guard let match = DNSManager.variant(activeVariantID) else { return nil }
        return "\(match.0.name) · \(match.1.name)"
    }

    // MARK: - Install

    func install(_ provider: DNSProvider, _ variant: DNSVariant) {
        do {
            let url = try writeProfile(provider, variant)
            pendingVariantID = variant.id
            UserDefaults.standard.set(variant.id, forKey: pendingKey)
            NSWorkspace.shared.open(url)
            Task { @MainActor [weak self] in
                try? await Task.sleep(nanoseconds: 1_200_000_000)
                self?.openProfilesSettings()
            }
            message = "Almost done: in System Settings, double-click “Agamemnon Encrypted DNS” and click Install."
            ActivityLog.shared.add(.dns, "Encrypted DNS profile created", "\(provider.name) · \(variant.name)")
            startPolling()
        } catch {
            message = "Couldn't create the DNS profile: \(error.localizedDescription)"
        }
    }

    private func writeProfile(_ provider: DNSProvider, _ variant: DNSVariant) throws -> URL {
        let payload: [String: Any] = [
            "PayloadType": "com.apple.dnsSettings.managed",
            "PayloadIdentifier": DNSManager.profileIdentifier + ".settings",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
            "PayloadDisplayName": "\(provider.name) DNS over HTTPS",
            "DNSSettings": [
                "DNSProtocol": "HTTPS",
                "ServerURL": variant.serverURL,
                "ServerAddresses": variant.addresses,
            ] as [String: Any],
        ]
        let profile: [String: Any] = [
            "PayloadContent": [payload],
            "PayloadDisplayName": "Agamemnon Encrypted DNS",
            "PayloadDescription": "Encrypts every DNS lookup on this Mac using \(provider.name) (\(variant.name)). Created by Agamemnon. Remove it any time in System Settings › General › Device Management.",
            "PayloadIdentifier": DNSManager.profileIdentifier,
            "PayloadOrganization": "Agamemnon",
            "PayloadRemovalDisallowed": false,
            "PayloadScope": "System",
            "PayloadType": "Configuration",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
        let url = AppPaths.profiles.appendingPathComponent("Agamemnon Encrypted DNS (\(provider.name)).mobileconfig")
        try data.write(to: url, options: .atomic)
        return url
    }

    // MARK: - Remove

    func remove() {
        do {
            try Privileged.run("/usr/bin/profiles remove -identifier \(DNSManager.profileIdentifier)",
                               prompt: "Agamemnon needs your password to turn off encrypted DNS.")
            pendingVariantID = nil
            UserDefaults.standard.removeObject(forKey: pendingKey)
            message = "Encrypted DNS is off. Your Mac uses your network's DNS again."
            ActivityLog.shared.add(.dns, "Encrypted DNS turned off")
            refreshStatus()
        } catch Privileged.Failure.cancelled {
            // nothing
        } catch {
            message = "Remove “Agamemnon Encrypted DNS” in System Settings › General › Device Management."
            openProfilesSettings()
        }
    }

    func openProfilesSettings() {
        let urls = [
            "x-apple.systempreferences:com.apple.Profiles-Settings.extension",
            "x-apple.systempreferences:com.apple.preferences.configurationprofiles",
        ]
        for s in urls {
            if let url = URL(string: s), NSWorkspace.shared.open(url) { return }
        }
    }

    // MARK: - Status

    /// Reads installed profiles (system_profiler works without admin rights).
    func refreshStatus() {
        guard !isChecking else { return }
        isChecking = true
        Task {
            let output = await Task.detached(priority: .utility) {
                Shell.run("/usr/sbin/system_profiler", ["SPConfigurationProfileDataType"], timeout: 30).stdout
            }.value
            var found: String?
            if output.contains(DNSManager.profileIdentifier) {
                for provider in DNSManager.providers {
                    for variant in provider.variants where output.contains(variant.serverURL) {
                        found = variant.id
                    }
                }
                if found == nil { found = self.pendingVariantID }
            }
            let wasActive = self.activeVariantID
            self.activeVariantID = found
            if let found, found != wasActive, found == self.pendingVariantID {
                self.message = nil
                if let match = DNSManager.variant(found) {
                    ActivityLog.shared.add(.dns, "Encrypted DNS is on", "\(match.0.name) · \(match.1.name)")
                }
            }
            if found != nil && found == self.pendingVariantID { self.stopPolling() }
            self.isChecking = false
        }
    }

    /// After creating a profile, check every few seconds until the user approves it.
    private func startPolling() {
        pollTimer?.invalidate()
        pollTicks = 0
        pollTimer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.pollTicks += 1
                if self.pollTicks > 75 { self.stopPolling() }
                self.refreshStatus()
            }
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }
}
