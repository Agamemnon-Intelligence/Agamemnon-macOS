import Foundation

/// UserDefaults keys shared by the services and the SwiftUI views (@AppStorage).
enum Prefs {
    static let autoQuarantine = "autoQuarantine"
    static let scanArchives = "scanArchives"
    static let useClamAV = "useClamAV"
    static let downloadProtection = "downloadProtection"
    static let quarantineUnnotarized = "quarantineUnnotarized"
    static let adminAlerts = "adminAlerts"
    static let backgroundItemAlerts = "backgroundItemAlerts"
    static let autoUpdateSignatures = "autoUpdateSignatures"
    static let notifications = "notifications"
    static let exclusions = "exclusions"
    static let watchedFolders = "watchedFolders"
    static let onboardingDone = "onboardingDone"
    static let behaviorProtection = "behaviorProtection"
    static let behaviorAutoStop = "behaviorAutoStop"
    static let trustedPrograms = "trustedPrograms"
    static let urlhausProtection = "urlhausProtection"
    static let virusShare = "virusShare"
    static let patternRules = "patternRules"
    static let startupSweep = "startupSweep"
    static let browserProtection = "browserProtection"
    static let ransomwareShield = "ransomwareShield"
    static let ransomwareFolders = "ransomwareFolders"
    static let autoInstallClamAV = "autoInstallClamAV"
    static let clamAVAutoInstallTried = "clamAVAutoInstallTried"
    static let trustedExtensions = "trustedExtensions"

    static func registerDefaults() {
        UserDefaults.standard.register(defaults: [
            autoQuarantine: true,
            scanArchives: true,
            useClamAV: true,
            downloadProtection: true,
            quarantineUnnotarized: false,
            adminAlerts: true,
            backgroundItemAlerts: true,
            autoUpdateSignatures: true,
            notifications: true,
            behaviorProtection: true,
            behaviorAutoStop: true,
            urlhausProtection: true,
            virusShare: true,
            patternRules: true,
            startupSweep: true,
            browserProtection: true,
            ransomwareShield: true,
            autoInstallClamAV: true,
        ])
    }

    static func bool(_ key: String) -> Bool { UserDefaults.standard.bool(forKey: key) }

    static var exclusionList: [String] {
        get { UserDefaults.standard.stringArray(forKey: exclusions) ?? [] }
        set { UserDefaults.standard.set(newValue, forKey: exclusions) }
    }
}
