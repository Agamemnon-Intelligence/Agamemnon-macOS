import Foundation

/// Something a running program did that malware typically does.
struct BehaviorFinding: Hashable {
    enum Confidence: Hashable {
        /// Almost never done by legitimate software. Can be stopped automatically.
        case high
        /// Worth a warning, but legitimate tools do it too. Never acted on automatically.
        case medium
    }

    let rule: String
    let title: String
    let explanation: String
    /// The malware families known to do this, shown to the user.
    let families: String
    let confidence: Confidence
}

/// Rules that recognise what current Mac infostealers, backdoors, adware and miners do
/// once they run, which still works after they change their files to dodge hash lists.
///
/// The rules only look at a process's path and command line. They're kept narrow on
/// purpose: a false alarm on a developer tool is worse than no rule.
enum BehaviorRules {
    static func evaluate(_ process: RunningProcess, ancestors: [RunningProcess]) -> BehaviorFinding? {
        let name = process.name.lowercased()
        let cmd = process.commandLine.lowercased()
        let path = process.path.lowercased()

        // AMOS, FrigidStealer, Cuckoo, Banshee: a fake "System Preferences" dialog asking for
        // the login password, shown with AppleScript.
        if name == "osascript", cmd.contains("display dialog"), cmd.contains("hidden answer") {
            return BehaviorFinding(
                rule: "fake-password-prompt",
                title: "Fake password prompt",
                explanation: "A script showed a password box pretending to be macOS. Real system prompts never come from AppleScript.",
                families: "AMOS (Atomic Stealer), FrigidStealer, Banshee",
                confidence: .high)
        }

        // AMOS, FrigidStealer, Banshee: AppleScript copying browser cookies and saved logins,
        // Apple Notes or the keychain file into a folder to send off.
        if name == "osascript", stealsBrowserData(cmd) {
            return BehaviorFinding(
                rule: "script-data-theft",
                title: "A script is collecting your browser data",
                explanation: "An AppleScript is reading saved logins, cookies, notes or keychain files. That's what infostealers do before uploading them.",
                families: "AMOS (Atomic Stealer), FrigidStealer, Banshee",
                confidence: .high)
        }

        // SysJoker installs itself as ~/Library/MacOsServices/updateMacOs.
        if path.contains("/library/macosservices/") || name == "updatemacos" {
            return BehaviorFinding(
                rule: "sysjoker",
                title: "Backdoor posing as a macOS update",
                explanation: "A program is running from a folder that the SysJoker backdoor uses. Real macOS updates never run from your Library folder.",
                families: "SysJoker",
                confidence: CodeIdentity.of(process.path).isUnvouched ? .high : .medium)
        }

        // AMOS and relatives check the password they phished with `dscl -authonly`.
        if name == "dscl", cmd.contains("-authonly") {
            let fromUnvouched = ancestors.contains { isUserLandUnvouched($0) }
            return BehaviorFinding(
                rule: "password-check",
                title: "Checking your login password",
                explanation: "A program tested whether a password is your Mac login password, a step stealers take right after phishing it.",
                families: "AMOS (Atomic Stealer), Banshee",
                confidence: fromUnvouched ? .high : .medium)
        }

        // KeySteal, AMOS: pulling the browser's encryption key (to decrypt saved passwords and
        // cards) or dumping the whole keychain from the command line.
        if name == "security",
           cmd.contains("dump-keychain") || (cmd.contains("find-generic-password") && cmd.contains("safe storage")) {
            return BehaviorFinding(
                rule: "keychain-theft",
                title: "Reading browser passwords from the keychain",
                explanation: "A program asked the keychain for your browser's password key or tried to dump the whole keychain. Browsers never do this through the command line.",
                families: "KeySteal, AMOS (Atomic Stealer)",
                confidence: .high)
        }

        // AMOS, Banshee, FrigidStealer: zip up the loot in a temp folder and POST it to a bare IP.
        if name == "curl" || name == "wget",
           cmd.contains("@/tmp/") || cmd.contains("@/private/tmp/") || cmd.contains("@/private/var/folders/"),
           containsRawIPURL(cmd) {
            return BehaviorFinding(
                rule: "exfiltration",
                title: "Uploading collected files",
                explanation: "A program is uploading a file from a temporary folder straight to an IP address, which is how stealers send off stolen data.",
                families: "AMOS (Atomic Stealer), FrigidStealer, Banshee",
                confidence: .high)
        }

        // CoinMiner and friends: any process talking the Stratum mining protocol.
        if cmd.contains("stratum+tcp://") || cmd.contains("stratum+ssl://") || cmd.contains("stratum2+")
            || ["xmrig", "xmr-stak", "minerd", "cpuminer", "nbminer", "t-rex", "lolminer"].contains(name) {
            return BehaviorFinding(
                rule: "crypto-miner",
                title: "Cryptocurrency miner",
                explanation: "A program is mining cryptocurrency, which uses your Mac's processor and slows it down.",
                families: "CoinMiner, XMRig droppers",
                confidence: .high)
        }

        // BeaverTail and its InvisibleFerret backdoor (fake job interviews) run from these folders.
        if beaverTailMarkers.contains(where: { cmd.contains($0) || path.contains($0) }) {
            return BehaviorFinding(
                rule: "beavertail",
                title: "Fake job-interview malware",
                explanation: "A program is running from a hidden folder used by malware spread through fake job interviews and coding tests.",
                families: "BeaverTail, InvisibleFerret",
                confidence: .high)
        }

        // "Paste this in Terminal" (ClickFix) installs: a shell running something it downloads.
        if ["sh", "bash", "zsh", "dash"].contains(name), cmd.contains(" -c"), pipesDownloadIntoShell(cmd),
           !trustedInstallers.contains(where: { cmd.contains($0) }) {
            return BehaviorFinding(
                rule: "download-and-run",
                title: "Running a script straight from the internet",
                explanation: "A command downloaded a script and ran it without saving it first. Fake “fix” and “verify you're human” pages trick people into pasting commands like this.",
                families: "AMOS (ClickFix), Shlayer, Bundlore",
                confidence: .medium)
        }

        // SysJoker, Shlayer, Bundlore and droppers run unsigned programs from temp and shared folders.
        if isOddLocation(process.path), CodeIdentity.of(process.path).isUnvouched {
            return BehaviorFinding(
                rule: "odd-location",
                title: "Unsigned program running from a hidden or temporary folder",
                explanation: "Nobody has signed this program and it's running from a place where apps don't normally live.",
                families: "SysJoker, Shlayer, Bundlore, droppers",
                confidence: .medium)
        }

        return nil
    }

    private static func stealsBrowserData(_ cmd: String) -> Bool {
        let browsers = ["google/chrome", "bravesoftware", "microsoft edge", "firefox/profiles", "com.apple.safari",
                        "/library/cookies/", "opera software", "vivaldi"]
        let loot = ["login data", "cookies", "web data", "formhistory", "logins.json", "key4.db"]
        let touchesBrowser = browsers.contains { cmd.contains($0) } && loot.contains { cmd.contains($0) }
        let touchesOther = cmd.contains("notestore.sqlite") || cmd.contains("login.keychain")
        return touchesBrowser || touchesOther
    }

    static let beaverTailMarkers = ["/.n2/", "/.n3/", "/.pyp/", "/.npl"]

    /// Well-known official installers that use `curl … | sh`.
    static let trustedInstallers = [
        "raw.githubusercontent.com/homebrew/", "sh.rustup.rs", "bun.sh/install", "deno.land/install",
        "get.pnpm.io", "raw.githubusercontent.com/nvm-sh/", "install.python-poetry.org", "astral.sh/uv",
        "claude.ai/install", "get.docker.com", "ohmyz.sh", "raw.githubusercontent.com/ohmyzsh/",
    ]

    private static func pipesDownloadIntoShell(_ cmd: String) -> Bool {
        let downloads = cmd.contains("curl") || cmd.contains("wget")
        let pipes = ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "$(curl", "`curl"].contains { cmd.contains($0) }
        let decodes = (cmd.contains("base64 -d") || cmd.contains("base64 --decode") || cmd.contains("base64 -d")) &&
            ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"].contains { cmd.contains($0) }
        return (downloads && pipes) || decodes
    }

    private static let rawIP = try! NSRegularExpression(pattern: #"https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?(/|\s|$|")"#)

    static func containsRawIPURL(_ text: String) -> Bool {
        rawIP.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
    }

    /// Places where real apps don't run from.
    static func isOddLocation(_ path: String) -> Bool {
        let home = AppPaths.home.path
        if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") || path.hasPrefix("/Users/Shared/") { return true }
        // A hidden folder directly inside ~/Library (e.g. ~/Library/.helper/agent).
        let library = home + "/Library/"
        if path.hasPrefix(library) {
            let rest = path.dropFirst(library.count)
            if rest.hasPrefix(".") { return true }
        }
        return false
    }

    /// Installed by a package manager or a version manager: ad-hoc signed but not suspicious.
    static func isPackageManaged(_ path: String) -> Bool {
        let home = AppPaths.home.path
        let prefixes = ["/opt/homebrew/", "/usr/local/", "/opt/local/", "/nix/",
                        home + "/.nvm/", home + "/.pyenv/", home + "/.cargo/", home + "/.rustup/",
                        home + "/.local/", home + "/.bun/", home + "/.volta/", home + "/.deno/",
                        home + "/.rbenv/", home + "/.sdkman/", home + "/go/", home + "/.npm/",
                        home + "/Library/Developer/", "/Applications/Xcode"]
        return prefixes.contains { path.hasPrefix($0) }
    }

    /// Part of macOS (on the sealed system volume or in Apple's own folders).
    static func isSystemPath(_ path: String) -> Bool {
        ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/bin/", "/sbin/",
         "/Library/Apple/"].contains { path.hasPrefix($0) }
    }

    /// An unsigned or ad-hoc program in the user's space (not macOS, not a package manager).
    static func isUserLandUnvouched(_ process: RunningProcess) -> Bool {
        !isSystemPath(process.path) && !isPackageManaged(process.path)
            && CodeIdentity.of(process.path).isUnvouched
    }
}
