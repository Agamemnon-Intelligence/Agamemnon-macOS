import Foundation

/// Agamemnon's built-in pattern rules: tell-tale strings and code of Mac malware families,
/// found inside scripts and unsigned programs. They catch new builds of a family that no
/// hash list has seen yet, before they run.
///
/// Rules only look at:
/// - scripts (shell, AppleScript, Python, JavaScript…), and
/// - programs (Mach-O) that nobody has signed, or that are only ad-hoc signed.
/// Apple-signed and Developer ID-signed programs are skipped: a match there is far more likely
/// to be a security tool than malware, and those programs can be revoked by Apple.
///
/// Every rule needs several strings together, so a single word never triggers it.
enum PatternRules {
    /// Some strings, at least `minimum` of which must appear.
    struct Group {
        let needles: [String]
        let minimum: Int
    }

    struct Rule {
        let id: String
        /// Shown as the threat name.
        let name: String
        /// Which kinds of file the rule applies to.
        let kinds: Set<FileKind>
        /// Every one of these must appear (all lower-case).
        let all: [String]
        /// Each group must also be satisfied.
        let groups: [Group]
        let level: ThreatLevel

        init(_ id: String, _ name: String, kinds: Set<FileKind> = [.script, .program],
             all: [String] = [], _ groups: Group..., level: ThreatLevel = .malicious) {
            self.id = id; self.name = name; self.kinds = kinds; self.all = all
            self.groups = groups; self.level = level
        }
    }

    private static func oneOf(_ needles: [String], _ minimum: Int = 1) -> Group { Group(needles: needles, minimum: minimum) }

    enum FileKind: Hashable { case script, program }

    static let maxScriptBytes = 4 * 1024 * 1024
    static let maxProgramBytes = 48 * 1024 * 1024

    private static let browsers = ["google/chrome", "bravesoftware", "microsoft edge", "vivaldi", "opera software",
                                   "com.operasoftware", "firefox/profiles", "yandex/yandexbrowser", "arc/user data", "chromium"]
    private static let browserLoot = ["login data", "cookies", "web data", "logins.json", "key4.db", "formhistory"]
    private static let exfil = ["curl", "http://", "https://", "ditto -c -k", "zip -r", "nsurlsession", "urlsession"]
    private static let tempFolders = ["/tmp/", "$tmpdir", "/users/shared/", "mktemp", "/private/var/folders/"]
    /// Places stealers post stolen files to: chat-app bots and webhooks rather than a server of their own.
    private static let dropChannels = ["discord.com/api/webhooks", "discordapp.com/api/webhooks",
                                       "api.telegram.org/bot", "/senddocument", "hooks.slack.com/services"]
    private static let walletApps = ["ledger live.app", "trezor suite.app", "exodus.app", "atomic wallet.app", "electrum.app"]

    static let rules: [Rule] = [
        Rule("fake-password-prompt", "MacOS.Stealer.PasswordPhish",
             all: ["display dialog", "hidden answer"],
             oneOf(["login data", "cookies", "web data", "login.keychain", "notestore.sqlite", "wallet", "-authonly", "/tmp/"], 2)),
        Rule("browser-loot", "MacOS.Stealer.BrowserData",
             oneOf(browsers, 3), oneOf(browserLoot, 2), oneOf(exfil)),
        Rule("wallets", "MacOS.Stealer.CryptoWallets",
             oneOf(BehaviorRules.walletMarkers, 3), oneOf(exfil)),
        Rule("vm-check", "MacOS.Stealer.SandboxEvasion",
             all: ["system_profiler"],
             oneOf(["qemu", "vmware", "virtualbox"]),
             oneOf(["display dialog", "login data", "wallet", "-authonly", "keychain"])),
        Rule("keychain-key", "MacOS.Stealer.BrowserKey",
             all: ["find-generic-password", "safe storage"], oneOf(["curl", "http://", "https://"]),
             level: .suspicious),
        Rule("dump-keychain", "MacOS.Stealer.KeychainDump",
             all: ["dump-keychain"], oneOf(["curl", "http://", "https://", "@/tmp/"])),
        Rule("miner", "MacOS.CoinMiner",
             oneOf(["stratum+tcp://", "stratum+ssl://", "stratum2+tcp://"]),
             oneOf(["xmrig", "randomx", "donate-level", "cryptonight", "--coin"])),
        Rule("shlayer", "MacOS.Dropper.Shlayer", kinds: [.script],
             all: ["openssl enc", "-base64", " -d"], oneOf(tempFolders), oneOf(["chmod", "open "])),
        Rule("gatekeeper-bypass", "MacOS.Dropper.GatekeeperBypass", kinds: [.script],
             all: ["curl", "xattr", "chmod +x"], oneOf(tempFolders), level: .suspicious),
        Rule("base64-pipe", "MacOS.Downloader.HiddenScript", kinds: [.script],
             oneOf(["base64 -d", "base64 --decode"]),
             oneOf(["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| osascript"]),
             level: .suspicious),
        Rule("reverse-shell", "MacOS.Backdoor.ReverseShell", kinds: [.script],
             all: ["/dev/tcp/"], oneOf(["bash -i", "sh -i", "exec 5<>", "0>&1"])),
        Rule("sysjoker", "MacOS.Backdoor.SysJoker",
             all: ["macosservices", "updatemacos"]),
        Rule("beavertail", "MacOS.Stealer.BeaverTail", kinds: [.script],
             all: ["local extension settings"],
             oneOf(["nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "hnfanknocfeofbddgcijnmhnfnkdnaad",
                  "ibnejdfjmmkpcnlpebklmnkoeoihofec", "fhbohimaelbohpjbbldcngcnapndodjp"], 2),
             oneOf(["/uploads", "pdown", "/.pyp", "solana_id", "/keys", "/clientdownload"])),
        Rule("tcc-tamper", "MacOS.Spyware.PrivacyTamper",
             all: ["tcc.db"], oneOf(["insert into access", "insert or replace into access", "replace into access"])),
        Rule("loot-upload", "MacOS.Stealer.Upload",
             oneOf(["@/tmp/", "@/private/var/folders/"]), oneOf(["curl", "wget"]),
             oneOf(["login data", "cookies", "keychain", "wallet", "notestore", "tdata"])),
        Rule("fake-apple-agent", "MacOS.Persistence.FakeAppleAgent", kinds: [.script],
             all: ["launchagents", "runatload", "com.apple."], oneOf(["/users/shared/", "/tmp/", "/library/."]),
             level: .suspicious),
        // AMOS / Atomic Stealer and its offshoots: notes, keychain and browser data zipped together.
        Rule("amos-grabber", "MacOS.Stealer.AMOS",
             oneOf(["notestore.sqlite", "group.com.apple.notes"]), oneOf(["login.keychain-db", "/keychains/"]),
             oneOf(browsers, 2), oneOf(["ditto -c -k", "zip -r", "/tmp/", "@/tmp/"])),
        // AMOS and others replace hardware-wallet apps with trojaned copies.
        Rule("wallet-app-swap", "MacOS.Stealer.WalletAppSwap",
             oneOf(walletApps), oneOf(["app.asar", "/contents/resources/"]),
             oneOf(["curl", "http://", "https://", "rm -rf", "ditto"]), oneOf(["killall", "pkill", "osascript", "rm -rf"])),
        // Python and Node stealers that post loot to a Discord webhook or a Telegram bot.
        Rule("chat-exfil", "MacOS.Stealer.ChatExfil",
             oneOf(dropChannels), oneOf(browserLoot + ["local storage/leveldb", "tdata", "wallet", ".ssh/id_", "login.keychain"], 2)),
        Rule("discord-token", "MacOS.Stealer.DiscordToken",
             all: ["local storage/leveldb"], oneOf(["discord", "discordcanary", "discordptb"]),
             oneOf(dropChannels + ["mfa\\.", "[\\w-]{24}", "dqw4w9wgxcq"])),
        Rule("telegram-session", "MacOS.Stealer.TelegramSession",
             all: ["tdata"], oneOf(["telegram desktop/tdata", "ru.keepcoder.telegram", "telegram desktop"]),
             oneOf(dropChannels + ["@/tmp/", "ditto -c -k", "zip -r"])),
        Rule("ssh-key-theft", "MacOS.Stealer.SSHKeys",
             oneOf([".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa"]), oneOf(dropChannels + ["@/tmp/", "@/private/var/folders/"])),
        // Clipboard "clippers" swap copied crypto addresses for the attacker's.
        Rule("crypto-clipper", "MacOS.Stealer.Clipper",
             oneOf(["pbpaste", "nspasteboard", "generalpasteboard", "pyperclip"]),
             oneOf(["pbcopy", "setstring", "pyperclip.copy", "clearcontents"]),
             oneOf(["^(bc1|[13])", "bc1[a-z0-9]", "0x[a-fa-f0-9]{40}", "^0x[a-f0-9]", "[13][a-km-za-hj-np-z1-9]{25,34}", "t[a-za-z0-9]{33}"], 2)),
        // Python reverse shell: a socket wired to a shell's input and output.
        Rule("python-reverse-shell", "MacOS.Backdoor.PythonReverseShell", kinds: [.script],
             all: ["socket", "os.dup2", ".connect("], oneOf(["pty.spawn", "\"/bin/sh\"", "\"/bin/bash\"", "\"/bin/zsh\"", "'/bin/sh'", "'/bin/bash'"])),
        // Turning off Apple's own protection before running something.
        Rule("disable-protection", "MacOS.Tamper.DisableProtection", kinds: [.script],
             oneOf(["spctl --master-disable", "spctl --global-disable", "com.apple.xprotect", "xprotectservice", "com.apple.mrt"]),
             oneOf(["curl", "launchctl unload", "launchctl bootout", "launchctl disable", "chmod +x"]),
             level: .suspicious),
        // Remote AppleScript: fetched from the internet and handed straight to osascript.
        Rule("remote-applescript", "MacOS.Downloader.RemoteAppleScript", kinds: [.script],
             all: ["curl"], oneOf(["| osascript", "|osascript", "osascript -e \"$(curl", "osascript -e \"$(/usr/bin/curl"]),
             level: .suspicious),
        // A program that adds itself to Login Items or a LaunchAgent and hides in a dot-folder.
        Rule("hidden-persistence", "MacOS.Persistence.HiddenAgent", kinds: [.script],
             oneOf(["launchagents/", "launchdaemons/", "make login item", "make new login item"]),
             oneOf(["runatload", "keepalive", "hidden:true", "hidden: true"]),
             oneOf(["/users/shared/.", "~/.", "$home/.", "/library/application support/."]),
             level: .suspicious),
    ]

    // MARK: - Matching

    /// What kind of file this is, if pattern rules apply to it.
    static func kind(of url: URL, size: Int64) -> FileKind? {
        guard size > 8 else { return nil }
        let ext = url.pathExtension.lowercased()
        let scriptExts: Set<String> = ["sh", "command", "tool", "zsh", "bash", "applescript", "scpt", "py", "js", "mjs", "cjs", "rb", "pl"]
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        let head = (try? handle.read(upToCount: 8)) ?? Data()
        try? handle.close()
        guard head.count >= 4 else { return nil }
        let magic = head.withUnsafeBytes { $0.load(as: UInt32.self) }
        let machO: Set<UInt32> = [0xfeedfacf, 0xcffaedfe, 0xfeedface, 0xcefaedfe, 0xcafebabe, 0xbebafeca]
        // Java class files start with CAFEBABE too. A universal binary follows it with a small
        // architecture count; a class file follows it with its version (major 45 or higher).
        if head.starts(with: [0xca, 0xfe, 0xba, 0xbe]) {
            guard head.count >= 8 else { return nil }
            let archCount = head.dropFirst(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            if archCount == 0 || archCount >= 30 { return nil }
        }
        if machO.contains(magic) { return size <= maxProgramBytes ? .program : nil }
        if head.starts(with: [0x23, 0x21]) || scriptExts.contains(ext) { return size <= maxScriptBytes ? .script : nil }
        return nil
    }

    /// The first rule that matches the file, or nil.
    /// Warning-level rules only look at small scripts: real droppers are tiny, and big
    /// bundles mention everything somewhere.
    static let maxSuspiciousScriptBytes: Int64 = 256 * 1024

    static func match(_ url: URL, kind: FileKind, size: Int64 = 0) -> Rule? {
        guard let raw = try? Data(contentsOf: url, options: .mappedIfSafe) else { return nil }
        let data = lowercasedASCII(raw)
        let bigScript = kind == .script && Int64(raw.count) > maxSuspiciousScriptBytes
        for rule in rules where rule.kinds.contains(kind) {
            if bigScript && rule.level == .suspicious { continue }
            if matches(rule, data) { return rule }
        }
        return nil
    }

    private static func matches(_ rule: Rule, _ data: Data) -> Bool {
        guard !rule.all.isEmpty || !rule.groups.isEmpty else { return false }
        for needle in rule.all where !contains(data, needle) { return false }
        for group in rule.groups {
            var hits = 0
            for needle in group.needles where contains(data, needle) {
                hits += 1
                if hits >= group.minimum { break }
            }
            if hits < group.minimum { return false }
        }
        return true
    }

    private static func contains(_ data: Data, _ needle: String) -> Bool {
        data.range(of: Data(needle.utf8)) != nil
    }

    /// Lower-cases ASCII letters only (binary content is left alone).
    private static func lowercasedASCII(_ data: Data) -> Data {
        var copy = data
        copy.withUnsafeMutableBytes { buffer in
            for i in buffer.indices where buffer[i] >= 65 && buffer[i] <= 90 { buffer[i] += 32 }
        }
        return copy
    }

    /// Runs the rules on a file, applying the signing guardrails. Returns a detection or nil.
    static func assess(_ url: URL, size: Int64, outer: URL, inner: String?, container: URL?) -> Detection? {
        // Package managers (Homebrew, pyenv, nvm…) install well-known tools; some of them
        // legitimately touch browser data (yt-dlp reading cookies, for example).
        if BehaviorRules.isPackageManaged(url.path) {
            return nil
        }
        guard let kind = kind(of: url, size: size) else { return nil }
        // Anything inside an app bundle that Apple or a Developer ID signed is sealed by that
        // signature (macOS refuses to run the app if it's changed), so it's judged by the
        // signature, hash list, ClamAV and behaviour instead.
        let bundle = BehaviorMonitor.quarantineTarget(for: url.path)
        if bundle != url.path, !CodeIdentity.of(bundle).isUnvouched { return nil }
        if kind == .program {
            if BehaviorRules.isSystemPath(url.path) { return nil }
            let identity = CodeIdentity.of(url.path)
            guard identity.isUnvouched else { return nil }
            // Every Agamemnon build contains these strings (they're its rules), including
            // older versions, so its own program is never judged by them.
            if identity.identifier == CodeIdentity.ownBundleID { return nil }
        }
        guard let rule = match(url, kind: kind, size: size) else { return nil }
        return Detection(fileURL: outer, innerPath: inner, threatName: rule.name, engine: "Agamemnon Patterns", level: rule.level)
    }
}
