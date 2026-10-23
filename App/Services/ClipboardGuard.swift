import Foundation
import Combine
import AppKit

/// Paste-command guard. The most common way Mac stealers (AMOS, Odyssey, Poseidon…) get in
/// today isn't a download at all: a fake CAPTCHA, "fix" or installer page tells you to copy a
/// command and paste it into Terminal. This watches what's copied and warns before it's pasted
/// when it's a command that downloads and runs something, or hides what it does.
///
/// Only the text's shape is checked, on this Mac; nothing is stored or sent anywhere. On macOS
/// versions that ask before apps read the clipboard, Agamemnon only reads it when macOS
/// allows that without asking.
@MainActor
final class ClipboardGuard: ObservableObject {
    struct Warning: Identifiable, Hashable {
        let id = UUID()
        let date = Date()
        let preview: String
        let reason: String
    }

    @Published private(set) var isRunning = false
    @Published private(set) var warnings: [Warning] = []
    @Published private(set) var blockedByPrivacy = false

    private var timer: Timer?
    private var lastChange = NSPasteboard.general.changeCount

    func applyPreference() {
        if Prefs.bool(Prefs.clipboardGuard) { start() } else { stop() }
    }

    func start() {
        guard timer == nil else { return }
        lastChange = NSPasteboard.general.changeCount
        timer = Timer.scheduledTimer(withTimeInterval: 0.6, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
        isRunning = true
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        isRunning = false
    }

    private func tick() {
        let board = NSPasteboard.general
        guard board.changeCount != lastChange else { return }
        lastChange = board.changeCount
        // Copies made inside Agamemnon (log exports, paths) aren't checked.
        if NSApp.isActive { return }
        if #available(macOS 15.4, *) {
            // .ask would show a "Paste from…" prompt every time something is copied.
            if board.accessBehavior == .ask || board.accessBehavior == .alwaysDeny {
                blockedByPrivacy = true
                return
            }
        }
        blockedByPrivacy = false
        guard let text = board.string(forType: .string), text.count >= 12, text.count <= 64 * 1024 else { return }
        guard let reason = ClipboardGuard.assess(text) else { return }
        let preview = String(text.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160))
        warnings.insert(Warning(preview: preview, reason: reason), at: 0)
        if warnings.count > 20 { warnings.removeLast(warnings.count - 20) }
        Notifier.post("Don't paste that into Terminal",
                      "The text you just copied \(reason). Websites that ask you to paste commands like this are almost always installing malware.",
                      critical: true)
        ActivityLog.shared.add(.threat, "Dangerous command copied to the clipboard", preview)
    }

    nonisolated private static let fetchAndRun = try! NSRegularExpression(
        pattern: #"(curl|wget|nscurl)\b[^\n|;&]*(\|\s*(sudo\s+)?((ba|z|da|fi)?sh|python3?|perl|ruby|osascript|node)\b|(&&|;)\s*(chmod\s|open\s|(ba|z)?sh\s|\./|/tmp/|/private/tmp/|~/))"#,
        options: [.caseInsensitive])
    nonisolated private static let decodeAndRun = try! NSRegularExpression(
        pattern: #"(base64\s+(-d|-D|--decode)|xxd\s+-r|openssl\s+(enc\s+)?(-d\s+)?-?base64|rev\b)[^\n]*\|\s*(sudo\s+)?(ba|z)?sh\b|eval\s*["'(]?\$\(\s*(echo|printf)"#,
        options: [.caseInsensitive])
    nonisolated private static let hiddenOsascript = try! NSRegularExpression(
        pattern: #"osascript\s+-e\s+['"]?(do shell script|display dialog)|osascript\s+-l\s+javascript"#,
        options: [.caseInsensitive])
    nonisolated private static let quarantineStrip = try! NSRegularExpression(
        pattern: #"xattr\s+(-[a-z]*c|-[a-z]*d\s+com\.apple\.quarantine)[^\n]*(&&|;)[^\n]*(open|\./|sh\b)"#,
        options: [.caseInsensitive])
    nonisolated private static let ipDownload = try! NSRegularExpression(pattern: #"(curl|wget)\b[^\n]*https?://\d{1,3}(\.\d{1,3}){3}"#, options: [.caseInsensitive])

    /// Why a copied command is dangerous, or nil. Well-known installers (Homebrew, rustup, nvm…)
    /// fetched over HTTPS from their official sites are left alone.
    nonisolated static func assess(_ text: String) -> String? {
        let range = NSRange(text.startIndex..., in: text)
        let lower = text.lowercased()
        let trustedInstallers = ["raw.githubusercontent.com/homebrew/install", "sh.rustup.rs", "raw.githubusercontent.com/nvm-sh/",
                                 "get.docker.com", "install.python-poetry.org", "bun.sh/install", "deno.land/install",
                                 "astral.sh/uv", "ohmyz.sh", "claude.ai/install.sh", "tailscale.com/install.sh",
                                 "get.sdkman.io", "pyenv.run", "install.determinate.systems", "nixos.org/nix/install"]
        let isTrusted = trustedInstallers.contains { lower.contains($0) }
        if decodeAndRun.firstMatch(in: text, range: range) != nil {
            return "decodes a hidden command and runs it"
        }
        if ipDownload.firstMatch(in: text, range: range) != nil, fetchAndRun.firstMatch(in: text, range: range) != nil {
            return "downloads a program from a bare IP address and runs it"
        }
        if hiddenOsascript.firstMatch(in: text, range: range) != nil, lower.contains("curl") || lower.contains("password") {
            return "runs a hidden AppleScript"
        }
        if quarantineStrip.firstMatch(in: text, range: range) != nil {
            return "removes macOS's malware check from a file and opens it"
        }
        if !isTrusted, fetchAndRun.firstMatch(in: text, range: range) != nil {
            return "downloads a program from the internet and runs it straight away"
        }
        return nil
    }

    func clear() { warnings.removeAll() }
}
