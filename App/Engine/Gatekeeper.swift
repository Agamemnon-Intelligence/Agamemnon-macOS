import Foundation

/// Asks macOS whether an app or installer would pass Gatekeeper
/// (signed by an identified developer and notarized by Apple).
enum Gatekeeper {
    struct Verdict {
        let accepted: Bool
        let reason: String
    }

    static func assess(_ url: URL) -> Verdict? {
        let ext = url.pathExtension.lowercased()
        let type: String
        switch ext {
        case "app": type = "execute"
        case "pkg", "mpkg": type = "install"
        default: return nil
        }
        let r = Shell.run("/usr/sbin/spctl", ["--assess", "--type", type, "-vv", url.path], timeout: 60)
        if r.timedOut { return nil }
        let text = (r.stderr + r.stdout).lowercased()
        if r.status == 0 { return Verdict(accepted: true, reason: "Notarized") }
        if text.contains("no usable signature") || text.contains("not signed") || text.contains("code object is not signed") {
            return Verdict(accepted: false, reason: "Unsigned app")
        }
        if text.contains("unnotarized") {
            return Verdict(accepted: false, reason: "Not notarized by Apple")
        }
        if text.contains("revoked") {
            return Verdict(accepted: false, reason: "Developer certificate revoked by Apple")
        }
        if text.contains("rejected") {
            return Verdict(accepted: false, reason: "Rejected by Gatekeeper")
        }
        return nil
    }
}
