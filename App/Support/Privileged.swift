import Foundation

/// Runs a shell command with administrator rights, using the standard macOS
/// password prompt (AppleScript `do shell script … with administrator privileges`).
/// Only used when a threat sits somewhere the user can't write to.
enum Privileged {
    /// Set while Agamemnon itself is asking for admin rights, so the admin-access
    /// monitor doesn't warn about Agamemnon.
    static var isPrompting = false

    enum Failure: LocalizedError {
        case cancelled
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .cancelled: return "Administrator access was cancelled."
            case .failed(let message): return message
            }
        }
    }

    @MainActor
    static func run(_ command: String, prompt: String) throws {
        let escapedCommand = command
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let escapedPrompt = prompt
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"\(escapedCommand)\" with prompt \"\(escapedPrompt)\" with administrator privileges"
        guard let script = NSAppleScript(source: source) else { throw Failure.failed("Couldn't prepare the request.") }
        isPrompting = true
        defer { isPrompting = false }
        var error: NSDictionary?
        script.executeAndReturnError(&error)
        if let error {
            let code = error[NSAppleScript.errorNumber] as? Int ?? 0
            if code == -128 { throw Failure.cancelled }
            throw Failure.failed(error[NSAppleScript.errorMessage] as? String ?? "The command failed.")
        }
    }
}
