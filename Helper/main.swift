import Foundation
import Darwin
import Security

// Agamemnon's protection helper: a small root background service (a LaunchDaemon) that
// installs from Settings ▸ Self-protection. It never stops or deletes anything itself; it only
// watches and reports to the app, which applies the usual safety rules before acting.
//
// 1. Watchdog: if Agamemnon disappears without being quit (malware killing it), it's started
//    again within seconds and the event is reported. Malware running as the user can't stop
//    the helper: it runs as root and launchd restarts it.
// 2. Live events through Apple's `eslogger` (Endpoint Security, needs Full Disk Access for the
//    helper): every new program the instant it starts, programs that aren't signed by a known
//    developer opening saved passwords, browser data, crypto wallets, notes or SSH keys, new
//    login items and launch agents, and XProtect detections.
// 3. Checks that Agamemnon.app itself hasn't been modified.
//
// Reports go to /Library/Application Support/Agamemnon/Helper/events.ndjson, which only root
// can write, so other programs can't fake or erase them.

setvbuf(stdout, nil, _IOLBF, 0)

let helperVersion = "3.1"
/// Bumped whenever the helper changes, so the app knows to restart an older running copy.
let helperBuild = 4
let stateDir = "/Library/Application Support/Agamemnon/Helper"
let eventsPath = stateDir + "/events.ndjson"
let statusPath = stateDir + "/status.json"

// Registered with SMAppService, the helper runs from inside the app bundle, so the app is
// wherever the helper is; the classic install passes --app instead.
var appPath = "/Applications/Agamemnon.app"
if let own = Bundle.main.executablePath, let range = own.range(of: ".app/Contents/MacOS/") {
    appPath = String(own[..<range.lowerBound]) + ".app"
}
var arguments = CommandLine.arguments.dropFirst().makeIterator()
while let arg = arguments.next() {
    if arg == "--app", let value = arguments.next() { appPath = value }
}
let appExecutable = appPath + "/Contents/MacOS/Agamemnon"

// MARK: - Output

let writeQueue = DispatchQueue(label: "helper.write")

func emit(_ event: [String: Any]) {
    var event = event
    event["time"] = Date().timeIntervalSince1970
    guard let data = try? JSONSerialization.data(withJSONObject: event), data.count < 16 * 1024 else { return }
    writeQueue.async {
        let fm = FileManager.default
        if let size = (try? fm.attributesOfItem(atPath: eventsPath))?[.size] as? NSNumber, size.intValue > 4 * 1024 * 1024 {
            try? fm.removeItem(atPath: eventsPath + ".1")
            try? fm.moveItem(atPath: eventsPath, toPath: eventsPath + ".1")
        }
        if !fm.fileExists(atPath: eventsPath) {
            fm.createFile(atPath: eventsPath, contents: nil, attributes: [.posixPermissions: 0o644])
        }
        guard let handle = FileHandle(forWritingAtPath: eventsPath) else { return }
        handle.seekToEndOfFile()
        handle.write(data + Data([0x0A]))
        try? handle.close()
    }
}

var esloggerState = "starting"
var restarts: [Date] = []

func writeStatus() {
    let status: [String: Any] = [
        "version": helperVersion, "build": helperBuild, "pid": getpid(), "updated": Date().timeIntervalSince1970,
        "eslogger": esloggerState, "app": appPath, "watchdogRestarts": restarts.count,
        "eventsPerMinute": streams.mapValues { $0.perMinute },
        "errors": streams.mapValues { $0.lastError },
    ]
    guard let data = try? JSONSerialization.data(withJSONObject: status) else { return }
    writeQueue.async { try? data.write(to: URL(fileURLWithPath: statusPath), options: .atomic) }
}

// MARK: - Processes

func allPIDs() -> [pid_t] {
    let count = proc_listallpids(nil, 0)
    guard count > 0 else { return [] }
    var pids = [pid_t](repeating: 0, count: Int(count) + 64)
    let filled = pids.withUnsafeMutableBufferPointer { proc_listallpids($0.baseAddress, Int32($0.count * MemoryLayout<pid_t>.size)) }
    return filled > 0 ? Array(pids.prefix(Int(filled))).filter { $0 > 0 } : []
}

func executablePath(_ pid: pid_t) -> String? {
    var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    return proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 ? String(cString: buffer) : nil
}

func uidOf(_ pid: pid_t) -> uid_t? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size ? info.pbi_uid : nil
}

/// The user at the screen (0 at the login window).
func consoleUser() -> (uid: uid_t, name: String, home: String)? {
    var st = stat()
    guard stat("/dev/console", &st) == 0, st.st_uid != 0, let pw = getpwuid(st.st_uid) else { return nil }
    return (st.st_uid, String(cString: pw.pointee.pw_name), String(cString: pw.pointee.pw_dir))
}

func agamemnonRunning(for uid: uid_t) -> Bool {
    allPIDs().contains { pid in
        guard let path = executablePath(pid), path.hasSuffix(".app/Contents/MacOS/Agamemnon") else { return false }
        return uidOf(pid) == uid
    }
}

// MARK: - Watchdog

var seenRunning: Set<uid_t> = []

func watchdog() {
    guard let user = consoleUser() else { return }
    if agamemnonRunning(for: user.uid) {
        seenRunning.insert(user.uid)
        return
    }
    // Only bring it back if it was running in this session (never start it on its own).
    guard seenRunning.contains(user.uid) else { return }
    seenRunning.remove(user.uid)
    // The app leaves this marker when it's quit normally (Quit menu, logout, shutdown).
    let marker = user.home + "/Library/Application Support/Agamemnon/.quit"
    if let modified = (try? FileManager.default.attributesOfItem(atPath: marker))?[.modificationDate] as? Date,
       Date().timeIntervalSince(modified) < 60 {
        emit(["type": "app-quit"])
        return
    }
    restarts = restarts.filter { Date().timeIntervalSince($0) < 600 }
    guard restarts.count < 5 else {
        emit(["type": "watchdog-gave-up", "reason": "Agamemnon stopped 5 times in 10 minutes"])
        return
    }
    restarts.append(Date())
    let open = Process()
    open.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    open.arguments = ["asuser", String(user.uid), "/usr/bin/sudo", "-u", user.name,
                      "/usr/bin/open", "-g", "-a", appPath, "--args", "--watchdog"]
    try? open.run()
    emit(["type": "relaunched", "reason": "Agamemnon stopped without being quit"])
}

// MARK: - App integrity

var appWasValid: Bool?

func checkAppIntegrity() {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: appPath) as CFURL, [], &code) == errSecSuccess, let code else { return }
    let valid = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), nil) == errSecSuccess
    if appWasValid == true && !valid {
        emit(["type": "app-modified", "path": appPath])
    }
    appWasValid = valid
}

// MARK: - Endpoint Security events (eslogger)

/// Files stealers go after, with a short category name.
let sensitiveMarkers: [(String, String)] = [
    ("/Library/Keychains/", "keychain"),
    ("/Login Data", "browser passwords"),
    ("/Cookies", "browser cookies"),
    ("/Web Data", "browser cards"),
    ("/logins.json", "browser passwords"),
    ("/key4.db", "browser passwords"),
    ("/cookies.sqlite", "browser cookies"),
    ("/Cookies.binarycookies", "browser cookies"),
    ("/Local Extension Settings/", "crypto wallets"),
    ("/Exodus/", "crypto wallets"),
    ("/Electrum/wallets", "crypto wallets"),
    ("/atomic/Local Storage", "crypto wallets"),
    ("/Ledger Live/", "crypto wallets"),
    ("/group.com.apple.notes/NoteStore.sqlite", "notes"),
    ("/Telegram Desktop/tdata", "Telegram session"),
    ("/.ssh/id_", "SSH keys"),
]
let markerBytes = sensitiveMarkers.map { Data($0.0.utf8) }
let quickMarkers = ["\"exec\"", "btm_launch_item_add", "xp_malware_detected", "tcc_modify", "\"create\"", "\"rename\""]
    .map { Data($0.utf8) }

// MARK: - On-access: files written anywhere

/// Folders whose files are never reported (system, caches, build output, package managers).
let skippedPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/private/var/db/", "/private/var/log/", "/Library/Caches/",
                       "/private/var/folders/", "/dev/", "/Library/Apple/", "/opt/homebrew/", "/usr/local/Cellar/",
                       "/Library/Application Support/Agamemnon/", "/private/var/protected/"]
let skippedParts = ["/Library/Caches/", "/Library/Developer/", "/DerivedData/", "/.git/", "/node_modules/", "/Library/Logs/",
                    "/Library/Containers/com.apple.", "/Library/Application Support/Agamemnon/", "/.Trash/", "/Library/Mail/",
                    "/Library/Metadata/", "/Library/Biome/", "/.cache/", "/__pycache__/", "/site-packages/", "/.npm/", "/.cargo/registry/"]
let riskyExtensions: Set<String> = ["app", "pkg", "mpkg", "dmg", "zip", "command", "tool", "sh", "zsh", "py", "scpt",
                                    "applescript", "jar", "dylib", "so", "plist", "7z", "rar", "iso", "workflow"]
var lastFileReport: [String: Date] = [:]

/// Mach-O, a script (#!), or a type that carries something runnable.
func isRunnable(_ path: String) -> Bool {
    let ext = (path as NSString).pathExtension.lowercased()
    if riskyExtensions.contains(ext) { return ext != "plist" || path.contains("/LaunchAgents/") || path.contains("/LaunchDaemons/") }
    guard let handle = FileHandle(forReadingAtPath: path) else { return false }
    defer { try? handle.close() }
    let head = handle.readData(ofLength: 4)
    guard head.count == 4 else { return false }
    let magic = head.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
    if [0xfeedfacf, 0xcffaedfe, 0xfeedface, 0xcefaedfe, 0xbebafeca].contains(magic) { return true }
    return head.starts(with: [0x23, 0x21])
}

func fileWritten(_ path: String, by process: [String: Any]) {
    guard path.hasPrefix("/"), !skippedPrefixes.contains(where: { path.hasPrefix($0) }),
          !skippedParts.contains(where: { path.contains($0) }) else { return }
    // Agamemnon's own work (quarantine, unpacking).
    let writer = describe(process)
    if writer.path.hasSuffix(".app/Contents/MacOS/Agamemnon") { return }
    if let last = lastFileReport[path], Date().timeIntervalSince(last) < 10 { return }
    guard isRunnable(path) else { return }
    lastFileReport[path] = Date()
    if lastFileReport.count > 5000 { lastFileReport.removeAll() }
    emit(["type": "new-file", "path": path, "by": writer.path])
}

/// System tools stealers drive. Opening secrets with these is reported; Apple's own apps and
/// background services (Safari, Spotlight, Time Machine…) are never reported.
let platformTools: Set<String> = ["osascript", "python3", "python", "curl", "sqlite3", "cp", "ditto", "zip", "security",
                                   "sh", "bash", "zsh", "perl", "ruby", "node", "cat", "base64", "tar", "rsync", "scp"]

func string(_ any: Any?) -> String? { any as? String }

/// The destination of a create or rename event: an existing file, or a folder plus a new name.
func destinationPath(_ event: [String: Any]) -> String? {
    let destination = dict(event["destination"])
    if let path = string(dict(destination["existing_file"])["path"]) { return path }
    let newPath = dict(destination["new_path"])
    if let dir = string(dict(newPath["dir"])["path"]), let name = string(newPath["filename"]) { return dir + "/" + name }
    return nil
}
func dict(_ any: Any?) -> [String: Any] { any as? [String: Any] ?? [:] }

func describe(_ process: [String: Any]) -> (path: String, pid: Int, platform: Bool, team: String?, ppid: Int) {
    let path = string(dict(process["executable"])["path"]) ?? ""
    let pid = dict(process["audit_token"])["pid"] as? Int ?? 0
    let platform = process["is_platform_binary"] as? Bool ?? false
    let team = string(process["team_id"]).flatMap { $0.isEmpty ? nil : $0 }
    let ppid = process["ppid"] as? Int ?? 0
    return (path, pid, platform, team, ppid)
}

var lastReported: [String: Date] = [:]

func handleEvent(_ line: Data) {
    // Most lines are file opens of nothing interesting; skip them before parsing JSON.
    let sensitive = markerBytes.contains { line.range(of: $0) != nil }
    guard sensitive || quickMarkers.contains(where: { line.range(of: $0) != nil }),
          let json = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { return }
    let event = dict(json["event"])

    if let exec = event["exec"] as? [String: Any] {
        let target = describe(dict(exec["target"]))
        // Only programs nobody vouches for; the app does the rest.
        guard !target.platform, target.team == nil, !target.path.isEmpty, target.pid > 0 else { return }
        emit(["type": "exec", "pid": target.pid, "path": target.path, "ppid": target.ppid])
        return
    }

    if let open = event["open"] as? [String: Any], sensitive {
        let file = string(dict(open["file"])["path"]) ?? ""
        guard let category = sensitiveMarkers.first(where: { file.contains($0.0) })?.1 else { return }
        let p = describe(dict(json["process"]))
        let name = (p.path as NSString).lastPathComponent
        let unvouched = !p.platform && p.team == nil
        let tool = p.platform && platformTools.contains(name)
        guard unvouched || tool, p.pid > 0 else { return }
        // Agamemnon itself (its scans read everything).
        if p.path.hasSuffix(".app/Contents/MacOS/Agamemnon") || p.path.hasPrefix(appPath) { return }
        let key = "\(p.pid)|\(category)"
        if let last = lastReported[key], Date().timeIntervalSince(last) < 30 { return }
        lastReported[key] = Date()
        if lastReported.count > 2000 { lastReported.removeAll() }
        emit(["type": "sensitive-open", "pid": p.pid, "ppid": p.ppid, "path": p.path, "file": file,
              "category": category, "signer": unvouched ? "unsigned" : "system-tool"])
        return
    }

    // New files: created, or moved into place (downloads are renamed from .crdownload/.download).
    if let change = (event["create"] ?? event["rename"]) as? [String: Any], let path = destinationPath(change) {
        let process = dict(json["process"])
        // A file that's just been created is usually still empty: look at it a moment later.
        let delay: TimeInterval = event["create"] != nil ? 2 : 0.2
        eventQueue.asyncAfter(deadline: .now() + delay) { fileWritten(path, by: process) }
        return
    }

    if let btm = event["btm_launch_item_add"] as? [String: Any] {
        let item = dict(btm["item"])
        let instigator = describe(dict(btm["instigator"]))
        emit(["type": "login-item", "item": string(item["item_url"]) ?? "", "app": string(item["app_url"]) ?? "",
              "executable": string(btm["executable_path"]) ?? "", "by": instigator.path])
        return
    }

    if let xp = event["xp_malware_detected"] as? [String: Any] {
        emit(["type": "xprotect", "malware": string(xp["malware_identifier"]) ?? "", "path": string(xp["detected_path"]) ?? "",
              "action": string(xp["detected_executable"]) ?? ""])
        return
    }

    if let tcc = event["tcc_modify"] as? [String: Any] {
        let instigator = describe(dict(tcc["instigator"]))
        guard !instigator.platform, instigator.team == nil else { return }
        emit(["type": "privacy-change", "service": string(tcc["service"]) ?? "", "identity": string(tcc["identity"]) ?? "",
              "by": instigator.path])
    }
}

/// Every event is handled on one queue, so the bookkeeping needs no locks.
let eventQueue = DispatchQueue(label: "helper.events", qos: .userInitiated)

/// One running `eslogger`. Two are used:
/// - "main": process starts, new files, login items, XProtect and privacy events, for every process;
/// - "files": file opens, but only by programs in places malware runs from (user folders,
///   temporary and shared folders, external drives) and the command-line tools stealers drive.
///   Everything macOS and signed apps open is ignored anyway, and leaving it out keeps the
///   helper's processor use low.
final class EventStream {
    let name: String
    let events: [String]
    let fallback: [String]?
    let select: [String]
    private var count = 0
    private var countSince = Date()
    private(set) var perMinute = 0
    /// eslogger's last error message, for the status file.
    private(set) var lastError = ""

    init(name: String, events: [String], fallback: [String]? = nil, select: [String] = []) {
        self.name = name; self.events = events; self.fallback = fallback; self.select = select
    }

    func counted() {
        count += 1
        let elapsed = Date().timeIntervalSince(countSince)
        if elapsed >= 60 { perMinute = Int(Double(count) * 60 / elapsed); count = 0; countSince = Date() }
    }

    func run(_ events: [String]? = nil) {
        let events = events ?? self.events
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/eslogger")
        process.arguments = select.flatMap { ["--select", $0] } + events
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        var buffer = Data()
        out.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { handle.readabilityHandler = nil; return }
            eventQueue.async {
                buffer.append(chunk)
                while let newline = buffer.firstIndex(of: 0x0A) {
                    let line = buffer[buffer.startIndex..<newline]
                    self.counted()
                    handleEvent(Data(line))
                    buffer.removeSubrange(buffer.startIndex...newline)
                }
                if buffer.count > 8 * 1024 * 1024 { buffer.removeAll() }
            }
        }
        let started = Date()
        do { try process.run() } catch {
            if name == "main" { esloggerState = "unavailable" }
            writeStatus()
            DispatchQueue.global().asyncAfter(deadline: .now() + 300) { self.run(events) }
            return
        }
        if name == "main" { esloggerState = "running" }
        writeStatus()
        DispatchQueue.global(qos: .utility).async {
            process.waitUntilExit()
            let raw = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            let message = raw.lowercased()
            self.lastError = String(raw.trimmingCharacters(in: .whitespacesAndNewlines).prefix(300))
            let quick = Date().timeIntervalSince(started) < 10
            if message.contains("not permitted") || message.contains("full disk access") || message.contains("not authorized") {
                if self.name == "main" { esloggerState = "needs-full-disk-access" }
            } else if quick, let fallback = self.fallback, events != fallback {
                // Older macOS doesn't know some of the newer event types.
                writeStatus()
                self.run(fallback)
                return
            } else if self.name == "main" {
                esloggerState = "stopped"
            }
            writeStatus()
            DispatchQueue.global().asyncAfter(deadline: .now() + (quick ? 60 : 5)) { self.run(events) }
        }
    }
}

let streams: [String: EventStream] = [
    "main": EventStream(name: "main",
                        events: ["exec", "create", "rename", "btm_launch_item_add", "xp_malware_detected", "tcc_modify"],
                        fallback: ["exec", "create", "rename"]),
    "files": EventStream(name: "files", events: ["open"],
                         select: ["/Users/", "/private/tmp/", "/tmp/", "/private/var/folders/", "/Volumes/",
                                  "/Library/Application Support/", "/usr/bin/", "/bin/", "/usr/local/bin/"]),
]

// MARK: - Updating itself

/// When Agamemnon is updated, the helper's program on disk changes; exit so launchd starts the new one.
let ownExecutable = Bundle.main.executablePath ?? CommandLine.arguments[0]
func fileIdentity(_ path: String) -> String? {
    var st = stat()
    guard stat(path, &st) == 0 else { return nil }
    return "\(st.st_ino)-\(st.st_mtimespec.tv_sec)"
}
let launchedIdentity = fileIdentity(ownExecutable)

func checkForNewerSelf() {
    let now = fileIdentity(ownExecutable)
    if now != launchedIdentity, now != nil {
        emit(["type": "helper-updated"])
        usleep(300_000)
        exit(0)
    }
    updateFromApp()
}

// MARK: - Updating the installed copy

/// The installed copy (in /Library/PrivilegedHelperTools) is replaced by the helper inside
/// Agamemnon.app when that one is different and signed by the same developer team. The new file
/// is copied to a root-only place first and checked there, so it can't be swapped after the
/// check. Unsigned (ad-hoc) helpers never update themselves this way.
let installedPath = "/Library/PrivilegedHelperTools/com.mirazbakis.Agamemnon.Helper"

func codeInfo(_ path: String) -> (team: String?, cdhash: Data?) {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else { return (nil, nil) }
    var info: CFDictionary?
    SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
    let dict = info as? [String: Any] ?? [:]
    return (dict[kSecCodeInfoTeamIdentifier as String] as? String, dict[kSecCodeInfoUnique as String] as? Data)
}

func satisfiesTeam(_ path: String, team: String) -> Bool {
    var code: SecStaticCode?
    var requirement: SecRequirement?
    let text = "identifier \"com.mirazbakis.Agamemnon.Helper\" and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
          SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else { return false }
    return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), requirement) == errSecSuccess
}

func updateFromApp() {
    guard ownExecutable == installedPath else { return }
    let bundled = appPath + "/Contents/MacOS/AgamemnonHelper"
    let mine = codeInfo(installedPath)
    guard let team = mine.team, FileManager.default.fileExists(atPath: bundled) else { return }
    let theirs = codeInfo(bundled)
    guard theirs.cdhash != nil, theirs.cdhash != mine.cdhash, theirs.team == team else { return }
    let staged = installedPath + ".new"
    try? FileManager.default.removeItem(atPath: staged)
    guard (try? FileManager.default.copyItem(atPath: bundled, toPath: staged)) != nil else { return }
    chown(staged, 0, 0)
    chmod(staged, 0o755)
    guard satisfiesTeam(staged, team: team) else {
        try? FileManager.default.removeItem(atPath: staged)
        emit(["type": "helper-update-refused", "reason": "The helper in Agamemnon.app isn't signed by the same team"])
        return
    }
    guard rename(staged, installedPath) == 0 else { try? FileManager.default.removeItem(atPath: staged); return }
    emit(["type": "helper-updated"])
    usleep(300_000)
    exit(0)   // launchd starts the new copy
}

// MARK: - Start

try? FileManager.default.createDirectory(atPath: stateDir, withIntermediateDirectories: true,
                                         attributes: [.posixPermissions: 0o755])
emit(["type": "helper-started", "version": helperVersion])
writeStatus()
streams["main"]?.run()
streams["files"]?.run()
checkAppIntegrity()

let selfUpdateTimer = DispatchSource.makeTimerSource(queue: .main)
selfUpdateTimer.schedule(deadline: .now() + 60, repeating: 60)
selfUpdateTimer.setEventHandler { checkForNewerSelf() }
selfUpdateTimer.resume()

let watchdogTimer = DispatchSource.makeTimerSource(queue: .main)
watchdogTimer.schedule(deadline: .now() + 3, repeating: 3)
watchdogTimer.setEventHandler { watchdog() }
watchdogTimer.resume()

let statusTimer = DispatchSource.makeTimerSource(queue: .main)
statusTimer.schedule(deadline: .now() + 10, repeating: 10)
statusTimer.setEventHandler { writeStatus() }
statusTimer.resume()

let integrityTimer = DispatchSource.makeTimerSource(queue: .global(qos: .background))
integrityTimer.schedule(deadline: .now() + 600, repeating: 600)
integrityTimer.setEventHandler { checkAppIntegrity() }
integrityTimer.resume()

signal(SIGTERM) { _ in
    emit(["type": "helper-stopped"])
    usleep(200_000)
    exit(0)
}

dispatchMain()
