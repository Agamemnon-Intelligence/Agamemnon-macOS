import Foundation
import Combine
import AppKit
import DiskArbitration
import IOKit
import IOKit.hid

/// USB protection. Macs never run anything from a drive automatically, so USB attacks on a
/// Mac come in two forms, and both are covered:
///
/// 1. **Infected drives.** When an external drive (USB stick, SD card, external disk) is
///    plugged in, every program, script, app, installer and archive on it is checked with all
///    engines, and tricks aimed at getting you to double-click are flagged: apps disguised as
///    documents (`Photos.jpg.app`), hidden apps, and Terminal scripts (`.command`) at the top
///    of the drive. Malware is quarantined, and the drive can be ejected automatically.
/// 2. **BadUSB / "Rubber Ducky" devices**: a stick that pretends to be a keyboard and types
///    commands. Agamemnon notices every new USB keyboard, recognises well-known attack
///    boards, and warns loudly when a new keyboard is followed within seconds by Terminal,
///    a shell or a download tool starting.
///
/// Neither needs extra permissions (no Input Monitoring: keystrokes are never read).
@MainActor
final class USBGuard: ObservableObject {
    struct DriveEvent: Identifiable, Hashable {
        let id = UUID()
        let date = Date()
        let name: String
        let path: String
        var verdict: String
        var threats: Int = 0
        var ejected = false
    }

    struct KeyboardEvent: Identifiable, Hashable {
        let id = UUID()
        let date = Date()
        let name: String
        let vendorID: Int
        let productID: Int
        var verdict: String
        var dangerous: Bool
    }

    @Published private(set) var isRunning = false
    @Published private(set) var drives: [DriveEvent] = []
    @Published private(set) var keyboards: [KeyboardEvent] = []

    private let vault: QuarantineVault
    private var mountObserver: NSObjectProtocol?
    private var hidPort: IONotificationPortRef?
    private var hidIterator: io_iterator_t = 0
    private var knownKeyboards: Set<UInt64> = []
    private var enumerated = false
    private var watchTimer: Timer?
    private var watchUntil = Date.distantPast
    private var watchKeyboard: String?
    private var processesBefore: Set<String> = []
    private let queue = DispatchQueue(label: "agamemnon.usb", qos: .userInitiated)

    init(vault: QuarantineVault) {
        self.vault = vault
    }

    func applyPreference() {
        if Prefs.bool(Prefs.usbProtection) { start() } else { stop() }
    }

    func start() {
        guard !isRunning else { return }
        mountObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didMountNotification, object: nil, queue: .main) { [weak self] note in
            guard let url = note.userInfo?[NSWorkspace.volumeURLUserInfoKey] as? URL else { return }
            Task { @MainActor in self?.volumeMounted(url) }
        }
        startKeyboardWatch()
        isRunning = true
    }

    func stop() {
        if let mountObserver { NSWorkspace.shared.notificationCenter.removeObserver(mountObserver) }
        mountObserver = nil
        if hidIterator != 0 { IOObjectRelease(hidIterator); hidIterator = 0 }
        if let hidPort { IONotificationPortDestroy(hidPort) }
        hidPort = nil
        knownKeyboards = []
        enumerated = false
        watchTimer?.invalidate()
        watchTimer = nil
        isRunning = false
    }

    // MARK: - Drives

    /// Describes a mounted volume through Disk Arbitration. nil for disk images, network shares
    /// and internal disks.
    nonisolated static func externalDrive(_ url: URL) -> (name: String, bus: String)? {
        guard let session = DASessionCreate(kCFAllocatorDefault),
              let disk = DADiskCreateFromVolumePath(kCFAllocatorDefault, session, url as CFURL),
              let info = DADiskCopyDescription(disk) as? [String: Any] else { return nil }
        let model = (info[kDADiskDescriptionDeviceModelKey as String] as? String ?? "").trimmingCharacters(in: .whitespaces)
        if model == "Disk Image" { return nil }
        if info[kDADiskDescriptionDeviceInternalKey as String] as? Bool == true { return nil }
        if info[kDADiskDescriptionVolumeNetworkKey as String] as? Bool == true { return nil }
        let bus = info[kDADiskDescriptionDeviceProtocolKey as String] as? String ?? "External"
        let name = info[kDADiskDescriptionVolumeNameKey as String] as? String ?? url.lastPathComponent
        return (name, bus)
    }

    private func volumeMounted(_ url: URL) {
        guard let drive = USBGuard.externalDrive(url) else { return }
        if Prefs.exclusionList.contains(url.path) { return }
        let event = DriveEvent(name: drive.name, path: url.path, verdict: "Checking…")
        drives.insert(event, at: 0)
        if drives.count > 30 { drives.removeLast(drives.count - 30) }
        ActivityLog.shared.add(.scan, "\(drive.bus) drive connected: \(drive.name)", "Checking it for malware")
        Notifier.post("Checking “\(drive.name)”", "Agamemnon is looking for malware on the drive you just connected.")
        let id = event.id

        var options = ScanController.options(for: .custom)
        queue.async {
            var detections = USBGuard.lureCheck(url)
            options.riskyOnly = true
            options.appSignatureCheck = false
            options.gatekeeperCheck = true
            // ClamAV is slow on big drives; it still checks smaller ones.
            let used = USBGuard.usedBytes(url)
            options.useClamAV = options.useClamAV && used < 32 * 1024 * 1024 * 1024
            let result = ScanEngine().run(roots: [url], options: options) { _ in }
            for d in result.detections where !detections.contains(where: { $0.fileURL == d.fileURL && $0.innerPath == d.innerPath }) {
                detections.append(d)
            }
            Task { @MainActor in self.finished(id: id, url: url, name: drive.name, detections: detections, files: result.filesScanned) }
        }
    }

    nonisolated private static func usedBytes(_ url: URL) -> Int64 {
        let values = try? url.resourceValues(forKeys: [.volumeTotalCapacityKey, .volumeAvailableCapacityKey])
        guard let total = values?.volumeTotalCapacity, let free = values?.volumeAvailableCapacity else { return 0 }
        return Int64(total - free)
    }

    private func finished(id: UUID, url: URL, name: String, detections: [Detection], files: Int) {
        guard let index = drives.firstIndex(where: { $0.id == id }) else { return }
        let malware = detections.filter { $0.level == .malicious }
        var quarantined = 0
        if Prefs.bool(Prefs.autoQuarantine) {
            for threat in malware where (try? vault.quarantine(threat)) != nil { quarantined += 1 }
        }
        drives[index].threats = detections.count
        if detections.isEmpty {
            drives[index].verdict = "No threats · \(files.formatted()) files checked"
            ActivityLog.shared.add(.scan, "Drive “\(name)” is clean", "\(files.formatted()) files checked")
            return
        }
        let names = Set(detections.map(\.threatName)).sorted().prefix(3).joined(separator: ", ")
        if malware.isEmpty {
            drives[index].verdict = "\(detections.count) suspicious item\(detections.count == 1 ? "" : "s"): \(names)"
            Notifier.post("Something on “\(name)” looks suspicious", "\(names). Check it in Agamemnon before opening anything from the drive.", critical: true)
        } else {
            drives[index].verdict = quarantined > 0 ? "Malware quarantined (\(quarantined)): \(names)" : "Malware found: \(names)"
            Notifier.post("Malware on USB drive “\(name)”", quarantined > 0 ? "\(quarantined) item(s) moved to quarantine: \(names)." : names, critical: true)
            if Prefs.bool(Prefs.usbAutoEject) {
                eject(url, index: index)
            }
        }
        for d in detections {
            ActivityLog.shared.add(.threat, "\(d.threatName) on drive “\(name)”", d.displayPath)
        }
    }

    func eject(_ event: DriveEvent) {
        guard let index = drives.firstIndex(where: { $0.id == event.id }) else { return }
        eject(URL(fileURLWithPath: event.path), index: index)
    }

    private func eject(_ url: URL, index: Int) {
        do {
            try NSWorkspace.shared.unmountAndEjectDevice(at: url)
            drives[index].ejected = true
            ActivityLog.shared.add(.info, "Ejected “\(drives[index].name)”", "It had malware on it")
        } catch {
            drives[index].verdict += " · couldn't eject: \(error.localizedDescription)"
        }
    }

    /// Tricks aimed at getting someone to double-click. Only looks at the top two levels.
    nonisolated static func lureCheck(_ root: URL) -> [Detection] {
        var out: [Detection] = []
        let documentExts: Set<String> = ["jpg", "jpeg", "png", "gif", "heic", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
                                         "pptx", "txt", "rtf", "mp4", "mov", "mp3", "zip", "pages", "key", "numbers"]
        let runnable: Set<String> = ["app", "command", "tool", "terminal", "workflow", "scpt", "applescript", "sh", "pkg"]
        func visit(_ dir: URL, depth: Int) {
            guard depth <= 1, let items = try? FileManager.default.contentsOfDirectory(
                at: dir, includingPropertiesForKeys: [.isHiddenKey, .isDirectoryKey], options: []) else { return }
            for item in items.prefix(2000) {
                let name = item.lastPathComponent
                let ext = item.pathExtension.lowercased()
                if name == ".Trashes" || name == ".Spotlight-V100" || name == ".fseventsd" || name.hasPrefix("._") { continue }
                let inner = (name as NSString).deletingPathExtension
                let innerExt = (inner as NSString).pathExtension.lowercased()
                if runnable.contains(ext), documentExts.contains(innerExt) {
                    out.append(Detection(fileURL: item, innerPath: nil, threatName: "Program disguised as a document (\(name))",
                                         engine: "USB Guard", level: .suspicious))
                } else if ext == "app", name.hasPrefix(".") {
                    out.append(Detection(fileURL: item, innerPath: nil, threatName: "Hidden app on a USB drive",
                                         engine: "USB Guard", level: .suspicious))
                } else if depth == 0, ["command", "tool", "terminal"].contains(ext) {
                    out.append(Detection(fileURL: item, innerPath: nil, threatName: "Terminal script at the top of a USB drive",
                                         engine: "USB Guard", level: .suspicious))
                } else if ext == "app", name.contains("\u{202E}") {   // right-to-left override hides the real extension
                    out.append(Detection(fileURL: item, innerPath: nil, threatName: "App with a reversed (disguised) name",
                                         engine: "USB Guard", level: .malicious))
                }
                if ext != "app", (try? item.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
                    visit(item, depth: depth + 1)
                }
            }
        }
        visit(root, depth: 0)
        return out
    }

    // MARK: - Keyboards (BadUSB)

    /// Boards sold or commonly flashed as keystroke injectors: (vendor, product or nil for any).
    nonisolated static let attackBoards: [(Int, Int?, String)] = [
        (0x16C0, 0x27DB, "Digispark (keystroke injector)"),
        (0x16D0, 0x0753, "Digispark (keystroke injector)"),
        (0x16C0, 0x0482, "Teensy keyboard"),
        (0x16C0, 0x0487, "Teensy keyboard"),
        (0x2341, 0x8036, "Arduino Leonardo acting as a keyboard"),
        (0x2341, 0x8037, "Arduino Micro acting as a keyboard"),
        (0x2A03, 0x8036, "Arduino Leonardo acting as a keyboard"),
        (0x1B4F, 0x9206, "SparkFun Pro Micro acting as a keyboard"),
        (0x0483, 0x5740, "Flipper Zero (BadUSB mode)"),
        (0x0483, 0x5741, "Flipper Zero (BadUSB mode)"),
        (0x1D50, 0x60E8, "O.MG / open hardware keystroke injector"),
        (0x239A, nil, "Adafruit board acting as a keyboard"),
        (0x2E8A, 0x000A, "Raspberry Pi Pico acting as a keyboard"),
        (0x2E8A, 0x0003, "Raspberry Pi Pico acting as a keyboard"),
        (0xF000, 0xFF01, "USB Rubber Ducky (default IDs)"),
    ]

    private func startKeyboardWatch() {
        guard let port = IONotificationPortCreate(kIOMainPortDefault) else { return }
        hidPort = port
        IONotificationPortSetDispatchQueue(port, DispatchQueue.main)
        let matching = IOServiceMatching(kIOHIDDeviceKey) as NSMutableDictionary
        matching[kIOHIDDeviceUsagePairsKey] = [
            [kIOHIDDeviceUsagePageKey: kHIDPage_GenericDesktop, kIOHIDDeviceUsageKey: kHIDUsage_GD_Keyboard],
            [kIOHIDDeviceUsagePageKey: kHIDPage_GenericDesktop, kIOHIDDeviceUsageKey: kHIDUsage_GD_Keypad],
        ]
        let context = Unmanaged.passUnretained(self).toOpaque()
        let callback: IOServiceMatchingCallback = { refcon, iterator in
            guard let refcon else { return }
            let guardian = Unmanaged<USBGuard>.fromOpaque(refcon).takeUnretainedValue()
            MainActor.assumeIsolated { guardian.keyboardsAppeared(iterator) }
        }
        let result = IOServiceAddMatchingNotification(port, kIOFirstMatchNotification, matching, callback, context, &hidIterator)
        guard result == KERN_SUCCESS else { return }
        // The first pass lists keyboards that were already there; those aren't new.
        keyboardsAppeared(hidIterator)
        enumerated = true
    }

    private func keyboardsAppeared(_ iterator: io_iterator_t) {
        while case let service = IOIteratorNext(iterator), service != 0 {
            defer { IOObjectRelease(service) }
            var entryID: UInt64 = 0
            IORegistryEntryGetRegistryEntryID(service, &entryID)
            func prop(_ key: String) -> Any? { IORegistryEntryCreateCFProperty(service, key as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() }
            let transport = prop(kIOHIDTransportKey) as? String ?? ""
            let builtIn = prop(kIOHIDBuiltInKey) as? Bool ?? false
            let vendor = prop(kIOHIDVendorIDKey) as? Int ?? 0
            let product = prop(kIOHIDProductIDKey) as? Int ?? 0
            let name = (prop(kIOHIDProductKey) as? String) ?? "Unknown keyboard"
            let maker = prop(kIOHIDManufacturerKey) as? String
            guard !knownKeyboards.contains(entryID) else { continue }
            knownKeyboards.insert(entryID)
            // Virtual keyboards (remote desktop, Sidecar) and Bluetooth ones can't be BadUSB sticks.
            guard enumerated, !builtIn, transport.uppercased() == "USB" else { continue }
            newKeyboard(name: maker.map { "\($0) \(name)" } ?? name, vendor: vendor, product: product)
        }
    }

    private func newKeyboard(name: String, vendor: Int, product: Int) {
        let board = USBGuard.attackBoards.first { $0.0 == vendor && ($0.1 == nil || $0.1 == product) }
        let ids = String(format: "%04X:%04X", vendor, product)
        var event = KeyboardEvent(name: name, vendorID: vendor, productID: product,
                                  verdict: "New USB keyboard (\(ids)). Watching what it does…", dangerous: board != nil)
        if let board {
            event.verdict = "Known attack device: \(board.2) (\(ids))"
            Notifier.post("Possible BadUSB device connected", "\(board.2) just connected as a keyboard. If you didn't plug in a keyboard, unplug it now.", critical: true)
            ActivityLog.shared.add(.threat, "Attack device connected as a keyboard", "\(board.2) · \(ids)")
        } else {
            ActivityLog.shared.add(.info, "New USB keyboard connected", "\(name) · \(ids)")
        }
        keyboards.insert(event, at: 0)
        if keyboards.count > 30 { keyboards.removeLast(keyboards.count - 30) }
        watchForTyping(keyboard: event)
    }

    /// For 20 seconds after a new keyboard appears, looks for what keystroke injectors do
    /// first: open Terminal (or Spotlight → Terminal) and start a shell or a download tool.
    private func watchForTyping(keyboard: KeyboardEvent) {
        processesBefore = Set(ProcessList.allPIDs().compactMap { ProcessList.info($0)?.key })
        watchUntil = Date().addingTimeInterval(20)
        watchKeyboard = keyboard.name
        let id = keyboard.id
        watchTimer?.invalidate()
        watchTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] timer in
            Task { @MainActor in
                guard let self else { timer.invalidate(); return }
                if Date() > self.watchUntil { timer.invalidate(); self.watchFinished(id); return }
                self.checkTyping(id)
            }
        }
    }

    nonisolated static let injectedTools: Set<String> = [
        "Terminal", "iTerm2", "osascript", "curl", "wget", "sh", "bash", "zsh", "python3", "python", "nc", "base64", "Script Editor",
    ]

    private func checkTyping(_ id: UUID) {
        guard let index = keyboards.firstIndex(where: { $0.id == id }), keyboards[index].verdict.hasPrefix("New USB keyboard") || keyboards[index].dangerous,
              !keyboards[index].verdict.contains("typing commands") else { return }
        var started: [RunningProcess] = []
        for pid in ProcessList.allPIDs() {
            guard let p = ProcessList.info(pid), !processesBefore.contains(p.key), p.uid == getuid() else { continue }
            if USBGuard.injectedTools.contains(p.name) { started.append(p) }
        }
        guard !started.isEmpty else { return }
        let names = Set(started.map(\.name)).sorted().joined(separator: ", ")
        keyboards[index].verdict = "Started \(names) right after connecting: it may be typing commands"
        keyboards[index].dangerous = true
        Notifier.post("A new keyboard may be typing commands",
                      "\(keyboards[index].name) was just plugged in and \(names) started straight away. This is how BadUSB attacks work: unplug it now.",
                      critical: true)
        ActivityLog.shared.add(.threat, "Possible BadUSB attack", "\(keyboards[index].name) · started \(names)")
        // Stop download tools it started (harmless to stop; Terminal itself is left alone).
        if Prefs.bool(Prefs.behaviorAutoStop) {
            for p in started where BehaviorMonitor.stoppableTools.contains(p.name.lowercased()) && BehaviorMonitor.mayStop(p) {
                kill(p.pid, SIGKILL)
            }
        }
    }

    private func watchFinished(_ id: UUID) {
        guard let index = keyboards.firstIndex(where: { $0.id == id }), keyboards[index].verdict.hasPrefix("New USB keyboard") else { return }
        keyboards[index].verdict = "Nothing unusual happened after it connected"
    }

    func clear() {
        drives.removeAll()
        keyboards.removeAll()
    }
}
