import Foundation
import Combine
import AppKit
import CoreAudio
import CoreMediaIO

/// Camera and microphone alerts. Spyware and remote-access trojans switch these on quietly.
/// macOS shows a coloured dot in the menu bar, which is easy to miss; Agamemnon also tells you
/// which app was in front when it happened, and keeps a list.
///
/// Reads only whether a device is in use (CoreMediaIO / CoreAudio "running somewhere"); never
/// the picture or sound.
@MainActor
final class PrivacyMonitor: ObservableObject {
    struct Event: Identifiable, Hashable {
        let id = UUID()
        let date = Date()
        let device: String
        let app: String
        var ended: Date?
    }

    @Published private(set) var isRunning = false
    @Published private(set) var events: [Event] = []

    private var timer: Timer?
    private var cameraOn = false
    private var micOn = false
    private var lastNotified: [String: Date] = [:]

    func applyPreference() {
        if Prefs.bool(Prefs.cameraMicAlerts) { start() } else { stop() }
    }

    func start() {
        guard timer == nil else { return }
        cameraOn = PrivacyMonitor.cameraInUse()
        micOn = PrivacyMonitor.microphoneInUse()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
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
        let camera = PrivacyMonitor.cameraInUse()
        let mic = PrivacyMonitor.microphoneInUse()
        if camera != cameraOn { changed("Camera", on: camera); cameraOn = camera }
        if mic != micOn { changed("Microphone", on: mic); micOn = mic }
    }

    private func changed(_ device: String, on: Bool) {
        if !on {
            if let i = events.firstIndex(where: { $0.device == device && $0.ended == nil }) { events[i].ended = Date() }
            return
        }
        let front = NSWorkspace.shared.frontmostApplication
        let app = front?.localizedName ?? "an app in the background"
        events.insert(Event(device: device, app: app), at: 0)
        if events.count > 30 { events.removeLast() }
        ActivityLog.shared.add(.behavior, "\(device) turned on", "While \(app) was in front")
        // One notification per app and device every 30 minutes, so calls don't spam.
        let key = device + "|" + app
        if let last = lastNotified[key], Date().timeIntervalSince(last) < 1800 { return }
        lastNotified[key] = Date()
        Notifier.post("\(device) turned on",
                      "Something started using your \(device.lowercased()) while \(app) was in front. If you didn't expect this, check Real-Time Protection in Agamemnon.")
    }

    // MARK: - Devices

    nonisolated static func cameraInUse() -> Bool {
        var address = CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(kCMIOHardwarePropertyDevices),
                                                mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                                                mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
        var size: UInt32 = 0
        guard CMIOObjectGetPropertyDataSize(CMIOObjectID(kCMIOObjectSystemObject), &address, 0, nil, &size) == 0, size > 0 else { return false }
        var devices = [CMIOObjectID](repeating: 0, count: Int(size) / MemoryLayout<CMIOObjectID>.size)
        var used: UInt32 = 0
        guard CMIOObjectGetPropertyData(CMIOObjectID(kCMIOObjectSystemObject), &address, 0, nil, size, &used, &devices) == 0 else { return false }
        for device in devices {
            var running = CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsRunningSomewhere),
                                                    mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeWildcard),
                                                    mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementWildcard))
            var value: UInt32 = 0
            var valueSize = UInt32(MemoryLayout<UInt32>.size)
            if CMIOObjectGetPropertyData(device, &running, 0, nil, valueSize, &valueSize, &value) == 0, value != 0 { return true }
        }
        return false
    }

    nonisolated static func microphoneInUse() -> Bool {
        var address = AudioObjectPropertyAddress(mSelector: kAudioHardwarePropertyDevices,
                                                 mScope: kAudioObjectPropertyScopeGlobal,
                                                 mElement: kAudioObjectPropertyElementMain)
        var size: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(AudioObjectID(kAudioObjectSystemObject), &address, 0, nil, &size) == noErr else { return false }
        var devices = [AudioObjectID](repeating: 0, count: Int(size) / MemoryLayout<AudioObjectID>.size)
        guard AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject), &address, 0, nil, &size, &devices) == noErr else { return false }
        for device in devices {
            // Input devices only (has input streams).
            var streams = AudioObjectPropertyAddress(mSelector: kAudioDevicePropertyStreams, mScope: kAudioObjectPropertyScopeInput,
                                                     mElement: kAudioObjectPropertyElementMain)
            var streamSize: UInt32 = 0
            guard AudioObjectGetPropertyDataSize(device, &streams, 0, nil, &streamSize) == noErr, streamSize > 0 else { continue }
            var running = AudioObjectPropertyAddress(mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
                                                     mScope: kAudioObjectPropertyScopeGlobal, mElement: kAudioObjectPropertyElementMain)
            var value: UInt32 = 0
            var valueSize = UInt32(MemoryLayout<UInt32>.size)
            if AudioObjectGetPropertyData(device, &running, 0, nil, &valueSize, &value) == noErr, value != 0 { return true }
        }
        return false
    }

    func clear() { events.removeAll() }
}
