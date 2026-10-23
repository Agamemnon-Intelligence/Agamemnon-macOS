import Foundation
import AppKit

/// "Scan with Agamemnon" in Finder's Services menu, and drops on the Dock icon.
final class ScanService: NSObject {
    @objc func scanFiles(_ pasteboard: NSPasteboard, userData: String?, error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        let urls = (pasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL]) ?? []
        Task { @MainActor in ScanService.scan(urls) }
    }

    @MainActor static func scan(_ urls: [URL]) {
        let files = urls.filter { $0.isFileURL }
        guard !files.isEmpty else { return }
        let model = AppModel.shared
        if model.scanner.isScanning {
            Notifier.post("A scan is already running", "Try again when it's finished.")
            return
        }
        model.scanner.start(.custom, targets: files)
        Navigator.shared.section = .scan
        NSApp.activate(ignoringOtherApps: true)
        NSApp.windows.first { $0.identifier?.rawValue == "main" || $0.title == "Agamemnon" }?.makeKeyAndOrderFront(nil)
    }
}
