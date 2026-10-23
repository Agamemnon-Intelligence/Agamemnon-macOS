import SwiftUI
import AppKit

@main
struct AgamemnonApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel.shared
    @StateObject private var nav = Navigator.shared
    @StateObject private var theme = ThemeSettings.shared

    var body: some Scene {
        Window("Agamemnon", id: "main") {
            ContentView()
                .agamemnonEnvironment(model, nav)
                .frame(minWidth: 980, minHeight: 660)
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
                .id(theme.revision)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1120, height: 760)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Scan") {
                Button("Quick Scan") { model.scanner.start(.quick); nav.section = .scan }
                    .keyboardShortcut("r", modifiers: [.command])
                Button("Full Scan") { model.scanner.start(.full); nav.section = .scan }
                    .keyboardShortcut("r", modifiers: [.command, .shift])
                Button("Stop Scan") { model.scanner.cancel() }
                    .keyboardShortcut(".", modifiers: [.command])
            }
        }

        MenuBarExtra {
            MenuBarView()
                .agamemnonEnvironment(model, nav)
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
                .id(theme.revision)
        } label: {
            Image(systemName: model.menuBarSymbol)
        }
        .menuBarExtraStyle(.window)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.appearance = NSAppearance(named: .darkAqua)
        Task { @MainActor in AppModel.shared.start() }
        // Finder ▸ right-click ▸ Services ▸ Scan with Agamemnon.
        NSApp.servicesProvider = ScanService()
        NSUpdateDynamicServices()
    }

    /// Files and folders dropped on Agamemnon's Dock icon are scanned.
    func application(_ application: NSApplication, open urls: [URL]) {
        Task { @MainActor in ScanService.scan(urls) }
    }

    /// A normal quit (not malware killing it), so the protection helper doesn't restart it.
    func applicationWillTerminate(_ notification: Notification) {
        SelfProtection.markQuit()
    }

    /// Keep protecting from the menu bar when the window is closed.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

extension View {
    @MainActor
    func agamemnonEnvironment(_ model: AppModel, _ nav: Navigator) -> some View {
        self
            .environmentObject(model)
            .environmentObject(nav)
            .environmentObject(model.activity)
            .environmentObject(model.signatures)
            .environmentObject(model.vault)
            .environmentObject(model.scanner)
            .environmentObject(model.downloads)
            .environmentObject(model.startupSweep)
            .environmentObject(model.browser)
            .environmentObject(model.ransomware)
            .environmentObject(model.checkup)
            .environmentObject(model.admin)
            .environmentObject(model.backgroundItems)
            .environmentObject(model.behavior)
            .environmentObject(model.dns)
            .environmentObject(model.scheduler)
            .environmentObject(model.usb)
            .environmentObject(model.clipboard)
            .environmentObject(model.selfProtection)
            .environmentObject(model.onAccess)
            .environmentObject(model.updater)
            .environmentObject(model.privacy)
            .environmentObject(model.selfUpdater)
    }
}
