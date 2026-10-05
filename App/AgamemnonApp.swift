import SwiftUI
import AppKit

@main
struct AgamemnonApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel.shared
    @StateObject private var nav = Navigator.shared

    var body: some Scene {
        Window("Agamemnon", id: "main") {
            ContentView()
                .agamemnonEnvironment(model, nav)
                .frame(minWidth: 980, minHeight: 660)
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
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
            .environmentObject(model.admin)
            .environmentObject(model.backgroundItems)
            .environmentObject(model.dns)
            .environmentObject(model.scheduler)
    }
}
