import SwiftUI
import PortnameCore
import AppKit

@main
struct PortnameApp: App {
    @NSApplicationDelegateAdaptor(AppLifecycleDelegate.self) private var delegate
    @State private var model: AppModel

    init() {
        let client = DaemonClient(socketPath: SocketPathResolver.userSocketPath())
        let copyText: @Sendable (String) -> Void = { text in
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            pasteboard.setString(text, forType: .string)
        }
        let openExternal: @Sendable (URL) -> Void = { url in
            NSWorkspace.shared.open(url)
        }
        let revealPath: @Sendable (String) -> Void = { path in
            NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: path)
        }
        _model = State(initialValue: AppModel(api: client,
                                              copyText: copyText,
                                              openExternal: openExternal,
                                              revealPath: revealPath))
        // The status item (and with it the icon state) exists from launch;
        // polling must start with it — not when the panel is first opened.
        // The panel's .task below only toggles panelVisible (poll cadence).
        delegate.model = model
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarPanel(model: model)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)
    }
}

/// Starts the poll loop from the app lifecycle, independent of any SwiftUI
/// scene mounting. SwiftUI creates the App struct before the delegate fires,
/// so the model is handed over in init and the loop starts on launch.
final class AppLifecycleDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        model?.start()
    }

    func applicationWillTerminate(_ notification: Notification) {
        model?.stopPolling()
    }
}

/// Monochrome menubar icon reflecting the connection state. Signpost
/// metaphor: every project gets a named address. Filled = connected,
/// outline = connecting, crossed variant = unreachable, warning = legacy
/// daemon (details shown in the panel).
struct MenuBarLabel: View {
    let model: AppModel

    private var iconName: String {
        switch model.connection {
        case .connected:
            return "signpost.right.fill"
        case .connecting:
            return "signpost.right"
        case .unreachable:
            return "signpost.right.and.left"
        case .incompatibleProtocol:
            return "exclamationmark.triangle.fill"
        }
    }

    var body: some View {
        Image(systemName: iconName)
    }
}
