import AppKit
import PortnameCore

/// Applies `PanelSizing` to the presented menubar panel window: the window
/// follows its SwiftUI content in both directions, top edge fixed.
@MainActor
enum PanelWindowSizer {

    /// Resizes the panel window so its content area is exactly
    /// `contentHeight` tall. Called on the next main-loop turn after the
    /// content height changed, never from inside SwiftUI's layout pass:
    /// resizing a window during its own layout is the re-entrancy that
    /// crashed the settings window (fix/settings-crash-preferredcontentsize).
    static func fit(contentHeight: CGFloat) {
        guard let window = MenuBarPanelDismissal.menuBarExtraWindow, window.isVisible else { return }
        let current = window.contentRect(forFrameRect: window.frame)
        guard let target = PanelSizing.contentRect(current: current, contentHeight: contentHeight) else { return }
        window.setFrame(window.frameRect(forContentRect: target), display: true, animate: false)
    }
}
