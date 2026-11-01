import AppKit
import SwiftUI
import PortnameCore

/// AppKit-hosted settings window. The SwiftUI `Settings` scene plus the
/// `openSettings` environment is unreliable for LSUIElement/menu-bar apps —
/// the window can be created without ever being activated or ordered front,
/// which looks like "nothing happens". Owning the window here and
/// activating the app explicitly makes the opening deterministic.
///
/// Exclusivity: the panel and this window both anchor near the top-right of
/// the screen and overlap, so they are mutually exclusive ("either panel or
/// settings"). The settings entry point dismisses the panel first
/// (`MenuBarPanelDismissal`); conversely, `MenuBarPanel.onAppear` calls
/// ``hideForPanel()`` when the panel opens over a visible settings window.
///
/// Positioning: on every open the window is anchored at the panel's
/// slide-out position — horizontally at the status item, top edge just
/// below the menu bar (`SettingsAnchoring`). Fallback chain, documented
/// and measured (macOS 27 probe):
/// 1. the status item button's frame (primary; robust on-screen lookup),
/// 2. the frame of the last presented panel window (`panelWindowFrame`,
///    captured before dismissal — the panel is the slide-out spot itself),
/// 3. centered, as the last resort.
@MainActor
final class SettingsWindowController {
    static let shared = SettingsWindowController()
    private var window: NSWindow?
    private var resizeObserver: NSObjectProtocol?
    /// The panel window's frame captured while it was last visible; the
    /// fallback anchor when the status item itself cannot be located.
    private var lastKnownPanelFrame: NSRect?

    var isSettingsVisible: Bool { window?.isVisible ?? false }

    func show(model: AppModel) {
        // Capture the panel frame while it is still presented: the panel is
        // the slide-out spot itself, and the only settings entry point sits
        // inside it, so its frame is the freshest fallback anchor.
        if let panelFrame = MenuBarPanelDismissal.panelWindowFrame {
            lastKnownPanelFrame = panelFrame
        }
        let actions = PanelSettingsExclusivity.actions(
            forSettingsRequest: MenuBarPanelDismissal.isPanelPresented)
        if actions.contains(.dismissPanel) {
            MenuBarPanelDismissal.dismissPanel()
        }
        // .showSettings is applied unconditionally below (re-focus on repeat).
        if window == nil {
            window = makeWindow(model: model)
        }
        // Re-anchor on EVERY open, after the panel dismissal (the status
        // item itself survives it) and before the window is ordered front,
        // so it never flashes at a stale position.
        applySlideOutFrame()
        // macOS 14+ cooperative activation (activate(ignoringOtherApps:) is
        // deprecated since the macOS 14 SDK). The request comes from a click
        // in our own panel, so the app is allowed to come forward.
        NSApp.activate()
        window?.makeKeyAndOrderFront(nil)
    }

    /// Creates the settings window at its final content size. A fresh
    /// `NSWindow(contentViewController:)` is 1×32 pt until the first SwiftUI
    /// layout pass — anchoring with that size mis-places the window on the
    /// FIRST open (measured on macOS 27: it then grows in place, keeping the
    /// origin computed for the tiny size). The hosting view's fitting size
    /// is available synchronously, so the window starts at its final size
    /// and the first placement is as exact as every later one.
    private func makeWindow(model: AppModel) -> NSWindow {
        let host = NSHostingController(rootView: SettingsView(model: model))
        // sizingOptions deliberately stays at the default — it must NOT
        // include `.preferredContentSize`. That option wires the SwiftUI
        // size query into AppKit's constraint pass: while the window runs
        // its updateConstraints pass, AppKit asks the hosting controller
        // for `preferredContentSize`; the SwiftUI answer invalidates the
        // same window's constraints (`NSHostingView` requestUpdate →
        // `setNeedsUpdateConstraints` →
        // `-[NSWindow _postWindowNeedsUpdateConstraints]`), and AppKit
        // throws NSGenericException ("more Update Constraints in Window
        // passes than there are views in the window") — the crash on the
        // gear click. The window is therefore sized once, manually, below
        // and keeps that size.
        let win = NSWindow(contentViewController: host)
        win.styleMask = [.titled, .closable]
        win.title = L10n.text("portname-Einstellungen")
        win.isReleasedWhenClosed = false
        // No frame autosave: a restored frame (e.g. saved while an
        // external display was unplugged) would beat the slide-out
        // anchoring below, and the requirement is "always exactly
        // where the panel opens". User moves therefore apply to the
        // current session only.
        win.setContentSize(host.view.fittingSize)
        // If the window size ever changes while visible (future content
        // sizing, programmatic resize), keep the top edge anchored below
        // the menu bar — a resize keeps the bottom-left origin fixed,
        // which would push the top edge up into the menu bar. The frame
        // mutation is deferred to the next runloop tick: this callback
        // runs inside AppKit's resize handling, and mutating geometry
        // synchronously here re-enters the layout pass (the same
        // layout-during-layout class of failure as the sizingOptions
        // crash above). User drags persist; only an actual resize
        // re-anchors.
        resizeObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.didResizeNotification, object: win, queue: .main
        ) { [weak self] _ in
            DispatchQueue.main.async { [weak self] in
                MainActor.assumeIsolated {
                    guard let self, self.window?.isVisible == true else { return }
                    self.applySlideOutFrame()
                }
            }
        }
        return win
    }

    /// Places the window at the panel's slide-out position: horizontally at
    /// the status item, top edge just below the menu bar — the settings
    /// open from the same spot the panel slides out from, not centered
    /// mid-screen. Geometry lives in the unit-tested
    /// ``SettingsAnchoring``; this only feeds it frames (see the fallback
    /// chain in the type docs).
    private func applySlideOutFrame() {
        guard let window else { return }
        guard let origin = slideOutOrigin(for: window.frame.size) else {
            // No anchor obtainable at all (status item not found and no
            // panel frame ever captured): previous behavior — centered.
            window.center()
            return
        }
        window.setFrameOrigin(origin)
    }

    private func slideOutOrigin(for size: CGSize) -> CGPoint? {
        let anchor: CGRect
        if let itemFrame = MenuBarPanelDismissal.statusItemButtonFrame {
            anchor = itemFrame
        } else if let panelFrame = lastKnownPanelFrame {
            // The last presented panel is the slide-out spot itself; its
            // frame maps to an item-like anchor in pure geometry.
            anchor = SettingsAnchoring.anchorFrame(fromPanelFrame: panelFrame)
        } else {
            return nil
        }
        // The anchor sits on exactly one screen (its menu bar); anchor into
        // that screen's visible frame so multi-display setups and odd icon
        // positions still keep the window fully on-screen.
        let screen = NSScreen.screens.first { $0.frame.intersects(anchor) }
            ?? NSScreen.main
        guard let visibleFrame = screen?.visibleFrame else { return nil }
        return SettingsAnchoring.origin(statusItemFrame: anchor,
                                        windowSize: size,
                                        visibleFrame: visibleFrame)
    }

    /// The panel became visible (status-item click); a visible settings
    /// window is ordered out. Keeping the window (and its view state) alive
    /// loses nothing: toggles persist immediately via their own services.
    /// The panel is visible right now, so its frame is captured as the
    /// freshest fallback anchor.
    func hideForPanel() {
        if let panelFrame = MenuBarPanelDismissal.panelWindowFrame {
            lastKnownPanelFrame = panelFrame
        }
        if PanelSettingsExclusivity.actions(forPanelOpen: isSettingsVisible)
            .contains(.hideSettings) {
            window?.orderOut(nil)
        }
    }
}
