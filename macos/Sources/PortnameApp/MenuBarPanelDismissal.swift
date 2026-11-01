import AppKit

/// Programmatic dismissal of the SwiftUI `MenuBarExtra` panel. SwiftUI has
/// no public API to close a window-style MenuBarExtra, and the presentation
/// mechanism is OS-version-dependent:
///
/// - macOS 27+: presentation runs through a private "expanded interface
///   session" on the status item (`NSStatusItemExpandedInterfaceSession`);
///   the status item button no longer has a target/action. Cancelling that
///   session is exactly how SwiftUI itself dismisses the panel — the state
///   stays consistent and the panel's `onDisappear` fires. Verified on
///   macOS 27 against the maintained orchetect/MenuBarExtraAccess reference
///   implementation.
/// - macOS 26 and earlier: the status item button's target/action toggles
///   the panel, so a synthesized click dismisses it through SwiftUI's own
///   path.
/// - Last resort: order the visible MenuBarExtraWindow out directly. On
///   systems where neither mechanism above exists, SwiftUI's internal
///   presented-state may then lag by one status-item click.
///
/// All SPI access is guarded by `responds(to:)` checks; on unsupported
/// systems every step degrades to a no-op or the direct `orderOut`.
@MainActor
enum MenuBarPanelDismissal {

    /// Whether the menubar panel is currently presented. The expanded
    /// interface session is authoritative where it exists; the panel window's
    /// visibility is the fallback on older systems.
    static var isPanelPresented: Bool {
        if statusItemSession != nil { return true }
        return menuBarExtraWindow?.isVisible ?? false
    }

    /// Dismisses the panel if it is presented. Called before the settings
    /// window is brought to front — panel and settings window overlap near
    /// the status item and must never be visible together.
    static func dismissPanel() {
        if let session = statusItemSession {
            session.perform(NSSelectorFromString("cancel"))
            return
        }
        if let button = statusItem?.button {
            // Legacy toggle path: the panel is presented, so the click
            // dismisses it through SwiftUI's own handling.
            button.performClick(nil)
            return
        }
        if let panel = menuBarExtraWindow, panel.isVisible {
            panel.orderOut(nil)
        }
    }

    // MARK: - Status item introspection

    /// The status item button's frame in global screen coordinates — the
    /// anchor the panel slides out from, and therefore where the settings
    /// window must appear (`SettingsAnchoring`). Process-wide lookup: the
    /// status item lives in the menu bar from launch on, so this works
    /// whether or not the panel window is currently presented (in
    /// particular also after `dismissPanel()` ran).
    static var statusItemButtonFrame: NSRect? {
        guard let button = statusItem?.button, let window = button.window else {
            return nil
        }
        return window.convertToScreen(button.convert(button.bounds, to: nil))
    }

    /// The active status item of the MenuBarExtra. `NSApp.windows` carries
    /// one `NSStatusBarWindow` per display — and macOS 27 additionally
    /// keeps a second, off-screen one per status item (measured at y = -34
    /// on a 1710×1107 display). Both answer the `statusItem` KVC key with
    /// an `NSSceneStatusItem`, so the item class alone does NOT identify
    /// the real menu-bar slot. Only a status-bar window that is visible
    /// and lies on a screen is the real slot; using an off-screen one
    /// would anchor the settings window at the screen corner after the
    /// clamp. Class preference stays as tie-breaker among on-screen
    /// windows (replica items on pre-26 systems are `NSStatusItemReplicant`).
    private static var statusItem: NSStatusItem? {
        let wantedClass: String
        if ProcessInfo.processInfo.isOperatingSystemAtLeast(
            OperatingSystemVersion(majorVersion: 26, minorVersion: 0, patchVersion: 0)) {
            wantedClass = "NSSceneStatusItem"
        } else {
            wantedClass = "NSStatusItem"
        }
        var classFallback: NSStatusItem?
        for window in NSApp.windows
        where String(describing: type(of: window)).contains("NSStatusBarWindow") {
            guard window.isVisible,
                  NSScreen.screens.contains(where: { $0.frame.intersects(window.frame) })
            else { continue }
            // "statusItem" is a private AppKit key on NSStatusBarWindow; KVC
            // is how it is read (no public accessor exists).
            guard let item = window.value(forKey: "statusItem") as? NSStatusItem
            else { continue }
            if String(describing: type(of: item)) == wantedClass {
                return item
            }
            if classFallback == nil { classFallback = item }
        }
        return classFallback
    }

    /// The presented panel window's frame in global coordinates, or nil
    /// while no panel window is visible. While presented, the panel IS the
    /// slide-out spot the settings window must reuse — the freshest
    /// fallback anchor for ``SettingsWindowController`` (captured before
    /// the panel is dismissed).
    static var panelWindowFrame: NSRect? {
        guard let panel = menuBarExtraWindow, panel.isVisible else { return nil }
        return panel.frame
    }

    /// The active expanded interface session while the panel is presented
    /// (macOS 27+), else nil.
    private static var statusItemSession: NSObject? {
        guard let item = statusItem,
              item.responds(to: NSSelectorFromString("expandedInterfaceSession"))
        else { return nil }
        return item.perform(NSSelectorFromString("expandedInterfaceSession"))?
            .takeUnretainedValue() as? NSObject
    }

    /// The window SwiftUI creates for a window-style MenuBarExtra while it
    /// is presented.
    /// The MenuBarExtra panel window, presented or not (also used by
    /// `PanelWindowSizer`).
    static var menuBarExtraWindow: NSWindow? {
        NSApp.windows.first { String(describing: type(of: $0)).contains("MenuBarExtraWindow") }
    }
}
