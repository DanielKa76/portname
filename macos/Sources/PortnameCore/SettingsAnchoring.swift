import CoreGraphics
import Foundation

/// Placement of the settings window: it must appear exactly where the
/// menubar panel slides out — horizontally at the status item, top edge
/// just below the menu bar — so the settings feels like it opens from the
/// same spot as the panel instead of floating centered mid-screen.
///
/// Pure geometry, unit-tested; the AppKit side only feeds it frames
/// (`MenuBarPanelDismissal.statusItemButtonFrame` plus the anchor screen's
/// `visibleFrame`) and applies the result (`SettingsWindowController`).
///
/// Anchor sources in priority order (the fallback chain lives in
/// `SettingsWindowController`): the status item's button frame, then the
/// frame of the last presented panel window mapped through
/// ``anchorFrame(fromPanelFrame:)``, then — last resort — a centered
/// window.
///
/// The window is centered on the status item and then clamped into the
/// screen's visible frame — the same model the panel follows. For an icon
/// near the right screen edge (the normal case) the clamp makes the window
/// right-aligned with the icon, i.e. exactly the slide-out corner the
/// panel occupies.
public enum SettingsAnchoring {

    /// Gap between the menu bar bottom (the status item button's bottom
    /// edge) and the window's top edge. The panel attaches flush below the
    /// bar, so the settings window does too.
    public static let topGap: CGFloat = 0

    /// Window origin (bottom-left, global screen coordinates) for a window
    /// of `windowSize` anchored at `statusItemFrame` (status item button
    /// frame in global coordinates), clamped into `visibleFrame` of the
    /// screen that shows the status item. The clamp wins over the anchor at
    /// screen edges so the window can never end up off-screen.
    public static func origin(statusItemFrame: CGRect,
                              windowSize: CGSize,
                              visibleFrame: CGRect) -> CGPoint {
        // Horizontal: centered on the icon, like the panel.
        let x = statusItemFrame.midX - windowSize.width / 2
        // Vertical: top edge flush below the menu bar — the status item
        // button's bottom edge is exactly the menu bar's bottom line.
        let y = statusItemFrame.minY - topGap - windowSize.height
        return clamped(CGPoint(x: x, y: y),
                       windowSize: windowSize,
                       visibleFrame: visibleFrame)
    }

    /// Maps a presented panel window's frame to a status-item-like anchor
    /// frame for ``origin(statusItemFrame:windowSize:visibleFrame:)``:
    /// horizontally the panel's center, vertically its top edge — so the
    /// settings window's top edge lands exactly on the panel's top edge,
    /// the same slide-out line. The returned frame is 2pt tall because the
    /// anchor screen selection needs a non-empty rectangle.
    public static func anchorFrame(fromPanelFrame panelFrame: CGRect) -> CGRect {
        CGRect(x: panelFrame.midX - 1,
               y: panelFrame.maxY,
               width: 2,
               height: 2)
    }

    /// Keeps the whole window inside the visible frame. When the window is
    /// wider or taller than the visible frame, it pins to the frame's
    /// bottom-left edge instead of producing a negative offset.
    private static func clamped(_ origin: CGPoint,
                                windowSize: CGSize,
                                visibleFrame: CGRect) -> CGPoint {
        let maxOriginX = visibleFrame.maxX - windowSize.width
        let maxOriginY = visibleFrame.maxY - windowSize.height
        return CGPoint(x: max(visibleFrame.minX, min(origin.x, maxOriginX)),
                       y: max(visibleFrame.minY, min(origin.y, maxOriginY)))
    }
}
