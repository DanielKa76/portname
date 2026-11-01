import CoreGraphics
import Foundation

/// Height of the menubar panel window: always exactly its SwiftUI content.
///
/// The panel is a window-style `MenuBarExtra`. On macOS 27 its window grows
/// with the content but never shrinks back. Switching from the project list
/// to a shorter view ("Manuell hinzufügen", rename) or losing a project left
/// the content centered in a taller window whose remaining area is
/// transparent, so the app behind showed through above and below the
/// content. Measured on macOS 27.0.1: list 300 pt, form 187 pt, window
/// stayed at 300 pt.
///
/// Pure geometry, unit-tested; `PanelWindowSizer` (PortnameApp) feeds it the
/// window's content rect and the measured content height and applies the
/// result.
public enum PanelSizing {

    /// Differences below this are layout rounding, never a reason to move
    /// the window (and to risk a resize feedback loop).
    public static let tolerance: CGFloat = 0.5

    /// The content rect (global screen coordinates, origin bottom-left) the
    /// panel window should have for `contentHeight`, or nil when it already
    /// fits. The top edge stays where it is, so the panel stays attached
    /// below the menu bar; width and horizontal position never change.
    public static func contentRect(current: CGRect, contentHeight: CGFloat) -> CGRect? {
        guard contentHeight.isFinite, contentHeight >= 1 else { return nil }
        guard abs(current.height - contentHeight) > tolerance else { return nil }
        return CGRect(x: current.minX,
                      y: current.maxY - contentHeight,
                      width: current.width,
                      height: contentHeight)
    }
}
