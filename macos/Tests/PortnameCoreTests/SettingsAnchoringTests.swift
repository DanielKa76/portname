import XCTest
@testable import PortnameCore

/// The settings window must open exactly where the menubar panel slides
/// out: centered under the status item, top edge flush below the menu bar,
/// clamped into the screen's visible frame. These tests pin the geometry
/// (`SettingsAnchoring`); the AppKit side (frame capture, window ordering)
/// is covered by manual verification.
///
/// Global screen coordinates: origin bottom-left, y increases upward. The
/// modeled main screen is 1512 × 982 points with a 24-point menu bar, so
/// its visible frame is (0, 0, 1512, 958) and the status item button's
/// bottom edge (= menu bar bottom) sits at y = 958.
final class SettingsAnchoringTests: XCTestCase {

    private static let windowSize = CGSize(width: 460, height: 520)
    private static let visibleFrame = CGRect(x: 0, y: 0, width: 1512, height: 958)

    private func origin(statusItemMidX: CGFloat,
                        statusItemMinY: CGFloat = 958,
                        statusItemWidth: CGFloat = 30,
                        // Spelled out: Swift 6.4 rejects a covariant `Self`
                        // in a default argument expression.
                        windowSize: CGSize = SettingsAnchoringTests.windowSize,
                        visibleFrame: CGRect = SettingsAnchoringTests.visibleFrame) -> CGPoint {
        SettingsAnchoring.origin(
            statusItemFrame: CGRect(x: statusItemMidX - statusItemWidth / 2,
                                    y: statusItemMinY,
                                    width: statusItemWidth,
                                    height: 24),
            windowSize: windowSize,
            visibleFrame: visibleFrame)
    }

    func testCentersWindowUnderStatusItem() {
        // Icon mid at x=1015: window is centered on it, no clamp needed.
        let origin = origin(statusItemMidX: 1015)
        XCTAssertEqual(origin.x, 1015 - Self.windowSize.width / 2, accuracy: 0.001)
    }

    func testTopEdgeSitsFlushBelowMenuBar() {
        // topGap is 0: window top edge == status item bottom edge, i.e. the
        // menu bar's bottom line — the same height the panel slides out at.
        let origin = origin(statusItemMidX: 1015)
        XCTAssertEqual(origin.y + Self.windowSize.height, 958, accuracy: 0.001)
    }

    func testRightScreenEdgeClampAlignsWindowRightUnderIcon() {
        // Icon 72pt from the right screen edge: centering would push the
        // window's right edge past the screen; the clamp moves it flush to
        // the visible frame — right-aligned under the icon, the same corner
        // the panel lands in.
        let origin = origin(statusItemMidX: 1440)
        XCTAssertEqual(origin.x, 1512 - Self.windowSize.width, accuracy: 0.001)
        // Still vertically anchored below the bar.
        XCTAssertEqual(origin.y + Self.windowSize.height, 958, accuracy: 0.001)
    }

    func testLeftScreenEdgeClampKeepsWindowOnScreen() {
        // Icon at the far left: centering would push the window off-screen
        // to the left; the clamp pins it to the visible frame's left edge.
        let origin = origin(statusItemMidX: 50)
        XCTAssertEqual(origin.x, 0, accuracy: 0.001)
    }

    func testAnchorsIntoTheScreenShowingTheStatusItem() {
        // Second display right of the main one; its visible frame is
        // shifted. The origin must be expressed in that screen's coordinate
        // space, not clamped against the main screen.
        let externalVisible = CGRect(x: -1920, y: 0, width: 1920, height: 1055)
        let origin = origin(statusItemMidX: -960, statusItemMinY: 1055,
                            visibleFrame: externalVisible)
        XCTAssertEqual(origin.x, -960 - Self.windowSize.width / 2, accuracy: 0.001)
        XCTAssertEqual(origin.y + Self.windowSize.height, 1055, accuracy: 0.001)
    }

    func testWindowTallerThanVisibleFramePinsToBottomEdge() {
        // Degenerate case: the clamp must pin to the visible frame instead
        // of producing a negative (off-screen) origin.
        let smallVisible = CGRect(x: 0, y: 0, width: 1512, height: 400)
        let origin = origin(statusItemMidX: 1015, windowSize: CGSize(width: 460, height: 520),
                            visibleFrame: smallVisible)
        XCTAssertEqual(origin.y, 0, accuracy: 0.001)
    }

    func testWindowWiderThanVisibleFramePinsToLeftEdge() {
        let narrowVisible = CGRect(x: 0, y: 0, width: 300, height: 958)
        let origin = origin(statusItemMidX: 150, windowSize: CGSize(width: 460, height: 520),
                            visibleFrame: narrowVisible)
        XCTAssertEqual(origin.x, 0, accuracy: 0.001)
    }

    func testTallMenuBarAnchorUsesActualMenuBarBottom() {
        // Notch-style menu bars are taller; the status item's bottom edge —
        // not a hardcoded bar height — is the anchor line.
        let origin = origin(statusItemMidX: 1015, statusItemMinY: 945)
        XCTAssertEqual(origin.y + Self.windowSize.height, 945, accuracy: 0.001)
    }

    // MARK: - Panel-frame fallback anchor

    /// The fallback chain (status item frame → last presented panel frame →
    /// centered) maps a captured panel frame through
    /// ``SettingsAnchoring.anchorFrame(fromPanelFrame:)``. Measured real
    /// panel frame on macOS 27 (420-wide panel under the status item at
    /// x = 956): (956, 1027, 420, 44).
    private static let measuredPanelFrame = CGRect(x: 956, y: 1027, width: 420, height: 44)

    func testPanelAnchorIsHorizontallyCenteredOnPanel() {
        let anchor = SettingsAnchoring.anchorFrame(fromPanelFrame: Self.measuredPanelFrame)
        XCTAssertEqual(anchor.midX, Self.measuredPanelFrame.midX, accuracy: 0.001)
    }

    func testPanelAnchorTopEdgeMatchesPanelTopEdge() {
        // The settings window's top edge must land on the panel's top edge —
        // the same slide-out line. Visible frame tall enough (menu-bar line
        // at 1076) that the clamp — covered by its own tests — stays out.
        let tallVisible = CGRect(x: 0, y: 0, width: 1710, height: 1076)
        let anchor = SettingsAnchoring.anchorFrame(fromPanelFrame: Self.measuredPanelFrame)
        let origin = SettingsAnchoring.origin(statusItemFrame: anchor,
                                              windowSize: Self.windowSize,
                                              visibleFrame: tallVisible)
        XCTAssertEqual(origin.y + Self.windowSize.height,
                       Self.measuredPanelFrame.maxY, accuracy: 0.001)
    }

    func testPanelAnchorStaysNonEmptyForScreenSelection() {
        // The anchor screen selection intersects the anchor with each
        // screen frame; a degenerate (zero-height) anchor would never
        // intersect and silently fall through to NSScreen.main. Uses the
        // real measured macOS 27 geometry (1710×1107 screen, visible frame
        // (0, 84, 1710, 989), panel top at y = 1071).
        let measuredVisibleFrame = CGRect(x: 0, y: 84, width: 1710, height: 989)
        let anchor = SettingsAnchoring.anchorFrame(fromPanelFrame: Self.measuredPanelFrame)
        XCTAssertFalse(anchor.isEmpty)
        XCTAssertTrue(measuredVisibleFrame.intersects(anchor))
    }

    func testPanelFallbackReoccupiesSlideOutSpotWithRealGeometry() {
        // Measured macOS 27 geometry (panel window (956, 1027, 420, 44)
        // under the status item window at x = 956): the panel is NOT
        // centered on the icon — its LEFT edge aligns with the icon's left
        // edge — so the fallback origin cannot equal the primary origin.
        // The measured invariants that matter: the fallback window is
        // centered on the panel (it re-occupies the slide-out spot) and
        // the status item stays inside the fallback window's horizontal
        // span. Uses the real production window size (520 wide, natural
        // height) and a visible frame tall enough that the clamp — covered
        // by its own tests — stays out of the comparison.
        let tallVisible = CGRect(x: 0, y: 0, width: 1710, height: 1076)
        let productionWindowSize = CGSize(width: 520, height: 560)
        let itemFrame = CGRect(x: 956, y: 1076, width: 32, height: 29)
        let primary = SettingsAnchoring.origin(statusItemFrame: itemFrame,
                                               windowSize: productionWindowSize,
                                               visibleFrame: tallVisible)
        let anchor = SettingsAnchoring.anchorFrame(fromPanelFrame: Self.measuredPanelFrame)
        let fallback = SettingsAnchoring.origin(statusItemFrame: anchor,
                                                windowSize: productionWindowSize,
                                                visibleFrame: tallVisible)
        // Centered on the panel.
        XCTAssertEqual(fallback.x + productionWindowSize.width / 2,
                       Self.measuredPanelFrame.midX, accuracy: 0.001)
        // The status item stays within the fallback window's span.
        let span = (fallback.x, fallback.x + productionWindowSize.width)
        XCTAssertTrue(span.0 <= itemFrame.minX && span.1 >= itemFrame.maxX,
                      "status item \(itemFrame) outside fallback span \(span)")
        // Panel top (1071) sits 5 pt below the icon bottom (1076).
        XCTAssertEqual(primary.y - fallback.y, 5, accuracy: 0.001)
    }
}
