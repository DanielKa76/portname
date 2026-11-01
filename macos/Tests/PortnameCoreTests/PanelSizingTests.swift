import XCTest
@testable import PortnameCore

/// The menubar panel window must be exactly as tall as its content, in both
/// directions, with its top edge pinned below the menu bar. Global screen
/// coordinates: origin bottom-left, y increases upward. The modeled panel
/// hangs from the menu bar bottom at y = 958.
final class PanelSizingTests: XCTestCase {

    private let listRect = CGRect(x: 1062, y: 658, width: 420, height: 300) // top at 958

    func testShrinksToShorterContentKeepingTheTopEdge() throws {
        // List (300 pt) -> "Manuell hinzufügen" (187 pt), as measured on macOS 27.0.1.
        let rect = try XCTUnwrap(PanelSizing.contentRect(current: listRect, contentHeight: 187))
        XCTAssertEqual(rect.maxY, 958, accuracy: 0.001, "the panel stays attached below the menu bar")
        XCTAssertEqual(rect.height, 187, accuracy: 0.001)
        XCTAssertEqual(rect.minX, listRect.minX)
        XCTAssertEqual(rect.width, listRect.width)
    }

    func testGrowsDownwardForTallerContent() throws {
        let rect = try XCTUnwrap(PanelSizing.contentRect(current: listRect, contentHeight: 452))
        XCTAssertEqual(rect.maxY, 958, accuracy: 0.001)
        XCTAssertEqual(rect.minY, 958 - 452, accuracy: 0.001)
    }

    func testLeavesAFittingWindowAlone() {
        XCTAssertNil(PanelSizing.contentRect(current: listRect, contentHeight: 300))
        XCTAssertNil(PanelSizing.contentRect(current: listRect, contentHeight: 300.4),
                     "rounding differences never move the window")
    }

    func testIgnoresHeightsThatAreNoLayoutResult() {
        // A zero or non-finite measurement (view not laid out yet) must
        // never collapse the window.
        XCTAssertNil(PanelSizing.contentRect(current: listRect, contentHeight: 0))
        XCTAssertNil(PanelSizing.contentRect(current: listRect, contentHeight: .infinity))
        XCTAssertNil(PanelSizing.contentRect(current: listRect, contentHeight: .nan))
    }
}
