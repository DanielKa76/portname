import XCTest
@testable import PortnameCore

/// The panel and the settings window overlap near the status item; the
/// required behavior is "either the panel or the settings window". These
/// tests pin the decision policy; the AppKit execution (window ordering,
/// panel dismissal) is covered by manual verification.
final class PanelSettingsExclusivityTests: XCTestCase {

    func testSettingsRequestDismissesVisiblePanelBeforeShowingSettings() {
        XCTAssertEqual(
            PanelSettingsExclusivity.actions(forSettingsRequest: true),
            [.dismissPanel, .showSettings])
    }

    func testSettingsRequestShowsSettingsWhenPanelAlreadyHidden() {
        XCTAssertEqual(
            PanelSettingsExclusivity.actions(forSettingsRequest: false),
            [.showSettings])
    }

    func testDismissalAlwaysPrecedesSettingsShow() {
        // Ordering contract: the panel is ordered out BEFORE the settings
        // window is brought front, so the two never overlap — not even for a
        // moment — regardless of visibility races.
        let actions = PanelSettingsExclusivity.actions(forSettingsRequest: true)
        XCTAssertEqual(actions.first, .dismissPanel)
        XCTAssertEqual(actions.last, .showSettings)
    }

    func testPanelOpenHidesVisibleSettings() {
        XCTAssertEqual(
            PanelSettingsExclusivity.actions(forPanelOpen: true),
            [.hideSettings])
    }

    func testPanelOpenDoesNothingWhenSettingsHidden() {
        XCTAssertEqual(
            PanelSettingsExclusivity.actions(forPanelOpen: false),
            [])
    }

    func testHideSettingsIsTheOnlyPanelOpenAction() {
        // Opening the panel must never touch the panel itself nor attempt to
        // show settings — hiding a visible settings window is the whole job.
        for settingsVisible in [true, false] {
            let actions = PanelSettingsExclusivity.actions(forPanelOpen: settingsVisible)
            XCTAssertTrue(actions.allSatisfy { $0 == .hideSettings })
        }
    }
}
