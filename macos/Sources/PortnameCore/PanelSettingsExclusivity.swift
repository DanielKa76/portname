import Foundation

/// Exclusivity policy between the menubar panel and the settings window.
/// Both anchor near the top-right of the screen and overlap when shown
/// together, so the requirement is "either the panel or the settings window"
/// — never both visible at once.
///
/// This type holds only the decision logic (pure, unit-tested); the AppKit
/// side executes the orders: `SettingsWindowController` on the settings
/// side, `MenuBarPanelDismissal` plus `MenuBarPanel.onAppear` on the panel
/// side.
public enum PanelSettingsExclusivity {

    public enum Action: Equatable, Sendable {
        /// Dismiss the presented menubar panel.
        case dismissPanel
        /// Order the settings window out.
        case hideSettings
        /// Bring the settings window to front and focus it.
        case showSettings
    }

    /// The settings entry point was used (gear in the panel header). A
    /// visible panel must be dismissed BEFORE the settings window appears —
    /// the ordering in the returned list is part of the contract. When the
    /// panel is already hidden, the request only (re-)shows settings.
    public static func actions(forSettingsRequest panelVisible: Bool) -> [Action] {
        var actions: [Action] = []
        if panelVisible { actions.append(.dismissPanel) }
        actions.append(.showSettings)
        return actions
    }

    /// The menubar panel became visible (status-item click). A still-visible
    /// settings window must be ordered out so the two never overlap. Settings
    /// state is not lost by hiding: toggles persist immediately and the
    /// window (with its view state) is kept alive by its controller.
    public static func actions(forPanelOpen settingsVisible: Bool) -> [Action] {
        settingsVisible ? [.hideSettings] : []
    }
}
