import Foundation
import ServiceManagement

/// GUI login item via SMAppService.mainApp. This is deliberately separate
/// from the daemon's own LaunchAgent (dev.portname.daemon): the toggle must
/// never touch, replace or disable that service, and no second autostart
/// technique is registered as a silent fallback.
@MainActor
final class LoginItemService: ObservableObject {
    @Published private(set) var status: SMAppService.Status = .notRegistered
    @Published var lastError: String?

    init() {
        refresh()
    }

    /// Reads the current SMAppService status. A failed setEnabled() must not
    /// have its error wiped by the follow-up refresh, so clearing the error
    /// is explicit and opt-in.
    func refresh(clearError: Bool = false) {
        status = SMAppService.mainApp.status
        if clearError {
            lastError = nil
        }
    }

    var isEnabledOrPending: Bool {
        status == .enabled || status == .requiresApproval
    }

    var statusText: String {
        switch status {
        case .enabled: return "aktiv"
        case .requiresApproval: return "Freigabe in den Systemeinstellungen erforderlich"
        case .notRegistered, .notFound: return "aus"
        @unknown default: return "unbekannt"
        }
    }

    func setEnabled(_ on: Bool) {
        lastError = nil
        do {
            if on {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            lastError = "Login-Einstellung fehlgeschlagen: \(error.localizedDescription)"
        }
        // Status refresh only — a just-set error stays visible until the
        // next deliberate attempt.
        refresh(clearError: false)
    }
}
