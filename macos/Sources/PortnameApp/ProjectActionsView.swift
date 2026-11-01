import SwiftUI
import PortnameCore

/// The per-project action menu: Finder reveal, rename, WLAN share toggle,
/// public share dialog, and — for manual entries only — removal.
/// Auto-rename and arbitrary process stops are deliberately not offered.
struct ProjectActionsMenu: View {
    let model: AppModel
    let route: Route
    let onRename: () -> Void
    let onShare: () -> Void
    let onRemoveAsk: () -> Void

    var body: some View {
        Button {
            model.revealProjectFolder(for: route)
        } label: {
            Label(L10n.text("Ordner im Finder zeigen"), systemImage: "folder")
        }
        .disabled(route.root == nil && route.cwd == nil)

        Divider()

        if route.isManual {
            Button {
                onRemoveAsk()
            } label: {
                Label(L10n.text("Manuelle Zuordnung entfernen …"), systemImage: "minus.circle")
            }
            .disabled(model.mutationsLocked || model.inFlightIDs.contains(route.id))
        } else {
            Button {
                onRename()
            } label: {
                Label(L10n.text("Umbenennen …"), systemImage: "character.cursor.ibeam")
            }
            .disabled(model.mutationsLocked || model.inFlightIDs.contains(route.id))
        }

        Divider()

        additionalServices

        wlanToggle

        Button {
            onShare()
        } label: {
            Label(L10n.text("Öffentlicher Link …"), systemImage: "globe")
        }
        .disabled(model.mutationsLocked)
    }

    /// Projects with more than one living service (frontend + backend) can
    /// switch which one carries the name. Stored per project root on the
    /// daemon; the row shows the effective target port.
    @ViewBuilder
    private var additionalServices: some View {
        let services = route.services ?? []
        if !route.isManual, services.count > 1 {
            Menu {
                ForEach(services) { service in
                    Button {
                        Task {
                            if let current = await model.currentRoute(for: route) {
                                _ = await model.setPrimaryService(current, port: service.port)
                            }
                        }
                    } label: {
                        if service.primary == true {
                            Label(L10n.format("Hauptdienst: :%ld", service.port), systemImage: "checkmark")
                        } else {
                            Text(L10n.format("Als Hauptdienst verwenden (:%ld · %@)", service.port, service.command ?? "proc"))
                        }
                    }
                    .disabled(service.primary == true || model.mutationsLocked || model.inFlightIDs.contains(route.id))
                }
            } label: {
                Label(L10n.text("Dienste"), systemImage: "square.stack.3d.up")
            }
            .menuIndicator(.hidden)
        }
    }

    @ViewBuilder
    private var wlanToggle: some View {
        let on = route.exposureRequested == true
        if route.awaitsExposureConfirmation {
            // Paused until the user confirms the current endpoint/network
            // (exposure from an older version, moved target, other network).
            // The wish stays set, so the toggle below can only switch it off;
            // confirming is an explicit `expose on` bound to the revision.
            Button {
                Task {
                    // Confirms this menu's route — the endpoint the user saw,
                    // with its revision — and only while a status read issued
                    // now still shows it waiting, unchanged (the remaining
                    // window is described at AppModel.confirmExposure).
                    _ = await model.confirmExposure(route)
                }
            } label: {
                Label(L10n.text("WLAN-Freigabe bestätigen"), systemImage: "checkmark.shield")
            }
            .disabled(model.mutationsLocked || model.inFlightIDs.contains(route.id))
        }
        Button {
            Task {
                if let current = await model.currentRoute(for: route) {
                    // Derive the new value from the *freshly resolved* route:
                    // the exposure wish may have changed since this menu was
                    // rendered, and the menu label is then stale.
                    _ = await model.setExposed(current, on: !(current.exposureRequested == true))
                }
            }
        } label: {
            if on {
                Label(L10n.text("WLAN-Freigabe ausschalten"), systemImage: "wifi.slash")
            } else {
                Label(L10n.format("Im WLAN freigeben (%@.local)", route.name), systemImage: "wifi")
            }
        }
        .disabled(model.mutationsLocked || model.inFlightIDs.contains(route.id))
    }
}
