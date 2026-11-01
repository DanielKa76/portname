import SwiftUI
import PortnameCore
import ServiceManagement

/// Small settings window: login item (GUI only), connection diagnostics,
/// version/protocol info and the explicitly confirmed daemon-restart
/// maintenance action.
struct SettingsView: View {
    let model: AppModel
    @StateObject private var loginItem = LoginItemService()
    @State private var confirmRestart = false
    @State private var restartMessage: String?
    @State private var restartInFlight = false
    @State private var daemonLogExists: Bool = false

    var body: some View {
        Form {
            Section {
                Toggle(L10n.text("App beim Anmelden öffnen"), isOn: Binding(
                    get: { loginItem.isEnabledOrPending },
                    set: { loginItem.setEnabled($0) }
                ))
                .disabled(!appIsInBundleLocation)
                if let loginError = loginItem.lastError {
                    // A failed autostart toggle must be visible, not silently
                    // swallowed — the error stays until the next attempt.
                    Label(loginError, systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 4) {
                    Text(loginItemText)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if loginItem.status == .requiresApproval {
                        Button(L10n.text("Systemeinstellungen öffnen")) {
                            // Apple's official API for exactly this pane;
                            // the private x-apple.systempreferences URL is
                            // not needed.
                            SMAppService.openSystemSettingsLoginItems()
                        }
                        .buttonStyle(.link)
                        .font(.caption)
                    }
                }
                Text(L10n.text("Dies startet nur die Menüleisten-App. Der Hintergrunddienst (LaunchAgent dev.portname.daemon) läuft unabhängig davon — Freigaben und Tunnel bleiben bei App-Ende aktiv."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text(L10n.text("Autostart"))
            }

            Section {
                LabeledContent(L10n.text("Socket")) {
                    // Wraps instead of truncating: the full path must stay
                    // readable (truncation cut it mid-word); text
                    // selection keeps copyability.
                    Text(SocketPathResolver.userSocketPath())
                        .font(.system(size: 11, design: .monospaced))
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                LabeledContent(L10n.text("Zustand")) {
                    Text(connectionText)
                }
                LabeledContent(L10n.text("Protokoll")) {
                    // Three distinct cases: never reached a daemon, reached a
                    // pre-v1 daemon, reached a versioned daemon.
                    switch model.connection {
                    case .connecting, .unreachable:
                        Text("—")
                    case .incompatibleProtocol:
                        Text(L10n.text("unversioniert (alter Daemon)")).foregroundStyle(.orange)
                    case .connected:
                        if let v = model.status?.protocolVersion {
                            Text("v\(v)")
                        } else {
                            Text(L10n.text("unversioniert (alter Daemon)")).foregroundStyle(.orange)
                        }
                    }
                }
                LabeledContent(L10n.text("Daemon-Instanz")) {
                    Text(model.status?.daemonInstanceId?.prefix(8).appending("…") ?? "—")
                        .font(.system(size: 11, design: .monospaced))
                }
                // Wraps to a column when the row is narrower than both
                // buttons need side by side — buttons cannot shrink, so a
                // plain HStack would overflow (measured form minimum at
                // 460 pt window width: 490 pt → right-side clipping).
                ViewThatFits(in: .horizontal) {
                    HStack {
                        Button(L10n.text("Verbindung erneut versuchen")) {
                            Task { await model.refreshNow() }
                        }
                        Button(L10n.text("Logdatei im Finder zeigen")) {
                            let logURL = URL(fileURLWithPath: NSHomeDirectory())
                                .appendingPathComponent(".portname/daemon.log")
                            NSWorkspace.shared.activateFileViewerSelecting([logURL])
                        }
                        .disabled(!daemonLogExists)
                    }
                    VStack(alignment: .leading) {
                        Button(L10n.text("Verbindung erneut versuchen")) {
                            Task { await model.refreshNow() }
                        }
                        Button(L10n.text("Logdatei im Finder zeigen")) {
                            let logURL = URL(fileURLWithPath: NSHomeDirectory())
                                .appendingPathComponent(".portname/daemon.log")
                            NSWorkspace.shared.activateFileViewerSelecting([logURL])
                        }
                        .disabled(!daemonLogExists)
                    }
                }
                if let message = restartMessage, confirmRestart == false {
                    Text(message)
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } header: {
                Text(L10n.text("Verbindung"))
            } footer: {
                EmptyView()
            }

            Section {
                if confirmRestart {
                    VStack(alignment: .leading, spacing: 6) {
                        Label(L10n.text("Hintergrunddienst jetzt neu starten? Laufende öffentliche Freigaben werden dabei beendet. Lokale Adressen bleiben bestehen."),
                              systemImage: "exclamationmark.triangle")
                            .font(.callout)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                        HStack {
                            Button(L10n.text("Neu starten"), role: .destructive) {
                                confirmRestart = false
                                performRestart()
                            }
                            .disabled(restartInFlight)
                            Button(L10n.text("Abbrechen"), role: .cancel) { confirmRestart = false }
                        }
                    }
                } else {
                    Button(role: .destructive) {
                        restartMessage = nil
                        confirmRestart = true
                    } label: {
                        if restartInFlight {
                            HStack(spacing: 6) {
                                ProgressView().controlSize(.mini)
                                Text(L10n.text("Wird neu gestartet …"))
                            }
                        } else {
                            Text(L10n.text("Hintergrunddienst neu starten …"))
                        }
                    }
                    .disabled(restartInFlight)
                }
            } header: {
                Text(L10n.text("Wartung"))
            }

            Section {
                LabeledContent(L10n.text("App-Version")) {
                    Text(appVersion)
                }
                LabeledContent(L10n.text("App-Bundle")) {
                    // Wraps instead of one-line middle truncation: the
                    // path identifies the running install and must stay
                    // fully readable (multi-line is fine).
                    Text(Bundle.main.bundleURL.path)
                        .font(.system(size: 10, design: .monospaced))
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            } header: {
                Text(L10n.text("Über"))
            }
        }
        .formStyle(.grouped)
        // Width fixed for a stable slide-out anchor; height natural so the
        // grouped form never scrolls or clips (the previous fixed 460×520
        // was narrower than the form's measured 490 pt minimum width, which
        // clipped every long row at the right edge).
        .frame(width: 520)
        .onAppear(perform: refreshFacts)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            loginItem.refresh()
        }
    }

    private var appIsInBundleLocation: Bool {
        Bundle.main.bundleURL.pathComponents.count > 1 &&
        !Bundle.main.bundleURL.path.contains("/.build/") &&
        !Bundle.main.bundleURL.path.contains("/dist/")
    }

    private var loginItemText: String {
        if !appIsInBundleLocation {
            return L10n.format("Login-Registrierung funktioniert nur aus einer installierten App (~/Applications), nicht aus dem Build-Verzeichnis. Status: %@", loginItem.statusText)
        }
        return L10n.format("Status: %@", loginItem.statusText)
    }

    private var connectionText: String {
        switch model.connection {
        case .connecting: return L10n.text("verbindet …")
        case .connected: return L10n.text("verbunden")
        case .unreachable: return L10n.text("nicht erreichbar")
        case .incompatibleProtocol: return L10n.text("inkompatibles Protokoll (Daemon aktualisieren)")
        }
    }

    private var appVersion: String {
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
        return short ?? L10n.text("Entwicklungsbau")
    }

    private func refreshFacts() {
        loginItem.refresh()
        let logURL = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".portname/daemon.log")
        daemonLogExists = FileManager.default.fileExists(atPath: logURL.path)
    }

    private func performRestart() {
        // launchctl runs off the main thread — a slow kickstart must never
        // freeze the settings window.
        restartInFlight = true
        Task {
            let result: Result<Void, Error> = await Task.detached(priority: .userInitiated) {
                do {
                    try DaemonMaintenance.restartDaemon()
                    return .success(())
                } catch {
                    return .failure(error)
                }
            }.value
            restartInFlight = false
            switch result {
            case .success:
                restartMessage = L10n.text("Hintergrunddienst wurde neu gestartet. Die Verbindung baut sich in wenigen Sekunden wieder auf.")
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                await model.refreshNow()
            case .failure(let error):
                restartMessage = L10n.format("Neustart fehlgeschlagen: %@", error.localizedDescription)
            }
        }
    }
}
