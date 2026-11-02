import SwiftUI
import PortnameCore

/// Panel navigation. Everything stays inside the menubar window so no
/// second window/focus choreography is needed.
enum PanelMode: Equatable {
    case list
    case addManual
    case rename(Route)
    case share(Route)
}

/// The menubar panel: project list, search, local actions, WLAN and public
/// share entry points — plus every degraded state (connecting, unreachable,
/// stale snapshot, legacy daemon, empty list).
struct MenuBarPanel: View {
    @Bindable var model: AppModel
    @State private var mode: PanelMode = .list
    @State private var diagnosticsExpanded = false
    @State private var confirmRevokeAll = false
    @State private var setupRunning = false
    @State private var setupError: String?
    /// Measured height of the list content; 0 until the first layout pass.
    @State private var measuredListHeight: CGFloat = 0
    @FocusState private var searchFocused: Bool

    var body: some View {
        Group {
            switch mode {
            case .list:
                listContent
            case .addManual:
                AddManualForm(model: model) { mode = .list }
            case .rename(let route):
                RenameForm(model: model, route: route) { mode = .list }
            case .share(let route):
                ShareView(model: model, route: route) { mode = .list }
            }
        }
        .padding(14)
        .frame(width: 420)
        // The window follows the content height in both directions
        // (PanelSizing): macOS 27 grows a MenuBarExtra window but never
        // shrinks it. Measured here, before the flexible frame below, so
        // this is the content's own height, not the window's.
        .onGeometryChange(for: CGFloat.self) { proxy in
            proxy.size.height
        } action: { height in
            DispatchQueue.main.async { PanelWindowSizer.fit(contentHeight: height) }
        }
        // Should the window still be taller for a moment, the content sits
        // at the top on an opaque background instead of floating centered
        // over a see-through area.
        .frame(maxHeight: .infinity, alignment: .top)
        .background(.background)
        .onAppear {
            mode = .list
            // Polling itself runs from the app lifecycle (AppLifecycleDelegate);
            // the panel only raises the cadence while it is open.
            model.setPanel(visible: true)
            // Mutual exclusivity with the settings window: both anchor near
            // the status item and overlap, so the panel wins this direction.
            SettingsWindowController.shared.hideForPanel()
        }
        .onDisappear { model.setPanel(visible: false) }
    }

    // MARK: - List

    private var listContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            statusLine
            if let banner = bannerText {
                Label(banner, systemImage: bannerIcon)
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let scanBanner = scanErrorBanner {
                Label(scanBanner, systemImage: "arrow.triangle.2.circlepath.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if model.networkChangePending {
                networkChangeNote
            }

            if model.connection == .connected || model.status != nil {
                searchField
                projectList
            } else {
                unreachablePlaceholder
            }
            if model.hasActiveOrStartingShare {
                quitSemanticsNote
            }
            footerButtons
        }
        .onExitCommand(perform: handleEscape)
        .onMoveCommand(perform: moveListSelection)
    }

    // Escape backs out one level at a time: leave a dialog, then clear the
    // search — the panel stays open.
    private func handleEscape() {
        if mode != .list {
            mode = .list
        } else if !model.searchText.isEmpty {
            model.searchText = ""
        }
    }

    /// A network change must never be presented as "still the same trusted
    /// Wi-Fi": when the daemon reports a different LAN interface/address,
    /// this note appears until the user acknowledges it. Exposures do not
    /// follow into another network — the daemon pauses them there
    /// ("network-changed") until the user confirms them in that row.
    private var networkChangeNote: some View {
        HStack(alignment: .top, spacing: 6) {
            Label(L10n.text("Netzwerkwechsel — das ist möglicherweise nicht mehr dasselbe vertraute WLAN. WLAN-Freigaben aus einem anderen Netz bleiben pausiert, bis du sie hier bestätigst."),
                  systemImage: "wifi.exclamationmark")
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button(L10n.text("Verstanden")) { model.dismissNetworkChange() }
                .controlSize(.small)
        }
    }

    /// Quit semantics, visible — not only in a tooltip: as long as public
    /// links exist, the panel states that quitting the app keeps them (and
    /// the daemon) running, right next to the distinct global revoke.
    private var quitSemanticsNote: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(L10n.plural(model.status?.shares.filter { ($0.phase == .active || $0.phase == .starting) && $0.expired != true }.count ?? 0,
                             one: "„App beenden“ schließt nur die Oberfläche: Hintergrunddienst und öffentlicher Link laufen weiter.",
                             other: "„App beenden“ schließt nur die Oberfläche: Hintergrunddienst und %ld öffentliche Links laufen weiter."))
                .font(.caption)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            if confirmRevokeAll {
                Text(L10n.text("Alle öffentlichen Links jetzt beenden? Aktive Besucher werden sofort getrennt."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button(L10n.text("Wirklich alle beenden"), role: .destructive) {
                        confirmRevokeAll = false
                        Task { await model.revokeAllShares() }
                    }
                    .disabled(model.mutationsLocked || model.inFlightIDs.contains("revoke-all"))
                    Button(L10n.text("Nicht beenden"), role: .cancel) { confirmRevokeAll = false }
                }
            } else {
                Button {
                    confirmRevokeAll = true
                } label: {
                    Label(L10n.text("Alle öffentlichen Links beenden …"), systemImage: "globe.badge.chevron.backward")
                }
                .buttonStyle(.plain)
                .font(.caption)
                .disabled(model.mutationsLocked || model.inFlightIDs.contains("revoke-all"))
                .help(L10n.text("Beendet jeden öffentlichen Link über den Hintergrunddienst — lokale Adressen und WLAN-Freigaben bleiben unverändert."))
            }
            if let feedback = model.feedback, feedback.routeID == "revoke-all" {
                FeedbackLine(text: feedback.text, kind: feedback.kind, onDismiss: { model.dismissFeedback() })
            }
        }
        .padding(8)
        .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 7))
    }

    // Arrow keys walk the visible list (the search field stays focused so
    // typing keeps working); Enter opens the selected project.
    private func moveListSelection(_ direction: MoveCommandDirection) {
        guard direction == .up || direction == .down else { return }
        let routes = model.filteredRoutes
        guard !routes.isEmpty else { return }
        let currentIndex = routes.firstIndex { $0.id == model.selectedRouteID }
            ?? (direction == .down ? -1 : 0)
        let next = direction == .down ? currentIndex + 1 : currentIndex - 1
        guard next >= 0, next < routes.count else { return }
        model.selectedRouteID = routes[next].id
    }

    private func openSelectedOrFirst() -> Route? {
        // Enter in the search field may only open a project that is actually
        // visible: a selection filtered out by the current query must never
        // be opened invisibly.
        let visible = model.filteredRoutes
        if let id = model.selectedRouteID, let selected = visible.first(where: { $0.id == id }) {
            return selected
        }
        return visible.first
    }
    private var header: some View {
        HStack {
            Text("portname")
                .font(.headline)
            Spacer()
            Button {
                SettingsWindowController.shared.show(model: model)
            } label: {
                Image(systemName: "gearshape")
            }
            .buttonStyle(.plain)
            .accessibilityLabel(L10n.text("Einstellungen"))
            .keyboardShortcut(",", modifiers: .command)
            .help(L10n.text("Einstellungen"))
        }
    }

    private var statusLine: some View {
        Group {
            switch model.connection {
            case .connecting:
                Label(L10n.text("Verbinde mit Hintergrunddienst …"), systemImage: "hourglass")
                    .foregroundStyle(.secondary)
            case .connected:
                Text(L10n.plural(model.routes.count,
                                 one: "1 Projekt · Hintergrunddienst verbunden",
                                 other: "%ld Projekte · Hintergrunddienst verbunden"))
                    .foregroundStyle(.secondary)
            case .unreachable where showsFirstRunSetup:
                Label(L10n.text("Hintergrunddienst noch nicht eingerichtet"), systemImage: "power.circle")
                    .foregroundStyle(.secondary)
            case .unreachable:
                Label(model.lastErrorText ?? L10n.text("Dienst nicht erreichbar"), systemImage: "bolt.slash")
                    .foregroundStyle(.orange)
            case .incompatibleProtocol:
                Label(L10n.text("Älterer Hintergrunddienst — neue Aktionen deaktiviert"), systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
        }
        .font(.callout)
    }

    private var bannerText: String? {
        if model.connection == .unreachable && model.status != nil {
            return L10n.text("Verbindung verloren — zeige den letzten Stand. Riskante Aktionen sind deaktiviert.")
        }
        if model.connection == .incompatibleProtocol {
            return L10n.text("Der Hintergrunddienst ist veraltet (kein Protokoll v1). Bitte Daemon aktualisieren und neu starten — Anzeige funktioniert, Aktionen nicht.")
        }
        return nil
    }

    private var scanErrorBanner: String? {
        guard model.connection == .connected, let scanError = model.status?.scanError, !scanError.isEmpty else {
            return nil
        }
        return L10n.format("Letzter Projekt-Scan fehlgeschlagen — die Liste zeigt den vorherigen Stand. (%@)", scanError)
    }

    private var bannerIcon: String {
        model.connection == .incompatibleProtocol ? "arrow.down.circle" : "wifi.slash"
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
            TextField(L10n.text("Projekte suchen …"), text: $model.searchText)
                .textFieldStyle(.plain)
                .focused($searchFocused)
                .keyboardShortcut("f", modifiers: .command)
                .onSubmit {
                    // Suche + Enter öffnet direkt die ausgewählte (oder erste
                    // treffende) Adresse — nur innerhalb des Suchergebnisses.
                    if let route = openSelectedOrFirst() {
                        model.openLocalURL(for: route)
                    }
                }
            if !model.searchText.isEmpty {
                Button {
                    model.searchText = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(L10n.text("Suche leeren"))
            }
        }
        .padding(6)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 7))
    }

    private var projectList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                let routes = model.filteredRoutes
                if routes.isEmpty && model.searchText.isEmpty && model.connection == .connected {
                    emptyState
                } else if routes.isEmpty && !model.searchText.isEmpty {
                    Text(L10n.format("Kein Treffer für „%@“.", model.searchText))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 18)
                        .frame(maxWidth: .infinity)
                } else {
                    ForEach(routes) { route in
                        ProjectRow(model: model, route: route,
                                   isSelected: model.selectedRouteID == route.id) {
                            mode = .rename(route)
                        } onShare: {
                            mode = .share(route)
                        }
                        Divider().padding(.leading, 4)
                    }
                }

                if !model.staleListeners.isEmpty && model.searchText.isEmpty {
                    staleSection
                }
            }
            // Rows grow with their notes (a feedback line, a pending result,
            // a paused Wi-Fi share): measure the stack instead of trusting
            // the fixed-row estimate, which clipped such lines.
            .onGeometryChange(for: CGFloat.self) { proxy in
                proxy.size.height
            } action: { height in
                measuredListHeight = height
            }
        }
        .frame(height: listHeight)
    }

    /// The menubar window sizes to the ideal content height; a bare
    /// ScrollView reports none. The measured row stack decides, capped at
    /// 480; before the first measurement an estimate stands in.
    private var listHeight: CGFloat {
        guard measuredListHeight < 1 else { return min(480, max(56, measuredListHeight.rounded(.up))) }
        return estimatedListHeight
    }

    /// Diagnostics count only while expanded — collapsed by default, the
    /// section is a single caption line.
    private var estimatedListHeight: CGFloat {
        let rowHeight: CGFloat = 52
        let staleCount = (diagnosticsExpanded && model.searchText.isEmpty) ? model.staleListeners.count : 0
        let staleHeight: CGFloat = staleCount > 0 ? CGFloat(staleCount) * 20 + 40 : 0
        let rows = CGFloat(max(model.filteredRoutes.count, model.routes.isEmpty ? 3 : 1))
        return min(480, max(56, rows * rowHeight + staleHeight))
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L10n.text("Keine Projekte entdeckt."))
                .font(.callout)
            Text(L10n.text("Starte einen Dev-Server — er erscheint hier innerhalb weniger Sekunden. Oder trag ihn manuell ein."))
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !model.mutationsLocked {
                Button(L10n.text("Manuell hinzufügen …")) { mode = .addManual }
                    .controlSize(.small)
            }
        }
        .padding(.vertical, 14)
    }

    private var staleSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            // Collapsed by default: this is diagnostics, not projects.
            Button {
                diagnosticsExpanded.toggle()
            } label: {
                Label(diagnosticsExpanded
                      ? L10n.text("Diagnose ausblenden")
                      : L10n.plural(model.staleListeners.count, one: "Diagnose · 1 Eintrag", other: "Diagnose · %ld Einträge"),
                      systemImage: diagnosticsExpanded ? "chevron.down" : "chevron.right")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)

            if diagnosticsExpanded {
                ForEach(model.staleListeners) { stale in
                    HStack {
                        Text(stale.name)
                            .font(.system(size: 12, design: .monospaced))
                        Spacer()
                        Group {
                            // verbatim: integer interpolation into Text
                            // formats with locale grouping ("5.173").
                            Text(verbatim: ":\(stale.port)\(stale.pid.map { "  pid \($0)" } ?? "")")
                        }
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    }
                    .help(staleHelp(for: stale))
                }
            }
        }
        .padding(.top, 4)
    }

    private func staleHelp(for stale: StaleListener) -> String {
        L10n.format("Port %ld, Prozess: %@. Dieser Listener ist rein diagnostisch: ein Debug-/Inspector-Port oder ein Port, den eine neuere Prozess-Generation desselben Projekts jetzt übernimmt. Andere Dienste desselben Projekts (z. B. Frontend und API mit unterschiedlichen PIDs) stehen dagegen regulär unter „Dienste“.",
                    stale.port, stale.command ?? L10n.text("unbekannt"))
    }

    private var footerButtons: some View {
        HStack {
            Button {
                mode = .addManual
            } label: {
                Label(L10n.text("Manuell hinzufügen"), systemImage: "plus")
            }
            .buttonStyle(.plain)
            .disabled(model.mutationsLocked)
            Spacer()
            Button {
                Task { await model.refreshNow() }
            } label: {
                Label(L10n.text("Aktualisieren"), systemImage: "arrow.clockwise")
            }
            .buttonStyle(.plain)
            .keyboardShortcut("r", modifiers: .command)
            .help(L10n.text("Aktualisieren"))
            Spacer()
            Button {
                NSApp.terminate(nil)
            } label: {
                Label(L10n.text("App beenden"), systemImage: "power")
            }
            .buttonStyle(.plain)
            .keyboardShortcut("q", modifiers: .command)
            .help(L10n.text("Beendet nur die Oberfläche — Hintergrunddienst und Freigaben laufen weiter."))
        }
        .font(.callout)
        .padding(.top, 2)
    }

    // MARK: - First-run setup

    /// The CLI to run for setup: only while nothing was ever loaded, the
    /// daemon is unreachable and no LaunchAgent exists (ServiceSetup).
    private var setupCLI: String? {
        guard model.connection == .unreachable, model.status == nil else { return nil }
        return BackgroundServiceSetup.offeredCLI()
    }

    /// The setup view stays while it runs or reports a failure, even though
    /// the agent file it just wrote ends the offer itself.
    private var showsFirstRunSetup: Bool {
        model.status == nil && (setupRunning || setupError != nil || setupCLI != nil)
    }

    private var firstRunSetup: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L10n.text("Einmal einrichten"))
                .font(.callout.weight(.semibold))
            Text(L10n.text("Portname braucht einen kleinen Hintergrunddienst, der deine Dev-Server findet. Er läuft unter deinem Benutzer, braucht kein Admin-Passwort und startet beim Anmelden."))
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                if let cli = setupCLI {
                    Button(L10n.text("Hintergrunddienst einrichten")) { runSetup(cli: cli) }
                        .buttonStyle(.borderedProminent)
                        .disabled(setupRunning)
                } else if !setupRunning {
                    Button(L10n.text("Erneut verbinden")) {
                        setupError = nil
                        Task { await model.refreshNow() }
                    }
                }
                if setupRunning {
                    ProgressView()
                        .controlSize(.small)
                    Text(L10n.text("Wird eingerichtet …"))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            if let setupError {
                FeedbackLine(text: L10n.format("Einrichtung fehlgeschlagen: %@", setupError),
                             onDismiss: { self.setupError = nil })
            }
        }
        .padding(.vertical, 10)
    }

    private func runSetup(cli: String) {
        setupRunning = true
        setupError = nil
        Task {
            if let failure = await BackgroundServiceSetup.install(cli: cli) {
                setupError = failure
                setupRunning = false
                return
            }
            // launchd starts the daemon right away; its socket appears within
            // a second or two. Poll briefly instead of waiting for the next
            // regular refresh.
            for _ in 0..<20 where model.connection != .connected {
                await model.refreshNow()
                if model.connection == .connected { break }
                try? await Task.sleep(for: .milliseconds(500))
            }
            setupRunning = false
            if model.connection != .connected {
                setupError = L10n.text("Der Dienst ist eingerichtet, antwortet aber noch nicht. Bitte gleich erneut verbinden.")
            }
        }
    }

    private var unreachablePlaceholder: some View {
        Group {
            if showsFirstRunSetup {
                firstRunSetup
            } else {
                diagnosisPlaceholder
            }
        }
    }

    private var diagnosisPlaceholder: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L10n.text("Dienst nicht erreichbar"))
                .font(.callout)
            Text(model.lastErrorText ?? L10n.text("Der Hintergrunddienst antwortet nicht. Läuft er? (portname install startet ihn dauerhaft.)"))
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(L10n.text("Erneut verbinden")) {
                    Task { await model.refreshNow() }
                }
            }
        }
        .padding(.vertical, 10)
    }
}
