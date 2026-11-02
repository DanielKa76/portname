import Foundation
import Observation

/// Outcome of a GUI mutation. `unclear` means the request timed out or the
/// connection dropped mid-flight — the daemon may or may not have executed
/// it; the UI shows "Ergebnis wird geprüft" and never retries blindly.
public enum MutationOutcome: Error, Equatable, Sendable {
    case success
    case staleTarget
    case failed(String)
    case unclear
}

/// A mutation whose outcome is unknown. A successful status snapshot that
/// shows the expected effect resolves the entry; when a poll succeeds
/// *without* the expected effect, the entry flips to `unresolved` — the UI
/// then states "Ausgang unklar" instead of claiming that the result is
/// still being verified. The resolution wording states what was actually
/// learned (see `AppModel.confirmationText`): an explicit answer to the
/// request is an operations proof, while a state read back from a later
/// snapshot is only that — observed state.
///
/// Expectations verify the *effect*, never a lookalike: they are bound to
/// stable target identity (route id / manual identity / target port) and —
/// where the mutation is not idempotent — to the operation's intent traits
/// (requested port for a manual add; requested ttl plus expiry window for a
/// share start; the endpoint and network a WLAN confirmation binds), so a
/// reused display name, a repointed target, a stale instance or an
/// unrelated state change cannot pass for the requested effect. Where the
/// visible state cannot be attributed to this operation at all (the target
/// already existed before the mutation), the expectation stays unmet: the
/// outcome remains an honest "unclear" instead of an invented success.
public struct PendingReconciliation: Equatable, Sendable {
    /// Intent markers of a share START: the requested lifetime and the
    /// moment the request was issued (GUI and daemon share one machine
    /// clock). A share started by this operation reports exactly this ttl
    /// and expires at about `startedAt + ttl`; an older share of the same
    /// name/port fails the window and must not pass for the requested
    /// effect. A competing start seconds EARLIER still passes the window —
    /// the traits attribute the observed share as a *matching* one; turning
    /// that observation into proof that THIS request ran requires the
    /// daemon's explicit ok answer, not a snapshot.
    public struct ShareStartTraits: Equatable, Sendable {
        public let ttlMinutes: Double
        public let startedAt: Date

        public init(ttlMinutes: Double, startedAt: Date) {
            self.ttlMinutes = ttlMinutes
            self.startedAt = startedAt
        }
    }

    public enum Expectation: Equatable, Sendable {
        case exposed(Bool)
        /// Confirming a paused exposure: `expose on` while the wish is
        /// already set, so the flag proves nothing. `target` is the binding
        /// the confirmation writes — the route's port and command and the
        /// current `lan.network`, captured when it is issued. `preBound`
        /// marks that the exposure was bound to exactly that tuple already
        /// (another router in the same subnet; routers are not part of the
        /// snapshot): no snapshot can then tell the new binding from the
        /// old one.
        case exposureConfirmed(target: ExposureTarget, preBound: Bool)
        case renamed(to: String)
        /// `pinnedPort` is the target port the share action was taken on (an
        /// operations/intent marker): a live share for the same name on a
        /// different port is a different share and must not confirm this one.
        /// `started` carries the start intent (requested ttl + issue time);
        /// it is nil for a stop, which is not bound to a start intent.
        case shareActive(Bool, name: String, pinnedPort: Int?, started: ShareStartTraits?)
        case removed
        /// `port` is the requested registration port; `preExisting` marks
        /// that a manual entry of this name already existed before the add —
        /// the strict create would then have been rejected, so the entry's
        /// presence afterwards can never confirm this operation.
        case addedManual(name: String, port: Int, preExisting: Bool)
        case primaryPort(port: Int, name: String)
        /// After a global revoke: no active/starting share is left at all.
        case noLiveShares
    }

    public var operation: String
    public var expectation: Expectation
    public var unresolved: Bool

    public init(operation: String, expectation: Expectation, unresolved: Bool = false) {
        self.operation = operation
        self.expectation = expectation
        self.unresolved = unresolved
    }
}

/// Inline feedback bound to one route (or nil route for global actions).
public struct RouteFeedback: Equatable, Sendable {
    /// How the panel presents the line. A confirmed success must not look
    /// like a warning, and an observation is neither.
    public enum Kind: Equatable, Sendable {
        /// Something failed, was refused or is unclear.
        case problem
        /// The daemon confirmed that this request was carried out.
        case success
        /// A state was observed, but not attributable to this request.
        case observed
    }

    public var routeID: String?
    public var text: String
    public var kind: Kind

    public init(routeID: String?, text: String, kind: Kind = .problem) {
        self.routeID = routeID
        self.text = text
        self.kind = kind
    }
}

/// Central UI state store. All socket I/O happens off the MainActor (the
/// client's transport dispatches to a background queue); state mutations
/// happen here on the MainActor. At most one status poll is in flight; every
/// response is generation-checked so late answers never overwrite newer
/// state.
@MainActor
@Observable
public final class AppModel {
    public private(set) var connection: ConnectionState = .connecting
    public private(set) var status: GatewayStatus?
    public private(set) var statusIsStale = false
    public private(set) var lastErrorText: String?
    public var searchText: String = ""
    public private(set) var panelVisible = false

    public private(set) var inFlightIDs: Set<String> = []
    public private(set) var pendingReconciliations: [String: PendingReconciliation] = [:]
    public private(set) var feedback: RouteFeedback?
    /// Set when the daemon reports a different LAN interface/address than the
    /// poll before: the machine roamed. The UI must never keep presenting the
    /// network as the same trusted Wi-Fi across such a change.
    public private(set) var networkChangePending = false

    public var selectedRouteID: String?

    private let api: any DaemonAPI
    private let copyText: @Sendable (String) -> Void
    private let openExternal: @Sendable (URL) -> Void
    private let revealPath: @Sendable (String) -> Void

    private var pollTask: Task<Void, Never>?
    private var pollGeneration = 0
    private var pollInFlight = false
    /// Set when a refresh was requested while another poll was in flight.
    /// The in-flight poll started earlier and must not serve the new caller;
    /// exactly one follow-up poll runs after it lands.
    private var rerunRequested = false
    private var knownDaemonInstanceId: String?
    private var knownLanIdentity: String?
    private var consecutiveFailures = 0
    /// Scheduling slack for the share-start expiry window: the daemon creates
    /// the share gate after the request arrives, so a fresh share never
    /// expires before `startedAt + ttl`; the slack only absorbs timer
    /// round-off, not an older share's lifetime.
    private static let shareExpirySlackSeconds: TimeInterval = 30

    public init(api: any DaemonAPI,
                copyText: @escaping @Sendable (String) -> Void,
                openExternal: @escaping @Sendable (URL) -> Void,
                revealPath: @escaping @Sendable (String) -> Void) {
        self.api = api
        self.copyText = copyText
        self.openExternal = openExternal
        self.revealPath = revealPath
    }

    public var isLegacyDaemon: Bool { connection == .incompatibleProtocol }

    /// New protocol-guarded mutations are only offered against a reachable,
    /// versioned daemon.
    public var mutationsLocked: Bool { connection != .connected || isLegacyDaemon }

    public var routes: [Route] {
        (status?.routes ?? []).sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    public var filteredRoutes: [Route] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return routes }
        return routes.filter { route in
            route.name.lowercased().contains(query)
                || (route.root?.lowercased().contains(query) ?? false)
                || (route.cwd?.lowercased().contains(query) ?? false)
                || (route.command?.lowercased().contains(query) ?? false)
        }
    }

    public var staleListeners: [StaleListener] { status?.stale ?? [] }

    public var selectedRoute: Route? {
        guard let selectedRouteID else { return nil }
        return routes.first { $0.id == selectedRouteID }
    }

    public func share(for route: Route) -> ShareStatus? {
        status?.share(forName: route.name)
    }

    /// Latest snapshot's route for a stable id. Dialogs capture a route
    /// object when they open; before any mutation they must re-resolve so
    /// the daemon receives the current revision, not a stale one.
    public func route(byID id: String) -> Route? {
        routes.first { $0.id == id }
    }

    /// Re-resolves a captured route against a fresh status read. Returns
    /// nil when the route no longer exists (caller should close/dismiss).
    public func currentRoute(for route: Route) async -> Route? {
        if self.route(byID: route.id) == nil {
            await refreshNow()
        }
        return self.route(byID: route.id)
    }

    public var hasActiveOrStartingShare: Bool {
        status?.shares.contains { $0.phase == .active || $0.phase == .starting } ?? false
    }

    /// Remaining lifetime of a share in seconds, derived strictly from the
    /// daemon's `expiresAt` (unix ms) — never from a chosen dropdown value.
    public func remainingSeconds(for share: ShareStatus, at date: Date = Date()) -> Int? {
        guard let expiresAt = share.expiresAt else { return nil }
        return max(0, Int(round(expiresAt / 1000 - date.timeIntervalSince1970)))
    }

    // MARK: - Lifecycle

    public func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            await self?.pollLoop()
        }
    }

    public func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    public func setPanel(visible: Bool) {
        panelVisible = visible
        if visible {
            // Timely refresh when the panel opens; the poll loop keeps its
            // own cadence otherwise.
            Task { await refreshNow() }
        }
    }

    private func pollLoop() async {
        while !Task.isCancelled {
            await refreshNow()
            var interval = PollPolicy.intervalSeconds(panelVisible: panelVisible,
                                                      hasActiveOrStartingShare: hasActiveOrStartingShare)
            // Bounded backoff while unreachable — retries stay timely after
            // wake/panel-open without spinning.
            if connection == .unreachable {
                interval = min(interval * Double(min(consecutiveFailures, 4)), 20)
            }
            do {
                try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            } catch {
                return
            }
        }
    }

    // MARK: - Status polling

    // Every request bumps the generation, so an in-flight poll that started
    // earlier is discarded on arrival — mirroring the daemon's refresh
    // barrier, a pre-mutation snapshot must never overwrite newer state.
    // A caller arriving during an in-flight poll gets one bounded follow-up
    // poll that started after its call.
    @discardableResult
    public func refreshNow() async -> Bool {
        pollGeneration += 1
        let generation = pollGeneration
        if pollInFlight {
            rerunRequested = true
            return false
        }
        pollInFlight = true
        var ok = await pollOnce(generation: generation)
        while rerunRequested, !Task.isCancelled {
            rerunRequested = false
            pollGeneration += 1
            let next = pollGeneration
            ok = (await pollOnce(generation: next)) || ok
        }
        pollInFlight = false
        return ok
    }

    /// One status read, generation-checked: only the latest request publishes.
    private func pollOnce(generation: Int) async -> Bool {
        do {
            let snapshot = try await api.status()
            guard generation == pollGeneration else { return true }
            apply(snapshot)
            return true
        } catch {
            guard generation == pollGeneration else { return false }
            handlePollError(error)
            return false
        }
    }

    private func apply(_ snapshot: GatewayStatus) {
        consecutiveFailures = 0
        status = snapshot
        statusIsStale = false
        lastErrorText = nil

        if snapshot.daemonInstanceId != knownDaemonInstanceId {
            // Daemon restarted (or version changed): all target and share
            // bindings the UI held are void — including the LAN identity,
            // whose change must not be reported as a roaming event.
            pendingReconciliations.removeAll()
            feedback = nil
            networkChangePending = false
            knownLanIdentity = nil
            knownDaemonInstanceId = snapshot.daemonInstanceId
        }
        trackNetworkIdentity(of: snapshot)
        reconcilePending(in: snapshot)
        connection = snapshot.isLegacyDaemon ? .incompatibleProtocol : .connected
    }

    // MARK: - Network identity

    /// Compares the daemon's LAN identity (interface + address) across
    /// polls. A change between two available reports means the machine
    /// switched networks — surface it instead of silently re-labeling the
    /// new network with the old trust. A report without a usable LAN (the
    /// gap while Wi-Fi switches or the Mac sleeps) is no identity and never
    /// becomes the baseline: A → no LAN → B must still surface, and
    /// A → no LAN → A must not.
    private func trackNetworkIdentity(of snapshot: GatewayStatus) {
        guard let identity = snapshot.lan.flatMap(Self.lanIdentity) else { return }
        if let known = knownLanIdentity, known != identity {
            networkChangePending = true
        }
        knownLanIdentity = identity
    }

    /// Nil when the daemon reports no usable LAN right now, or predates the
    /// network identity fields — then no roaming statement can be made.
    static func lanIdentity(_ lan: LANInfo) -> String? {
        guard lan.available, lan.interfaceName != nil || lan.address != nil else { return nil }
        return "\(lan.interfaceName ?? "-")|\(lan.address ?? "-")"
    }

    public func dismissNetworkChange() {
        networkChangePending = false
    }

    // MARK: - Unclear-result reconciliation

    /// Reads back, from a fresh snapshot, whether an unclear mutation took
    /// effect. Called on every successful poll so "Ergebnis wird geprüft"
    /// resolves itself instead of lingering until the next mutation.
    private func reconcilePending(in snapshot: GatewayStatus) {
        guard !pendingReconciliations.isEmpty else { return }
        var confirmations: [RouteFeedback] = []
        for (routeID, pending) in pendingReconciliations {
            if Self.isExpectationMet(pending.expectation, routeID: routeID, in: snapshot) {
                pendingReconciliations[routeID] = nil
                confirmations.append(RouteFeedback(routeID: routeID, text: Self.confirmationText(for: pending),
                                                   kind: Self.confirmationKind(for: pending)))
            } else if Self.shareStartIsInProgress(pending.expectation, routeID: routeID, in: snapshot) {
                // A visible in-progress start (accepted, tunnel still
                // booting) is better information than "unclear": keep
                // waiting until it activates or disappears — never confirm
                // STARTING as a successful activation.
                pendingReconciliations[routeID]?.unresolved = false
            } else if !pending.unresolved {
                // Poll succeeded, effect not observable: stop claiming that
                // the outcome is still being checked.
                pendingReconciliations[routeID]?.unresolved = true
            }
        }
        if let last = confirmations.last {
            feedback = last
        }
    }

    /// Confirmation wording states honestly what was learned. For most
    /// mutations the visible effect proves the operation ran. Two cases
    /// report OBSERVED STATE only:
    /// - A manual add: the visible entry may predate the request (created
    ///   concurrently, e.g. via the CLI), so only its VISIBILITY is
    ///   confirmed — never that this operation created it.
    /// - A share start resolved through a later snapshot: identity, port,
    ///   ttl and expiry window attribute the share as a MATCHING one, but a
    ///   competing start seconds earlier passes the same checks, so the
    ///   state observation alone never reads as "this request was carried
    ///   out". Only an explicit ok answer to the very request
    ///   (`explicitSuccessText`) is an operations proof.
    static func confirmationText(for pending: PendingReconciliation) -> String {
        switch pending.expectation {
        case .addedManual(let name, _, _):
            return L10n.format("Geprüft: Zuordnung „%@“ ist jetzt sichtbar (ob deine Anfrage sie angelegt hat, ist nicht eindeutig zuordenbar).", name)
        case .shareActive(true, name: let name, pinnedPort: _, started: _):
            // Reconciled from a status read, not from an answer to this
            // request: the observed state is real, its attribution is not.
            return L10n.format("Geprüft: Ein passender öffentlicher Link für „%@“ ist jetzt aktiv (ob deine Anfrage ihn erstellt hat, ist nicht eindeutig feststellbar).", name)
        default:
            return explicitSuccessText(operation: pending.operation)
        }
    }

    /// Presentation of a reconciled confirmation: the two observed-state
    /// cases above stay neutral, every other one is proven by its visible
    /// effect and reads as a success.
    static func confirmationKind(for pending: PendingReconciliation) -> RouteFeedback.Kind {
        switch pending.expectation {
        case .addedManual, .shareActive(true, name: _, pinnedPort: _, started: _):
            return .observed
        default:
            return .success
        }
    }

    /// Wording for a mutation the daemon answered with an explicit ok on
    /// THIS request — the only honest basis for "was carried out". The
    /// reconciliation path reports observed state instead.
    static func explicitSuccessText(operation: String) -> String {
        L10n.format("Geprüft: „%@“ wurde ausgeführt.", operation)
    }

    /// True when a lost share START is visible as accepted and still in
    /// progress: the route still exists under its stable identity and a
    /// share under its name is STARTING with matching intent traits. Such a
    /// snapshot is neither a confirmation (the tunnel is not up yet) nor a
    /// final "unclear" — the UI keeps "wird geprüft" until the share
    /// activates (with full proof) or disappears.
    static func shareStartIsInProgress(_ expectation: PendingReconciliation.Expectation,
                                       routeID: String,
                                       in snapshot: GatewayStatus) -> Bool {
        guard case .shareActive(true, name: let name, pinnedPort: let pinnedPort, started: let started) = expectation,
              let started else { return false }
        guard let route = snapshot.routes.first(where: { $0.id == routeID }),
              route.name == name,
              let share = snapshot.shares.first(where: { $0.name == name }),
              share.phase == .starting, share.expired != true else { return false }
        if let pinnedPort, let sharePinnedPort = share.pinnedPort, sharePinnedPort != pinnedPort {
            return false
        }
        if let shareTtl = share.ttlMinutes, shareTtl != started.ttlMinutes {
            return false
        }
        return true
    }

    static func isExpectationMet(_ expectation: PendingReconciliation.Expectation,
                                 routeID: String,
                                 in snapshot: GatewayStatus) -> Bool {
        func hasRoute(where predicate: (Route) -> Bool) -> Bool {
            snapshot.routes.contains(where: predicate)
        }
        switch expectation {
        case .exposed(let value):
            // A switch-on binds the current endpoint and network: a route
            // that waits for a confirmation carries the wish, not such a
            // binding. (Confirming a paused exposure is `.exposureConfirmed`.)
            return hasRoute {
                $0.id == routeID && $0.exposureRequested == value && !(value && $0.awaitsExposureConfirmation)
            }
        case .exposureConfirmed(let target, let preBound):
            // Only the BINDING proves a confirmation: the route's
            // `exposureTarget` now carries exactly the endpoint and network
            // confirmed, and the route no longer waits for a confirmation.
            // Another pause reason (no Wi-Fi, a stale scan, a router being
            // identified) or a return to the network or endpoint confirmed
            // before lifts the wait without that binding and proves nothing.
            // When the binding looked the same before, the outcome stays
            // honestly unclear instead of inventing a success.
            if preBound { return false }
            return hasRoute { route in
                guard route.id == routeID, route.exposureRequested == true,
                      !route.awaitsExposureConfirmation else { return false }
                return route.exposureTarget == target
            }
        case .renamed(let newName):
            // A display name alone proves nothing — another object may carry
            // it: the renamed route itself must now answer to the new name.
            return hasRoute { $0.id == routeID && $0.name == newName }
        case .shareActive(let live, name: let name, pinnedPort: let pinnedPort, started: let started):
            if !live {
                // A stop is confirmed when NO live share remains under the
                // name (stopping is by name, so a repointed share is still
                // not stopped).
                let liveShare = snapshot.shares.contains { share in
                    guard share.name == name,
                          share.phase == .active || share.phase == .starting,
                          share.expired != true else { return false }
                    return true
                }
                return !liveShare
            }
            // These checks attribute an observed ACTIVE share as A MATCHING
            // share — state evidence for the honest observed-state wording
            // (confirmationText), never proof that THIS request ran: a
            // competing start seconds earlier passes the same checks, and
            // only the daemon's explicit ok answer is an operations proof.
            // Three identity layers must hold at once:
            //   1. route identity — the route with this stable id still
            //      exists and still carries the name (a same-named object
            //      elsewhere never counts);
            //   2. share intent — pinned to the intended target port and
            //      running with the requested ttl;
            //   3. activation + window — the share is ACTIVE (STARTING is
            //      "accepted, in progress", never a confirmed activation)
            //      and expires inside the window derived from the issue
            //      time: the gate is created after the request arrives, so
            //      a share started by this operation never expires before
            //      `startedAt + ttl` minus a small scheduling slack; an
            //      older share's earlier expiry exposes it. The window is a
            //      helper for state attribution only — it can never turn
            //      the observation into an operations proof.
            // Every field is REQUIRED: a snapshot missing one (older
            // daemon shape) cannot even establish the matching-state
            // observation and degrades to "unclear" in the caller instead
            // of faking a success.
            guard let started,
                  let route = snapshot.routes.first(where: { $0.id == routeID }),
                  route.name == name,
                  let pinnedPort,
                  let share = snapshot.shares.first(where: { $0.name == name }),
                  share.phase == .active, share.expired != true,
                  let sharePinnedPort = share.pinnedPort, sharePinnedPort == pinnedPort,
                  let shareTtl = share.ttlMinutes, shareTtl == started.ttlMinutes,
                  let expiresAt = share.expiresAt else { return false }
            let earliest = started.startedAt.addingTimeInterval(
                started.ttlMinutes * 60 - Self.shareExpirySlackSeconds)
            return Date(timeIntervalSince1970: expiresAt / 1000) >= earliest
        case .removed:
            return !hasRoute { $0.id == routeID }
        case .addedManual(let name, let port, let preExisting):
            // Only a manual registration (root == nil) with the REQUESTED
            // port proves the add: a discovered project reusing the name, or
            // a manual entry of the same name on another port, is a different
            // object. When a manual entry of this name already existed before
            // the mutation, its presence is not attributable (the strict
            // create would have been rejected) — the outcome stays honestly
            // unclear instead of inventing a success.
            if preExisting { return false }
            return hasRoute { $0.isManual && $0.name == name && $0.port == port }
        case .primaryPort(let port, _):
            // The effective primary port may predate the mutation; the stored
            // per-root wish (`preferredPort`) is what set-primary changes.
            return hasRoute { $0.id == routeID && $0.preferredPort == port }
        case .noLiveShares:
            return !snapshot.shares.contains {
                ($0.phase == .active || $0.phase == .starting) && $0.expired != true
            }
        }
    }

    public func pendingReconciliation(for routeID: String) -> PendingReconciliation? {
        pendingReconciliations[routeID]
    }

    private func handlePollError(_ error: Error) {
        if case TransportError.cancelled = error { return }
        consecutiveFailures += 1
        statusIsStale = true
        connection = .unreachable
        switch error {
        case let control as ControlError:
            lastErrorText = control.message
        case let transport as TransportError:
            lastErrorText = Self.describe(transport)
        default:
            lastErrorText = error.localizedDescription
        }
    }

    public static func describe(_ error: TransportError) -> String {
        switch error {
        case .socketNotFound:
            return L10n.text("Dienst nicht erreichbar (Socket nicht gefunden).")
        case .permissionDenied:
            return L10n.text("Dienst nicht erreichbar (Zugriff verweigert).")
        case .connectFailed:
            return L10n.text("Dienst nicht erreichbar (Verbindung fehlgeschlagen).")
        case .connectionClosed:
            return L10n.text("Verbindung zum Hintergrunddienst wurde unerwartet beendet.")
        case .badResponse:
            return L10n.text("Ungültige Antwort vom Hintergrunddienst.")
        case .requestTooLarge, .responseTooLarge:
            return L10n.text("Antwort des Hintergrunddienstes hat die Größenbegrenzung überschritten.")
        case .timedOut:
            return L10n.text("Zeitüberschreitung beim Hintergrunddienst.")
        case .pathTooLong:
            return L10n.text("Socket-Pfad ist zu lang.")
        case .cancelled:
            return L10n.text("Abgebrochen.")
        }
    }

    // MARK: - Mutations

    /// Runs one mutation with per-route coordination. `expectation` must
    /// describe the observable state that verifies the mutation's effect —
    /// it drives the automatic reconciliation of unclear outcomes and the
    /// wording their resolution shows (see `confirmationText`).
    private func perform(routeID: String,
                         operation: String,
                         expectation: PendingReconciliation.Expectation,
                         _ body: () async throws -> Void) async -> MutationOutcome {
        guard !mutationsLocked else { return .failed(L10n.text("Keine Verbindung zum Hintergrunddienst.")) }
        // Coordinate per route: identical concurrent starts are collapsed,
        // while other routes stay usable.
        guard !inFlightIDs.contains(routeID) else { return .failed(L10n.text("Aktion läuft bereits.")) }
        inFlightIDs.insert(routeID)
        feedback = nil
        // Anything a poll answers from here on must postdate this mutation:
        // invalidate an in-flight poll that started earlier (its snapshot may
        // show pre-mutation state, which must never overwrite newer state).
        pollGeneration += 1
        defer { inFlightIDs.remove(routeID) }

        do {
            try await body()
            // A definitive result makes any older uncertainty moot.
            pendingReconciliations[routeID] = nil
            await refreshNow()
            return .success
        } catch let control as ControlError {
            pendingReconciliations[routeID] = nil
            if control.isStaleTarget {
                feedback = RouteFeedback(routeID: routeID,
                                         text: L10n.text("Ziel hat sich inzwischen geändert — Liste wurde neu geladen. Bitte Aktion erneut ausführen."))
                await refreshNow()
                return .staleTarget
            }
            feedback = RouteFeedback(routeID: routeID, text: control.message)
            await refreshNow()
            return .failed(control.message)
        } catch let transport as TransportError where transport == .cancelled {
            // Cancellation here means the request never completed; treat
            // like any other interrupted mutation: unclear, not retried.
            pendingReconciliations[routeID] = PendingReconciliation(operation: operation,
                                                                   expectation: expectation)
            await refreshNow()
            return .unclear
        } catch let transport as TransportError {
            if transport.resultMayBeUnknown {
                // The request may have reached the daemon; only status can
                // tell. Local refusals (no socket, oversized request, …)
                // never take this branch — they are plain failures below.
                pendingReconciliations[routeID] = PendingReconciliation(operation: operation,
                                                                       expectation: expectation)
                feedback = RouteFeedback(routeID: routeID, text: L10n.format("Ergebnis wird geprüft — %@", Self.describe(transport)))
                await refreshNow()
                return .unclear
            }
            pendingReconciliations[routeID] = nil
            feedback = RouteFeedback(routeID: routeID, text: Self.describe(transport))
            await refreshNow()
            return .failed(Self.describe(transport))
        } catch {
            pendingReconciliations[routeID] = nil
            feedback = RouteFeedback(routeID: routeID, text: error.localizedDescription)
            return .failed(error.localizedDescription)
        }
    }

    public func renameRoute(_ route: Route, to newName: String) async -> MutationOutcome {
        await perform(routeID: route.id, operation: L10n.text("Umbenennen"),
                      expectation: .renamed(to: newName)) {
            try await api.rename(name: route.name, newName: newName, expectedRouteRevision: route.revision)
        }
    }

    public func addManual(name: String, port: Int) async -> MutationOutcome {
        // Attribution marker: with a manual entry of this name already
        // present, the daemon's strict create (createOnly) would have
        // rejected the add — seeing an "api" entry afterwards can never
        // prove that this operation ran, so the expectation stays unmet.
        //
        // Residual window: a competing manual entry with the same name+port
        // created between this snapshot and the add (e.g. via the CLI) can
        // still make a lost response resolve as confirmed. Closing that
        // window needs request attribution from the daemon protocol.
        let nameTaken = status?.routes.contains { $0.isManual && $0.name == name } ?? false
        return await perform(routeID: "add-manual", operation: L10n.text("Manuell hinzufügen"),
                      expectation: .addedManual(name: name, port: port, preExisting: nameTaken)) {
            try await api.add(name: name, port: port, createOnly: true)
        }
    }

    public func removeRoute(_ route: Route) async -> MutationOutcome {
        await perform(routeID: route.id, operation: L10n.text("Entfernen"),
                      expectation: .removed) {
            try await api.remove(name: route.name, expectedRouteRevision: route.revision)
        }
    }

    public func setExposed(_ route: Route, on: Bool) async -> MutationOutcome {
        await perform(routeID: route.id,
                      operation: on ? L10n.text("Im WLAN freigeben") : L10n.text("WLAN-Freigabe beenden"),
                      expectation: .exposed(on)) {
            try await api.expose(name: route.name, on: on, expectedRouteRevision: route.revision)
        }
    }

    /// Confirms a paused exposure for the endpoint and network the panel
    /// showed (`expose on` while the wish stays set). `route` is the route
    /// as the user saw it.
    ///
    /// Whether a confirmation is still awaited is decided on a status read
    /// issued after the call, not on the cached snapshot (up to one poll
    /// interval old): an `expose off` from elsewhere (e.g. the CLI) that
    /// landed before the read is never switched back on. That read never
    /// supplies WHAT is confirmed: when it shows another endpoint (the
    /// revision pins port and process; another listener of the project,
    /// e.g. a debug port, may have taken over the name) or another network
    /// than the panel showed, nothing is sent. The request carries the
    /// revision the user saw, so the daemon refuses an endpoint that changes
    /// after the read as well. Not detected: an `expose off` or a network
    /// change between the read and the daemon's decision — the route
    /// revision covers neither the exposure state nor the network.
    public func confirmExposure(_ route: Route) async -> MutationOutcome {
        guard !mutationsLocked else { return .failed(L10n.text("Keine Verbindung zum Hintergrunddienst.")) }
        // The network the panel shows next to the route (its pause note
        // reads `status.lan.network`), taken before anything below yields.
        let seenNetwork = status?.lan?.network
        // A read of its own: a poll already in flight may have started
        // before the call, and a refresh does not wait for its follow-up.
        let fresh: GatewayStatus
        do {
            fresh = try await api.status()
        } catch let transport as TransportError {
            feedback = RouteFeedback(routeID: route.id, text: Self.describe(transport))
            return .failed(Self.describe(transport))
        } catch {
            feedback = RouteFeedback(routeID: route.id, text: error.localizedDescription)
            return .failed(error.localizedDescription)
        }
        guard let current = fresh.routes.first(where: { $0.id == route.id }),
              current.awaitsExposureConfirmation else {
            feedback = RouteFeedback(routeID: route.id,
                                     text: L10n.text("WLAN-Freigabe wartet nicht mehr auf eine Bestätigung — Liste wurde neu geladen."))
            await refreshNow()
            return .staleTarget
        }
        // The binding this confirmation writes, as the daemon reports it
        // afterwards in `exposureTarget`: the endpoint and network the user
        // saw. Still waiting, but for another endpoint or on another network
        // means confirming now would expose what the user never saw.
        let target = ExposureTarget(port: route.port, command: route.command, network: seenNetwork)
        guard current.revision == route.revision,
              ExposureTarget(port: current.port, command: current.command, network: fresh.lan?.network) == target else {
            feedback = RouteFeedback(routeID: route.id,
                                     text: L10n.text("Ziel hat sich inzwischen geändert — Liste wurde neu geladen. Bitte Aktion erneut ausführen."))
            await refreshNow()
            return .staleTarget
        }
        return await perform(routeID: route.id, operation: L10n.text("WLAN-Freigabe bestätigen"),
                             expectation: .exposureConfirmed(target: target, preBound: current.exposureTarget == target)) {
            try await api.expose(name: route.name, on: true, expectedRouteRevision: route.revision)
        }
    }

    /// Chooses which living service of a project carries the name (e.g. the
    /// Vite frontend instead of the API). The daemon stores the wish per
    /// project root, so it survives restarts and process generations.
    public func setPrimaryService(_ route: Route, port: Int) async -> MutationOutcome {
        await perform(routeID: route.id, operation: L10n.format("Hauptdienst auf Port %ld", port),
                      expectation: .primaryPort(port: port, name: route.name)) {
            try await api.setPrimary(name: route.name, port: port, expectedRouteRevision: route.revision)
        }
    }

    /// Starts a public share. The secret link in the daemon's answer is
    /// discarded immediately; copies and opens fetch it on demand via the
    /// read-only `share-link` command, so no full link lingers in memory.
    public func startShare(route: Route, ttlMinutes: Double) async -> MutationOutcome {
        let started = PendingReconciliation.ShareStartTraits(ttlMinutes: ttlMinutes, startedAt: Date())
        let operation = L10n.text("Öffentlichen Link erstellen")
        let outcome = await perform(routeID: route.id, operation: operation,
                              expectation: .shareActive(true, name: route.name, pinnedPort: route.port, started: started)) {
            _ = try await api.share(name: route.name, ttlMinutes: ttlMinutes, expectedRouteRevision: route.revision)
        }
        if outcome == .success {
            // The daemon answered THIS request with ok: a true operations
            // proof. Only here — never on the reconciled-state path — may
            // the success wording be shown.
            feedback = RouteFeedback(routeID: route.id,
                                     text: Self.explicitSuccessText(operation: operation),
                                     kind: .success)
        }
        return outcome
    }

    /// Targeted stop bound to the share id from the latest snapshot; also
    /// works while the share is still STARTING. A versioned daemon whose
    /// snapshot shows a live share *without* a shareId is inconsistent —
    /// fail closed instead of silently degrading to stop-by-name.
    public func stopShare(route: Route) async -> MutationOutcome {
        let share = status?.share(forName: route.name)
        if let share, isLiveShare(share), !isLegacyDaemon, share.shareId == nil {
            return .failed(L10n.text("Freigabe-Status inkonsistent — Liste aktualisieren und erneut versuchen."))
        }
        let shareId = share?.shareId
        return await perform(routeID: route.id, operation: L10n.text("Öffentlicher Link beenden"),
                             expectation: .shareActive(false, name: route.name, pinnedPort: nil, started: nil)) {
            try await api.unshare(name: route.name, expectedShareId: shareId, expectedRouteRevision: route.revision)
        }
    }

    /// The clearly labeled global revoke: every live public link is ended
    /// through the daemon's `unshare-all` (same per-share stop path as a
    /// targeted unshare). Never fired implicitly — always from a confirmed
    ///, distinctly named UI action.
    public func revokeAllShares() async -> MutationOutcome {
        await perform(routeID: "revoke-all", operation: L10n.text("Alle öffentlichen Links beenden"),
                      expectation: .noLiveShares) {
            _ = try await api.revokeAllShares()
        }
    }

    private func isLiveShare(_ share: ShareStatus) -> Bool {
        (share.phase == .active || share.phase == .starting) && share.expired != true
    }

    // MARK: - Share link (explicit copy/open only)

    public func fetchShareLink(for route: Route) async -> Result<ShareLink, MutationOutcome> {
        guard let share = status?.share(forName: route.name) else {
            return .failure(.failed(L10n.format("Kein öffentlicher Link für „%@“ vorhanden.", route.name)))
        }
        guard share.phase.isActiveShare, share.expired != true else {
            return .failure(.failed(L10n.format("Der öffentliche Link für „%@“ ist nicht mehr aktiv.", route.name)))
        }
        guard let shareId = share.shareId else {
            return .failure(.failed(L10n.text("Hintergrunddienst ist veraltet — bitte Daemon aktualisieren und Link über die CLI kopieren.")))
        }
        do {
            let link = try await api.shareLink(name: route.name, expectedShareId: shareId)
            return .success(link)
        } catch let control as ControlError {
            if control.isStaleTarget {
                await refreshNow()
                return .failure(.staleTarget)
            }
            return .failure(.failed(control.message))
        } catch let transport as TransportError {
            return .failure(.failed(Self.describe(transport)))
        } catch {
            return .failure(.failed(error.localizedDescription))
        }
    }

    /// Copies the current public link. A copy never starts, replaces or
    /// re-times a tunnel.
    public func copyShareLink(for route: Route) async -> MutationOutcome {
        switch await fetchShareLink(for: route) {
        case .success(let link):
            copyText(link.url)
            return .success
        case .failure(let outcome):
            feedback = RouteFeedback(routeID: route.id, text: feedbackText(from: outcome))
            return outcome
        }
    }

    /// Explicitly requested open of the public link in the browser.
    public func openShareLink(for route: Route) async -> MutationOutcome {
        switch await fetchShareLink(for: route) {
        case .success(let link):
            let originHost = URL(string: status?.share(forName: route.name)?.url ?? "")?.host ?? ""
            guard let url = SafeURL.shareURL(link.url, expectedOriginHost: originHost) else {
                feedback = RouteFeedback(routeID: route.id, text: L10n.text("Unerwartete Link-Adresse — Öffnen wurde verweigert."))
                return .failed(L10n.text("Unerwartete Link-Adresse"))
            }
            openExternal(url)
            return .success
        case .failure(let outcome):
            feedback = RouteFeedback(routeID: route.id, text: feedbackText(from: outcome))
            return outcome
        }
    }

    private func feedbackText(from outcome: MutationOutcome) -> String {
        switch outcome {
        case .failed(let text): return text
        case .staleTarget: return L10n.text("Öffentlicher Link hat sich geändert — Liste wurde neu geladen.")
        default: return L10n.text("Aktion konnte nicht ausgeführt werden.")
        }
    }

    // MARK: - Local actions

    public func openLocalURL(for route: Route) {
        let urlString = route.localUrl ?? SafeURL.localURLString(name: route.name, gatewayPort: status?.proxyPort ?? 80)
        guard let urlString, let url = SafeURL.localBrowserURL(urlString) else {
            feedback = RouteFeedback(routeID: route.id, text: L10n.text("Unerwartete Projektadresse — Öffnen wurde verweigert."))
            return
        }
        openExternal(url)
    }

    /// Copies the local browser URL. Returns false when the address failed
    /// validation — callers must not show a success flash in that case.
    @discardableResult
    public func copyLocalURL(for route: Route) -> Bool {
        let urlString = route.localUrl ?? SafeURL.localURLString(name: route.name, gatewayPort: status?.proxyPort ?? 80)
        guard let urlString, SafeURL.localBrowserURL(urlString) != nil else {
            feedback = RouteFeedback(routeID: route.id, text: L10n.text("Unerwartete Projektadresse — Kopieren wurde verweigert."))
            return false
        }
        copyText(urlString)
        return true
    }

    public func revealProjectFolder(for route: Route) {
        guard let path = route.root ?? route.cwd, SafeURL.localDirectory(path) != nil else {
            feedback = RouteFeedback(routeID: route.id, text: L10n.text("Projektordner nicht gefunden."))
            return
        }
        revealPath(path)
    }

    public func dismissFeedback() {
        feedback = nil
    }
}
