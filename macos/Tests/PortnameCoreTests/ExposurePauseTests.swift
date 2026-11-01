import XCTest
@testable import PortnameCore

/// Paused WLAN exposures: which daemon reasons wait for the user's
/// confirmation, the wording chosen per reason, the additive fields that
/// wording uses, and the reconciliation of a confirmation whose answer got
/// lost.
@MainActor
final class ExposurePauseTests: XCTestCase {

    override func tearDown() {
        L10n.forcedLocalization = nil
        super.tearDown()
    }

    private func pausedRoute(_ reason: String?, port: Int = 5173, command: String? = "vite",
                             target: ExposureTarget? = nil) -> Route {
        Route(id: "/demo/shop", name: "shop", revision: "rev-2", root: "/demo/shop", port: port,
              command: command, localUrl: "http://shop.localhost/", lanUrl: "http://shop.local/",
              exposureRequested: true, exposureEffective: "paused", exposurePauseReason: reason,
              exposureTarget: target)
    }

    // MARK: - Reason → confirmation

    func testReasonsParseAndUnknownSpellingsStayUnknown() {
        XCTAssertEqual(ExposurePauseReason("target-not-verified"), .targetNotVerified)
        XCTAssertEqual(ExposurePauseReason("target-unconfirmed"), .targetUnconfirmed)
        XCTAssertEqual(ExposurePauseReason("target-changed"), .targetChanged)
        XCTAssertEqual(ExposurePauseReason("network-changed"), .networkChanged)
        XCTAssertEqual(ExposurePauseReason("network-unidentified"), .networkUnidentified)
        XCTAssertEqual(ExposurePauseReason("no-lan-interface"), .noLanInterface)
        XCTAssertEqual(ExposurePauseReason("loopback-bind"), .loopbackBind)
        XCTAssertEqual(ExposurePauseReason("future-reason"), .unknown("future-reason"))
    }

    func testOnlyBindingReasonsAwaitConfirmation() {
        XCTAssertTrue(ExposurePauseReason.targetUnconfirmed.awaitsConfirmation)
        XCTAssertTrue(ExposurePauseReason.targetChanged.awaitsConfirmation)
        XCTAssertTrue(ExposurePauseReason.networkChanged.awaitsConfirmation)
        XCTAssertFalse(ExposurePauseReason.targetNotVerified.awaitsConfirmation,
                       "a stale verification heals by itself; the daemon refuses an activation meanwhile")
        XCTAssertFalse(ExposurePauseReason.networkUnidentified.awaitsConfirmation,
                       "the router identification heals it; the daemon refuses a confirmation meanwhile")
        XCTAssertFalse(ExposurePauseReason.noLanInterface.awaitsConfirmation)
        XCTAssertFalse(ExposurePauseReason.loopbackBind.awaitsConfirmation)
        XCTAssertFalse(ExposurePauseReason.unknown("future-reason").awaitsConfirmation)
    }

    func testRouteAwaitsConfirmationOnlyWhilePausedAndRequested() {
        XCTAssertTrue(pausedRoute("target-unconfirmed").awaitsExposureConfirmation)
        XCTAssertTrue(pausedRoute("target-changed").awaitsExposureConfirmation)
        XCTAssertTrue(pausedRoute("network-changed").awaitsExposureConfirmation)
        XCTAssertFalse(pausedRoute("target-not-verified").awaitsExposureConfirmation)
        XCTAssertFalse(pausedRoute("network-unidentified").awaitsExposureConfirmation)
        XCTAssertFalse(pausedRoute("future-reason").awaitsExposureConfirmation)
        XCTAssertFalse(pausedRoute(nil).awaitsExposureConfirmation)

        var notRequested = pausedRoute("target-changed")
        notRequested.exposureRequested = false
        XCTAssertFalse(notRequested.awaitsExposureConfirmation, "nothing to confirm without a wish")

        var active = pausedRoute(nil)
        active.exposureEffective = "active"
        XCTAssertNil(active.pauseReason)
        XCTAssertFalse(active.awaitsExposureConfirmation)

        // Older daemon: no effective field — never paused, nothing to confirm.
        var legacy = pausedRoute("target-changed")
        legacy.exposureEffective = nil
        XCTAssertNil(legacy.pauseReason)
        XCTAssertFalse(legacy.awaitsExposureConfirmation)
    }

    // MARK: - Reason → wording

    func testBadgeHelpIsChosenPerReason() {
        L10n.forcedLocalization = "de"
        XCTAssertEqual(ExposurePauseText.badgeHelp(for: .targetNotVerified),
                       "WLAN-Freigabe bleibt gewünscht, ist aber derzeit pausiert: Der Hintergrunddienst gewährt gerade keinen Zugriff (Ziel nicht frisch verifiziert). Das Beenden der Freigabe bleibt möglich.")
        let generic = "WLAN-Freigabe bleibt gewünscht, ist aber derzeit pausiert: Der Hintergrunddienst gewährt gerade keinen Zugriff. Das Beenden der Freigabe bleibt möglich."
        XCTAssertEqual(ExposurePauseText.badgeHelp(for: .unknown("future-reason")), generic,
                       "an unknown reason gets the neutral text, never 'not verified'")
        XCTAssertTrue(ExposurePauseText.badgeHelp(for: .targetUnconfirmed).contains("älteren Version"))
        XCTAssertTrue(ExposurePauseText.badgeHelp(for: .targetChanged).contains("anderer Dienst"))
        XCTAssertTrue(ExposurePauseText.badgeHelp(for: .networkChanged).contains("anderes Netz"))
        XCTAssertFalse(ExposurePauseText.badgeHelp(for: .networkChanged).contains("noch nicht erkannt"),
                       "a router that is not identified yet is network-unidentified, never network-changed")
        XCTAssertTrue(ExposurePauseText.badgeHelp(for: .networkUnidentified).contains("von selbst weiter"))
        let texts: [ExposurePauseReason] = [.targetNotVerified, .targetUnconfirmed, .targetChanged, .networkChanged, .networkUnidentified, .unknown("x")]
        XCTAssertEqual(Set(texts.map { ExposurePauseText.badgeHelp(for: $0) }).count, texts.count,
                       "every reason gets its own text")
    }

    func testNotesNameTheEndpointAConfirmationWouldExpose() {
        L10n.forcedLocalization = "de"
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("target-unconfirmed"), currentNetwork: nil),
                       "WLAN-Freigabe pausiert: seit dem Update noch nicht bestätigt — Zugriff ist solange gesperrt. „WLAN-Freigabe bestätigen“ gibt :5173 (vite) im WLAN frei.")
        let moved = pausedRoute("target-changed", target: ExposureTarget(port: 3000, command: "node", network: "192.168.1.0/24"))
        XCTAssertEqual(ExposurePauseText.note(for: moved, currentNetwork: "192.168.1.0/24"),
                       "WLAN-Freigabe pausiert: Ziel geändert — bestätigt war :3000 (node), jetzt :5173 (vite). „WLAN-Freigabe bestätigen“ gibt das neue Ziel frei.")
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("target-changed", command: nil), currentNetwork: nil),
                       "WLAN-Freigabe pausiert: Ziel geändert — jetzt :5173 (unbekannt). „WLAN-Freigabe bestätigen“ gibt das neue Ziel frei.")
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("target-not-verified"), currentNetwork: nil),
                       "WLAN-Freigabe pausiert: Ziel nicht (mehr) verifiziert — Zugriff ist solange gesperrt. Sobald der Hintergrunddienst das Ziel wieder frisch sieht, greift die Freigabe erneut.")
    }

    func testNetworkNotesCompareConfirmedAndCurrentSubnet() {
        L10n.forcedLocalization = "de"
        let home = ExposureTarget(port: 5173, command: "vite", network: "192.168.1.0/24")
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("network-changed", target: home), currentNetwork: "10.0.0.0/24"),
                       "WLAN-Freigabe pausiert: bestätigt im Netz 192.168.1.0/24, jetzt 10.0.0.0/24. Erst nach Bestätigung in diesem Netz erreichbar.")
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("network-changed", target: home), currentNetwork: "192.168.1.0/24"),
                       "WLAN-Freigabe pausiert: gleicher Adressbereich (192.168.1.0/24), aber ein anderer Router als bei der Bestätigung. Erst nach Bestätigung in diesem Netz erreichbar.",
                       "same subnet: the daemon identified ANOTHER router (an unidentified one is network-unidentified) — nothing heals by itself")
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("network-changed"), currentNetwork: "10.0.0.0/24"),
                       "WLAN-Freigabe pausiert: Sie wurde in einem anderen Netz bestätigt. Erst nach Bestätigung in diesem Netz erreichbar.")
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("network-unidentified", target: home), currentNetwork: "192.168.1.0/24"),
                       "WLAN-Freigabe pausiert: Router noch nicht erkannt (z. B. kurz nach dem Aufwachen) — Zugriff ist solange gesperrt. Im bestätigten Netz geht es von selbst weiter, sobald der Router erkannt ist.")
    }

    func testNoNoteWithoutPauseOrWithoutAnyWlanPath() {
        L10n.forcedLocalization = "de"
        var active = pausedRoute(nil)
        active.exposureEffective = "active"
        XCTAssertNil(ExposurePauseText.note(for: active, currentNetwork: nil))
        XCTAssertNil(ExposurePauseText.note(for: pausedRoute("no-lan-interface"), currentNetwork: nil))
        XCTAssertNil(ExposurePauseText.note(for: pausedRoute("loopback-bind"), currentNetwork: nil))
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("future-reason"), currentNetwork: nil),
                       "WLAN-Freigabe pausiert — der Hintergrunddienst gewährt derzeit keinen WLAN-Zugriff.")
    }

    func testEnglishTableCarriesTheNewTexts() {
        L10n.forcedLocalization = "en"
        XCTAssertEqual(L10n.text("WLAN-Freigabe bestätigen"), "Confirm Wi-Fi Exposure")
        XCTAssertEqual(ExposurePauseText.badgeHelp(for: .networkUnidentified),
                       "Wi-Fi exposure paused: this network's router is not identified yet (e.g. just after wake). It resumes by itself once the confirmed router is identified.")
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("target-unconfirmed"), currentNetwork: nil),
                       "Wi-Fi exposure paused: not confirmed since the update — access is withheld meanwhile. \u{201c}Confirm Wi-Fi Exposure\u{201d} shares :5173 (vite) on Wi-Fi.")
        let home = ExposureTarget(port: 5173, command: "vite", network: "192.168.1.0/24")
        XCTAssertEqual(ExposurePauseText.note(for: pausedRoute("network-changed", target: home), currentNetwork: "192.168.1.0/24"),
                       "Wi-Fi exposure paused: same address range (192.168.1.0/24), but a different router than the one it was confirmed with. Reachable on this network only after you confirm it.")
    }

    // MARK: - Additive fields

    func testExposureTargetAndLanNetworkDecode() throws {
        let json = """
        {
          "protocolVersion": 1, "daemonInstanceId": "x", "proxyPort": 80, "bind": "wildcard",
          "daemonVersion": "0.9.0", "runtimeVersion": "v24.22.2",
          "lan": { "available": true, "reason": null, "interfaceName": "en0",
                   "address": "10.0.0.7", "network": "10.0.0.0/24" },
          "routes": [ {
            "name": "shop", "id": "/p", "root": "/p", "port": 5173, "command": "vite",
            "exposureRequested": true, "lanUrl": "http://shop.local/",
            "exposureEffective": "paused", "exposurePauseReason": "network-changed",
            "exposureTarget": { "port": 5173, "command": "vite", "network": "192.168.1.0/24" }
          } ],
          "stale": [], "exposed": [], "shares": []
        }
        """.data(using: .utf8)!
        let status = try JSONDecoder().decode(GatewayStatus.self, from: json)
        XCTAssertEqual(status.lan?.network, "10.0.0.0/24")
        XCTAssertEqual(status.daemonVersion, "0.9.0")
        XCTAssertEqual(status.runtimeVersion, "v24.22.2")
        XCTAssertEqual(status.routes[0].exposureTarget,
                       ExposureTarget(port: 5173, command: "vite", network: "192.168.1.0/24"))
        XCTAssertEqual(status.routes[0].pauseReason, .networkChanged)
        XCTAssertTrue(status.routes[0].awaitsExposureConfirmation)
    }

    func testAbsentOrNullAdditiveFieldsStillDecode() throws {
        let json = """
        {
          "protocolVersion": 1, "daemonInstanceId": "x", "proxyPort": 80, "bind": "wildcard",
          "lan": { "available": true, "reason": null },
          "routes": [
            { "name": "shop", "id": "/p", "root": "/p", "port": 3000, "exposureRequested": true,
              "exposureEffective": "paused", "exposurePauseReason": "target-unconfirmed",
              "exposureTarget": null },
            { "name": "api", "id": "/q", "root": "/q", "port": 8000,
              "exposureTarget": { "network": null } }
          ],
          "stale": [], "exposed": [], "shares": []
        }
        """.data(using: .utf8)!
        let status = try JSONDecoder().decode(GatewayStatus.self, from: json)
        XCTAssertNil(status.lan?.network)
        XCTAssertNil(status.daemonVersion)
        XCTAssertNil(status.runtimeVersion)
        XCTAssertNil(status.routes[0].exposureTarget)
        XCTAssertEqual(status.routes[1].exposureTarget, ExposureTarget())
    }

    // MARK: - Confirmation reconciliation

    private func makeModel(_ api: FakeDaemonAPI) -> AppModel {
        AppModel(api: api, copyText: { _ in }, openExternal: { _ in }, revealPath: { _ in })
    }

    func testLostConfirmationIsNotReconciledFromTheWishAlone() async {
        L10n.forcedLocalization = "de"
        let api = FakeDaemonAPI()
        let model = makeModel(api)
        let paused = pausedRoute("target-changed", target: ExposureTarget(port: 3000, command: "node", network: nil))
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [paused])), // the snapshot the menu shows
            .success(FakeDaemonAPI.status(routes: [paused])), // the confirmation's own read
            .success(FakeDaemonAPI.status(routes: [paused])), // the refresh after the lost answer
        ]
        _ = await model.refreshNow()
        api.exposeError = TransportError.timedOut // the daemon may have acted

        let outcome = await model.confirmExposure(paused)
        XCTAssertEqual(outcome, .unclear)
        XCTAssertEqual(api.exposeCalls.last?.on, true)
        XCTAssertEqual(api.exposeCalls.last?.rev, "rev-2", "the confirmation binds the revision the user saw")
        // The wish was already set before the confirmation: a snapshot that
        // still waits for it proves nothing.
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true)
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false)

        var confirmed = paused
        confirmed.exposureEffective = "active"
        confirmed.exposurePauseReason = nil
        confirmed.exposureTarget = ExposureTarget(port: 5173, command: "vite", network: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [confirmed]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"),
                     "the binding to the confirmed endpoint resolves it")
        XCTAssertEqual(model.feedback?.text, "Geprüft: „WLAN-Freigabe bestätigen“ wurde ausgeführt.")
    }

    func testLostConfirmationIsNotReconciledByUnrelatedStateChanges() async {
        L10n.forcedLocalization = "de"
        let api = FakeDaemonAPI()
        let model = makeModel(api)
        let homeLan = LANInfo(available: true, reason: nil, network: "192.168.1.0/24")
        let cafeLan = LANInfo(available: true, reason: nil, network: "10.0.0.0/24")
        let paused = pausedRoute("network-changed",
                                 target: ExposureTarget(port: 5173, command: "vite", network: "192.168.1.0/24"))
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [paused], lan: cafeLan)),
            .success(FakeDaemonAPI.status(routes: [paused], lan: cafeLan)),
            .success(FakeDaemonAPI.status(routes: [paused], lan: cafeLan)),
        ]
        _ = await model.refreshNow()
        api.exposeError = TransportError.timedOut // lost answer; the daemon did not bind

        let outcome = await model.confirmExposure(paused)
        XCTAssertEqual(outcome, .unclear)
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true)

        // Each of these lifts the confirmation wait while the exposure stays
        // bound to the home network: the Wi-Fi drops, the scan goes stale,
        // the home router is being identified, the Mac is back home.
        var noLan = paused
        noLan.exposurePauseReason = "no-lan-interface"
        var notVerified = paused
        notVerified.exposurePauseReason = "target-not-verified"
        var unidentified = paused
        unidentified.exposurePauseReason = "network-unidentified"
        var backHome = paused
        backHome.exposureEffective = "active"
        backHome.exposurePauseReason = nil
        let unrelated: [GatewayStatus] = [
            FakeDaemonAPI.status(routes: [noLan], lan: LANInfo(available: false, reason: "no-lan-interface")),
            FakeDaemonAPI.status(routes: [notVerified], lan: cafeLan),
            FakeDaemonAPI.status(routes: [unidentified], lan: homeLan),
            FakeDaemonAPI.status(routes: [backHome], lan: homeLan),
        ]
        for snapshot in unrelated {
            api.statusResults = [.success(snapshot)]
            _ = await model.refreshNow()
            XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true,
                           "a state change without the confirmed binding proves nothing")
            XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false)
        }

        // Only the binding the confirmation writes resolves it.
        var bound = paused
        bound.exposureEffective = "active"
        bound.exposurePauseReason = nil
        bound.exposureTarget = ExposureTarget(port: 5173, command: "vite", network: "10.0.0.0/24")
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [bound], lan: cafeLan))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
        XCTAssertEqual(model.feedback?.text, "Geprüft: „WLAN-Freigabe bestätigen“ wurde ausgeführt.")
    }

    func testSameSubnetConfirmationStaysUnclearWhenTheBindingLooksAlike() async {
        L10n.forcedLocalization = "de"
        let api = FakeDaemonAPI()
        let model = makeModel(api)
        let homeLan = LANInfo(available: true, reason: nil, network: "192.168.1.0/24")
        // Same subnet, another router: the binding a confirmation writes
        // carries the same port, command and network as the old one.
        let paused = pausedRoute("network-changed",
                                 target: ExposureTarget(port: 5173, command: "vite", network: "192.168.1.0/24"))
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [paused], lan: homeLan)),
            .success(FakeDaemonAPI.status(routes: [paused], lan: homeLan)),
            .success(FakeDaemonAPI.status(routes: [paused], lan: homeLan)),
        ]
        _ = await model.refreshNow()
        api.exposeError = TransportError.timedOut

        let outcome = await model.confirmExposure(paused)
        XCTAssertEqual(outcome, .unclear)

        var active = paused
        active.exposureEffective = "active"
        active.exposurePauseReason = nil
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [active], lan: homeLan))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true,
                       "back on the old router looks exactly like the new binding: never claimed as executed")
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false)
    }

    func testConfirmationDecidesOnAFreshReadNotOnTheMenuSnapshot() async {
        L10n.forcedLocalization = "de"
        let api = FakeDaemonAPI()
        let model = makeModel(api)
        let paused = pausedRoute("target-changed", target: ExposureTarget(port: 3000, command: "node", network: nil))
        var switchedOff = paused
        switchedOff.exposureRequested = false
        switchedOff.exposureEffective = "off"
        switchedOff.exposurePauseReason = nil
        switchedOff.exposureTarget = nil
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [paused])),      // the snapshot the menu shows
            .success(FakeDaemonAPI.status(routes: [switchedOff])), // switched off meanwhile (e.g. via the CLI)
            .success(FakeDaemonAPI.status(routes: [switchedOff])),
        ]
        _ = await model.refreshNow()
        XCTAssertTrue(model.routes[0].awaitsExposureConfirmation, "the cached snapshot still offers the confirmation")

        let outcome = await model.confirmExposure(paused)
        XCTAssertEqual(outcome, .staleTarget)
        XCTAssertTrue(api.exposeCalls.isEmpty, "an exposure switched off meanwhile is never switched back on")
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
        XCTAssertEqual(model.feedback?.text,
                       "WLAN-Freigabe wartet nicht mehr auf eine Bestätigung — Liste wurde neu geladen.")
        XCTAssertEqual(model.routes[0].exposureRequested, false, "the list shows the state the decision saw")
    }

    func testConfirmationNeverConfirmsAnEndpointTheUserDidNotSee() async {
        L10n.forcedLocalization = "de"
        let api = FakeDaemonAPI()
        let model = makeModel(api)
        // The row offers to confirm :5173 (vite) …
        let paused = pausedRoute("target-changed", target: ExposureTarget(port: 3000, command: "node", network: nil))
        // … but another listener of the project (a debug port) took over the
        // name before the click: still waiting for a confirmation, for :9229.
        var takenOver = pausedRoute("target-changed", port: 9229, command: "node",
                                    target: ExposureTarget(port: 3000, command: "node", network: nil))
        takenOver.revision = "rev-3"
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [paused])),    // the snapshot the menu shows
            .success(FakeDaemonAPI.status(routes: [takenOver])), // the confirmation's own read
            .success(FakeDaemonAPI.status(routes: [takenOver])),
        ]
        _ = await model.refreshNow()
        XCTAssertEqual(ExposurePauseText.note(for: model.routes[0], currentNetwork: model.status?.lan?.network),
                       "WLAN-Freigabe pausiert: Ziel geändert — bestätigt war :3000 (node), jetzt :5173 (vite). „WLAN-Freigabe bestätigen“ gibt das neue Ziel frei.")

        let outcome = await model.confirmExposure(paused)
        XCTAssertEqual(outcome, .staleTarget)
        XCTAssertTrue(api.exposeCalls.isEmpty, "the user confirmed :5173, never the endpoint waiting now")
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
        XCTAssertEqual(model.feedback?.text,
                       "Ziel hat sich inzwischen geändert — Liste wurde neu geladen. Bitte Aktion erneut ausführen.")
        XCTAssertEqual(model.routes[0].port, 9229, "the list shows the endpoint now waiting, for a decision of its own")
    }

    func testConfirmationNeverConfirmsANetworkTheUserDidNotSee() async {
        L10n.forcedLocalization = "de"
        let api = FakeDaemonAPI()
        let model = makeModel(api)
        let cafeLan = LANInfo(available: true, reason: nil, network: "10.0.0.0/24")
        let hotelLan = LANInfo(available: true, reason: nil, network: "172.16.0.0/24")
        let paused = pausedRoute("network-changed",
                                 target: ExposureTarget(port: 5173, command: "vite", network: "192.168.1.0/24"))
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [paused], lan: cafeLan)),  // the snapshot the row shows
            .success(FakeDaemonAPI.status(routes: [paused], lan: hotelLan)), // the Mac moved on before the click
            .success(FakeDaemonAPI.status(routes: [paused], lan: hotelLan)),
        ]
        _ = await model.refreshNow()
        XCTAssertEqual(ExposurePauseText.note(for: model.routes[0], currentNetwork: model.status?.lan?.network),
                       "WLAN-Freigabe pausiert: bestätigt im Netz 192.168.1.0/24, jetzt 10.0.0.0/24. Erst nach Bestätigung in diesem Netz erreichbar.")

        let outcome = await model.confirmExposure(paused)
        XCTAssertEqual(outcome, .staleTarget)
        XCTAssertTrue(api.exposeCalls.isEmpty, "the user confirmed 10.0.0.0/24, never the network the Mac is on now")
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
        XCTAssertEqual(model.feedback?.text,
                       "Ziel hat sich inzwischen geändert — Liste wurde neu geladen. Bitte Aktion erneut ausführen.")
        XCTAssertEqual(model.status?.lan?.network, "172.16.0.0/24", "the list shows the network now current")
    }
}
