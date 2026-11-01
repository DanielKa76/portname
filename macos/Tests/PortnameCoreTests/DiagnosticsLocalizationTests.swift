import XCTest
@testable import PortnameCore

/// Tests for the diagnostics and localization UX: the localization table
/// contract, the new additive protocol fields (LAN identity, share
/// verification), the network-change surfacing, and the global share
/// revocation flow.
@MainActor
final class DiagnosticsLocalizationTests: XCTestCase {

    override func tearDown() {
        L10n.forcedLocalization = nil
        super.tearDown()
    }

    // MARK: - L10n table contract

    func testTablesComeFromTheSwiftPMResourceBundleNotTheMainFallback() {
        // The explicit search must find the real resource bundle on its
        // own: in DEBUG the last-resort fallback is Bundle.module, which
        // carries the same file name, so the resolved bundle's name alone
        // cannot tell a working search from a broken one.
        guard let explicit = L10n.explicitResourceBundle() else {
            return XCTFail("the explicit candidate search must find \(L10n.resourceBundleName)")
        }
        XCTAssertEqual(explicit.bundleURL.lastPathComponent, L10n.resourceBundleName)
        XCTAssertNotNil(explicit.path(forResource: "Localizable", ofType: "strings",
                                      inDirectory: nil, forLocalization: "en"),
                        "the bundle found must carry the tables")
        XCTAssertEqual(L10n.resourceBundle.bundleURL.standardizedFileURL, explicit.bundleURL.standardizedFileURL,
                       "the tables are read from the explicitly found bundle, not from a fallback")
    }

    func testLocalizationTablesHaveIdenticalKeySets() {
        let de = L10n.table(for: "de")
        let en = L10n.table(for: "en")
        XCTAssertFalse(de.isEmpty, "the German table must be present")
        XCTAssertEqual(Set(de.keys), Set(en.keys),
                       "de and en tables must cover exactly the same source strings")
        for (key, value) in de {
            XCTAssertFalse(value.isEmpty)
            XCTAssertFalse(en[key]!.isEmpty)
        }
    }

    func testForcedEnglishResolvesAndFormats() {
        L10n.forcedLocalization = "en"
        XCTAssertEqual(L10n.text("Projekte suchen …"), "Search projects …")
        XCTAssertEqual(L10n.text("App beenden"), "Quit App")
        XCTAssertEqual(L10n.format("%ld Projekte · Hintergrunddienst verbunden", 3),
                       "3 projects · daemon connected")
        XCTAssertEqual(L10n.format("Öffentlicher Link für „%@“", "shop"),
                       "Public link for \u{201c}shop\u{201d}")
    }

    func testGermanStaysTheSourceString() {
        L10n.forcedLocalization = "de"
        XCTAssertEqual(L10n.text("Projekte suchen …"), "Projekte suchen …")
        XCTAssertEqual(L10n.format("→ :%ld", 3000), "→ :3000")
    }

    func testMissingKeyFallsBackToTheGermanSource() {
        // A string that has not joined the tables yet must never show up as
        // a raw key or an empty label — the fallback is the source itself.
        L10n.forcedLocalization = "en"
        XCTAssertEqual(L10n.text("Noch nicht übersetzter Beispielsatz."), "Noch nicht übersetzter Beispielsatz.")
    }

    // MARK: - Additive protocol fields

    func testLanIdentityAndShareVerificationDecode() throws {
        let json = """
        {
          "protocolVersion": 1, "daemonInstanceId": "i-1", "proxyPort": 80, "bind": "wildcard",
          "lan": { "available": true, "reason": null, "interfaceName": "en0", "address": "192.168.1.42" },
          "routes": [], "stale": [], "exposed": [],
          "shares": [ { "name": "shop", "state": "ACTIVE", "lastVerifiedAt": 1780000000000 } ]
        }
        """.data(using: .utf8)!
        let status = try JSONDecoder().decode(GatewayStatus.self, from: json)
        XCTAssertEqual(status.lan?.interfaceName, "en0")
        XCTAssertEqual(status.lan?.address, "192.168.1.42")
        XCTAssertEqual(status.shares[0].lastVerifiedAt, 1780000000000)
        XCTAssertEqual(AppModel.lanIdentity(status.lan!), "en0|192.168.1.42")
    }

    func testOlderDaemonWithoutNewFieldsStillDecodes() throws {
        let json = """
        {
          "protocolVersion": 1, "daemonInstanceId": "i-1", "proxyPort": 80, "bind": "wildcard",
          "lan": { "available": true, "reason": null },
          "routes": [], "stale": [], "exposed": [],
          "shares": [ { "name": "shop", "state": "ACTIVE" } ]
        }
        """.data(using: .utf8)!
        let status = try JSONDecoder().decode(GatewayStatus.self, from: json)
        XCTAssertNil(status.lan?.interfaceName)
        XCTAssertNil(status.lan?.address)
        XCTAssertNil(status.shares[0].lastVerifiedAt)
        // Without any identity fields no roaming statement can be made.
        XCTAssertNil(AppModel.lanIdentity(status.lan!))
    }

    // MARK: - Network change surfacing

    private func makeModel() -> (AppModel, FakeDaemonAPI) {
        let api = FakeDaemonAPI()
        let model = AppModel(api: api,
                             copyText: { _ in },
                             openExternal: { _ in },
                             revealPath: { _ in })
        return (model, api)
    }

    private func status(lan: LANInfo?, instanceId: String = "inst-1") -> GatewayStatus {
        FakeDaemonAPI.status(routes: [], instanceId: instanceId, lan: lan)
    }
    func testNetworkChangeIsSurfacedAndDismissible() async {
        let (model, api) = makeModel()
        api.statusResults = [
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en0", address: "192.168.1.42"))),
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en0", address: "10.0.0.7"))),
        ]
        _ = await model.refreshNow()
        XCTAssertFalse(model.networkChangePending, "the first known network must not be flagged")

        _ = await model.refreshNow()
        XCTAssertTrue(model.networkChangePending,
                      "a changed LAN identity must surface, never silently re-label the new network")

        model.dismissNetworkChange()
        XCTAssertFalse(model.networkChangePending)
    }

    func testIdenticalNetworkAndDaemonRestartDoNotFlag() async {
        let (model, api) = makeModel()
        api.statusResults = [
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en0", address: "192.168.1.42"))),
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en0", address: "192.168.1.42"))),
        ]
        _ = await model.refreshNow()
        _ = await model.refreshNow()
        XCTAssertFalse(model.networkChangePending, "identical polls are not a network change")

        // A daemon restart resets the identity baseline: the first report of
        // the new instance is not a roaming event.
        _ = await model.refreshNow() // script exhausted → default status, new instance id below
        api.statusResults = [
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en1", address: "192.168.2.20"), instanceId: "inst-2")),
        ]
        _ = await model.refreshNow()
        XCTAssertFalse(model.networkChangePending,
                       "after a daemon restart the identity baseline must start fresh")
    }

    func testNetworkChangeAcrossAGapWithoutLanIsSurfaced() async {
        // Switching Wi-Fi passes through a report without LAN. That gap is
        // no identity: it must not become the baseline the next network is
        // compared with.
        let (model, api) = makeModel()
        api.statusResults = [
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en0", address: "192.168.1.42"))),
            .success(status(lan: LANInfo(available: false, reason: "no-lan-interface", interfaceName: "en0", address: nil))),
            .success(status(lan: LANInfo(available: false, reason: "no-lan-interface"))),
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en0", address: "10.0.0.7"))),
        ]
        _ = await model.refreshNow()
        _ = await model.refreshNow()
        _ = await model.refreshNow()
        XCTAssertFalse(model.networkChangePending, "losing the LAN alone is not a network change")

        _ = await model.refreshNow()
        XCTAssertTrue(model.networkChangePending,
                      "A → no LAN → B must surface as a network change")
    }

    func testReturningToTheSameNetworkAfterAGapDoesNotFlag() async {
        let (model, api) = makeModel()
        api.statusResults = [
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en0", address: "192.168.1.42"))),
            .success(status(lan: LANInfo(available: false, reason: "no-lan-interface", interfaceName: "en0", address: nil))),
            .success(status(lan: nil)),
            .success(status(lan: LANInfo(available: true, reason: nil, interfaceName: "en0", address: "192.168.1.42"))),
        ]
        for _ in 0..<4 {
            _ = await model.refreshNow()
        }
        XCTAssertFalse(model.networkChangePending,
                       "A → no LAN → A is the same network, not a roaming event")
    }

    func testLanIdentityNeedsAnAvailableLan() {
        XCTAssertNil(AppModel.lanIdentity(LANInfo(available: false, reason: "no-lan-interface",
                                                  interfaceName: "en0", address: nil)))
        XCTAssertNil(AppModel.lanIdentity(LANInfo(available: false, reason: "loopback-bind")))
        XCTAssertEqual(AppModel.lanIdentity(LANInfo(available: true, reason: nil,
                                                    interfaceName: "en0", address: "10.0.0.7")),
                       "en0|10.0.0.7")
    }

    // MARK: - Global share revocation

    func testRevokeAllSharesSucceedsAndReconcilesImmediately() async {
        let (model, api) = makeModel()
        let share = ShareStatus(name: "shop", shareId: "s1", url: nil, state: "ACTIVE",
                                expiresAt: 0, expired: false, pinnedPort: nil, targetPort: nil,
                                pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()
        XCTAssertTrue(model.hasActiveOrStartingShare)
        api.revokedNames = ["shop"]

        let outcome = await model.revokeAllShares()
        XCTAssertEqual(outcome, .success)
        XCTAssertEqual(api.revokeAllCalls, 1)
        XCTAssertNil(model.pendingReconciliation(for: "revoke-all"),
                     "the follow-up poll shows no live shares — the expectation resolves")
        XCTAssertFalse(model.hasActiveOrStartingShare)
    }

    func testRevokeAllSharesWithUnclearOutcomeStaysPendingUntilPollResolves() async {
        let (model, api) = makeModel()
        let share = ShareStatus(name: "shop", shareId: "s1", url: nil, state: "ACTIVE",
                                expiresAt: 0, expired: false, pinnedPort: nil, targetPort: nil,
                                pinnedHost: nil, targetHost: nil)
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share])),
            .success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share])),
        ]
        _ = await model.refreshNow()
        api.revokedNames = []
        api.revokeAllError = TransportError.timedOut // the daemon may have acted

        let outcome = await model.revokeAllShares()
        XCTAssertEqual(outcome, .unclear)
        XCTAssertNotNil(model.pendingReconciliation(for: "revoke-all"))

        // A later poll without live shares proves the revoke happened.
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: []))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "revoke-all"),
                     "a successful poll that proves the effect must resolve the pending entry")
    }

    private func shopRoute() -> Route {
        Route(id: "root-shop", name: "shop", root: "/tmp/root-shop", port: 3000)
    }
}
