import XCTest
@testable import PortnameCore

/// Scriptable DaemonAPI fake for deterministic store tests.
@MainActor
final class FakeDaemonAPI: DaemonAPI {
    var statusResults: [Result<GatewayStatus, Error>] = [] {
        didSet { statusScriptPosition = 0 }
    }
    private var statusScriptPosition = 0
    private(set) var statusCallCount = 0

    private(set) var renameCalls: [(name: String, newName: String, rev: String?)] = []
    var renameError: Error?
    var renameDelay: TimeInterval = 0

    private(set) var addCalls: [(name: String, port: Int, createOnly: Bool)] = []
    var addError: Error?

    private(set) var removeCalls: [String] = []
    private(set) var exposeCalls: [(name: String, on: Bool, rev: String?)] = []
    var exposeError: Error?
    private(set) var setPrimaryCalls: [(name: String, port: Int, rev: String?)] = []
    var setPrimaryError: Error?
    private(set) var unshareCalls: [(name: String, shareId: String?, rev: String?)] = []
    var unshareError: Error?

    private(set) var shareCalls: [(name: String, ttl: Double, rev: String?)] = []
    var shareError: Error?
    var shareDelay: TimeInterval = 0

    private(set) var shareLinkCalls: [(name: String, expectedShareId: String)] = []
    var shareLinkResult: Result<ShareLink, Error>?

    /// Test gate: when armed, the NEXT status() call suspends until released.
    /// Lets tests stage a poll that is in flight while something else happens.
    private var gateArmed = false
    private(set) var gateContinuation: CheckedContinuation<Void, Never>?
    func armStatusGate() { gateArmed = true }
    func releaseStatusGate() {
        gateContinuation?.resume()
        gateContinuation = nil
    }

    func status() async throws -> GatewayStatus {
        statusCallCount += 1
        if gateArmed {
            gateArmed = false
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                self.gateContinuation = c
            }
        }
        if statusScriptPosition < statusResults.count {
            defer { statusScriptPosition += 1 }
            switch statusResults[statusScriptPosition] {
            case .success(let s): return s
            case .failure(let e): throw e
            }
        }
        return Self.emptyStatus()
    }

    func rename(name: String, newName: String, expectedRouteRevision: String?) async throws {
        renameCalls.append((name, newName, expectedRouteRevision))
        if renameDelay > 0 { try await Task.sleep(nanoseconds: UInt64(renameDelay * 1_000_000_000)) }
        if let renameError { throw renameError }
    }

    func add(name: String, port: Int, createOnly: Bool) async throws {
        addCalls.append((name, port, createOnly))
        if let addError { throw addError }
    }

    func remove(name: String, expectedRouteRevision: String?) async throws {
        removeCalls.append(name)
    }

    func expose(name: String, on: Bool, expectedRouteRevision: String?) async throws {
        exposeCalls.append((name, on, expectedRouteRevision))
        if let exposeError { throw exposeError }
    }

    func setPrimary(name: String, port: Int, expectedRouteRevision: String?) async throws {
        setPrimaryCalls.append((name, port, expectedRouteRevision))
        if let setPrimaryError { throw setPrimaryError }
    }

    func share(name: String, ttlMinutes: Double, expectedRouteRevision: String?) async throws -> ShareStartResult {
        shareCalls.append((name, ttlMinutes, expectedRouteRevision))
        if shareDelay > 0 { try await Task.sleep(nanoseconds: UInt64(shareDelay * 1_000_000_000)) }
        if let shareError { throw shareError }
        return ShareStartResult(url: "https://demo.trycloudflare.com/secret/", expiresAt: 0, ttlMinutes: ttlMinutes, shareId: "s1")
    }

    func unshare(name: String, expectedShareId: String?, expectedRouteRevision: String?) async throws {
        unshareCalls.append((name, expectedShareId, expectedRouteRevision))
        if let unshareError { throw unshareError }
    }

    func shareLink(name: String, expectedShareId: String) async throws -> ShareLink {
        shareLinkCalls.append((name, expectedShareId))
        switch shareLinkResult {
        case .success(let link): return link
        case .failure(let error): throw error
        case nil:
            return ShareLink(url: "https://demo.trycloudflare.com/secret/", expiresAt: 0, shareId: expectedShareId)
        }
    }

    private(set) var revokeAllCalls = 0
    var revokeAllError: Error?
    /// Names the fake reports as revoked by `revokeAllShares`.
    var revokedNames: [String] = []

    func revokeAllShares() async throws -> [String] {
        revokeAllCalls += 1
        if let revokeAllError { throw revokeAllError }
        return revokedNames
    }

    // Helpers

    static func emptyStatus(protocolVersion: Int? = 1, instanceId: String = "inst-1") -> GatewayStatus {
        GatewayStatus(protocolVersion: protocolVersion, daemonInstanceId: instanceId,
                      proxyPort: 80, bind: "wildcard", lan: LANInfo(available: true, reason: nil),
                      routes: [], stale: [], exposed: [], shares: [])
    }

    static func status(routes: [Route], shares: [ShareStatus] = [], protocolVersion: Int? = 1, instanceId: String = "inst-1", lan: LANInfo? = LANInfo(available: true, reason: nil)) -> GatewayStatus {
        GatewayStatus(protocolVersion: protocolVersion, daemonInstanceId: instanceId,
                      proxyPort: 80, bind: "wildcard", lan: lan,
                      routes: routes, stale: [], exposed: [], shares: shares)
    }
}

/// Simple recorder passed into the AppModel hooks (invoked on the MainActor
/// by the model; plain storage is enough for tests).
final class Recorder: @unchecked Sendable {
    var copied: [String] = []
    var opened: [URL] = []
    var revealed: [String] = []
}

@MainActor
final class AppModelTests: XCTestCase {
    private let recorder = Recorder()
    private var api: FakeDaemonAPI!
    private var model: AppModel!

    override func setUp() async throws {
        recorder.copied = []
        recorder.opened = []
        recorder.revealed = []
        api = FakeDaemonAPI()
        makeModel()
    }

    private var copied: [String] { recorder.copied }
    private var opened: [URL] { recorder.opened }
    private var revealed: [String] { recorder.revealed }

    private func makeModel() {
        let route = Route(id: "/demo/shop", name: "shop", revision: "rev-1", root: "/demo/shop", port: 3000,
                          command: "node", localUrl: "http://shop.localhost/", lanUrl: nil, exposureRequested: false)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [route], instanceId: "inst-1"))]
        model = AppModel(api: api,
                         copyText: { [recorder] in recorder.copied.append($0) },
                         openExternal: { [recorder] in recorder.opened.append($0) },
                         revealPath: { [recorder] in recorder.revealed.append($0) })
    }

    private func shopRoute() -> Route {
        Route(id: "/demo/shop", name: "shop", revision: "rev-1", root: "/demo/shop", port: 3000,
              command: "node", localUrl: "http://shop.localhost/", lanUrl: nil, exposureRequested: false)
    }

    func testApplySnapshotAndConnectionStates() async {
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [shopRoute()])),
        ]
        let ok = await model.refreshNow()
        XCTAssertTrue(ok)
        XCTAssertEqual(model.connection, .connected)
        XCTAssertEqual(model.routes.count, 1)
        XCTAssertFalse(model.mutationsLocked)

        api.statusResults = [.failure(TransportError.socketNotFound)]
        _ = await model.refreshNow()
        XCTAssertEqual(model.connection, .unreachable)
        // Network failure is not an empty project list.
        XCTAssertEqual(model.routes.count, 1)
        XCTAssertTrue(model.statusIsStale)
        XCTAssertTrue(model.mutationsLocked)
    }

    func testLegacyDaemonLocksMutations() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], protocolVersion: nil))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.connection, .incompatibleProtocol)
        XCTAssertTrue(model.isLegacyDaemon)
        XCTAssertTrue(model.mutationsLocked)

        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        guard case .failed = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(api.shareCalls.isEmpty, "legacy daemon must not receive guarded mutations")
    }

    func testStartingShareIsNeverActiveAndBlocksCopy() async {
        let share = ShareStatus(name: "shop", shareId: "s1", url: "https://demo.trycloudflare.com",
                                state: "STARTING", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()
        XCTAssertTrue(model.hasActiveOrStartingShare)

        let outcome = await model.copyShareLink(for: shopRoute())
        guard case .failed(let text) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(text.contains("nicht mehr aktiv"))
        XCTAssertTrue(copied.isEmpty, "STARTING must never hand out a link")
        XCTAssertTrue(api.shareLinkCalls.isEmpty)
    }

    func testUnknownShareStateIsNeverActive() async {
        let share = ShareStatus(name: "shop", shareId: "s1", url: nil,
                                state: "CURIOUS", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()
        let outcome = await model.copyShareLink(for: shopRoute())
        guard case .failed = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(copied.isEmpty)
    }

    func testCopyShareLinkUsesTargetedShareLinkAndNeverStarts() async {
        let share = ShareStatus(name: "shop", shareId: "share-42", url: "https://demo.trycloudflare.com",
                                state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()

        let outcome = await model.copyShareLink(for: shopRoute())
        XCTAssertEqual(outcome, .success)
        XCTAssertEqual(api.shareLinkCalls.count, 1, "copy must fetch via share-link")
        XCTAssertEqual(api.shareLinkCalls.first?.name, "shop")
        XCTAssertEqual(api.shareLinkCalls.first?.expectedShareId, "share-42", "copy must be bound to the known shareId")
        XCTAssertEqual(api.shareCalls.count, 0, "copy must never start or replace a share")
        XCTAssertEqual(copied, ["https://demo.trycloudflare.com/secret/"])
    }

    func testFailedMutationShowsNoSuccessAndKeepsError() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.renameError = ControlError(code: "NAME_CONFLICT", message: "name \"boutique\" is already manually registered")

        let outcome = await model.renameRoute(shopRoute(), to: "boutique")
        guard case .failed(let text) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(text.contains("already manually registered"))
        XCTAssertNotNil(model.feedback)
        XCTAssertEqual(model.feedback?.kind, .problem, "a refusal keeps the warning look")
        // A fresh status read followed the mutation.
        XCTAssertGreaterThanOrEqual(api.statusCallCount, 2)
    }

    func testStaleTargetLeadsToRefreshAndNoBlindExecution() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.renameError = ControlError(code: "STALE_TARGET", message: "route \"shop\" changed; reload the project list and retry")

        let outcome = await model.renameRoute(shopRoute(), to: "boutique")
        XCTAssertEqual(outcome, .staleTarget)
        XCTAssertEqual(model.feedback?.text.contains("erneut ausführen"), true)
    }

    func testUnclearResultOnTimeoutAndNoAutomaticRetry() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareDelay = 0.2
        api.shareError = TransportError.timedOut

        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)
        XCTAssertEqual(api.shareCalls.count, 1, "timeout must not trigger an automatic second share request")
        XCTAssertNotNil(model.pendingReconciliation(for: "/demo/shop"))
    }

    func testDoubleClickDoesNotStartTwoShares() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareDelay = 0.15

        async let first: MutationOutcome = model.startShare(route: shopRoute(), ttlMinutes: 60)
        try? await Task.sleep(nanoseconds: 30_000_000)
        async let second: MutationOutcome = model.startShare(route: shopRoute(), ttlMinutes: 60)
        let results = await [first, second]
        XCTAssertEqual(api.shareCalls.count, 1, "concurrent identical starts must be collapsed")
        XCTAssertTrue(results.contains(.success))
    }

    func testStopShareBindsToCurrentShareId() async {
        let share = ShareStatus(name: "shop", shareId: "share-77", url: nil,
                                state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()

        let outcome = await model.stopShare(route: shopRoute())
        XCTAssertEqual(outcome, .success)
        XCTAssertEqual(api.unshareCalls.first?.shareId, "share-77", "stop must carry the share id from the latest snapshot")
    }

    func testDaemonRestartDiscardsBindingsAndUnclearResults() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()

        // Produce a genuine unclear result via a timed-out mutation.
        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)
        XCTAssertNotNil(model.pendingReconciliation(for: "/demo/shop"))

        // The daemon restarts: bindings and unclear markers are void.
        api.shareError = nil
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], instanceId: "inst-2"))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"), "instance change must discard stale bindings")

        // A follow-up stop uses no stale data — status now comes from inst-2.
        let stopOutcome = await model.stopShare(route: shopRoute())
        XCTAssertEqual(stopOutcome, .success)
        XCTAssertNil(api.unshareCalls.first?.shareId, "no shareId may survive a daemon restart")
    }

    func testClosingPanelTriggersNoShareTeardown() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()],
                                                          shares: [ShareStatus(name: "shop", shareId: "s", url: nil, state: "ACTIVE",
                                                                               expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                                                               pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)]))]
        _ = await model.refreshNow()
        let callsBefore = api.unshareCalls.count
        model.setPanel(visible: false)
        try? await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(api.unshareCalls.count, callsBefore, "closing the GUI must never unshare")
    }

    func testSearchIsPurelyLocal() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(),
                                                                    Route(id: "manual:api", name: "api", revision: "r2", root: nil, port: 8000,
                                                                          command: "manual", localUrl: "http://api.localhost/")]))]
        _ = await model.refreshNow()
        let callsBefore = api.statusCallCount

        model.searchText = "sh"
        XCTAssertEqual(model.filteredRoutes.map(\.name), ["shop"])
        model.searchText = "manual"
        XCTAssertEqual(model.filteredRoutes.map(\.name), ["api"])
        model.searchText = "/demo"
        XCTAssertEqual(model.filteredRoutes.map(\.name), ["shop"], "search matches paths too")
        XCTAssertEqual(api.statusCallCount, callsBefore, "searching must not query the daemon")
    }

    func testSelectionSurvivesPolls() async {
        api.statusResults = [
            .success(FakeDaemonAPI.status(routes: [shopRoute()])),
            .success(FakeDaemonAPI.status(routes: [shopRoute()])),
        ]
        _ = await model.refreshNow()
        model.selectedRouteID = "/demo/shop"
        _ = await model.refreshNow()
        XCTAssertEqual(model.selectedRoute?.name, "shop")
    }

    func testRemainingSecondsComesFromExpiresAt() {
        let share = ShareStatus(name: "shop", shareId: "s", url: nil, state: "ACTIVE",
                                expiresAt: 1_781_000_000_000, expired: false, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        let at = Date(timeIntervalSince1970: 1_781_000_000_000 / 1000 - 120)
        XCTAssertEqual(model.remainingSeconds(for: share, at: at), 120)
        let after = Date(timeIntervalSince1970: 1_781_000_000_000 / 1000 + 5)
        XCTAssertEqual(model.remainingSeconds(for: share, at: after), 0)
    }

    func testCurrentRouteResolvesLatestRevisionFromFreshStatus() async {
        let oldRoute = Route(id: "/demo/shop", name: "shop", revision: "rev-1", root: "/demo/shop", port: 3000,
                             command: "node", localUrl: "http://shop.localhost/")
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [oldRoute]))]
        _ = await model.refreshNow()

        // Daemon moved on (new generation), the captured object is stale.
        let newRoute = Route(id: "/demo/shop", name: "shop", revision: "rev-2", root: "/demo/shop", port: 3001,
                             command: "node", localUrl: "http://shop.localhost/")
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [newRoute]))]
        _ = await model.refreshNow()

        let resolved = await model.currentRoute(for: oldRoute)
        XCTAssertEqual(resolved?.revision, "rev-2", "captured routes must re-resolve to the current revision")
        XCTAssertEqual(resolved?.port, 3001)
    }

    func testCurrentRouteRefreshesOnMissAndReturnsRedicoveredRoute() async {
        let stale = Route(id: "/demo/shop", name: "shop", revision: "rev-1", root: "/demo/shop", port: 3000)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: []))]
        _ = await model.refreshNow()

        // Route is missing from the applied snapshot; currentRoute must
        // refresh once and find it again (e.g. discovery just re-attached).
        let rediscovered = Route(id: "/demo/shop", name: "shop", revision: "rev-2", root: "/demo/shop", port: 3001)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [rediscovered]))]
        let resolved = await model.currentRoute(for: stale)
        XCTAssertEqual(resolved?.revision, "rev-2")
        XCTAssertEqual(api.statusCallCount, 2, "exactly one extra status read for the miss")
    }

    func testCurrentRouteReturnsNilWhenRouteStaysGone() async {
        let stale = Route(id: "/demo/shop", name: "shop", revision: "rev-1", root: "/demo/shop", port: 3000)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: []))]
        _ = await model.refreshNow()

        api.statusResults = [.success(FakeDaemonAPI.status(routes: []))]
        let resolved = await model.currentRoute(for: stale)
        XCTAssertNil(resolved, "a route that stays gone after the refresh must yield nil")
    }

    func testExpiredShareIsNotCopyable() async {
        let share = ShareStatus(name: "shop", shareId: "s1", url: "https://demo.trycloudflare.com",
                                state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: true, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()

        let outcome = await model.copyShareLink(for: shopRoute())
        guard case .failed(let text) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(text.contains("nicht mehr aktiv"))
        XCTAssertTrue(copied.isEmpty)
        XCTAssertTrue(api.shareLinkCalls.isEmpty)
    }

    func testStopShareAlsoBindsDuringStarting() async {
        let share = ShareStatus(name: "shop", shareId: "starting-1", url: nil,
                                state: "STARTING", expiresAt: nil, expired: false, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()
        XCTAssertTrue(model.hasActiveOrStartingShare)

        let outcome = await model.stopShare(route: shopRoute())
        XCTAssertEqual(outcome, .success)
        XCTAssertEqual(api.unshareCalls.first?.shareId, "starting-1",
                       "a targeted stop with the right share id must also work during STARTING")
    }

    func testUnclearResultReconcilesFromSuccessfulStatus() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)
        // The mutation's follow-up refresh already polled successfully and
        // saw no share: the UI must not keep claiming "wird geprüft".
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true)

        // A later poll that observes the live share resolves the entry.
        // The share carries the full identity (route, pinned port, requested
        // ttl, expiry inside the start window) — but that is STATE evidence
        // from a later snapshot, not an answer to this very request: the
        // wording must stay honest about the attribution.
        let share = ShareStatus(name: "shop", shareId: "sX", url: "https://demo.trycloudflare.com",
                                state: "ACTIVE",
                                expiresAt: Date().addingTimeInterval(60 * 60 - 5).timeIntervalSince1970 * 1000,
                                expired: false, ttlMinutes: 60,
                                pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"),
                     "a poll that observes the expected effect must resolve the entry")
        XCTAssertEqual(model.feedback?.text.contains("jetzt aktiv"), true,
                       "reconciliation reports the observed state, not the operation")
        XCTAssertEqual(model.feedback?.text.contains("wurde ausgeführt"), false,
                       "a snapshot can never read as this request being executed")
    }

    func testUnclearResultStaysPendingWhilePollsFail() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        // The mutation's follow-up refresh fails too (connection lost):
        // without a successful poll nothing may flip to unresolved.
        api.statusResults = [.failure(TransportError.connectionClosed)]
        _ = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, false,
                       "the UI legitimately keeps saying “Ergebnis wird geprüft” while polls fail")

        // The first successful poll without the share flips to unresolved.
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true,
                       "successful poll without the expected effect stops the “wird geprüft” claim")
    }

    func testPreSendTransportFailureIsPlainFailureNotUnclear() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()

        for preSendError in [TransportError.socketNotFound,
                             TransportError.permissionDenied,
                             TransportError.pathTooLong,
                             TransportError.connectFailed(errno: ECONNREFUSED),
                             TransportError.requestTooLarge] {
            api.shareError = preSendError
            let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
            guard case .failed = outcome else {
                return XCTFail("\(preSendError) cannot have reached the daemon — expected a definitive failure")
            }
            XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"),
                         "\(preSendError) must never enter the reconciliation state")
        }
    }

    func testStopShareFailsClosedWhenLiveShareHasNoShareId() async {
        let share = ShareStatus(name: "shop", shareId: nil, url: nil,
                                state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()

        let outcome = await model.stopShare(route: shopRoute())
        guard case .failed = outcome else { return XCTFail("expected fail-closed refusal") }
        XCTAssertTrue(api.unshareCalls.isEmpty, "a versioned daemon must not silently receive a stop-by-name")
    }

    func testInvalidLocalURLCopyIsRefusedWithoutFlash() async {
        let bad = Route(id: "/demo/shop", name: "shop", revision: "r", root: "/demo/shop", port: 3000,
                        localUrl: "file:///etc/passwd")
        XCTAssertFalse(model.copyLocalURL(for: bad), "a refused URL must report failure")
        XCTAssertTrue(copied.isEmpty, "no clipboard write, so the view must not flash “Kopiert”")
    }

    func testSetPrimaryServiceSwitchesTargetAndReconciles() async {
        // Project with frontend + backend: switching the primary re-points
        // the name; a following status showing the new port resolves it.
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()

        let outcome = await model.setPrimaryService(shopRoute(), port: 5173)
        XCTAssertEqual(outcome, .success)
        XCTAssertEqual(api.setPrimaryCalls.first?.port, 5173)
        XCTAssertEqual(api.setPrimaryCalls.first?.rev, "rev-1", "switch must carry the route revision guard")

        // Unclear path: timeout may still have been applied daemon-side.
        api.setPrimaryError = TransportError.timedOut
        let unclear = await model.setPrimaryService(shopRoute(), port: 5173)
        XCTAssertEqual(unclear, .unclear)
        XCTAssertNotNil(model.pendingReconciliation(for: "/demo/shop"))
    }

    func testSetPrimaryServiceDefinitiveFailureIsNotUnclear() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.setPrimaryError = ControlError(code: "INVALID_REQUEST", message: "\"shop\" has no running service on port 9999")
        let outcome = await model.setPrimaryService(shopRoute(), port: 9999)
        guard case .failed(let text) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(text.contains("no running service"))
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
    }

    func testOpenShareLinkValidatesHostAgainstStatusOrigin() async {
        let share = ShareStatus(name: "shop", shareId: "s1", url: "https://demo.trycloudflare.com",
                                state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [share]))]
        _ = await model.refreshNow()

        // Matching host: opens the exact link from share-link.
        let outcome = await model.openShareLink(for: shopRoute())
        XCTAssertEqual(outcome, .success)
        XCTAssertEqual(opened, [URL(string: "https://demo.trycloudflare.com/secret/")!])

        // A share-link answer pointing at a different host is refused.
        recorder.opened.removeAll()
        api.shareLinkResult = .success(ShareLink(url: "https://evil.example.net/secret/", expiresAt: 0, shareId: "s1"))
        let refused = await model.openShareLink(for: shopRoute())
        guard case .failed = refused else { return XCTFail("expected refusal") }
        XCTAssertTrue(opened.isEmpty, "unexpected tunnel hosts must never be opened")
    }

    func testLocalOpenAndCopyUseValidatedURLs() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()

        model.openLocalURL(for: shopRoute())
        model.copyLocalURL(for: shopRoute())
        XCTAssertEqual(opened, [URL(string: "http://shop.localhost/")!])
        XCTAssertEqual(copied, ["http://shop.localhost/"])

        model.revealProjectFolder(for: shopRoute())
        XCTAssertTrue(revealed.isEmpty, "folder reveal must be skipped when the path does not exist")
    }

    // MARK: - Service identity: unambiguous result verification

    private func waitUntil(_ condition: () -> Bool, maxMs: Int = 1000) async {
        for _ in 0..<maxMs {
            if condition() { return }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
    }

    func testRenamedExpectationRequiresSameRouteIdentityNotMereName() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.renameError = TransportError.timedOut

        let outcome = await model.renameRoute(shopRoute(), to: "boutique")
        XCTAssertEqual(outcome, .unclear)
        XCTAssertNotNil(model.pendingReconciliation(for: "/demo/shop"))

        // A DIFFERENT object that carries the new name must not confirm the
        // rename — the old route still answers to "shop".
        let decoy = Route(id: "manual:boutique", name: "boutique", revision: "r9", root: nil, port: 9090)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(), decoy]))]
        _ = await model.refreshNow()
        XCTAssertNotNil(model.pendingReconciliation(for: "/demo/shop"),
                        "a name collision on another object is no proof of the rename")

        // The renamed route itself (same stable id) does confirm.
        let renamed = Route(id: "/demo/shop", name: "boutique", revision: "r2", root: "/demo/shop", port: 3000)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [renamed]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"),
                     "the renamed route under its stable identity resolves the outcome")
    }

    func testAddedManualExpectationRequiresManualIdentity() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.addError = TransportError.timedOut

        let outcome = await model.addManual(name: "api", port: 8000)
        XCTAssertEqual(outcome, .unclear)

        // A discovered project that happens to carry the name is a different
        // object: no confirmation.
        let discovered = Route(id: "/elsewhere/api", name: "api", revision: "r", root: "/elsewhere/api", port: 8000)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(), discovered]))]
        _ = await model.refreshNow()
        XCTAssertNotNil(model.pendingReconciliation(for: "add-manual"))

        // Only the manual registration itself (root == nil) confirms.
        let manual = Route(id: "manual:api", name: "api", revision: "r", root: nil, port: 8000, manual: true)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(), manual]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "add-manual"))
    }

    func testSetPrimaryExpectationChecksStoredWishNotPreexistingPort() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.setPrimaryError = TransportError.timedOut

        // Setting the primary to the port the route ALREADY serves: the
        // effective port proves nothing — only the stored per-root wish does.
        let outcome = await model.setPrimaryService(shopRoute(), port: 3000)
        XCTAssertEqual(outcome, .unclear)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        XCTAssertNotNil(model.pendingReconciliation(for: "/demo/shop"),
                        "the pre-existing primary port must not fake a confirmation")

        let wished = Route(id: "/demo/shop", name: "shop", revision: "rev-2", root: "/demo/shop",
                           port: 3000, preferredPort: 3000)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [wished]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
    }

    func testShareStartExpectationBindsToTheIntendedTargetPort() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)

        // A live share under the same name but pinned to ANOTHER port is a
        // different share (the name was repointed): no confirmation.
        let otherPort = ShareStatus(name: "shop", shareId: "s2", url: "https://demo.trycloudflare.com",
                                    state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                    pinnedPort: 4444, targetPort: 4444, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [otherPort]))]
        _ = await model.refreshNow()
        XCTAssertNotNil(model.pendingReconciliation(for: "/demo/shop"),
                        "a share on a repointed target must not confirm the old start")

        // The share pinned to the intended target port confirms.
        let intended = ShareStatus(name: "shop", shareId: "s3", url: "https://demo.trycloudflare.com",
                                   state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                   pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [intended]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
    }

    func testAddedManualExpectationChecksRequestedPort() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.addError = TransportError.timedOut

        let outcome = await model.addManual(name: "api", port: 8000)
        XCTAssertEqual(outcome, .unclear)

        // A manual entry of the same name on a DIFFERENT port is not what
        // was asked for — no confirmation.
        let wrongPort = Route(id: "manual:api", name: "api", revision: "r", root: nil, port: 9000, manual: true)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(), wrongPort]))]
        _ = await model.refreshNow()
        XCTAssertNotNil(model.pendingReconciliation(for: "add-manual"),
                        "a same-name manual entry on another port must not confirm the add")
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false)

        // The manual registration with the requested name AND port confirms.
        let requested = Route(id: "manual:api", name: "api", revision: "r", root: nil, port: 8000, manual: true)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(), requested]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "add-manual"))
    }

    func testAddedManualPreExistingIdenticalEntryStaysHonestlyUnclear() async {
        // The identical entry already exists BEFORE the mutation: the
        // daemon's strict create would have rejected a second add, so even
        // a lost (likely rejected) answer leaves this entry visible. Its
        // presence proves nothing — the outcome stays "Ausgang unklar".
        let existing = Route(id: "manual:api", name: "api", revision: "r", root: nil, port: 8000, manual: true)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(), existing]))]
        _ = await model.refreshNow()

        api.addError = TransportError.timedOut
        let outcome = await model.addManual(name: "api", port: 8000)
        XCTAssertEqual(outcome, .unclear)

        // The very same entry is still there after a successful poll —
        // wish visible, but attribution impossible: no success invention.
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(), existing]))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "add-manual")?.unresolved, true,
                       "a pre-existing identical entry must not fake a confirmation")
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false,
                      "the UI must not claim the operation was executed")
    }

    func testShareStartExpectationChecksRequestedTtl() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)

        // A live share under the same name on the same port but with a
        // DIFFERENT lifetime is a different start intent — no confirmation.
        let otherTtl = ShareStatus(name: "shop", shareId: "s5", url: "https://demo.trycloudflare.com",
                                   state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 15,
                                   pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [otherTtl]))]
        _ = await model.refreshNow()
        XCTAssertNotNil(model.pendingReconciliation(for: "/demo/shop"),
                        "a pre-existing share with another runtime must not confirm the new start")

        // The share with the requested lifetime confirms.
        let requestedTtl = ShareStatus(name: "shop", shareId: "s6", url: "https://demo.trycloudflare.com",
                                       state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                       pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [requestedTtl]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
    }

    func testShareStartDoesNotConfirmOlderSameTraitsShare() async {
        // A share that matches name, port AND ttl but predates the start
        // request (its expiry window cannot come from this mutation) must
        // not confirm it — the start may have failed or been superseded.
        let staleShareExpiry = Date().addingTimeInterval(120).timeIntervalSince1970 * 1000
        let oldShare = ShareStatus(name: "shop", shareId: "old", url: "https://demo.trycloudflare.com",
                                   state: "ACTIVE", expiresAt: staleShareExpiry, expired: false, ttlMinutes: 60,
                                   pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [oldShare]))]
        _ = await model.refreshNow()

        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)

        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [oldShare]))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true,
                       "an older share with identical traits is no proof of the new start")
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false)
    }

    func testForeignShareStartedJustBeforeTheLostRequestReadsAsObservedState() async {
        // Another client (CLI, second GUI) started a matching 60-minute
        // share ten seconds BEFORE this GUI request; this request's answer
        // is lost. The 30-s expiry tolerance admits the foreign share's
        // expiry as "inside the window", so the identity checks pass — the
        // honest outcome is the observed-state wording, never an operation
        // claim: the request's own outcome is genuinely unknown.
        let foreignExpiry = Date().addingTimeInterval(60 * 60 - 10).timeIntervalSince1970 * 1000
        let foreign = ShareStatus(name: "shop", shareId: "foreign", url: "https://demo.trycloudflare.com",
                                  state: "ACTIVE", expiresAt: foreignExpiry, expired: false, ttlMinutes: 60,
                                  pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [foreign]))]
        _ = await model.refreshNow()

        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)

        api.shareError = nil
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [foreign]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"),
                     "a matching share IS observable — the entry resolves as observed state")
        XCTAssertEqual(model.feedback?.text.contains("jetzt aktiv"), true,
                       "the wording confirms the observed state")
        XCTAssertEqual(model.feedback?.text.contains("wurde ausgeführt"), false,
                       "a foreign share within the 30-s tolerance must never read as this request being executed")
    }

    func testCompetingShareAfterTheLostRequestReadsAsObservedState() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)

        // A matching share appears whose expiry sits inside the start
        // window — it could be this request's effect or a competitor's
        // start seconds later; without request attribution the two are
        // indistinguishable, so only the state may be reported.
        let laterExpiry = Date().addingTimeInterval(60 * 60 - 2).timeIntervalSince1970 * 1000
        let later = ShareStatus(name: "shop", shareId: "later", url: "https://demo.trycloudflare.com",
                                state: "ACTIVE", expiresAt: laterExpiry, expired: false, ttlMinutes: 60,
                                pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.shareError = nil
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [later]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
        XCTAssertEqual(model.feedback?.text.contains("jetzt aktiv"), true)
        XCTAssertEqual(model.feedback?.text.contains("wurde ausgeführt"), false,
                       "a competing start can never read as this request being executed")
        XCTAssertEqual(model.feedback?.kind, .observed,
                       "an observed state is neither a success nor a problem")
    }

    func testExplicitShareSuccessCarriesOperationProofWording() async {
        // Positive control: the daemon answered THIS request with ok — the
        // one basis on which "was carried out" may be claimed. No honest-
        // state disclaimer applies here.
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .success)
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
        XCTAssertEqual(api.shareCalls.count, 1)
        XCTAssertEqual(model.feedback?.text.contains("wurde ausgeführt"), true,
                       "an explicit successful response earns the success wording")
        XCTAssertEqual(model.feedback?.kind, .success,
                       "a confirmed success must not be presented like a warning")
    }

    // MARK: - Honest mutation outcomes (operation proof vs. state observation)

    func testShareStartReconciliationRequiresProofFields() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)

        // A live share under the name WITHOUT the proof fields (older daemon
        // shape: no pinned port) is state observation, never operation
        // proof: the outcome degrades to "unclear" instead of faking success.
        let missingFields = ShareStatus(name: "shop", shareId: "s9", url: "https://demo.trycloudflare.com",
                                        state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                                        pinnedPort: nil, targetPort: nil, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [missingFields]))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true,
                       "missing proof fields must degrade to unclear, not success")
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false,
                      "the UI must not claim the operation was executed")
    }

    func testShareStartReconciliationReportsObservedStateNotOperationProof() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)

        // Full identity: the route still exists under its stable id, and the
        // ACTIVE share carries pinned port, requested ttl and an expiry
        // inside the start window. That combination proves a MATCHING share
        // is active — state evidence — but it is not an answer to this
        // request (a competing start seconds earlier passes the same
        // checks), so the wording reports the observed state, never
        // "carried out".
        let full = ShareStatus(name: "shop", shareId: "s7", url: "https://demo.trycloudflare.com",
                               state: "ACTIVE",
                               expiresAt: Date().addingTimeInterval(60 * 60 - 5).timeIntervalSince1970 * 1000,
                               expired: false, ttlMinutes: 60,
                               pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [full]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
        XCTAssertEqual(model.feedback?.text.contains("jetzt aktiv"), true)
        XCTAssertEqual(model.feedback?.text.contains("wurde ausgeführt"), false,
                       "the reconciled path must not claim the operation was executed")
    }

    func testShareStartStartingStateKeepsWaitingInsteadOfConfirming() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        let outcome = await model.startShare(route: shopRoute(), ttlMinutes: 60)
        XCTAssertEqual(outcome, .unclear)
        // The follow-up poll saw nothing: "unclear" for the moment.
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true)

        // The share now shows up STARTING: accepted and in progress —
        // neither a confirmation of activation nor a final "unclear".
        let starting = ShareStatus(name: "shop", shareId: "booting", url: nil,
                                   state: "STARTING", expiresAt: nil, expired: false, ttlMinutes: 60,
                                   pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [starting]))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, false,
                       "a visible in-progress start is better information than “unclear” — keep waiting")
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false,
                      "STARTING must never be confirmed as a successful activation")

        // The tunnel finishes: the matching share is now observable as
        // ACTIVE — the entry resolves with the honest observed-state
        // wording, still not an operations proof.
        let active = ShareStatus(name: "shop", shareId: "booting", url: "https://demo.trycloudflare.com",
                                 state: "ACTIVE",
                                 expiresAt: Date().addingTimeInterval(60 * 60 - 10).timeIntervalSince1970 * 1000,
                                 expired: false, ttlMinutes: 60,
                                 pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [active]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "/demo/shop"))
        XCTAssertEqual(model.feedback?.text.contains("jetzt aktiv"), true)
        XCTAssertEqual(model.feedback?.text.contains("wurde ausgeführt"), false)
    }

    func testShareStartStartingWithLaterFailureEndsUnclearNotSuccess() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        _ = await model.startShare(route: shopRoute(), ttlMinutes: 60)

        // Slow boot becomes visible, then the startup fails and the share
        // disappears: the honest outcome is "unclear", never success.
        let starting = ShareStatus(name: "shop", shareId: "booting", url: nil,
                                   state: "STARTING", expiresAt: nil, expired: false, ttlMinutes: 60,
                                   pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()], shares: [starting]))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, false)

        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true,
                       "a vanished in-progress start must end as unclear")
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false)
    }

    func testShareStartBindsToTheRouteIdentity() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.shareError = TransportError.timedOut
        _ = await model.startShare(route: shopRoute(), ttlMinutes: 60)

        // A share under the same NAME appears — but the route with the
        // stable id "/demo/shop" no longer exists (the name now belongs to a
        // different identity). A name alone proves nothing: no confirmation.
        let otherIdentity = Route(id: "manual:shop", name: "shop", revision: "r", root: nil, port: 3000,
                                  command: "manual", localUrl: "http://shop.localhost/")
        let full = ShareStatus(name: "shop", shareId: "s8", url: "https://demo.trycloudflare.com",
                               state: "ACTIVE", expiresAt: 9_999_999_999_999, expired: false, ttlMinutes: 60,
                               pinnedPort: 3000, targetPort: 3000, pinnedHost: nil, targetHost: nil)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [otherIdentity], shares: [full]))]
        _ = await model.refreshNow()
        XCTAssertEqual(model.pendingReconciliation(for: "/demo/shop")?.unresolved, true,
                       "a same-named share under a different route identity must not confirm the start")
        XCTAssertTrue(model.feedback?.text.contains("wurde ausgeführt") == false)
    }

    func testAddedManualConfirmationIsVisibilityNotOperationProof() async {
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute()]))]
        _ = await model.refreshNow()
        api.addError = TransportError.timedOut
        let outcome = await model.addManual(name: "api", port: 8000)
        XCTAssertEqual(outcome, .unclear)

        // The manual entry with the requested port is now visible — the
        // outcome resolves as VISIBILITY of the desired state, not as proof
        // that THIS operation created it (a concurrent CLI add cannot be
        // excluded without request attribution).
        let manual = Route(id: "manual:api", name: "api", revision: "r", root: nil, port: 8000, manual: true)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [shopRoute(), manual]))]
        _ = await model.refreshNow()
        XCTAssertNil(model.pendingReconciliation(for: "add-manual"))
        XCTAssertEqual(model.feedback?.text.contains("sichtbar"), true,
                       "the honest wording states the entry is visible")
        XCTAssertEqual(model.feedback?.text.contains("wurde ausgeführt"), false,
                       "the UI must not claim the add itself was executed")
    }

    func testPausedExposureSurfacesFromSnapshot() async {
        // New daemon: the route carries the effective exposure; paused is
        // surfaced so the UI can replace the plain WLAN badge.
        let paused = Route(id: "/demo/shop", name: "shop", revision: "rev-1", root: "/demo/shop", port: 3000,
                           command: "node", localUrl: "http://shop.localhost/", lanUrl: "http://shop.local:80/",
                           exposureRequested: true, exposureEffective: "paused",
                           exposurePauseReason: "target-not-verified")
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [paused]))]
        _ = await model.refreshNow()
        XCTAssertTrue(model.routes[0].isExposurePaused)

        // Older daemon: no effective field — not paused, legacy display.
        let legacy = Route(id: "/demo/shop", name: "shop", revision: "rev-1", root: "/demo/shop", port: 3000,
                           command: "node", localUrl: "http://shop.localhost/", lanUrl: "http://shop.local:80/",
                           exposureRequested: true)
        api.statusResults = [.success(FakeDaemonAPI.status(routes: [legacy]))]
        _ = await model.refreshNow()
        XCTAssertFalse(model.routes[0].isExposurePaused)
    }

    func testLatePreMutationStatusNeverOverwritesNewerState() async {
        let oldSnapshot = FakeDaemonAPI.status(routes: [shopRoute()])
        let newSnapshot = FakeDaemonAPI.status(routes: [
            Route(id: "/demo/shop", name: "boutique", revision: "rev-2", root: "/demo/shop", port: 3000),
        ])
        api.statusResults = [.success(oldSnapshot), .success(newSnapshot)]

        // Stage a poll that is in flight, then issue a newer refresh request.
        api.armStatusGate()
        let inFlight = Task { await model.refreshNow() }
        await waitUntil { [weak api] in api?.gateContinuation != nil }
        XCTAssertNotNil(api.gateContinuation, "the first poll should be in flight now")

        let second = await model.refreshNow()
        XCTAssertFalse(second, "an in-flight poll must not serve the newer request")

        // The in-flight poll lands with the PRE-mutation snapshot: discarded.
        // The guaranteed follow-up poll delivers the newer state.
        api.releaseStatusGate()
        _ = await inFlight.value
        XCTAssertEqual(model.routes.first?.name, "boutique",
                       "a late pre-mutation snapshot must never overwrite newer state")
    }
}
