import XCTest
@testable import PortnameCore

final class ModelDecodingTests: XCTestCase {
    private let decoder = JSONDecoder()

    func testFullV1StatusDecodes() throws {
        let json = """
        {
          "ok": true,
          "protocolVersion": 1,
          "daemonInstanceId": "11111111-2222-3333-4444-555555555555",
          "proxyPort": 80,
          "bind": "wildcard",
          "lan": { "available": true, "reason": null },
          "routes": [
            {
              "name": "shop", "id": "/Users/demo/shop", "revision": "abcd1234abcd1234",
              "root": "/Users/demo/shop", "port": 3000, "upstreamHost": "127.0.0.1",
              "pid": 42, "processKey": "42:abc", "external": false, "command": "node",
              "cwd": "/Users/demo/shop", "since": 100,
              "localUrl": "http://shop.localhost/", "lanUrl": "http://shop.local/",
              "exposureRequested": true
            },
            {
              "name": "db", "id": "manual:db", "revision": "ffff0000ffff0000",
              "root": null, "port": 55432, "manual": true,
              "localUrl": "http://db.localhost/", "lanUrl": null, "exposureRequested": false
            }
          ],
          "stale": [ { "name": "shop", "port": 2999, "pid": 41 } ],
          "exposed": ["shop"],
          "shares": [
            { "name": "shop", "shareId": "abc12345", "url": "https://demo.trycloudflare.com",
              "state": "ACTIVE", "expiresAt": 1780000000000, "expired": false, "ttlMinutes": 60 }
          ]
        }
        """.data(using: .utf8)!

        let status = try decoder.decode(GatewayStatus.self, from: json)
        XCTAssertFalse(status.isLegacyDaemon)
        XCTAssertEqual(status.routes.count, 2)
        XCTAssertEqual(status.routes[0].id, "/Users/demo/shop")
        XCTAssertEqual(status.routes[0].localUrl, "http://shop.localhost/")
        XCTAssertEqual(status.routes[1].id, "manual:db")
        XCTAssertTrue(status.routes[1].isManual)
        XCTAssertEqual(status.shares[0].phase, .active)
        XCTAssertEqual(status.lan?.available, true)
    }

    func testAdditiveUnknownFieldsAreIgnored() throws {
        let json = """
        {
          "protocolVersion": 1, "daemonInstanceId": "x", "proxyPort": 7777, "bind": "loopback",
          "futureTopLevel": { "a": 1 },
          "routes": [ { "name": "shop", "port": 3000, "futureRouteField": true } ],
          "stale": [], "exposed": [], "shares": []
        }
        """.data(using: .utf8)!
        let status = try decoder.decode(GatewayStatus.self, from: json)
        XCTAssertEqual(status.routes[0].name, "shop")
        XCTAssertEqual(status.proxyPort, 7777)
    }

    func testServiceIdentityFieldsDecodeAdditively() throws {
        // Daemon v1.1+: services carry the stable role identity and the
        // cross-generation marker; stale carries the role identity too.
        let json = """
        {
          "protocolVersion": 1, "daemonInstanceId": "x", "proxyPort": 80, "bind": "wildcard",
          "routes": [ {
            "name": "proj", "id": "/wt/main/proj", "root": "/wt/main/proj", "port": 3333,
            "processKey": "10:T2", "pid": 10,
            "services": [
              { "port": 3333, "pid": 10, "processKey": "10:T2", "primary": true,
                "serviceId": "/wt/main/proj#3333", "crossGeneration": false },
              { "port": 5173, "pid": 20, "processKey": "20:T1", "primary": false,
                "serviceId": "/wt/main/proj#5173", "crossGeneration": true }
            ]
          } ],
          "stale": [ { "name": "proj", "port": 3000, "pid": 30, "serviceId": "/wt/main/proj#3000" } ],
          "exposed": [], "shares": []
        }
        """.data(using: .utf8)!
        let status = try decoder.decode(GatewayStatus.self, from: json)
        let services = try XCTUnwrap(status.routes[0].services)
        XCTAssertEqual(services.count, 2)
        XCTAssertEqual(services[0].serviceId, "/wt/main/proj#3333")
        XCTAssertEqual(services[0].crossGeneration, false)
        XCTAssertEqual(services[1].serviceId, "/wt/main/proj#5173")
        XCTAssertEqual(services[1].crossGeneration, true)
        XCTAssertEqual(status.stale[0].serviceId, "/wt/main/proj#3000")
    }

    func testServiceIdentityFieldsAreOptionalForOlderDaemons() throws {
        // Older v1 daemon: no serviceId/crossGeneration — decoding must not
        // fail, the fields stay nil and the UI degrades gracefully.
        let json = """
        {
          "protocolVersion": 1, "daemonInstanceId": "x", "proxyPort": 80, "bind": "wildcard",
          "routes": [ {
            "name": "proj", "id": "/p", "root": "/p", "port": 3000,
            "services": [ { "port": 3000, "pid": 10, "primary": true } ]
          } ],
          "stale": [ { "name": "proj", "port": 2999, "pid": 9 } ],
          "exposed": [], "shares": []
        }
        """.data(using: .utf8)!
        let status = try decoder.decode(GatewayStatus.self, from: json)
        let services = try XCTUnwrap(status.routes[0].services)
        XCTAssertNil(services[0].serviceId)
        XCTAssertNil(services[0].crossGeneration)
        XCTAssertNil(status.stale[0].serviceId)
    }

    func testEffectiveExposureFieldsDecodeAdditively() throws {
        // Daemon v1.x: every route reports the EFFECTIVE WLAN exposure with
        // the machine-readable pause reason; decoding stays tolerant.
        let json = """
        {
          "protocolVersion": 1, "daemonInstanceId": "x", "proxyPort": 80, "bind": "wildcard",
          "routes": [ {
            "name": "proj", "id": "/p", "root": "/p", "port": 3000,
            "exposureRequested": true,
            "lanUrl": "http://proj.local:80/",
            "exposureEffective": "paused",
            "exposurePauseReason": "target-not-verified",
            "exposureVerifiedAt": 1700000000000
          } ],
          "stale": [], "exposed": ["proj"], "shares": []
        }
        """.data(using: .utf8)!
        let status = try decoder.decode(GatewayStatus.self, from: json)
        XCTAssertEqual(status.routes[0].exposureEffective, "paused")
        XCTAssertEqual(status.routes[0].exposurePauseReason, "target-not-verified")
        XCTAssertTrue(status.routes[0].isExposurePaused,
                      "paused must be detectable so the UI can replace the plain WLAN badge")

        // Older daemon: the fields are absent — decoding succeeds and the
        // route falls back to the legacy lanUrl-based display.
        let legacy = """
        {
          "protocolVersion": 1, "daemonInstanceId": "x", "proxyPort": 80, "bind": "wildcard",
          "routes": [ { "name": "proj", "id": "/p", "root": "/p", "port": 3000,
                        "exposureRequested": true, "lanUrl": "http://proj.local:80/" } ],
          "stale": [], "exposed": ["proj"], "shares": []
        }
        """.data(using: .utf8)!
        let old = try decoder.decode(GatewayStatus.self, from: legacy)
        XCTAssertNil(old.routes[0].exposureEffective)
        XCTAssertNil(old.routes[0].exposurePauseReason)
        XCTAssertFalse(old.routes[0].isExposurePaused)
    }

    func testLegacyDaemonStatusDecodesWithNilProtocolVersion() throws {
        // Pre-v1 daemon: no protocolVersion/daemonInstanceId/lan, routes
        // without id/revision/urls.
        let json = """
        {
          "proxyPort": 80, "bind": "wildcard",
          "routes": [ { "name": "shop", "root": "/x", "port": 3000 } ],
          "stale": [], "exposed": [], "shares": []
        }
        """.data(using: .utf8)!
        let status = try decoder.decode(GatewayStatus.self, from: json)
        XCTAssertTrue(status.isLegacyDaemon)
        XCTAssertEqual(status.routes[0].id, "legacy:shop")
        XCTAssertNil(status.routes[0].revision)
        XCTAssertNil(status.routes[0].localUrl)
    }

    func testMissingRequiredFieldsThrow() throws {
        let json = """
        { "protocolVersion": 1, "daemonInstanceId": "x", "bind": "wildcard", "routes": [], "stale": [], "exposed": [], "shares": [] }
        """.data(using: .utf8)! // proxyPort missing
        XCTAssertThrowsError(try decoder.decode(GatewayStatus.self, from: json))

        let routeJSON = """
        { "protocolVersion": 1, "daemonInstanceId": "x", "proxyPort": 80, "bind": "wildcard",
          "routes": [ { "root": "/x" } ], "stale": [], "exposed": [], "shares": [] }
        """.data(using: .utf8)! // route without name and port
        XCTAssertThrowsError(try decoder.decode(GatewayStatus.self, from: routeJSON))
    }

    func testUnknownShareStateIsNeverActive() {
        XCTAssertEqual(SharePhase("ACTIVE").isActiveShare, true)
        XCTAssertEqual(SharePhase("STARTING").isActiveShare, false)
        XCTAssertEqual(SharePhase("STOPPING").isActiveShare, false)
        XCTAssertEqual(SharePhase("STOPPED").isActiveShare, false)
        // Any unknown spelling must never pass as active.
        XCTAssertEqual(SharePhase("active ").isActiveShare, false)
        XCTAssertEqual(SharePhase("ACTIVE_NOW").isActiveShare, false)
        XCTAssertEqual(SharePhase("weird-state").isActiveShare, false)
        XCTAssertEqual(SharePhase("weird-state"), .unknown("weird-state"))
    }

    func testShareLinkDecodes() throws {
        let json = """
        { "ok": true, "url": "https://demo.trycloudflare.com/deadbeef/", "expiresAt": 1780000000000, "shareId": "abc123" }
        """.data(using: .utf8)!
        let link = try decoder.decode(ShareLink.self, from: json)
        XCTAssertEqual(link.shareId, "abc123")
        XCTAssertTrue(link.url.contains("deadbeef"))
    }
}

final class SafeURLTests: XCTestCase {
    func testLocalBrowserURLAcceptsExpectedShapes() {
        XCTAssertNotNil(SafeURL.localBrowserURL("http://shop.localhost/"))
        XCTAssertNotNil(SafeURL.localBrowserURL("http://shop.localhost:7777/"))
        XCTAssertNotNil(SafeURL.localBrowserURL("http://shop.local/"))
        XCTAssertNotNil(SafeURL.localBrowserURL("http://shop.local:7777/path?q=1"))
        XCTAssertNotNil(SafeURL.localBrowserURL("http://my-app-2.localhost/"))
    }

    func testLocalBrowserURLRejectsUnexpectedShapes() {
        XCTAssertNil(SafeURL.localBrowserURL("file:///etc/passwd"))
        XCTAssertNil(SafeURL.localBrowserURL("javascript:alert(1)"))
        XCTAssertNil(SafeURL.localBrowserURL("https://shop.localhost/")) // local must stay http
        XCTAssertNil(SafeURL.localBrowserURL("http://user:pw@shop.localhost/"))
        XCTAssertNil(SafeURL.localBrowserURL("http://evil.example.com/"))
        XCTAssertNil(SafeURL.localBrowserURL("http://a.b.localhost/")) // no multi-label
        XCTAssertNil(SafeURL.localBrowserURL("http://shop.localhost:80@evil.com/"))
        XCTAssertNil(SafeURL.localBrowserURL("http://localhost/"))
    }

    func testShareURLRequiresExactExpectedHost() {
        XCTAssertNotNil(SafeURL.shareURL("https://demo-abc.trycloudflare.com/token/", expectedOriginHost: "demo-abc.trycloudflare.com"))
        XCTAssertNotNil(SafeURL.shareURL("https://demo-abc.trycloudflare.com:443/token/", expectedOriginHost: "demo-abc.trycloudflare.com"))
        XCTAssertNil(SafeURL.shareURL("https://evil.example.com/token/", expectedOriginHost: "demo-abc.trycloudflare.com"))
        XCTAssertNil(SafeURL.shareURL("http://demo-abc.trycloudflare.com/token/", expectedOriginHost: "demo-abc.trycloudflare.com"))
        XCTAssertNil(SafeURL.shareURL("https://demo-abc.trycloudflare.com:8080/token/", expectedOriginHost: "demo-abc.trycloudflare.com"))
        XCTAssertNil(SafeURL.shareURL("https://user:pw@demo-abc.trycloudflare.com/", expectedOriginHost: "demo-abc.trycloudflare.com"))
    }

    func testLocalURLStringMirrorsNodeHelper() {
        XCTAssertEqual(SafeURL.localURLString(name: "shop", gatewayPort: 80), "http://shop.localhost/")
        XCTAssertEqual(SafeURL.localURLString(name: "shop", gatewayPort: 7777), "http://shop.localhost:7777/")
        XCTAssertEqual(SafeURL.localURLString(name: "shop", gatewayPort: 0), "http://shop.localhost/")
        XCTAssertNil(SafeURL.localURLString(name: "not a name", gatewayPort: 80))
    }

    func testLocalDirectoryRequiresExistingDirectory() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        XCTAssertNotNil(SafeURL.localDirectory(dir.path))
        XCTAssertNil(SafeURL.localDirectory("/definitely/not/here"))
        XCTAssertNil(SafeURL.localDirectory("relative/path"))
    }
}

final class PollPolicyTests: XCTestCase {
    func testPollIntervals() {
        XCTAssertEqual(PollPolicy.intervalSeconds(panelVisible: true, hasActiveOrStartingShare: false), 3)
        XCTAssertEqual(PollPolicy.intervalSeconds(panelVisible: true, hasActiveOrStartingShare: true), 3)
        XCTAssertEqual(PollPolicy.intervalSeconds(panelVisible: false, hasActiveOrStartingShare: true), 5)
        XCTAssertEqual(PollPolicy.intervalSeconds(panelVisible: false, hasActiveOrStartingShare: false), 15)
    }
}
