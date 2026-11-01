import XCTest
@testable import PortnameCore

/// The language-boundary proof: a real portname Node daemon is started in an
/// isolated PORTNAME_DIR (loopback bind on an ephemeral port, own socket
/// file) together with a harmless local upstream server, and the Swift
/// DaemonClient talks to the daemon over the real Unix domain socket. No
/// mocks involved on either side.
final class DaemonIntegrationTests: XCTestCase {
    private func repoRoot() -> URL {
        // .../portname/macos/Tests/PortnameCoreTests/X.swift
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // PortnameCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // macos
            .deletingLastPathComponent() // repo root
    }

    /// realpath(3): matches the daemon's path.resolve() canonical form
    /// (/private/var/... on macOS) that lsof-based discovery reports.
    private func realpathC(_ path: String) -> String {
        var buffer = [CChar](repeating: 0, count: 4096)
        guard let resolved = realpath(path, &buffer) else { return path }
        return String(cString: resolved)
    }

    private func locateNode() -> URL? {
        let candidates = ["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"]
        for c in candidates where FileManager.default.isExecutableFile(atPath: c) {
            return URL(fileURLWithPath: c)
        }
        return nil
    }

    private func waitForFileSync(_ path: String, timeout: TimeInterval) throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: path) { return }
            usleep(100_000)
        }
        XCTFail("daemon socket never appeared at \(path)")
    }

    /// Polls until a TCP listener answers on 127.0.0.1:port.
    private func waitForTcpPort(_ port: Int, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { usleep(100_000); continue }
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = UInt16(port).bigEndian
            addr.sin_addr = in_addr(s_addr: INADDR_LOOPBACK.bigEndian)
            let result = withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            let connected = (result == 0)
            close(fd)
            if connected { return true }
            usleep(100_000)
        }
        return false
    }

    private func waitUntilExit(_ process: Process, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if !process.isRunning { return true }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        return !process.isRunning
    }

    func testSwiftClientTalksToRealNodeDaemon() async throws {
        guard let node = locateNode() else {
            throw XCTSkip("node executable not found — integration test requires a local Node >= 22")
        }
        let binPath = repoRoot().appendingPathComponent("bin/portname.js").path
        guard FileManager.default.fileExists(atPath: binPath) else {
            XCTFail("bin/portname.js not found at \(binPath)")
            return
        }

        // Darwin sun_path is 103 bytes max — keep the directory name short.
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pn-i-\(Int.random(in: 100_000..<999_999))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        // A harmless auto-discoverable upstream: its own folder with a .git
        // marker inside the isolated dir becomes the project root ("up1").
        let appDir = dir.appendingPathComponent("up1", isDirectory: true)
        try FileManager.default.createDirectory(at: appDir.appendingPathComponent(".git", isDirectory: true),
                                                withIntermediateDirectories: true)
        // lsof reports the resolved cwd (/private/var/...), so compare
        // against the symlink-resolved canonical path.
        let canonicalAppDir = realpathC(appDir.path)
        let upstreamPort = Int.random(in: 42000..<50000)
        let upstream = Process()
        upstream.executableURL = node
        upstream.arguments = ["-e",
            "require('http').createServer((q,s)=>s.end('up-ok')).listen(\(upstreamPort),'127.0.0.1')"]
        upstream.currentDirectoryURL = appDir
        upstream.standardOutput = Pipe()
        upstream.standardError = Pipe()
        try upstream.run()
        defer {
            if upstream.isRunning { upstream.terminate(); upstream.waitUntilExit() }
        }
        XCTAssertTrue(waitForTcpPort(upstreamPort, timeout: 10),
                      "upstream server must be listening on \(upstreamPort)")

        // Isolated daemon: loopback bind on an ephemeral port, control on.
        let configJSON = "{ \"bind\": \"loopback\", \"loopbackPort\": 0, \"control\": true }"
        try configJSON.write(to: dir.appendingPathComponent("config.json"), atomically: true, encoding: .utf8)

        let sockPath = dir.appendingPathComponent("daemon.sock").path
        let daemon = Process()
        daemon.executableURL = node
        daemon.arguments = [binPath, "daemon"]
        daemon.environment = [
            "PORTNAME_DIR": dir.path,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
        ]
        let stderrPipe = Pipe()
        daemon.standardError = stderrPipe
        daemon.standardOutput = Pipe()
        try daemon.run()
        defer {
            if daemon.isRunning {
                daemon.terminate()
                daemon.waitUntilExit()
            }
            try? FileManager.default.removeItem(at: dir)
        }

        try waitForFileSync(sockPath, timeout: 15)
        let client = DaemonClient(socketPath: sockPath)

        // 1. status over the real socket: protocol metadata present.
        let status = try await client.status()
        XCTAssertEqual(status.protocolVersion, 1)
        XCTAssertNotNil(status.daemonInstanceId)
        XCTAssertEqual(status.bind, "loopback")
        XCTAssertEqual(status.lan?.available, false, "loopback bind must report LAN unavailable")
        XCTAssertEqual(status.lan?.reason, "loopback-bind")

        // 2. Real discovery: the daemon finds the upstream and names it after
        //    its project root. Discovery runs on the daemon's refresh
        //    cadence, so poll the status until the route appears.
        var discovered: Route?
        var gatewayPort = 0
        for _ in 0..<50 {
            let s = try await client.status()
            gatewayPort = s.proxyPort
            if let found = s.routes.first(where: { $0.name == "up1" }) {
                discovered = found
                break
            }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        let route = try XCTUnwrap(discovered, "daemon must discover the upstream project")
        XCTAssertEqual(route.id, canonicalAppDir, "auto identity is the canonical project root")
        XCTAssertEqual(route.root, canonicalAppDir)
        XCTAssertEqual(route.port, upstreamPort)
        XCTAssertEqual(route.localUrl, "http://up1.localhost:\(gatewayPort)/",
                       "browser URL must carry the gateway port")
        XCTAssertFalse(route.localUrl?.contains(String(upstreamPort)) ?? true,
                       "upstream port must not appear in the browser URL")
        XCTAssertNotNil(route.revision)

        // 3. add with createOnly succeeds once and conflicts afterwards.
        try await client.add(name: "mtest", port: upstreamPort + 1, createOnly: true)
        do {
            try await client.add(name: "mtest", port: upstreamPort + 2, createOnly: true)
            XCTFail("expected NAME_CONFLICT")
        } catch let error as ControlError {
            XCTAssertEqual(error.code, "NAME_CONFLICT")
            XCTAssertEqual(error.message, "name \"mtest\" is already manually registered")
        }

        // 4. Stale guards: a wrong revision refuses rename and remove.
        do {
            try await client.rename(name: "up1", newName: "up2", expectedRouteRevision: "bogus")
            XCTFail("expected STALE_TARGET")
        } catch let error as ControlError {
            XCTAssertEqual(error.code, "STALE_TARGET")
        }
        do {
            try await client.remove(name: "mtest", expectedRouteRevision: "bogus")
            XCTFail("expected STALE_TARGET")
        } catch let error as ControlError {
            XCTAssertEqual(error.code, "STALE_TARGET")
        }

        // 5. rename with the correct revision succeeds; a fresh read shows it.
        try await client.rename(name: "up1", newName: "up2", expectedRouteRevision: route.revision)
        let status3 = try await client.status()
        XCTAssertEqual(status3.routes.first { $0.id == canonicalAppDir }?.name, "up2")

        // 6. share-link without an active share answers SHARE_NOT_ACTIVE and
        //    never starts anything.
        do {
            _ = try await client.shareLink(name: "up2", expectedShareId: "whatever")
            XCTFail("expected SHARE_NOT_ACTIVE")
        } catch let error as ControlError {
            XCTAssertEqual(error.code, "SHARE_NOT_ACTIVE")
        }
        let status4 = try await client.status()
        XCTAssertTrue(status4.shares.isEmpty)

        // 7. legacy CLI-style unshare on a non-existent share keeps the
        //    legacy error text and carries no code.
        do {
            try await client.unshare(name: "up2", expectedShareId: nil, expectedRouteRevision: nil)
            XCTFail("expected legacy unshare error")
        } catch let error as ControlError {
            XCTAssertNil(error.code)
            XCTAssertEqual(error.message, "no active share for \"up2\"")
        }

        // 8. clean shutdown: SIGTERM → exit code 0, socket removed.
        daemon.terminate()
        let exited = await waitUntilExit(daemon, timeout: 10)
        XCTAssertTrue(exited, "daemon must exit after SIGTERM")
        XCTAssertEqual(daemon.terminationStatus, 0, "daemon must shut down cleanly")
        XCTAssertFalse(FileManager.default.fileExists(atPath: sockPath), "daemon must remove its socket on shutdown")

        // Outside the LaunchAgent the daemon writes its log lines to stderr
        // (docs/diagnostics.md), e.g. "daemon listening …". A clean run
        // carries no error or failure line.
        let stderr = String(decoding: stderrPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let problems = stderr.split(separator: "\n").filter {
            let line = $0.lowercased()
            return line.contains("error") || line.contains("fail")
        }
        XCTAssertEqual(problems, [], "daemon must not log errors during a clean run:\n\(stderr)")
    }
}
