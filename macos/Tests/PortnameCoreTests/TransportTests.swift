import XCTest
@testable import PortnameCore

final class TransportTests: XCTestCase {
    private var workDir: URL!
    private var server: TestUnixServer!

    override func setUpWithError() throws {
        workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pn-t-\(Int.random(in: 100_000..<999_999))", isDirectory: true)
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        server = TestUnixServer(path: workDir.appendingPathComponent("test.sock").path)
    }

    override func tearDown() {
        server.stop()
        try? FileManager.default.removeItem(at: workDir)
    }

    private var socketPath: String { workDir.appendingPathComponent("test.sock").path }

    func testRoundTripWithChunkedUTF8Response() async throws {
        // Response split mid-UTF-8-character and mid-line across writes.
        server.handler = { fd in
            guard let request = TestSocketIO.readLine(fd: fd) else { return }
            XCTAssertEqual(String(decoding: request, as: UTF8.self), "{\"cmd\":\"ping\"}")
            let payload = "{\"ok\":true,\"text\":\"Grüße aus München — ✓\"}".data(using: .utf8)!
            let half = payload.index(payload.startIndex, offsetBy: payload.count / 2)
            TestSocketIO.writeAll(fd: fd, data: payload[..<half])
            Thread.sleep(forTimeInterval: 0.05)
            TestSocketIO.writeAll(fd: fd, data: payload[half...])
            TestSocketIO.writeAll(fd: fd, data: Data([0x0A]))
        }
        try server.start()

        let transport = UnixSocketTransport(socketPath: socketPath)
        let reply = try await transport.sendLine(Data("{\"cmd\":\"ping\"}".utf8), timeout: 5)
        XCTAssertEqual(String(decoding: reply, as: UTF8.self), "{\"ok\":true,\"text\":\"Grüße aus München — ✓\"}")
        XCTAssertEqual(server.connections, 1)
    }

    func testPartialWriteOfLargeRequest() async throws {
        // A request larger than typical socket buffers forces the transport
        // through partial-write handling.
        server.handler = { fd in
            guard let request = TestSocketIO.readLine(fd: fd) else { return }
            XCTAssertEqual(request.count, 300_000)
            TestSocketIO.writeAll(fd: fd, data: Data("{\"ok\":true}".utf8))
            TestSocketIO.writeAll(fd: fd, data: Data([0x0A]))
        }
        try server.start()

        let transport = UnixSocketTransport(socketPath: socketPath, maxRequestBytes: 512 * 1024)
        var big = Data("{}".utf8)
        big.append(contentsOf: [UInt8](repeating: UInt8(ascii: "a"), count: 300_000 - 2))
        let reply = try await transport.sendLine(big, timeout: 10)
        XCTAssertEqual(String(decoding: reply, as: UTF8.self), "{\"ok\":true}")
    }

    func testEOFArrivesBeforeNewline() async throws {
        server.handler = { fd in
            _ = TestSocketIO.readLine(fd: fd)
            TestSocketIO.writeAll(fd: fd, data: Data("{\"ok\":true}".utf8))
            // No newline; the peer then sees EOF when we close.
        }
        try server.start()

        let transport = UnixSocketTransport(socketPath: socketPath)
        do {
            _ = try await transport.sendLine(Data("{}".utf8), timeout: 5)
            XCTFail("expected connectionClosed")
        } catch let error as TransportError {
            XCTAssertEqual(error, .connectionClosed)
        }
    }

    func testInvalidUTF8InCompleteLineIsBadResponse() async throws {
        server.handler = { fd in
            _ = TestSocketIO.readLine(fd: fd)
            var line = Data([0x7B, 0x22, 0x6F, 0x6B, 0x22, 0x3A, 0x74, 0x72, 0x75, 0x65, 0x7D]) // {"ok":true}
            line.append(contentsOf: [0xFF, 0xFE]) // invalid UTF-8 bytes
            line.append(0x0A)
            TestSocketIO.writeAll(fd: fd, data: line)
        }
        try server.start()

        let transport = UnixSocketTransport(socketPath: socketPath)
        do {
            _ = try await transport.sendLine(Data("{}".utf8), timeout: 5)
            XCTFail("expected badResponse")
        } catch let error as TransportError {
            XCTAssertEqual(error, .badResponse)
        }
    }

    func testOversizedResponseIsRejected() async throws {
        server.handler = { fd in
            _ = TestSocketIO.readLine(fd: fd)
            // 2 MiB without a newline: exceeds the 1 MiB response limit.
            var chunk = [UInt8](repeating: UInt8(ascii: "x"), count: 64 * 1024)
            chunk[0] = 0x7B
            while true {
                if !TestSocketIO.writeAll(fd: fd, data: Data(chunk)) { break }
            }
        }
        try server.start()

        let transport = UnixSocketTransport(socketPath: socketPath)
        do {
            _ = try await transport.sendLine(Data("{}".utf8), timeout: 10)
            XCTFail("expected responseTooLarge")
        } catch let error as TransportError {
            XCTAssertEqual(error, .responseTooLarge)
        }
    }

    func testMissingSocketIsSocketNotFound() async throws {
        let transport = UnixSocketTransport(socketPath: workDir.appendingPathComponent("missing.sock").path)
        do {
            _ = try await transport.sendLine(Data("{}".utf8), timeout: 2)
            XCTFail("expected socketNotFound")
        } catch let error as TransportError {
            XCTAssertEqual(error, .socketNotFound)
        }
    }

    func testSocketPathTooLongIsRejectedWithoutSyscall() async throws {
        let longPath = String(repeating: "p", count: 200)
        let transport = UnixSocketTransport(socketPath: "/tmp/\(longPath)")
        do {
            _ = try await transport.sendLine(Data("{}".utf8), timeout: 2)
            XCTFail("expected pathTooLong")
        } catch let error as TransportError {
            XCTAssertEqual(error, .pathTooLong)
        }
    }

    func testDeadlineIsObservedWhenServerNeverAnswers() async throws {
        server.handler = { fd in
            _ = TestSocketIO.readLine(fd: fd)
            Thread.sleep(forTimeInterval: 5) // never answers
        }
        try server.start()

        let transport = UnixSocketTransport(socketPath: socketPath)
        let start = Date()
        do {
            _ = try await transport.sendLine(Data("{}".utf8), timeout: 0.4)
            XCTFail("expected timedOut")
        } catch let error as TransportError {
            XCTAssertEqual(error, .timedOut)
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 3, "deadline must cut the wait short")
    }

    func testCancellationDuringRequestCleansUp() async throws {
        final class Flag: @unchecked Sendable {
            private let lock = NSLock()
            private var value = false
            var isSet: Bool {
                lock.lock(); defer { lock.unlock() }
                return value
            }
            func set() {
                lock.lock(); value = true; lock.unlock()
            }
        }
        let gotRequest = Flag()
        server.handler = { fd in
            _ = TestSocketIO.readLine(fd: fd)
            gotRequest.set()
            Thread.sleep(forTimeInterval: 5) // answer long after the client gave up
        }
        try server.start()

        let transport = UnixSocketTransport(socketPath: socketPath)
        let task = Task {
            try await transport.sendLine(Data("{}".utf8), timeout: 30)
        }
        let deadline = Date().addingTimeInterval(2)
        while !gotRequest.isSet && Date() < deadline {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        XCTAssertTrue(gotRequest.isSet, "server should have received the request")
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancelled")
        } catch let error as TransportError {
            XCTAssertEqual(error, .cancelled)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testOneConnectionPerRequest() async throws {
        server.handler = { fd in
            _ = TestSocketIO.readLine(fd: fd)
            TestSocketIO.writeAll(fd: fd, data: Data("{\"ok\":true}\n".utf8))
        }
        try server.start()

        let transport = UnixSocketTransport(socketPath: socketPath)
        for _ in 0..<3 {
            let reply = try await transport.sendLine(Data("{}".utf8), timeout: 5)
            XCTAssertEqual(String(decoding: reply, as: UTF8.self), "{\"ok\":true}")
        }
        XCTAssertEqual(server.connections, 3)
    }
}

