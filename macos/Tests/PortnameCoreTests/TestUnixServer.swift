import Foundation
@testable import PortnameCore

/// Minimal controllable Unix domain socket test server: the test installs a
/// handler that receives each accepted client descriptor on a private
/// queue and drives the conversation (read line, write scripted bytes).
final class TestUnixServer: @unchecked Sendable {
    let path: String
    private var serverFD: Int32 = -1
    private let queue = DispatchQueue(label: "portname.test.server")
    private(set) var connectionCount = 0
    private let lock = NSLock()
    var handler: ((Int32) -> Void)?

    init(path: String) {
        self.path = path
    }

    var connections: Int {
        lock.lock(); defer { lock.unlock() }
        return connectionCount
    }

    func start() throws {
        try? FileManager.default.removeItem(atPath: path)
        let bytes = Array(path.utf8)
        guard bytes.count <= UnixSocketTransport.maxPathBytes else {
            throw NSError(domain: "TestUnixServer", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "test socket path too long (\(bytes.count) bytes)"])
        }
        serverFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENODEV) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { dest in
            dest.copyBytes(from: bytes)
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(serverFD, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENODEV) }
        guard listen(serverFD, 16) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENODEV) }

        // The blocking accept loop gets its own thread; scripted handlers run
        // on a global queue so they can never starve the accept loop.
        let thread = Thread { [weak self] in
            self?.acceptLoop()
        }
        thread.name = "portname.test.server.accept"
        thread.start()
    }

    func stop() {
        if serverFD >= 0 {
            close(serverFD)
            serverFD = -1
        }
        try? FileManager.default.removeItem(atPath: path)
    }

    private func acceptLoop() {
        while serverFD >= 0 {
            let client = accept(serverFD, nil, nil)
            guard client >= 0 else { return }
            lock.lock()
            connectionCount += 1
            lock.unlock()
            var one: Int32 = 1
            setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.handler?(client)
                close(client)
            }
        }
    }
}

enum TestSocketIO {
    /// Blocking read of one newline-terminated line from the client fd.
    static func readLine(fd: Int32, limit: Int = 1024 * 1024) -> Data? {
        var received = [UInt8]()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while received.count < limit {
            let n = chunk.withUnsafeMutableBytes { raw in
                recv(fd, raw.baseAddress, raw.count, 0)
            }
            if n > 0 {
                received.append(contentsOf: chunk[0..<n])
                if let idx = received.firstIndex(of: 0x0A) {
                    return Data(received[0..<idx])
                }
            } else if n == 0 {
                return received.isEmpty ? nil : Data(received)
            } else if errno != EINTR {
                return received.isEmpty ? nil : Data(received)
            }
        }
        return nil
    }

    /// Writes all bytes, tolerating partial writes.
    @discardableResult
    static func writeAll(fd: Int32, data: Data) -> Bool {
        var offset = 0
        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            while offset < data.count {
                let n = raw.baseAddress!.advanced(by: offset).withMemoryRebound(to: UInt8.self, capacity: data.count - offset) { p in
                    send(fd, p, data.count - offset, 0)
                }
                if n > 0 {
                    offset += n
                } else if n < 0 && errno == EINTR {
                    continue
                } else {
                    return false
                }
            }
            return true
        }
    }
}
