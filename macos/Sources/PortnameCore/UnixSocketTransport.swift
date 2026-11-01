import Foundation

/// Transport-level failures. All cases are mapped to user-visible state by
/// the caller; none is recoverable inside the transport itself.
public enum TransportError: Error, Equatable, Sendable {
    case pathTooLong
    case socketNotFound
    case permissionDenied
    case connectFailed(errno: Int32)
    /// EOF before a full line arrived, or a write against a closed peer.
    case connectionClosed
    /// A complete line arrived but is not valid UTF-8.
    case badResponse
    case requestTooLarge
    case responseTooLarge
    case timedOut
    case cancelled

    /// True when the failure occurred at a point where the daemon may
    /// already have received (and acted on) the request — the caller must
    /// treat the outcome as unknown and reconcile via `status`. False means
    /// the request provably never left the client (pre-connect refusal),
    /// so a plain failure is safe to report.
    public var resultMayBeUnknown: Bool {
        switch self {
        case .pathTooLong, .socketNotFound, .permissionDenied,
             .connectFailed, .requestTooLarge:
            return false
        case .connectionClosed, .badResponse, .responseTooLarge,
             .timedOut, .cancelled:
            return true
        }
    }
}

/// One-shot Unix domain socket request/response transport.
///
/// Contract: one connection per request, exactly one newline-terminated
/// request line out, one newline-terminated response line back. Framing
/// limits are enforced (default 64 KiB request / 1 MiB response); an
/// overflow is a defined error, never unbounded growth.
///
/// Concurrency: the POSIX loop runs on a background queue and is driven by
/// short poll() slices so cancellation and deadlines are observed without
/// ever closing a descriptor from two threads. The continuation is resumed
/// exactly once, from the loop itself.
public final class UnixSocketTransport: Sendable {
    public static let defaultMaxRequestBytes = 64 * 1024
    public static let defaultMaxResponseBytes = 1024 * 1024

    /// Darwin sockaddr_un.sun_path is 104 bytes including the NUL terminator.
    static let maxPathBytes = 103

    public let socketPath: String
    private let maxRequestBytes: Int
    private let maxResponseBytes: Int

    public init(socketPath: String,
                maxRequestBytes: Int = UnixSocketTransport.defaultMaxRequestBytes,
                maxResponseBytes: Int = UnixSocketTransport.defaultMaxResponseBytes) {
        self.socketPath = socketPath
        self.maxRequestBytes = maxRequestBytes
        self.maxResponseBytes = maxResponseBytes
    }

    /// Sends `line` (without trailing newline — one is appended) and returns
    /// the raw response line bytes (without the trailing newline).
    public func sendLine(_ line: Data, timeout: TimeInterval) async throws -> Data {
        guard socketPath.utf8.count <= Self.maxPathBytes else { throw TransportError.pathTooLong }
        guard line.count <= maxRequestBytes else { throw TransportError.requestTooLarge }

        let flag = CancelFlag()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
                // Monotone deadline: a wall-clock change must not extend or
                // cut short an in-flight request.
                let deadline = ContinuousClock.now.advanced(by: .seconds(timeout))
                DispatchQueue.global(qos: .userInitiated).async {
                    cont.resume(with: Result {
                        try self.blockingRoundTrip(line: line, deadline: deadline, flag: flag)
                    })
                }
            }
        } onCancel: {
            flag.cancel()
        }
    }

    // MARK: - POSIX loop (runs off the main thread)

    private final class CancelFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var cancelled = false
        var isCancelled: Bool {
            lock.lock(); defer { lock.unlock() }
            return cancelled
        }
        func cancel() {
            lock.lock(); defer { lock.unlock() }
            cancelled = true
        }
    }

    private func blockingRoundTrip(line: Data, deadline: ContinuousClock.Instant, flag: CancelFlag) throws -> Data {
        // A cancelled task may not even have started its loop yet.
        if flag.isCancelled { throw TransportError.cancelled }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw TransportError.connectFailed(errno: errno) }
        var closed = false
        func closeOnce() {
            if !closed {
                closed = true
                close(fd)
            }
        }
        defer { closeOnce() }

        // SO_NOSIGPIPE: writes to a dead peer must return EPIPE, never raise.
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        // Non-blocking from birth: the connect phase below is driven by the
        // same deadline/cancel poll slices as read and write, so no phase of
        // the request can ever block unbounded.
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let pathBytes = Array(socketPath.utf8)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { dest in
            dest.copyBytes(from: pathBytes)
        }

        let connected = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        if connected != 0 {
            let connectErrno = errno
            switch connectErrno {
            case EINPROGRESS, EALREADY:
                guard try pollOnce(fd: fd, events: Int16(POLLOUT), deadline: deadline, flag: flag) else {
                    throw flag.isCancelled ? TransportError.cancelled : TransportError.timedOut
                }
                var soError: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len)
                if soError != 0 { throw mapConnectErrno(soError) }
            case ENOENT:
                throw TransportError.socketNotFound
            case EACCES, EPERM:
                throw TransportError.permissionDenied
            default:
                throw mapConnectErrno(connectErrno)
            }
        }

        // --- Write loop (handles partial writes, EINTR, EPIPE, EAGAIN) ---
        var writeOffset = 0
        var out = line
        out.append(0x0A) // newline terminator
        try out.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            while writeOffset < out.count {
                if flag.isCancelled { throw TransportError.cancelled }
                try checkDeadline(deadline)

                let n = raw.baseAddress!.advanced(by: writeOffset).withMemoryRebound(to: UInt8.self, capacity: out.count - writeOffset) { p in
                    send(fd, p, out.count - writeOffset, Int32(MSG_DONTWAIT))
                }
                if n > 0 {
                    writeOffset += n
                } else if n == 0 {
                    throw TransportError.connectionClosed
                } else {
                    switch errno {
                    case EINTR:
                        continue
                    case EAGAIN, EWOULDBLOCK:
                        guard try pollOnce(fd: fd, events: Int16(POLLOUT), deadline: deadline, flag: flag) else {
                            throw flag.isCancelled ? TransportError.cancelled : TransportError.timedOut
                        }
                    case EPIPE, ECONNRESET:
                        throw TransportError.connectionClosed
                    default:
                        throw TransportError.connectionClosed
                    }
                }
            }
        }
        if writeOffset < out.count { throw TransportError.connectionClosed }

        // --- Read loop: assemble the full byte line, decode only afterwards ---
        var received = [UInt8]()
        received.reserveCapacity(4096)
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        var newlineIndex: Int? = nil

        readLoop: while true {
            if flag.isCancelled { throw TransportError.cancelled }
            try checkDeadline(deadline)

            let n = chunk.withUnsafeMutableBytes { raw in
                recv(fd, raw.baseAddress, raw.count, 0)
            }
            if n > 0 {
                if received.count + n > maxResponseBytes {
                    throw TransportError.responseTooLarge
                }
                // Search only the newly arrived region for the terminator;
                // Array slice indices equal absolute indices here.
                let regionStart = received.count
                received.append(contentsOf: chunk[0..<n])
                if let idx = received[regionStart...].firstIndex(of: 0x0A) {
                    newlineIndex = idx
                    break readLoop
                }
            } else if n == 0 {
                // EOF: premature unless the line was already complete.
                throw TransportError.connectionClosed
            } else {
                switch errno {
                case EINTR:
                    continue
                case EAGAIN, EWOULDBLOCK:
                    guard try pollOnce(fd: fd, events: Int16(POLLIN), deadline: deadline, flag: flag) else {
                        throw flag.isCancelled ? TransportError.cancelled : TransportError.timedOut
                    }
                default:
                    throw TransportError.connectionClosed
                }
            }
        }

        guard let idx = newlineIndex else { throw TransportError.connectionClosed }
        let lineData = Data(received[0..<idx])
        // Decode only now that the full byte line is assembled; invalid
        // UTF-8 across chunk boundaries is a defined error.
        guard String(bytes: lineData, encoding: .utf8) != nil else {
            throw TransportError.badResponse
        }
        return lineData
    }

    private func mapConnectErrno(_ err: Int32) -> TransportError {
        switch err {
        case ENOENT: return .socketNotFound
        case EACCES, EPERM: return .permissionDenied
        case ECONNREFUSED: return .connectFailed(errno: err)
        default: return .connectFailed(errno: err)
        }
    }

    private func checkDeadline(_ deadline: ContinuousClock.Instant) throws {
        if ContinuousClock.now >= deadline { throw TransportError.timedOut }
    }

    /// One bounded poll() slice. Returns true when the fd became ready.
    /// Never blocks longer than ~50 ms, so cancellation is observed promptly
    /// and no other thread needs to touch the descriptor.
    private func pollOnce(fd: Int32, events: Int16, deadline: ContinuousClock.Instant, flag: CancelFlag) throws -> Bool {
        var pfd = pollfd(fd: fd, events: events, revents: 0)
        while true {
            if flag.isCancelled { throw TransportError.cancelled }
            try checkDeadline(deadline)
            let remaining = deadline - ContinuousClock.now
            let remainingMs = remaining.components.seconds * 1000
                + remaining.components.attoseconds / 1_000_000_000_000_000
            let sliceMs = Int32(clamping: min(Int64(50), max(1, remainingMs)))
            let result = poll(&pfd, 1, sliceMs)
            if result > 0 {
                if pfd.revents & Int16(POLLERR | POLLHUP | POLLNVAL) != 0 && pfd.revents & events == 0 {
                    throw TransportError.connectionClosed
                }
                return true
            }
            if result == 0 { continue } // slice elapsed; re-check cancel/deadline
            if errno == EINTR { continue }
            throw TransportError.connectFailed(errno: errno)
        }
    }
}
