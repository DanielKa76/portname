import Foundation

/// A failed control command. `code` is the stable machine-readable code from
/// docs/control-protocol.md (may be nil for legacy error answers); `message`
/// keeps the daemon's human-readable legacy `error` text.
public struct ControlError: Error, Sendable, Equatable {
    public let code: String?
    public let message: String

    public init(code: String?, message: String) {
        self.code = code
        self.message = message
    }

    public var errorDescription: String? { message }

    public var isStaleTarget: Bool { code == "STALE_TARGET" }
}

public protocol DaemonAPI: Sendable {
    func status() async throws -> GatewayStatus
    func rename(name: String, newName: String, expectedRouteRevision: String?) async throws
    func add(name: String, port: Int, createOnly: Bool) async throws
    func remove(name: String, expectedRouteRevision: String?) async throws
    func expose(name: String, on: Bool, expectedRouteRevision: String?) async throws
    func setPrimary(name: String, port: Int, expectedRouteRevision: String?) async throws
    func share(name: String, ttlMinutes: Double, expectedRouteRevision: String?) async throws -> ShareStartResult
    func unshare(name: String, expectedShareId: String?, expectedRouteRevision: String?) async throws
    func shareLink(name: String, expectedShareId: String) async throws -> ShareLink
    /// Revokes every live public link via the daemon's additive
    /// `unshare-all` command. Returns the revoked names.
    func revokeAllShares() async throws -> [String]
}

/// Request deadlines (start values).
public enum ControlTimeouts: Sendable {
    /// Ordinary requests get a total deadline of 5 s.
    public static let standard: TimeInterval = 5
    /// Share creation may legitimately take up to a minute (tunnel setup).
    public static let share: TimeInterval = 60
    /// Switching a WLAN exposure answers only after a discovery pass, and
    /// switching it on first looks up the current router (bounded, once
    /// more after a DHCP renewal): together more than the standard deadline
    /// allows, which would turn an answer that is merely late into an
    /// unclear outcome.
    public static let expose: TimeInterval = 20
}

/// Typed client for the portname control socket. The GUI always sends the
/// expectation fields (`expectedRouteRevision` / `expectedShareId`) so the
/// daemon can reject stale targets; the legacy CLI keeps sending neither.
public struct DaemonClient: DaemonAPI {
    private let transport: UnixSocketTransport
    private let encoder: JSONEncoder

    public init(socketPath: String) {
        self.transport = UnixSocketTransport(socketPath: socketPath)
        self.encoder = JSONEncoder()
    }

    public init(transport: UnixSocketTransport) {
        self.transport = transport
        self.encoder = JSONEncoder()
    }

    // MARK: - Request plumbing

    private struct Envelope: Decodable {
        let ok: Bool
        let error: String?
        let code: String?
    }

    private func dispatch(_ payload: Data, timeout: TimeInterval) async throws -> Data {
        let line = try await transport.sendLine(payload, timeout: timeout)
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: line) else {
            throw TransportError.badResponse
        }
        guard envelope.ok else {
            throw ControlError(code: envelope.code, message: envelope.error ?? L10n.text("unbekannter Fehler"))
        }
        return line
    }

    private func request<T: Decodable>(_ payload: Data, timeout: TimeInterval, as type: T.Type) async throws -> T {
        let line = try await dispatch(payload, timeout: timeout)
        do {
            return try JSONDecoder().decode(T.self, from: line)
        } catch {
            throw TransportError.badResponse
        }
    }

    private func encoded(_ object: some Encodable) -> Data {
        // Internal construction only; encoding of our own request types
        // cannot fail, so trapping here is acceptable and keeps call sites
        // free of impossible error handling.
        try! encoder.encode(object)
    }

    private struct StatusRequest: Encodable { let cmd = "status" }

    public func status() async throws -> GatewayStatus {
        try await request(encoded(StatusRequest()), timeout: ControlTimeouts.standard, as: GatewayStatus.self)
    }

    private struct RenameRequest: Encodable {
        let cmd = "rename"
        let name: String
        let newName: String
        var expectedRouteRevision: String?
    }

    public func rename(name: String, newName: String, expectedRouteRevision: String?) async throws {
        _ = try await dispatch(encoded(RenameRequest(name: name, newName: newName, expectedRouteRevision: expectedRouteRevision)),
                         timeout: ControlTimeouts.standard)
    }

    private struct AddRequest: Encodable {
        let cmd = "add"
        let name: String
        let port: Int
        var createOnly: Bool?
    }

    public func add(name: String, port: Int, createOnly: Bool) async throws {
        _ = try await dispatch(encoded(AddRequest(name: name, port: port, createOnly: createOnly)),
                         timeout: ControlTimeouts.standard)
    }

    private struct RemoveRequest: Encodable {
        let cmd = "remove"
        let name: String
        var expectedRouteRevision: String?
    }

    public func remove(name: String, expectedRouteRevision: String?) async throws {
        _ = try await dispatch(encoded(RemoveRequest(name: name, expectedRouteRevision: expectedRouteRevision)),
                         timeout: ControlTimeouts.standard)
    }

    private struct ExposeRequest: Encodable {
        let cmd = "expose"
        let name: String
        let on: Bool
        var expectedRouteRevision: String?
    }

    public func expose(name: String, on: Bool, expectedRouteRevision: String?) async throws {
        _ = try await dispatch(encoded(ExposeRequest(name: name, on: on, expectedRouteRevision: expectedRouteRevision)),
                         timeout: ControlTimeouts.expose)
    }

    private struct SetPrimaryRequest: Encodable {
        let cmd = "set-primary"
        let name: String
        let port: Int
        var expectedRouteRevision: String?
    }

    public func setPrimary(name: String, port: Int, expectedRouteRevision: String?) async throws {
        _ = try await dispatch(encoded(SetPrimaryRequest(name: name, port: port, expectedRouteRevision: expectedRouteRevision)),
                         timeout: ControlTimeouts.standard)
    }

    private struct ShareRequest: Encodable {
        let cmd = "share"
        let name: String
        let ttlMinutes: Double
        var expectedRouteRevision: String?
    }

    public func share(name: String, ttlMinutes: Double, expectedRouteRevision: String?) async throws -> ShareStartResult {
        try await request(encoded(ShareRequest(name: name, ttlMinutes: ttlMinutes, expectedRouteRevision: expectedRouteRevision)),
                    timeout: ControlTimeouts.share,
                    as: ShareStartResult.self)
    }

    private struct UnshareRequest: Encodable {
        let cmd = "unshare"
        let name: String
        var expectedShareId: String?
        var expectedRouteRevision: String?
    }

    public func unshare(name: String, expectedShareId: String?, expectedRouteRevision: String?) async throws {
        _ = try await dispatch(encoded(UnshareRequest(name: name, expectedShareId: expectedShareId, expectedRouteRevision: expectedRouteRevision)),
                         timeout: ControlTimeouts.standard)
    }

    private struct ShareLinkRequest: Encodable {
        let cmd = "share-link"
        let name: String
        let expectedShareId: String
    }

    public func shareLink(name: String, expectedShareId: String) async throws -> ShareLink {
        try await request(encoded(ShareLinkRequest(name: name, expectedShareId: expectedShareId)),
                    timeout: ControlTimeouts.standard,
                    as: ShareLink.self)
    }

    /// Response of the additive `unshare-all` command (daemon v1.1+): the
    /// names revoked by this call.
    private struct UnshareAllResult: Decodable {
        let stopped: [String]
    }

    private struct UnshareAllRequest: Encodable {
        let cmd = "unshare-all"
    }

    public func revokeAllShares() async throws -> [String] {
        // A global revoke may tear down several tunnels — each stop is
        // bounded, but the sum can take a while; use the share deadline.
        try await request(encoded(UnshareAllRequest()),
                    timeout: ControlTimeouts.share,
                    as: UnshareAllResult.self).stopped
    }
}
