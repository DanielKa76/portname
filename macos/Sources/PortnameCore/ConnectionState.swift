import Foundation

/// High-level connection state shown in the UI. An unreachable control
/// socket is NOT an empty project list — the last snapshot is kept and
/// marked stale.
public enum ConnectionState: Equatable, Sendable {
    case connecting
    case connected
    /// Socket missing, refused, permission denied or timed out.
    case unreachable
    /// Daemon answered but without a protocolVersion: needs a daemon update.
    case incompatibleProtocol
}
