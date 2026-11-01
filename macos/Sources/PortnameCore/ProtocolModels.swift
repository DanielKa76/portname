import Foundation

// Codable models for the portname control protocol (see
// docs/control-protocol.md). Decoding is deliberately tolerant about
// *additive* unknown fields (JSONDecoder default) and about fields an older
// daemon does not send yet, but strict about the fields the UI needs.

public struct GatewayStatus: Codable, Equatable, Sendable {
    public var protocolVersion: Int?
    public var daemonInstanceId: String?
    public var proxyPort: Int
    public var bind: String
    public var lan: LANInfo?
    public var routes: [Route]
    public var stale: [StaleListener]
    public var exposed: [String]
    public var shares: [ShareStatus]
    /// Set when the last discovery scan failed: the routes shown are the
    /// previous scan's result and must be treated as possibly outdated.
    public var scanError: String?
    /// Build identity of the running daemon (package version and the Node.js
    /// runtime serving the gateway). Additive v1 fields; nil from older
    /// daemons. Display/diagnostics only.
    public var daemonVersion: String?
    public var runtimeVersion: String?

    /// True when the answering daemon predates protocol v1 (no
    /// protocolVersion field). Display works, guarded mutations must not be
    /// offered against it.
    ///
    /// Forward policy (docs/control-protocol.md, "Versioning"): protocol
    /// evolution is additive-only. Any non-nil version >= 1 is treated as
    /// compatible; a future daemon that breaks additivity must bump the
    /// version and v1 clients degrade by ignoring unknown fields/commands
    /// rather than misbehave.
    public var isLegacyDaemon: Bool { protocolVersion == nil }

    public func share(forName name: String) -> ShareStatus? {
        shares.first { $0.name == name }
    }
}

public struct LANInfo: Codable, Equatable, Sendable {
    public var available: Bool
    public var reason: String?
    /// BSD interface name of the selected LAN/Wi-Fi interface (e.g. "en0"),
    /// daemon v1.1+; nil from older daemons. Together with `address` it forms
    /// the network identity: when it changes between polls, the machine
    /// roamed and the UI must not keep claiming the same trusted Wi-Fi.
    public var interfaceName: String?
    /// LAN IPv4 address; display/identity use only, never shown as text.
    public var address: String?
    /// Current LAN subnet (e.g. "192.168.1.0/24"), comparable with
    /// `ExposureTarget.network`; nil when unknown or from older daemons.
    public var network: String?
}

/// The endpoint a WLAN exposure is bound to and the subnet it was confirmed
/// on (route field `exposureTarget`). Every field is optional: display
/// only, and a partial object must never break status decoding.
public struct ExposureTarget: Codable, Equatable, Sendable {
    public var port: Int?
    public var command: String?
    public var network: String?

    public init(port: Int? = nil, command: String? = nil, network: String? = nil) {
        self.port = port
        self.command = command
        self.network = network
    }
}

public struct RouteService: Codable, Equatable, Sendable, Identifiable {
    public var port: Int
    public var upstreamHost: String?
    public var command: String?
    public var pid: Int?
    public var processKey: String?
    public var since: Double?
    public var primary: Bool?
    /// Stable service identity: `<project root>#<port>` — project/worktree
    /// identity plus role (port), independent of the process generation.
    /// Daemon v1.1+; nil from older daemons.
    public var serviceId: String?
    /// True when this service belongs to another *living* process generation
    /// of the same project (frontend and backend as two PIDs are the normal
    /// case). Such services are valid, never "superseded". Daemon v1.1+.
    public var crossGeneration: Bool?

    public var id: String { "\(processKey ?? String(pid ?? -1)):\(port)" }
}

public struct Route: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var name: String
    public var revision: String?
    public var root: String?
    public var port: Int
    public var upstreamHost: String?
    public var pid: Int?
    public var processKey: String?
    public var external: Bool?
    public var command: String?
    public var cwd: String?
    public var since: Double?
    public var manual: Bool?
    public var localUrl: String?
    public var lanUrl: String?
    public var exposureRequested: Bool?
    /// The daemon's EFFECTIVE WLAN exposure ("active" / "paused" / "off"),
    /// derived from the same decision that gates gateway access — not from
    /// the desired flag alone. Daemon v1.x+; nil from older daemons (the UI
    /// then falls back to the legacy lanUrl-based display).
    public var exposureEffective: String?
    /// Why the effective exposure is "paused": "target-not-verified" (the
    /// gateway refuses requests until a fresh scan re-verifies the target),
    /// "target-unconfirmed" / "target-changed" / "network-changed" (refused
    /// until the user confirms the current endpoint or network with a new
    /// expose), "no-lan-interface" or "loopback-bind". New reasons are
    /// additive (see `ExposurePauseReason`). Daemon v1.x+; nil otherwise.
    public var exposurePauseReason: String?
    /// The endpoint and subnet the exposure was confirmed for; nil when no
    /// exposure is requested, none was confirmed yet, or from older daemons.
    public var exposureTarget: ExposureTarget?
    /// All usable listeners of the winning generation (frontend + backend is
    /// normal). Daemon v1.1+; nil from older daemons.
    public var services: [RouteService]?
    /// The stored per-root preference; nil when none is set.
    public var preferredPort: Int?
    /// The preference points at no living listener — the effective primary
    /// fell back to the default rule and the UI should say so.
    public var preferredMissing: Bool?

    public var isManual: Bool { root == nil }

    /// The WLAN wish is set but access is currently withheld (e.g. the
    /// target's verification went stale). Older daemons report no effective
    /// field — there the legacy lanUrl display applies unchanged.
    public var isExposurePaused: Bool { exposureEffective == "paused" }

    private enum CodingKeys: String, CodingKey {
        case id, name, revision, root, port, upstreamHost, pid, processKey
        case external, command, cwd, since, manual, localUrl, lanUrl, exposureRequested
        case exposureEffective, exposurePauseReason, exposureTarget
        case services, preferredPort, preferredMissing
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Protocol v1 carries a stable identity; a legacy daemon answers
        // without one — fall back to the (then-stable-per-run) name.
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? "legacy:\(try c.decode(String.self, forKey: .name))"
        name = try c.decode(String.self, forKey: .name)
        revision = try c.decodeIfPresent(String.self, forKey: .revision)
        root = try c.decodeIfPresent(String.self, forKey: .root)
        port = try c.decode(Int.self, forKey: .port)
        upstreamHost = try c.decodeIfPresent(String.self, forKey: .upstreamHost)
        pid = try c.decodeIfPresent(Int.self, forKey: .pid)
        processKey = try c.decodeIfPresent(String.self, forKey: .processKey)
        external = try c.decodeIfPresent(Bool.self, forKey: .external)
        command = try c.decodeIfPresent(String.self, forKey: .command)
        cwd = try c.decodeIfPresent(String.self, forKey: .cwd)
        since = try c.decodeIfPresent(Double.self, forKey: .since)
        manual = try c.decodeIfPresent(Bool.self, forKey: .manual)
        localUrl = try c.decodeIfPresent(String.self, forKey: .localUrl)
        lanUrl = try c.decodeIfPresent(String.self, forKey: .lanUrl)
        exposureRequested = try c.decodeIfPresent(Bool.self, forKey: .exposureRequested)
        exposureEffective = try c.decodeIfPresent(String.self, forKey: .exposureEffective)
        exposurePauseReason = try c.decodeIfPresent(String.self, forKey: .exposurePauseReason)
        exposureTarget = try c.decodeIfPresent(ExposureTarget.self, forKey: .exposureTarget)
        services = try c.decodeIfPresent([RouteService].self, forKey: .services)
        preferredPort = try c.decodeIfPresent(Int.self, forKey: .preferredPort)
        preferredMissing = try c.decodeIfPresent(Bool.self, forKey: .preferredMissing)
    }

    public init(id: String, name: String, revision: String? = nil, root: String? = nil, port: Int,
                upstreamHost: String? = nil, pid: Int? = nil, processKey: String? = nil,
                external: Bool? = nil, command: String? = nil, cwd: String? = nil, since: Double? = nil,
                manual: Bool? = nil, localUrl: String? = nil, lanUrl: String? = nil,
                exposureRequested: Bool? = nil, exposureEffective: String? = nil,
                exposurePauseReason: String? = nil, services: [RouteService]? = nil,
                preferredPort: Int? = nil, preferredMissing: Bool? = nil,
                exposureTarget: ExposureTarget? = nil) {
        self.id = id
        self.name = name
        self.revision = revision
        self.root = root
        self.port = port
        self.upstreamHost = upstreamHost
        self.pid = pid
        self.processKey = processKey
        self.external = external
        self.command = command
        self.cwd = cwd
        self.since = since
        self.manual = manual
        self.localUrl = localUrl
        self.lanUrl = lanUrl
        self.exposureRequested = exposureRequested
        self.exposureEffective = exposureEffective
        self.exposurePauseReason = exposurePauseReason
        self.services = services
        self.preferredPort = preferredPort
        self.preferredMissing = preferredMissing
        self.exposureTarget = exposureTarget
    }
}

public struct StaleListener: Codable, Equatable, Sendable, Identifiable {
    public var name: String
    public var port: Int
    public var upstreamHost: String?
    public var pid: Int?
    public var processKey: String?
    public var command: String?
    public var since: Double?
    /// Role identity `<project root>#<port>` of the superseded listener.
    /// Daemon v1.1+; nil from older daemons. Stale means genuinely replaced
    /// (same port/role in a newer generation) or diagnostic-only
    /// (inspector/debug) — never just "different PID".
    public var serviceId: String?

    public var id: String { "\(name):\(port):\(pid ?? -1)" }
}

public struct ShareStatus: Codable, Equatable, Sendable, Identifiable {
    public var name: String
    public var shareId: String?
    /// Public origin only — never contains the secret token.
    public var url: String?
    public var state: String
    /// Absolute expiry in unix milliseconds (daemon clock basis).
    public var expiresAt: Double?
    public var expired: Bool?
    public var ttlMinutes: Double?
    public var pinnedPort: Int?
    public var targetPort: Int?
    public var pinnedHost: String?
    public var targetHost: String?
    /// When a successful discovery pass last verified this share's binding
    /// (unix ms, daemon v1.1+); nil from older daemons. Shown as a small
    /// security detail explaining why the project is currently reachable.
    public var lastVerifiedAt: Double?

    public var id: String { shareId ?? "unidentified:\(name)" }

    public var phase: SharePhase { SharePhase(state) }
}

/// Strict share phase: an unknown state spelling must never be treated as
/// active. `STARTING` is never active either.
public enum SharePhase: Equatable, Sendable {
    case starting
    case active
    case stopping
    case stopped
    case unknown(String)

    public init(_ state: String) {
        switch state.uppercased() {
        case "STARTING": self = .starting
        case "ACTIVE": self = .active
        case "STOPPING": self = .stopping
        case "STOPPED": self = .stopped
        default: self = .unknown(state)
        }
    }

    public var isActiveShare: Bool {
        if case .active = self { return true }
        return false
    }
}

/// Response of the read-only `share-link` command — the only sanctioned way
/// for a running client to obtain the full secret link after creation.
public struct ShareLink: Codable, Equatable, Sendable {
    public var url: String
    public var expiresAt: Double
    public var shareId: String
}

public struct ShareStartResult: Codable, Equatable, Sendable {
    public var url: String
    public var expiresAt: Double
    public var ttlMinutes: Double?
    public var shareId: String?
}

/// Poll interval policy (start values, not performance promises).
public enum PollPolicy: Sendable {
    public static func intervalSeconds(panelVisible: Bool, hasActiveOrStartingShare: Bool) -> TimeInterval {
        if panelVisible { return 3 }
        return hasActiveOrStartingShare ? 5 : 15
    }
}
