import Foundation

/// Resolves the control socket path. Production always trusts the socket in
/// the user's portname directory — no persisted preference can redirect the
/// production app to another IPC endpoint. Intentional development starts
/// use the PORTNAME_SOCKET environment variable; the UserDefaults override
/// (`defaults write dev.portname.app socketPath`) exists in DEBUG builds
/// only, and tests inject the path via dependency injection anyway.
enum SocketPathResolver {
    static func userSocketPath(defaults: UserDefaults = .standard) -> String {
        #if DEBUG
        if let custom = defaults.string(forKey: "socketPath"), !custom.isEmpty {
            return custom
        }
        #endif
        // Explicit opt-in for test launches; Finder/launchd environments do
        // not carry this variable.
        if let env = ProcessInfo.processInfo.environment["PORTNAME_SOCKET"], !env.isEmpty {
            return env
        }
        let dir = ProcessInfo.processInfo.environment["HOME"]
            .map { ($0 as NSString).expandingTildeInPath } ?? NSHomeDirectory()
        return (dir as NSString).appendingPathComponent(".portname/daemon.sock")
    }
}
