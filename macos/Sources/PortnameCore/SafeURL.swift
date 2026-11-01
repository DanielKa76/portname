import Foundation

/// Validation for URLs that cross from daemon data to NSWorkspace. Only
/// expected shapes pass: plain `http` to `<label>.localhost` /
/// `<label>.local`, or `https` to the exact expected tunnel host. Anything
/// else (file:, javascript:, credentials in the authority, ports that do not
/// belong, embedded hosts) is refused — daemon data is data, not commands.
public enum SafeURL {
    public static let localHostSuffixes = [".localhost", ".local"]

    /// Mirrors lib/urls.js: `http://<name>.localhost/` at gateway port 80,
    /// `http://<name>.localhost:<port>/` otherwise. Only used as fallback
    /// when a (legacy) daemon did not send `localUrl`.
    public static func localURLString(name: String, gatewayPort: Int) -> String? {
        guard isPlainLabel(Substring(name.lowercased())) else { return nil }
        let unlabeled = gatewayPort == 80 || gatewayPort == 0
        let host = unlabeled ? "\(name).localhost" : "\(name).localhost:\(gatewayPort)"
        return "http://\(host)/"
    }

    /// `true` for a single DNS label of `[a-z0-9-]` (empty refused).
    static func isPlainLabel(_ label: Substring) -> Bool {
        !label.isEmpty
            && label.allSatisfy { ($0 >= "a" && $0 <= "z") || ($0 >= "0" && $0 <= "9") || $0 == "-" }
    }

    /// A local browser address: http, no credentials, host is exactly one
    /// label plus `.localhost`/`.local`. Loopback-bind URLs carry the
    /// gateway port; any port is accepted here, the daemon built it.
    public static func localBrowserURL(_ string: String) -> URL? {
        guard let url = URL(string: string),
              url.scheme?.lowercased() == "http",
              url.user == nil, url.password == nil,
              let host = url.host?.lowercased() else { return nil }

        for suffix in localHostSuffixes {
            if host.hasSuffix(suffix) {
                if isPlainLabel(host.dropLast(suffix.count)) {
                    return url
                }
            }
        }
        return nil
    }

    /// A public share address: https to the exact expected tunnel origin
    /// (the host the daemon already showed in status), no credentials, no
    /// exotic port.
    public static func shareURL(_ string: String, expectedOriginHost: String) -> URL? {
        guard let url = URL(string: string),
              url.scheme?.lowercased() == "https",
              url.user == nil, url.password == nil,
              let host = url.host?.lowercased(),
              host == expectedOriginHost.lowercased(),
              url.port == nil || url.port == 443 else { return nil }
        return url
    }

    /// A local directory path for Finder reveal: absolute, existing, no
    /// funny business.
    public static func localDirectory(_ path: String) -> String? {
        guard path.hasPrefix("/") else { return nil }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
              isDirectory.boolValue else { return nil }
        return path
    }
}
