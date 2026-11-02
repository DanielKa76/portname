import Foundation

/// First-run setup of the background service from the menubar panel.
///
/// The self-contained app carries the CLI in
/// `Contents/Resources/bin/portname-cli`. A downloaded app used to need one
/// Terminal command (`portname-cli install`) before the panel showed
/// anything; the panel now offers the same command as a button.
///
/// The offer exists only while no LaunchAgent is installed. With an agent in
/// place, an unreachable daemon is a different problem (stopped, crashed,
/// mid-update), and re-running install from the app could re-point a
/// developer's agent at the bundle, so the panel keeps its diagnosis text.
/// Developer builds without a bundled CLI never offer setup.
public enum ServiceSetup {
    /// Where `portname install` writes the agent, relative to the home folder.
    public static let agentPlistRelativePath = "Library/LaunchAgents/dev.portname.daemon.plist"
    /// The CLI wrapper inside `Contents/Resources` of the self-contained app.
    public static let bundledCLIRelativePath = "bin/portname-cli"

    /// The bundled CLI the panel may run, or nil when it must not offer setup.
    public static func setupCLI(resourcesPath: String?,
                                homeDirectory: String,
                                fileExists: (String) -> Bool,
                                isExecutable: (String) -> Bool) -> String? {
        guard let resourcesPath, !resourcesPath.isEmpty, !homeDirectory.isEmpty else { return nil }
        let cli = (resourcesPath as NSString).appendingPathComponent(bundledCLIRelativePath)
        guard isExecutable(cli) else { return nil }
        let agent = (homeDirectory as NSString).appendingPathComponent(agentPlistRelativePath)
        return fileExists(agent) ? nil : cli
    }

    /// Longest reason the panel shows for a failed setup.
    static let maxReasonLength = 300

    /// A short reason from a failed install's combined output: the last
    /// non-empty line (the CLI prints `portname: <message>` there), bounded
    /// so a stack trace cannot flood the panel. Without output, the exit
    /// status is the reason.
    public static func failureReason(output: String, status: Int32) -> String {
        let last = output
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .last { !$0.isEmpty }
        guard let last else {
            return L10n.format("portname-cli install wurde mit Status %ld beendet.", Int(status))
        }
        guard last.count > maxReasonLength else { return last }
        return String(last.prefix(maxReasonLength - 1)) + "…"
    }
}
