import Foundation
import PortnameCore

/// Explicit maintenance actions against the already-installed daemon
/// LaunchAgent. Uses /bin/launchctl with a separate argument array and the
/// exact label + UID — never a shell string. Only reachable from the
/// settings window behind a confirmation dialog.
enum DaemonMaintenance {
    static let launchdLabel = "dev.portname.daemon"

    /// `launchctl kickstart -k gui/<uid>/dev.portname.daemon`
    /// Public shares die with the daemon restart — the UI must warn first.
    static func restartDaemon() throws {
        let uid = getuid()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["kickstart", "-k", "gui/\(uid)/\(launchdLabel)"]
        let stderrPipe = Pipe()
        process.standardOutput = Pipe()
        process.standardError = stderrPipe
        try process.run()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let stderrText = String(decoding: stderrData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            let reason = L10n.format("launchctl kickstart wurde mit Status %ld beendet%@. Ist der Hintergrunddienst über portname install eingerichtet?",
                                     process.terminationStatus, stderrText.isEmpty ? "" : ": " + stderrText)
            throw NSError(domain: "dev.portname.app.maintenance", code: Int(process.terminationStatus),
                          userInfo: [NSLocalizedDescriptionKey: reason])
        }
    }
}
