import Foundation
import PortnameCore

/// Runs the bundled `portname-cli install` for the panel's first-run setup
/// (see ``ServiceSetup``). A fixed executable with an argument array, never
/// a shell string; it runs as the user, like the Terminal command it
/// replaces, and needs no admin password.
enum BackgroundServiceSetup {
    /// The CLI to run when the panel may offer setup, else nil.
    static func offeredCLI() -> String? {
        let home = ProcessInfo.processInfo.environment["HOME"]
            .map { ($0 as NSString).expandingTildeInPath } ?? NSHomeDirectory()
        let files = FileManager.default
        return ServiceSetup.setupCLI(resourcesPath: Bundle.main.resourcePath,
                                     homeDirectory: home,
                                     fileExists: { files.fileExists(atPath: $0) },
                                     isExecutable: { files.isExecutableFile(atPath: $0) })
    }

    /// Runs `install` off the main actor. Returns nil on success, otherwise
    /// a short reason for the panel.
    static func install(cli: String) async -> String? {
        await Task.detached(priority: .userInitiated) { () -> String? in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: cli)
            process.arguments = ["install"]
            let output = Pipe()
            process.standardOutput = output
            process.standardError = output
            process.standardInput = FileHandle.nullDevice
            do {
                try process.run()
            } catch {
                return error.localizedDescription
            }
            // Read to EOF before waiting: a full pipe would otherwise block
            // the child. The daemon itself is started by launchd, not as a
            // child, so it never holds this pipe open.
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                return ServiceSetup.failureReason(output: String(decoding: data, as: UTF8.self),
                                                  status: process.terminationStatus)
            }
            return nil
        }.value
    }
}
