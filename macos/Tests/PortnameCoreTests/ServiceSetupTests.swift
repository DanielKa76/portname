import XCTest
@testable import PortnameCore

/// First-run setup offer, its failure wording, and count wording.
@MainActor
final class ServiceSetupTests: XCTestCase {

    override func tearDown() {
        L10n.forcedLocalization = nil
        super.tearDown()
    }

    private let resources = "/Applications/Portname.app/Contents/Resources"
    private let home = "/Users/demo"
    private var cli: String { resources + "/bin/portname-cli" }
    private var agent: String { home + "/Library/LaunchAgents/dev.portname.daemon.plist" }

    // MARK: - Setup offer

    func testSetupIsOfferedWithABundledCLIAndNoAgent() {
        let offered = ServiceSetup.setupCLI(resourcesPath: resources, homeDirectory: home,
                                            fileExists: { _ in false },
                                            isExecutable: { $0 == self.cli })
        XCTAssertEqual(offered, cli)
    }

    func testNoSetupOnceAnAgentExists() {
        // An unreachable daemon with an agent in place is a different
        // problem; re-running install could re-point a developer's agent.
        let offered = ServiceSetup.setupCLI(resourcesPath: resources, homeDirectory: home,
                                            fileExists: { $0 == self.agent },
                                            isExecutable: { $0 == self.cli })
        XCTAssertNil(offered)
    }

    func testNoSetupWithoutABundledCLI() {
        // Developer builds carry no CLI in their resources.
        XCTAssertNil(ServiceSetup.setupCLI(resourcesPath: resources, homeDirectory: home,
                                           fileExists: { _ in false }, isExecutable: { _ in false }))
        XCTAssertNil(ServiceSetup.setupCLI(resourcesPath: nil, homeDirectory: home,
                                           fileExists: { _ in false }, isExecutable: { _ in true }))
        XCTAssertNil(ServiceSetup.setupCLI(resourcesPath: resources, homeDirectory: "",
                                           fileExists: { _ in false }, isExecutable: { _ in true }))
    }

    // MARK: - Failure wording

    func testFailureReasonIsTheLastNonEmptyLine() {
        let output = "Installed background service payload to /x\n\nportname: launchctl bootstrap failed: 5\n  \n"
        XCTAssertEqual(ServiceSetup.failureReason(output: output, status: 1),
                       "portname: launchctl bootstrap failed: 5")
    }

    func testFailureReasonWithoutOutputNamesTheStatus() {
        L10n.forcedLocalization = "en"
        XCTAssertEqual(ServiceSetup.failureReason(output: " \n", status: 3),
                       "portname-cli install exited with status 3.")
    }

    func testFailureReasonIsBounded() {
        let reason = ServiceSetup.failureReason(output: String(repeating: "x", count: 2000), status: 1)
        XCTAssertEqual(reason.count, ServiceSetup.maxReasonLength)
        XCTAssertTrue(reason.hasSuffix("…"))
    }

    // MARK: - Count wording

    func testCountWordingDistinguishesOneFromMany() {
        L10n.forcedLocalization = "en"
        XCTAssertEqual(L10n.plural(1, one: "1 Projekt · Hintergrunddienst verbunden",
                                   other: "%ld Projekte · Hintergrunddienst verbunden"),
                       "1 project · daemon connected")
        XCTAssertEqual(L10n.plural(4, one: "1 Projekt · Hintergrunddienst verbunden",
                                   other: "%ld Projekte · Hintergrunddienst verbunden"),
                       "4 projects · daemon connected")
        XCTAssertEqual(L10n.plural(1, one: "„App beenden“ schließt nur die Oberfläche: Hintergrunddienst und öffentlicher Link laufen weiter.",
                                   other: "„App beenden“ schließt nur die Oberfläche: Hintergrunddienst und %ld öffentliche Links laufen weiter."),
                       "“Quit App” closes only this UI: the daemon and the public link keep running.")
        L10n.forcedLocalization = "de"
        XCTAssertEqual(L10n.plural(1, one: "Diagnose · 1 Eintrag", other: "Diagnose · %ld Einträge"),
                       "Diagnose · 1 Eintrag")
        XCTAssertEqual(L10n.plural(2, one: "Diagnose · 1 Eintrag", other: "Diagnose · %ld Einträge"),
                       "Diagnose · 2 Einträge")
    }
}
