import Foundation

/// Why the daemon pauses a requested WLAN exposure (`exposurePauseReason`,
/// docs/control-protocol.md). The daemon decides; the app only maps its
/// answer to wording and to the one action the protocol asks clients to
/// offer. Reasons are additive: an unknown spelling stays `.unknown` and
/// reads as "paused, reason unknown" — never as one of the known ones.
public enum ExposurePauseReason: Equatable, Sendable {
    case targetNotVerified
    case targetUnconfirmed
    case targetChanged
    case networkChanged
    case networkUnidentified
    case noLanInterface
    case loopbackBind
    case unknown(String)

    public init(_ raw: String) {
        switch raw {
        case "target-not-verified": self = .targetNotVerified
        case "target-unconfirmed": self = .targetUnconfirmed
        case "target-changed": self = .targetChanged
        case "network-changed": self = .networkChanged
        case "network-unidentified": self = .networkUnidentified
        case "no-lan-interface": self = .noLanInterface
        case "loopback-bind": self = .loopbackBind
        default: self = .unknown(raw)
        }
    }

    /// True for the pauses only a new `expose { on: true }` lifts: the
    /// daemon waits for the user to confirm the current endpoint (a wish
    /// stored by an older version, or a name that moved to another port or
    /// program) or the current network. Never for `target-not-verified`
    /// (the next fresh scan heals it; an activation is refused meanwhile),
    /// for `network-unidentified` (the router identification heals it; the
    /// daemon refuses a confirmation meanwhile), for the reasons without any
    /// WLAN path, or for an unknown reason.
    public var awaitsConfirmation: Bool {
        switch self {
        case .targetUnconfirmed, .targetChanged, .networkChanged:
            return true
        case .targetNotVerified, .networkUnidentified, .noLanInterface, .loopbackBind, .unknown:
            return false
        }
    }
}

extension Route {
    /// The reason of a paused exposure; nil unless the daemon reports the
    /// effective exposure as "paused". A pause without a reason counts as
    /// an unknown reason.
    public var pauseReason: ExposurePauseReason? {
        guard isExposurePaused else { return nil }
        return ExposurePauseReason(exposurePauseReason ?? "")
    }

    /// The exposure is still requested but paused until the user confirms
    /// it. `exposureRequested` stays true meanwhile, so a plain on/off
    /// toggle can only switch it off — the confirmation must be offered
    /// separately.
    public var awaitsExposureConfirmation: Bool {
        exposureRequested == true && pauseReason?.awaitsConfirmation == true
    }
}

/// Wording for a paused WLAN exposure, chosen by reason. Every text is a
/// literal at an `L10n` call site, so the table parity harness
/// (test/l10n-parity.test.js) covers it.
public enum ExposurePauseText {
    /// Tooltip of the "WLAN (pausiert)" badge.
    public static func badgeHelp(for reason: ExposurePauseReason) -> String {
        switch reason {
        case .targetNotVerified:
            return L10n.text("WLAN-Freigabe bleibt gewünscht, ist aber derzeit pausiert: Der Hintergrunddienst gewährt gerade keinen Zugriff (Ziel nicht frisch verifiziert). Das Beenden der Freigabe bleibt möglich.")
        case .targetUnconfirmed:
            return L10n.text("WLAN-Freigabe pausiert: Sie stammt aus einer älteren Version und ist noch an kein Ziel gebunden. Bitte einmal bestätigen.")
        case .targetChanged:
            return L10n.text("WLAN-Freigabe pausiert: Unter diesem Namen läuft jetzt ein anderer Dienst (anderer Port oder anderes Programm). Erst nach Bestätigung im WLAN erreichbar.")
        case .networkChanged:
            return L10n.text("WLAN-Freigabe pausiert: Sie wurde für ein anderes Netz bestätigt (anderes Subnetz oder anderer Router). Erst nach Bestätigung in diesem Netz erreichbar.")
        case .networkUnidentified:
            return L10n.text("WLAN-Freigabe pausiert: Der Router dieses Netzes ist noch nicht erkannt (z. B. kurz nach dem Aufwachen). Sobald der bestätigte Router erkannt ist, geht es von selbst weiter.")
        case .noLanInterface, .loopbackBind, .unknown:
            return L10n.text("WLAN-Freigabe bleibt gewünscht, ist aber derzeit pausiert: Der Hintergrunddienst gewährt gerade keinen Zugriff. Das Beenden der Freigabe bleibt möglich.")
        }
    }

    /// Row note for a paused exposure: names the endpoint a confirmation
    /// would expose (the route's own port and command) and what was
    /// confirmed before (`exposureTarget`), or the networks involved
    /// (`exposureTarget.network` vs. the current `lan.network`). Nil when
    /// the route is not paused, and for the reasons without any WLAN path —
    /// the row's network note covers those.
    public static func note(for route: Route, currentNetwork: String?) -> String? {
        guard let reason = route.pauseReason else { return nil }
        let unknownCommand = L10n.text("unbekannt")
        switch reason {
        case .targetNotVerified:
            return L10n.text("WLAN-Freigabe pausiert: Ziel nicht (mehr) verifiziert — Zugriff ist solange gesperrt. Sobald der Hintergrunddienst das Ziel wieder frisch sieht, greift die Freigabe erneut.")
        case .targetUnconfirmed:
            return L10n.format("WLAN-Freigabe pausiert: seit dem Update noch nicht bestätigt — Zugriff ist solange gesperrt. „WLAN-Freigabe bestätigen“ gibt :%ld (%@) im WLAN frei.",
                               route.port, route.command ?? unknownCommand)
        case .targetChanged:
            if let confirmedPort = route.exposureTarget?.port {
                return L10n.format("WLAN-Freigabe pausiert: Ziel geändert — bestätigt war :%ld (%@), jetzt :%ld (%@). „WLAN-Freigabe bestätigen“ gibt das neue Ziel frei.",
                                   confirmedPort, route.exposureTarget?.command ?? unknownCommand,
                                   route.port, route.command ?? unknownCommand)
            }
            return L10n.format("WLAN-Freigabe pausiert: Ziel geändert — jetzt :%ld (%@). „WLAN-Freigabe bestätigen“ gibt das neue Ziel frei.",
                               route.port, route.command ?? unknownCommand)
        case .networkChanged:
            guard let confirmedNetwork = route.exposureTarget?.network, let currentNetwork else {
                return L10n.text("WLAN-Freigabe pausiert: Sie wurde in einem anderen Netz bestätigt. Erst nach Bestätigung in diesem Netz erreichbar.")
            }
            if confirmedNetwork == currentNetwork {
                // Same subnet: the daemon identified a router other than the
                // confirmed one. A router it cannot identify right now is
                // "network-unidentified", never this reason — nothing here
                // heals by itself.
                return L10n.format("WLAN-Freigabe pausiert: gleicher Adressbereich (%@), aber ein anderer Router als bei der Bestätigung. Erst nach Bestätigung in diesem Netz erreichbar.",
                                   currentNetwork)
            }
            return L10n.format("WLAN-Freigabe pausiert: bestätigt im Netz %@, jetzt %@. Erst nach Bestätigung in diesem Netz erreichbar.",
                               confirmedNetwork, currentNetwork)
        case .networkUnidentified:
            return L10n.text("WLAN-Freigabe pausiert: Router noch nicht erkannt (z. B. kurz nach dem Aufwachen) — Zugriff ist solange gesperrt. Im bestätigten Netz geht es von selbst weiter, sobald der Router erkannt ist.")
        case .noLanInterface, .loopbackBind:
            return nil
        case .unknown:
            return L10n.text("WLAN-Freigabe pausiert — der Hintergrunddienst gewährt derzeit keinen WLAN-Zugriff.")
        }
    }
}
