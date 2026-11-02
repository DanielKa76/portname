import SwiftUI
import PortnameCore

/// Public share dialog. A conscious action — never a plain switch. States:
/// not shared (creation form), starting, active (copy/open/stop),
/// expired, and error/unclear. The secret link is fetched on demand via
/// the read-only `share-link` command for explicit copy/open only; it is
/// never displayed or stored in full.
struct ShareView: View {
    let model: AppModel
    let route: Route
    let done: () -> Void

    @State private var ttlMinutes: Double = 60
    @State private var working = false
    @State private var confirmStop = false
    @State private var copiedFlash = false

    /// Default TTL choices (backend contract stays 0.1–1440 min).
    private let ttlChoices: [(label: String, minutes: Double)] = [
        ("15 Min", 15), ("1 Std", 60), ("3 Std", 180), ("24 Std", 1440),
    ]
    // ("15 Min" etc. are translated through the L10n table at render time.)

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Button {
                    done()
                } label: {
                    Image(systemName: "chevron.left")
                }
                .buttonStyle(.plain)
                .accessibilityLabel(L10n.text("Zurück"))
                Text(L10n.format("Öffentlicher Link für „%@“", route.name))
                    .font(.headline)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            if let share = model.share(for: route) {
                stateView(share)
            } else {
                creationForm
            }

            if let feedback = model.feedback, feedback.routeID == route.id {
                FeedbackLine(text: feedback.text, kind: feedback.kind, onDismiss: { model.dismissFeedback() })
            }
        }
    }

    // MARK: - Creation form (no share)

    private var creationForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(L10n.text("Jeder mit diesem Link kann auf diesen Entwicklungsserver zugreifen. Nur für Demos, nicht für sensible Daten."),
                  systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .padding(8)
                .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 7))

            VStack(alignment: .leading, spacing: 4) {
                Text(L10n.text("Läuft ab nach:"))
                    .font(.callout)
                Picker(L10n.text("Laufzeit"), selection: $ttlMinutes) {
                    ForEach(ttlChoices, id: \.minutes) { choice in
                        Text(L10n.text(choice.label)).tag(choice.minutes)
                    }
                }
                .pickerStyle(.segmented)
                .accessibilityLabel(L10n.text("Gültigkeitsdauer des öffentlichen Links"))
            }

            if route.external == true {
                Label(L10n.text("Dieser Server lauscht bereits selbst auf anderen Netzwerkschnittstellen. Portname kann das nicht abschalten."),
                      systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Text(L10n.text("Quick Tunnels von Cloudflare bleiben Demo-Technik: kein SLA, keine SSE-Garantie. Beendet wird der Link, sobald du ihn stoppst, der Server verschwindet oder der Ziel-Port wechselt."))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Spacer()
                Button(L10n.text("Abbrechen")) { done() }
                Button {
                    createShare()
                } label: {
                    if working {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.mini)
                            Text(L10n.text("Wird erstellt …"))
                        }
                    } else {
                        Text(L10n.text("Link erstellen"))
                    }
                }
                .disabled(working || model.mutationsLocked)
                .keyboardShortcut(.defaultAction)
            }
        }
    }

    // MARK: - Existing share states

    @ViewBuilder
    private func stateView(_ share: ShareStatus) -> some View {
        switch share.phase {
        case .starting where share.expired != true:
            startingView
        case .active where share.expired != true:
            activeView(share)
        case .stopping:
            Label("Freigabe wird beendet …", systemImage: "hourglass")
                .foregroundStyle(.secondary)
        case .unknown(let raw):
            unknownStateView(raw)
        default:
            expiredView
        }
    }

    private func unknownStateView(_ raw: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(L10n.format("Der Hintergrunddienst meldet einen unbekannten Freigabe-Status (%@). Bitte Liste aktualisieren — es wird kein Link angezeigt, solange der Zustand unklar ist.", raw),
                  systemImage: "questionmark.circle")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button(L10n.text("Liste aktualisieren")) {
                    Task { await model.refreshNow() }
                }
            }
        }
    }

    private var startingView: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                Text(L10n.text("Öffentlicher Link wird erstellt … Das dauert bis zu einer Minute."))
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(L10n.text("Dieses Fenster schließen oder die App beenden bricht den Vorgang nicht ab."))
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Spacer()
                Button(L10n.text("Abbrechen")) { done() }
                Button(L10n.text("Freigabe beenden"), role: .destructive) {
                    Task {
                        if let current = await model.currentRoute(for: route) {
                            _ = await model.stopShare(route: current)
                        }
                    }
                }
                .disabled(working || model.mutationsLocked || model.inFlightIDs.contains(route.id))
            }
        }
    }

    private func activeView(_ share: ShareStatus) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(L10n.text("Öffentliche Adresse (nur dieses Muster — der vollständige geheime Link wird erst beim Kopieren/Öffnen geholt):"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let origin = share.url {
                    Text(origin + "/…/")
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                ShareCountdownBadge(model: model, share: share)
                    .font(.caption)
                // Small security detail: WHY this project is currently
                // reachable — the last discovery pass that verified the
                // binding (port, host, process generation).
                if let verified = share.lastVerifiedAt {
                    Text(L10n.format("Ziel zuletzt verifiziert vor %ld s.", max(0, Int(Date().timeIntervalSince1970 - verified / 1000))))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            if copiedFlash {
                Label(L10n.text("Link in die Zwischenablage kopiert."), systemImage: "checkmark.circle")
                    .font(.callout)
                    .foregroundStyle(.green)
            }

            HStack {
                Button {
                    copyLink()
                } label: {
                    Label(L10n.text("Öffentlichen Link kopieren"), systemImage: "doc.on.doc")
                }
                .keyboardShortcut(.defaultAction)
                .disabled(working || model.mutationsLocked)
                Button {
                    Task {
                        if let current = await model.currentRoute(for: route) {
                            _ = await model.openShareLink(for: current)
                        }
                    }
                } label: {
                    Label(L10n.text("Im Browser öffnen"), systemImage: "safari")
                }
                .disabled(working || model.mutationsLocked || model.inFlightIDs.contains(route.id))
                Spacer()
            }

            HStack {
                Spacer()
                if confirmStop {
                    Text(L10n.text("Öffentlichen Link jetzt beenden? Aktive Besucher werden sofort getrennt."))
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Button(L10n.text("Wirklich beenden"), role: .destructive) {
                        confirmStop = false
                        Task {
                            if let current = await model.currentRoute(for: route) {
                                _ = await model.stopShare(route: current)
                            }
                        }
                    }
                    .disabled(working || model.mutationsLocked || model.inFlightIDs.contains(route.id))
                    Button(L10n.text("Nicht beenden"), role: .cancel) { confirmStop = false }
                } else {
                    Button(L10n.text("Freigabe beenden …"), role: .destructive) { confirmStop = true }
                        .disabled(working || model.mutationsLocked || model.inFlightIDs.contains(route.id))
                }
            }
        }
    }

    private var expiredView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(L10n.text("Der öffentliche Link für dieses Projekt ist abgelaufen oder beendet."),
                  systemImage: "clock.badge.exclamationmark")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button(L10n.text("Neuen Link erstellen")) {
                    // A conscious new action: this can revoke what the daemon
                    // still lists (the daemon replaces/renews the instance).
                    createShare()
                }
                .disabled(working)
            }
        }
    }

    // MARK: - Actions

    private func createShare() {
        guard !working else { return }
        working = true
        Task {
            guard let current = await model.currentRoute(for: route) else {
                working = false
                done()
                return
            }
            let outcome = await model.startShare(route: current, ttlMinutes: ttlMinutes)
            working = false
            if outcome == .success {
                // Status refreshed by the model; the dialog switches to the
                // active view. The secret URL from the response was dropped.
                copiedFlash = false
            }
        }
    }

    private func copyLink() {
        Task {
            guard let current = await model.currentRoute(for: route) else { return }
            let outcome = await model.copyShareLink(for: current)
            if outcome == .success {
                copiedFlash = true
                Task {
                    try? await Task.sleep(nanoseconds: 2_500_000_000)
                    copiedFlash = false
                }
            }
        }
    }
}
