import SwiftUI
import PortnameCore

/// One project row: name, reachability badges, browser URL and the three
/// row actions (open, copy, menu). States are never signalled by color
/// alone — every badge carries text or an icon.
struct ProjectRow: View {
    let model: AppModel
    let route: Route
    var isSelected: Bool = false
    let onRename: () -> Void
    let onShare: () -> Void

    @State private var copiedLocalURL = false
    @State private var showRemoveConfirm = false

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(route.name)
                    .font(.system(size: 13, weight: .medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(route.root ?? route.name)
                badges
                Spacer()
                actionButtons
            }

            if displayURL != nil {
                HStack(spacing: 6) {
                    // Compact single-line address: no scheme/trailing slash in
                    // display (copy/open still use the full validated URL),
                    // plus the actual target port — that is what tells
                    // frontend from backend.
                    Text(verbatim: displayAddress)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(isSelected ? Color.primary.opacity(0.8) : Color.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    if serviceSummary != nil {
                        Text(verbatim: serviceSummary!)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if copiedLocalURL {
                        Label(L10n.text("Kopiert"), systemImage: "checkmark")
                            .font(.caption)
                            .foregroundStyle(.green)
                            .transition(.opacity)
                    }
                    Spacer(minLength: 0)
                }
            }

            if route.preferredMissing == true {
                Label(L10n.text("Der gewählte Hauptdienst läuft nicht mehr — es wird wieder der neueste Server verwendet."),
                      systemImage: "questionmark.square.dashed")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if route.external == true {
                Label(L10n.text("⚠ Server bindet auch außerhalb von localhost"),
                      systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .help(L10n.text("Portname steuert nur seine eigenen Freigaben. Dass dieser Server direkt aus dem Netzwerk erreichbar ist, wird dadurch nicht abgeschaltet — und ist auch kein erfolgreicher Erreichbarkeitstest von einem anderen Gerät."))
            }

            if let lanNote = lanNote {
                Label(lanNote, systemImage: "wifi.exclamationmark")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let actionError = model.feedback, actionError.routeID == route.id {
                FeedbackLine(text: actionError.text, kind: actionError.kind, onDismiss: { model.dismissFeedback() })
            }

            if let pending = model.pendingReconciliation(for: route.id) {
                HStack(spacing: 6) {
                    if pending.unresolved {
                        Label(L10n.format("Ausgang unklar — aktuellen Zustand bitte prüfen. Letzte Aktion: „%@“.", pending.operation),
                              systemImage: "exclamationmark.circle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    } else {
                        Label(L10n.format("Ergebnis wird geprüft — die letzte Aktion („%@“) ist möglicherweise trotzdem ausgeführt.", pending.operation),
                              systemImage: "questionmark.circle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                    Button(L10n.text("Liste aktualisieren")) {
                        // Never clears the marker itself: only a successful
                        // poll that reconciles the expectation may do that.
                        Task { await model.refreshNow() }
                    }
                    .buttonStyle(.plain)
                    .font(.caption)
                }
                .fixedSize(horizontal: false, vertical: true)
            }

            if showRemoveConfirm {
                HStack(spacing: 8) {
                    Text(L10n.format("Manuelle Zuordnung „%@“ entfernen? (Stoppt keine fremden Server, löscht keine Dateien.)", route.name))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                HStack {
                    Button(L10n.text("Entfernen"), role: .destructive) {
                        showRemoveConfirm = false
                        Task {
                            if let current = await model.currentRoute(for: route) {
                                _ = await model.removeRoute(current)
                            }
                        }
                    }
                    .controlSize(.small)
                    Button(L10n.text("Abbrechen"), role: .cancel) { showRemoveConfirm = false }
                        .controlSize(.small)
                }
            }
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 4)
        .background(isSelected ? Color.accentColor.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
        .contentShape(Rectangle())
        .contextMenu {
            ProjectActionsMenu(model: model, route: route,
                               onRename: onRename, onShare: onShare,
                               onRemoveAsk: { showRemoveConfirm = true })
        }
    }

    private var displayURL: String? {
        route.localUrl ?? SafeURL.localURLString(name: route.name, gatewayPort: model.status?.proxyPort ?? 80)
    }

    /// Compact address without scheme and trailing slash, e.g.
    /// `shop.localhost:7777` — verbatim, never locale-formatted.
    private var displayAddress: String {
        if let urlString = displayURL, let url = URL(string: urlString) {
            return url.host ?? urlString
        }
        return displayURL ?? ""
    }

    /// Right-hand service hint: the effective target port and — when the
    /// daemon reports more than one — the number of living services.
    private var serviceSummary: String? {
        if route.isManual { return nil }
        let count = route.services?.count ?? 0
        let extra = count > 1 ? L10n.format(" · %ld Dienste", count) : ""
        return L10n.format("→ :%ld", route.port) + extra
    }

    // MARK: - Badges

    @ViewBuilder
    private var badges: some View {
        HStack(spacing: 4) {
            if let share = model.share(for: route) {
                switch share.phase {
                case .active where share.expired != true:
                    ShareCountdownBadge(model: model, share: share)
                case .starting:
                    Label(L10n.text("Wird erstellt …"), systemImage: "hourglass")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .help(L10n.text("Öffentlicher Link wird erstellt. Das dauert bis zu einer Minute."))
                case .active, .stopping, .stopped, .unknown:
                    // expired or transitional — shown as expired note below
                    EmptyView()
                }
            }
            if route.lanUrl != nil {
                if let pauseReason = route.pauseReason {
                    Label(L10n.text("WLAN (pausiert)"), systemImage: "wifi.slash")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .help(ExposurePauseText.badgeHelp(for: pauseReason))
                } else {
                    Label(L10n.text("WLAN"), systemImage: "wifi")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .help(L10n.format("Freigegeben im lokalen Netz: %@", route.lanUrl ?? ""))
                }
            }
        }
    }

    private var lanNote: String? {
        // Paused with a still-advertised address: the note names the reason
        // — a stale verification heals by itself, a moved target or another
        // network waits for the user's confirmation (actions menu). The
        // reasons without any WLAN path — no interface / loopback — have no
        // lanUrl and fall through to the existing network note below.
        if route.lanUrl != nil, let note = ExposurePauseText.note(for: route, currentNetwork: model.status?.lan?.network) {
            return note
        }
        guard route.exposureRequested == true, route.lanUrl == nil else { return nil }
        return L10n.text("Freigabe aktiviert · Netzwerk derzeit nicht verfügbar")
    }

    // MARK: - Actions

    @ViewBuilder
    private var actionButtons: some View {
        let busy = model.inFlightIDs.contains(route.id)
        HStack(spacing: 2) {
            if busy {
                ProgressView()
                    .controlSize(.mini)
                    .padding(.horizontal, 6)
            } else {
                Button {
                    model.openLocalURL(for: route)
                } label: {
                    Image(systemName: "arrow.up.forward")
                        .frame(width: 20, height: 18)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(L10n.format("%@ im Browser öffnen", route.name))
                .help(L10n.text("Lokale Adresse im Browser öffnen"))

                Button {
                    // Flash only on a real copy — a refused URL must never
                    // show "Kopiert".
                    if model.copyLocalURL(for: route) {
                        copiedLocalURL = true
                        Task {
                            try? await Task.sleep(nanoseconds: 1_500_000_000)
                            copiedLocalURL = false
                        }
                    }
                } label: {
                    Image(systemName: copiedLocalURL ? "checkmark" : "doc.on.doc")
                        .frame(width: 20, height: 18)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(L10n.text("Lokale Adresse kopieren"))
                .help(L10n.text("Lokale Adresse kopieren"))

                Menu {
                    ProjectActionsMenu(model: model, route: route,
                                       onRename: onRename, onShare: onShare,
                                       onRemoveAsk: { showRemoveConfirm = true })
                } label: {
                    Image(systemName: "ellipsis")
                        .frame(width: 20, height: 18)
                }
                .menuStyle(.borderlessButton)
                // The three-dots icon is the menu affordance; SwiftUI's extra
                // chevron duplicates it and crowds the row.
                .menuIndicator(.hidden)
                .fixedSize()
                .accessibilityLabel(L10n.format("Weitere Aktionen für %@", route.name))
            }
        }
    }
}

/// Live countdown derived strictly from the daemon's `expiresAt`. Minute
/// granularity display — a 1-second timeline would wake the view every
/// second for nothing.
struct ShareCountdownBadge: View {
    let model: AppModel
    let share: ShareStatus

    var body: some View {
        TimelineView(.periodic(from: .now, by: 60)) { context in
            let remaining = model.remainingSeconds(for: share, at: context.date) ?? 0
            Label(L10n.format("Öffentlich · %@", Self.format(remaining)), systemImage: "globe")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .help(L10n.format("Öffentlicher Link läuft in %@ ab (aus der echten Ablaufzeit des Dienstes).", Self.format(remaining)))
        }
    }

    static func format(_ seconds: Int) -> String {
        let total = max(0, seconds)
        if total < 60 { return "<1 min" }
        let minutes = total / 60
        if minutes < 60 { return "\(minutes) min" }
        let hours = minutes / 60
        let rest = minutes % 60
        return rest == 0 ? "\(hours) h" : "\(hours) h \(rest) min"
    }
}

struct FeedbackLine: View {
    let text: String
    var kind: RouteFeedback.Kind = .problem
    let onDismiss: () -> Void

    /// A confirmed success reads as one (green check), an observation stays
    /// neutral; only problems keep the orange warning look.
    private var icon: String {
        switch kind {
        case .problem: return "exclamationmark.circle"
        case .success: return "checkmark.circle.fill"
        case .observed: return "info.circle"
        }
    }

    private var tint: Color {
        switch kind {
        case .problem: return .orange
        case .success: return .green
        case .observed: return .secondary
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: icon)
                .foregroundStyle(tint)
            Text(text)
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button {
                onDismiss()
            } label: {
                Image(systemName: "xmark")
                    .font(.caption2)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(L10n.text("Hinweis schließen"))
        }
        .padding(6)
        .background(tint.opacity(kind == .observed ? 0.08 : 0.12), in: RoundedRectangle(cornerRadius: 6))
    }
}
