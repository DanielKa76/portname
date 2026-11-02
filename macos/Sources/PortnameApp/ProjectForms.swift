import SwiftUI
import PortnameCore

/// Rename and manual-add forms. Both validate early in the UI and let the
/// daemon deliver the final verdict; daemon errors are surfaced verbatim.

/// Mirrors lib/naming.js (RFC 1035 label): 1–63 chars, [a-z0-9-],
/// starting and ending alphanumeric.
enum NameRules {
    static func validate(_ raw: String) -> String? {
        let name = raw.lowercased().trimmingCharacters(in: .whitespaces)
        if name.isEmpty || name.count > 63 {
            return L10n.text("Der Name muss 1–63 Zeichen lang sein.")
        }
        if !name.allSatisfy({ ($0 >= "a" && $0 <= "z") || ($0 >= "0" && $0 <= "9") || $0 == "-" }) {
            return L10n.text("Nur Kleinbuchstaben, Zahlen und Bindestriche.")
        }
        guard let first = name.first, let last = name.last else {
            return L10n.text("Der Name muss 1–63 Zeichen lang sein.")
        }
        let alnum = { (c: Character) in (c >= "a" && c <= "z") || (c >= "0" && c <= "9") }
        if !alnum(first) || !alnum(last) {
            return L10n.text("Muss mit einem Buchstaben oder einer Zahl beginnen und enden.")
        }
        return nil
    }
}

struct RenameForm: View {
    let model: AppModel
    let route: Route
    let done: () -> Void

    @State private var newName: String
    @State private var working = false
    @FocusState private var nameFieldFocused: Bool

    init(model: AppModel, route: Route, done: @escaping () -> Void) {
        self.model = model
        self.route = route
        self.done = done
        _newName = State(initialValue: route.name)
    }

    private var trimmed: String { newName.trimmingCharacters(in: .whitespaces) }
    private var validationError: String? { NameRules.validate(trimmed) }
    private var changed: Bool { trimmed != route.name }

    /// Rename stops a running public share — STARTING counts, because the
    /// daemon tears that down too and the user would otherwise lose the
    /// (still materializing) link without warning.
    private var liveShare: ShareStatus? {
        guard let share = model.share(for: route),
              share.phase == .active || share.phase == .starting,
              share.expired != true else { return nil }
        return share
    }

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
                .keyboardShortcut(.cancelAction)
                Text(L10n.format("„%@“ umbenennen", route.name))
                    .font(.headline)
            }

            TextField(L10n.text("Neuer Name"), text: $newName)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 13, design: .monospaced))
                .focused($nameFieldFocused)
                .onSubmit(submit)

            if let validationError {
                Text(validationError)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("Wird zu http://\(trimmed).localhost\(portSuffix)/")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if liveShare != nil {
                Label(L10n.format("Achtung: Der laufende öffentliche Link dieses Projekts%@ wird durch das Umbenennen beendet.", sharePhaseHint),
                      systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let feedback = model.feedback, feedback.routeID == route.id {
                FeedbackLine(text: feedback.text, kind: feedback.kind, onDismiss: { model.dismissFeedback() })
            }

            HStack {
                Spacer()
                Button(L10n.text("Abbrechen")) { done() }
                Button(L10n.text("Umbenennen"), action: submit)
                    .disabled(validationError != nil || !changed || working || model.mutationsLocked)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .onAppear { nameFieldFocused = true }
    }

    private var portSuffix: String {
        let port = model.status?.proxyPort ?? 80
        return port == 80 || port == 0 ? "" : ":\(port)"
    }

    private var sharePhaseHint: String {
        liveShare?.phase == .starting ? L10n.text(" (wird gerade erstellt)") : ""
    }

    private func submit() {
        guard validationError == nil, changed, !working else { return }
        working = true
        Task {
            // Re-resolve against the latest snapshot: after a STALE_TARGET
            // the daemon already moved on and the captured route's revision
            // would fail forever. A nil route means the project is gone —
            // close the form (the list refresh already happened).
            let current = await model.currentRoute(for: route)
            guard let current else {
                working = false
                done()
                return
            }
            let outcome = await model.renameRoute(current, to: trimmed)
            working = false
            if outcome == .success {
                done()
            }
            // .staleTarget / .failed keep the form open with the feedback
            // line so the user can read and retry after the refresh.
        }
    }
}

struct AddManualForm: View {
    let model: AppModel
    let done: () -> Void

    @State private var name = ""
    @State private var portText = ""
    @State private var working = false
    @FocusState private var nameFieldFocused: Bool

    private var trimmedName: String { name.trimmingCharacters(in: .whitespaces) }
    private var nameError: String? { trimmedName.isEmpty ? nil : NameRules.validate(trimmedName) }
    private var port: Int? {
        guard let p = Int(portText.trimmingCharacters(in: .whitespaces)) else { return nil }
        return (1...65535).contains(p) ? p : nil
    }
    private var portError: String? {
        portText.trimmingCharacters(in: .whitespaces).isEmpty ? nil :
            (port == nil ? L10n.text("Port muss eine ganze Zahl zwischen 1 und 65535 sein.") : nil)
    }

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
                .keyboardShortcut(.cancelAction)
                Text(L10n.text("Manuell hinzufügen"))
                    .font(.headline)
            }

            Label(L10n.text("Für Server, die portname nicht zuordnen kann (z. B. Docker). Portname macht daraus eine HTTP-Adresse — rohe PostgreSQL-/Redis-Verbindungen bleiben unverändert."),
                  systemImage: "info.circle")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            TextField(L10n.text("Name (z. B. api)"), text: $name)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 13, design: .monospaced))
                .focused($nameFieldFocused)
            if let nameError {
                Text(nameError).font(.caption).foregroundStyle(.secondary)
            }

            TextField(L10n.text("Port (z. B. 3000)"), text: $portText)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 13, design: .monospaced))
                .onSubmit(submit)
            if let portError {
                Text(portError).font(.caption).foregroundStyle(.secondary)
            }

            if let feedback = model.feedback, feedback.routeID == "add-manual" {
                FeedbackLine(text: feedback.text, kind: feedback.kind, onDismiss: { model.dismissFeedback() })
            }

            HStack {
                Spacer()
                Button(L10n.text("Abbrechen")) { done() }
                Button(L10n.text("Hinzufügen"), action: submit)
                    .disabled(trimmedName.isEmpty || nameError != nil || port == nil || working || model.mutationsLocked)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .onAppear { nameFieldFocused = true }
    }

    private func submit() {
        guard let port, nameError == nil, !working else { return }
        working = true
        Task {
            let outcome = await model.addManual(name: trimmedName, port: port)
            working = false
            if outcome == .success { done() }
        }
    }
}
