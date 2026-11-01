# macOS Manual Smoke Checklist — GUI

Manual, read-mostly checks for the native menubar app (`macos/`). This file
is the contract for *how* to smoke the GUI; it does not claim that any run
happened. **Status of the last run: see the end of this file — no visual run
was performed for the localization/diagnostics changes (no GUI screen access
in the working environment); nothing below was verified visually.**

Rules for any future run: screenshots only from an actual run, never staged;
note the macOS version and appearance; note anything that looked wrong even
if it passed.

## Panel basics

- [ ] Menubar icon appears at launch and reflects state (filled = connected,
      outline = connecting, crossed = unreachable, warning = legacy daemon).
- [ ] Panel opens on click; project list renders; polling cadence rises
      while open (status line stays current after starting/stopping a server).
- [ ] Dark mode and light mode: banners (orange), feedback lines and badges
      stay readable; nothing relies on color alone (icon + text always present).

## Keyboard

- [ ] `Cmd+F` focuses search; typing filters; `Esc` clears the search, a
      second `Esc` (or `Esc` in a dialog) leaves rename/share/add dialogs.
- [ ] Arrow keys move the row selection through the *visible* (filtered)
      list; `Enter` in search opens the selected project.
- [ ] With an active search filter, a selected row that is filtered out must
      NOT be opened by `Enter` — the first visible match opens instead.
- [ ] `Cmd+R` refreshes, `Cmd+,` opens settings, `Cmd+Q` quits the app.
- [ ] VoiceOver: rows announce name, address and badges; buttons announce
      localized labels ("Projekte suchen …"/"Search projects …", …).

## Quit semantics and global revoke (new)

- [ ] With zero public links: no orange note above the footer; "App beenden"
      tooltip explains daemon/shares keep running.
- [ ] Start a public link: the note "„App beenden“ schließt nur die
      Oberfläche …" becomes VISIBLE in the panel (not only a tooltip) and
      states the number of running links.
- [ ] "Alle öffentlichen Links beenden …" is visible next to it; clicking
      asks for confirmation; confirming ends every public link (verify via
      `portname status --json`: `shares` empty) and local/WLAN exposure
      stays untouched.
- [ ] Quitting the app while links run does NOT end the links
      (`portname status --json` still lists them) and the panel never
      suggested it would.
- [ ] English appearance (System Settings → Language & Region, add English
      as app language for portname): the quit note, revoke-all confirmation,
      banners and share dialog render in English; no raw keys, no mixed
      half-sentences from interpolation.

## Network change (new)

- [ ] While a project is exposed on Wi-Fi, switch networks (or disable/
      enable Wi-Fi with a different interface active): the panel shows the
      orange "Netzwerkwechsel …" note with a "Verstanden" button; WLAN badges
      must not keep implying the old network.
- [ ] After acknowledging, the note stays away while the network identity is
      stable; a daemon restart (settings → restart) must NOT produce a false
      network-change note.

## Share dialog

- [ ] States render distinctly: creation form → "Wird erstellt …" (up to a
      minute) → active (origin pattern + countdown + "Ziel zuletzt
      verifiziert vor N s.") → expired/ended; unknown daemon states show the
      explanatory view, never a link.
- [ ] The full secret link is never displayed; copy/open fetch it on demand.

## Long names, many services, many projects

- [ ] A 63-character project name truncates in the middle (row, dialog
      title, browser URL line) without breaking layout; badges stay visible.
- [ ] A project with 3+ services shows the service count and the "Dienste"
      menu; switching the primary service updates the row's target port and
      shows the "preferred service missing" note after killing that service.
- [ ] 15+ projects scroll within the capped panel height; search keeps the
      list usable; stale-list "Diagnose · N Einträge" expands/collapses.

## CLI counterparts (can be checked without GUI access)

- [x] `portname status --json` exits 0 with schema `portname.status/1`
      against a running daemon, exits 1 without one; output contains no
      project paths, no share origins, no LAN IP.
- [x] `portname doctor` (and `--json`) exits 0/1/2 per docs/diagnostics.md;
      the report states it repairs nothing.
- [x] `portname unshare-all` revokes every public link and is idempotent.

---

## Run log (honest record)

- 2026-09-18 (`feat/06-ux-diagnostics`): NO visual GUI run performed — the
  working environment has no GUI/screen access for this session and
  `swift test` is currently blocked by the toolchain situation (CLT ships no
  XCTest module; Xcode 27 requires `sudo xcodebuild -license`, which this
  project's guardrails forbid). Compensating checks actually run:
  `swift build` (all targets incl. app) green; standalone L10n harness
  (table parity 164 keys, English lookups, German fallback) green; full
  Node suite green. All visual checkboxes above remain UNCHECKED and must
  be run manually before calling the GUI verified.
