# Release checklist — self-contained macOS bundle

Machine-checkable local gates run in `scripts/release-check.sh`; the
real-world gates below are manual and are **all still OPEN**. Nothing here is
claimed as done without a dated run note. Rule from docs/macos-smoke-checklist.md
applies: screenshots/notes only from actual runs, never staged.

## Verified locally (latest run)

- [x] `scripts/release-check.sh` full pass — 2026-09-18, arm64, macOS 27.0
      (26A428): node test suite, `swift build`, dev app build + invariants
      (codesign, plutil, `dev-adhoc` marker), self-contained bundle
      (pinned node v24.21.0 tarball SHA-256 verified, manifest verified,
      bundled CLI runs), **isolated install dry-run** in a temp `$HOME`:
      LaunchAgent plist generated, `plutil`-validated, ProgramArguments point
      only into `~/Library/Application Support/Portname/` (never checkout,
      Cellar, .app or temp-download), payload manifest verified, bundled
      runtime + wrapper execute, uninstall dry-run clean.
      `launchctl` was **never invoked**; nothing was loaded; the production
      installation of the authoring machine was untouched.
- [x] Re-run with the new pins: the bundled Node runtime was re-pinned from
      v24.21.0 to v24.22.2 (2026-10-31, security release line 24.22.1), and
      cloudflared is now the pinned official release asset 2026.10.7 instead
      of the build machine's Homebrew copy. `scripts/release-check.sh` passed
      all seven steps on 2026-11-01, arm64, macOS 27.0.1 (26A434), with
      both pins verified in the beta bundle and the node test suite run on
      the bundled runtime. The isolated install again used the `launchctl`
      stub; nothing was loaded by the check.

## Before every release (recurring)

- [ ] Bundled Node is the newest security release of its line
      (`scripts/release-check.sh` enforces this online; offline it only warns —
      then check nodejs.org/en/blog/vulnerability by hand).
- [ ] cloudflared pin checked against the latest upstream release and its
      RELEASE_NOTES (`VULN-…` / Go security entries); re-pin version, archive,
      binary and license SHA-256 in `scripts/runtime-pin.env` when needed.
- [ ] `node scripts/scan-release-secrets.js` on the repository root: 0
      critical. If the existing GitHub repository (not a fresh root) is
      made public, also re-check every PR body and comment via `gh` — the
      scanner does not cover GitHub texts.
- [ ] The candidate carries no internal process references (change-request
      and prompt numbers, review-round tags, finding ids, working-copy paths)
      and no real home folder: test/release-candidate-list.test.js passes
      (its guard allows none in any candidate file), and after
      `node scripts/build-release-candidate.js` (it stages the committed
      HEAD, so commit first; uncommitted edits are left out) the
      scanner's `--json` details list no `internal-reference` finding in
      the `staging` area (review-level, so the exit code does not show it).

## OPEN — clean machine (no repo, no Xcode, no Homebrew node)

- [ ] Install the zipped app on a clean supported Mac or VM (arm64, macOS 14+)
      that has never had portname, Xcode or Homebrew. Verify:
      app launches, `portname-cli install` provisions the payload, daemon runs
      at login, `portname doctor` is green except optional cloudflared notes
      (bundled) if applicable.
      Status: **OPEN** — no clean VM available in the working environment.
- [ ] Confirm absence of dev-machine accidentals: no reference to the build
      user's home in `launchctl print gui/$(id -u)/dev.portname.daemon`.
      Status: **OPEN** (requires the clean machine).

## OPEN — Gatekeeper / quarantine

- [ ] Distribute the release zip the way a user gets it (browser download or
      AirDrop) so it carries the quarantine flag; double-click launch shows
      the expected Developer-ID-verified dialog (no right-click workaround
      needed); for the `beta-adhoc` artifact the expected block dialog must
      appear (it is not distributable).
      Status: **OPEN** — requires Developer ID signature + notarization
      (below) and a second machine.

## OPEN — reboot / login restart

- [ ] After a full reboot and fresh login the daemon is running
      (`launchctl print gui/$(id -u)/dev.portname.daemon` state: running),
      projects resolve via `*.localhost`, GUI reconnects.
- [ ] Kill -9 the daemon; KeepAlive restarts it within seconds (one killed
      within 30 s of its start only after the `ThrottleInterval`); shares
      are NOT resurrected after the restart.
      Status: **OPEN** — no reboot available for the authoring machine so
      far; only the plist-level invariants (RunAtLoad, KeepAlive,
      ThrottleInterval, payload paths) are machine-verified.

## OPEN — upgrade / rollback (real install)

- [ ] Upgrade in place: install beta N, then beta N+1 over it (same machine,
      existing `~/.portname`): config and manual registrations survive,
      no share re-enabled automatically, agent points at the new payload.
- [ ] Rollback: re-install beta N over N+1; daemon healthy; state still loads
      (older daemon refuses incompatible state fail-closed rather than
      corrupting).
- [ ] Update signature check end-to-end: verify SHA-256 of the downloaded
      zip, `codesign --verify`, `spctl --assess`, stapled ticket on a real
      release artifact.
      Status: **OPEN** — only the idempotent sync/repair/replace semantics
      are covered by unit tests and the isolated dry-run so far.

## OPEN — uninstall (real install)

- [ ] `portname uninstall`: agent gone from `launchctl print`, plist gone,
      `~/Library/Application Support/Portname` gone, `~/.portname` and the
      app kept; localhost URLs unaffected.
- [ ] Drag app to trash afterwards: nothing portname-related left running.
- [ ] Uninstall with a *foreign* directory at the payload path (managed
      machine): the foreign directory must survive.
      Status: **OPEN** on a real install; the foreign-directory refusal is
      unit-tested (test/bundleinstall.test.js).

## OPEN — Developer ID signing + notarization (execution)

- [ ] Run `scripts/release-package.sh` with `MACOS_SIGNING_IDENTITY` and
      `NOTARYTOOL_KEYCHAIN_PROFILE` configured; confirm notarytool "Accepted",
      stapler validate, `spctl --assess --type execute` on the stapled app.
- [ ] Confirm the fail-closed behavior once with credentials absent (script
      must print "NOT RELEASED" and produce nothing).
      Status: **OPEN** — no signing identity and no notarization credentials
      exist for this project; nothing was signed, notarized, uploaded or
      published. The script was reviewed but not executed.

## OPEN — GUI smoke on the bundle

- [ ] Run docs/macos-smoke-checklist.md against a bundle-built app on a real
      screen (the checklist itself documents that no visual run happened for
      earlier rounds either).
      Status: **OPEN** — no GUI screen access in the working environment.

## Non-goals (deliberate)

- Intel/Universal builds: not built, not tested, not promised.
- Auto-update infrastructure: none, by design (see docs/macos-bundle.md).
- Any change to firewall, privacy or privilege settings: none.
