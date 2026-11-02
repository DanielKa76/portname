# The self-contained macOS bundle

This describes the standalone installable macOS artifact built from this
repository (`scripts/bundle-macos.sh`). The daemon architecture is unchanged:
the Node daemon remains the sole state owner, the SwiftUI menubar app remains
a pure client of the daemon's Unix-socket control protocol.

## What the artifact is

`dist/Portname.app` — a self-contained menubar app that runs on a supported
Mac **without this git repository, without Xcode and without preinstalled
Homebrew node**. Supported target: Apple silicon (arm64), macOS 14+.
The build refuses to produce an artifact for any other architecture: Intel or
Universal builds are **not** promised until they are separately built and
tested.

```
Portname.app/
  Contents/
    Info.plist                  PortnameBuildChannel marks the artifact class
    MacOS/
      Portname                  SwiftUI menubar app (SwiftPM release build)
    Resources/
      portname-macos_PortnameCore.bundle
                                the GUI's localization tables (de/en
                                Localizable.strings; SwiftPM resource bundle,
                                resolved explicitly by L10n — never via the
                                build machine's .build path)
      MANIFEST.json             generated inventory: every shipped file with
                                size, mode, SHA-256 + component versions
      daemon/                   daemon payload (bin/portname.js, lib/*.js,
                                package.json)
      runtime/bin/node          pinned Node.js runtime (see below)
      runtime/bin/cloudflared   pinned cloudflared (see below); omitted only
                                by --skip-cloudflared builds
      bin/portname-cli          CLI wrapper: bundled node + bundled CLI,
                                works without any system node
      bin/portname              payload CLI wrapper (lands in the stable
                                install location via `install`)
      LICENSES/                 portname, node and cloudflared license texts,
                                portname notice
```

## Bundled runtimes: controlled procurement, no download-and-execute

- **Node.js** is pinned in `scripts/runtime-pin.env` (currently
  `v24.22.2` LTS "Krypton" — includes the 2026-10-20 security release
  v24.22.1 — platform `darwin-arm64`, tarball SHA-256
  `aa9549349e47dffaa42dcf95d6e06ade8c4bdafc980979883b88767670df385a`, taken
  from the official, GPG-signed `SHASUMS256.txt` at pin time).
  `scripts/release-check.sh` fails while nodejs.org lists a newer security
  release of the pinned line (offline it only warns). The build script verifies
  the tarball checksum **always** — cached or freshly downloaded — and aborts
  on any mismatch. Only `bin/node` and the license file are extracted from the
  official distribution; the pinned binary is self-contained (system libraries
  only). Homebrew's node is deliberately **not** bundled: it is keg-linked
  against ~20 Homebrew-only dylibs and would not run on a clean Mac.
- **cloudflared** is pinned the same way (`CLOUDFLARED_*` in
  `scripts/runtime-pin.env`, currently `2026.10.7`): the official
  `cloudflared-darwin-arm64.tgz` release asset of cloudflare/cloudflared, its
  archive SHA-256, the SHA-256 of the binary inside it (the value Cloudflare
  publishes in the release notes' "SHA256 Checksums" under the asset name)
  and the SHA-256 of the Apache-2.0 license text from the same tag. The
  build verifies all three, checks the binary links system libraries only
  and reports the pinned version, and aborts on any mismatch — it never
  copies whatever a local Homebrew happens to have. Pin, version and
  SHA-256s are recorded in the manifest. cloudflared stays an optional
  component: `--skip-cloudflared` builds without it, and then everything
  local keeps working; only `share` (public links) needs it —
  the same contract as the Homebrew workflow, enforced by the daemon's
  existing resolver and `portname doctor`. Which binary the daemon runs is a
  fixed precedence (see "cloudflared resolution" below): an explicit
  `cloudflaredBin` config always wins; in payload operation the shipped
  binary is the unambiguous default.
- **Offline builds**: every pinned input accepts a verified local copy,
  checked against its pin before it is used or cached — `--node-tarball
  FILE`, `--cloudflared-tarball FILE` and `--cloudflared-license FILE` (the
  LICENSE text of the pinned cloudflared tag). Pre-seeding `dist/cache/` with
  the verified files under their cache names
  (`node-v<version>-darwin-arm64.tar.gz`,
  `cloudflared-<version>-cloudflared-darwin-arm64.tgz`,
  `cloudflared-<version>-LICENSE`) works as well: a cached file that matches
  its pin is never downloaded again.
- `MANIFEST.json` is generated at build time and lists **every** shipped file
  with its SHA-256. It is the integrity base for install (idempotent sync +
  repair), for the release check and for manual audits.

## Install, repair, uninstall (user context, no root)

Everything runs as the user; nothing touches firewall, DNS, certificates or
any privileged setting.

- `…/Portname.app/Contents/Resources/bin/portname-cli install`
  1. Syncs the payload (daemon + runtime + wrappers + licenses) to the stable
     per-user location `~/Library/Application Support/Portname/` — atomically:
     copy to a temp dir, verify the full manifest, then rename into place, old
     copy removed only afterwards. An aborted install leaves the previous
     payload intact.
  2. Writes `~/Library/LaunchAgents/dev.portname.daemon.plist` and loads it
     with `launchctl bootstrap gui/<uid>` (bootout first, failure tolerated).
- From the app: on first start, while the daemon is unreachable and no
  LaunchAgent exists, the panel offers "Set Up Background Service", which
  runs the same bundled `portname-cli install` (fixed executable, argument
  array, user context) and switches to the project list once the daemon
  answers. With an agent in place the panel never offers it: an unreachable
  daemon is then a different problem, and re-running install from the app
  could re-point a developer's agent at the bundle.
- **Idempotent**: re-running `install` is the repair path. An intact payload
  with the same manifest content id is left untouched; a damaged or outdated
  one is replaced. The agent plist is rewritten and the agent reloaded.
  The existing target is only ever replaced when it is **verifiably ours**:
  a directory carrying a valid `MANIFEST.json` with the portname bundle id
  (`dev.portname.app`). Anything else — a directory without a valid manifest
  (including a corrupt/unreadable one), a manifest naming a different bundle
  id, a plain file, or a symlink — is left **byte-for-byte untouched** and the
  install is refused with the path and a remedy; portname never renames,
  replaces or deletes content it cannot identify as its own. Damage alone is
  a repair condition, not an ownership question: a verifiably own
  installation with corrupted files stays repairable via `install`; once the
  manifest itself is unreadable the ownership check fails closed and the
  directory must be moved away manually.
- `install --dry-run` validates and reports only: it checks the planned
  payload and agent paths and prints what `install` would do — no payload
  sync, no plist is written, `launchctl` is never invoked, nothing is loaded
  or unloaded. This is what automated checks use.
- The LaunchAgent references **only** paths inside the stable payload
  (`~/Library/Application Support/Portname/…`) — never the developer
  checkout, never a `Portname.app` path, never a Homebrew Cellar version
  path, never a temp/download dir. The agent's `PATH` starts with the
  payload's `runtime/bin` so the bundled cloudflared is found on machines
  without Homebrew.
- `portname uninstall` (or the payload wrapper
  `~/Library/Application Support/Portname/bin/portname`) stops and removes the
  agent and removes the stable payload **only if it is verifiably ours**
  (manifest bundle id). It deliberately **keeps**:
  - `~/.portname/` — your config, project registry, logs;
  - `Portname.app` — the GUI.
  Removing the app (drag to Trash) does **not** remove the background service,
  and uninstalling the service does **not** remove the app. The docs for both
  directions are this section; `portname help` states it too.
- `portname` on your `PATH`: link the payload wrapper into a directory on
  `PATH`, e.g.
  `ln -s ~/Library/Application\ Support/Portname/bin/portname ~/.local/bin/portname`
  (or `/opt/homebrew/bin`, `/usr/local/bin`). Both wrappers resolve symlinks
  before locating the bundled runtime, so a link works like the original.

### App movement, permissions, aborted installs

- Moving `Portname.app` anywhere has no effect on the running daemon: the
  agent points at the stable payload, not the app.
- Deleting the app leaves the daemon running (it is a separate service);
  `uninstall` removes it.
- Missing write permissions (e.g. a managed `~/Library`): the failing step
  aborts with the concrete filesystem error before anything is loaded —
  a half-installed state is impossible because the payload swap is atomic and
  the plist is written only after the payload is verified.
- Re-installing over a running daemon is safe: `bootout` (tolerated failure)
  → `bootstrap`; shares are not resurrected (see below).

### cloudflared resolution

The daemon resolves the tunnel binary with a fixed precedence:

1. an explicit `cloudflaredBin` in `~/.portname/config.json` — a deliberate
   user override; always wins, also over the bundled binary;
2. in **payload operation** (the daemon runs from the stable install
   location): the bundled `runtime/bin/cloudflared` — the shipped,
   manifest-inventoried binary is the unambiguous default, so an installed
   app never silently runs a different Homebrew version;
3. Homebrew locations (`/opt/homebrew/bin/cloudflared`,
   `/usr/local/bin/cloudflared`);
4. whatever `cloudflared` resolves to on `PATH`.

Without a bundled component (e.g. `--skip-cloudflared` builds, or the
developer checkout) steps 3–4 apply unchanged, so a Homebrew install keeps
working exactly as before. The LaunchAgent `PATH` still starts with the
payload's `runtime/bin` as defense in depth.

## Migration from existing setups

- Existing `~/.portname/config.json` stays authoritative; the bundled daemon
  reads the same state directory and schema as the CLI from this repo
  (a developer-install migration needs no conversion). Hand edits to it
  (`bind`, ports, `ignoreCommands`, `cloudflaredBin`) take effect after a
  daemon restart (`portname install`); the daemon never overwrites them in
  the meantime.
- **No share is ever re-enabled without an explicit action.** The daemon does
  not persist active shares across restarts: on start it runs orphan
  cleanup, and public links die with the daemon that created them. A reboot,
  upgrade or reinstall therefore never silently publishes anything.
- Upgrading from the developer-checkout LaunchAgent: run
  `portname uninstall` from the old checkout (removes the old agent), then
  `portname-cli install` from the bundle. The old agent's node path (Cellar or
  checkout) is replaced by the payload paths.

## Version compatibility GUI ↔ daemon ↔ state

The bundle always ships the GUI and the daemon from the same source tree, so
matching versions are guaranteed for a fresh install. For mixed situations
(old daemon, newer GUI or vice versa) the control protocol handshake is the
gate: the status response carries `protocolVersion` (protocol v1, additive
only — see docs/control-protocol.md). The GUI decodes it and refuses guarded
mutations against a daemon that predates protocol v1 (`isLegacyDaemon`),
displaying a warning instead; `portname doctor` reports the protocol version
and flags an unversioned daemon. State files (`~/.portname/`) are schema-
validated fail-closed by the daemon (config hardening), so an incompatible
state aborts startup with a concrete remedy rather than running half-broken.

## Development vs release artifacts

| Channel marker   | Produced by                  | Signature        | Meaning                                   |
|------------------|------------------------------|------------------|-------------------------------------------|
| `dev-adhoc`      | `scripts/build-macos-app.sh` | ad-hoc           | developer artifact, not for distribution  |
| `beta-adhoc`     | `scripts/bundle-macos.sh`    | ad-hoc           | self-contained local beta; Gatekeeper will block it; not for distribution |
| `release`        | `scripts/release-package.sh` | Developer ID + notarization + stapling | distributable (see below)  |

`PortnameBuildChannel` in `Contents/Info.plist` makes the class of an
artifact machine-checkable (`plutil -extract`), and the build scripts assert
it. Ad-hoc signing marks a development/beta artifact only.

## Release path (prepared, deliberately not executed)

`scripts/release-package.sh` implements the real distribution path and is
**fail-closed**: without `MACOS_SIGNING_IDENTITY` (Developer ID Application)
and `NOTARYTOOL_KEYCHAIN_PROFILE` it exits with "NOT RELEASED" and produces
nothing release-like. With credentials it: removes a distributable zip left
by an earlier run → builds the bundle (`PORTNAME_RELEASE_PREBUILT=1` takes the
existing `dist/Portname.app` instead) → verifies the payload **before
anything is signed** (`scripts/lib/release-preflight.js`): it must match its
`MANIFEST.json` with no edited, added or missing file, its recorded node and
cloudflared components must equal the current pins in
`scripts/runtime-pin.env`, the unsigned runtime binaries must hash to the
pinned binaries, and the channel marker must be `beta-adhoc` (or `release`
when re-notarizing an already signed bundle, whose binaries are then checked
through the manifest only) → sets the `release` channel marker → signs every
Mach-O with Hardened Runtime and timestamps (minimal entitlements:
`com.apple.security.cs.allow-jit` for the node runtime's V8, empty dicts for
GUI and cloudflared — see `scripts/release/entitlements-*.plist`) →
regenerates the manifest entries of the re-signed runtime binaries only (any
other change since the bundle build fails closed) → packs the
**notarization archive** (a zip; notarytool accepts archives, disk images
and signed flat packages, never an `.app` directory) → submits **the archive** to notarization
(`notarytool submit <zip> --wait`) → staples the ticket → validates the
staple and runs `spctl --assess` → packs the signature-preserving
distributable zip **from the stapled bundle** with its SHA-256 and removes
the interim notarization archive. Publishing remains a separate,
deliberate decision. No signing or notarization has been executed so far
(no credentials on the build machine); see docs/release-checklist.md.

## Updates and rollback

- **No proprietary auto-update infrastructure** — an unsigned or weakly
  checked updater would be the weakest link, so there is none.
- Consequence: a shipped runtime stays frozen until the next app release.
  Every security release of a bundled component (the Node line of the pin,
  cloudflared) that affects the pinned version triggers a re-pin and a new
  app release.
- An update is: obtain a release zip from a trusted channel, verify its
  recorded SHA-256, unpack, replace the app, run
  `portname-cli install` once (idempotent payload upgrade + agent reload).
  For a `release` artifact, Gatekeeper + `codesign --verify` +
  `spctl --assess` on the Developer ID signature and the stapled notarization
  ticket are the signature check; the manifest verifies the payload on disk.
- **Rollback** = keep the previous versioned zip, re-install it the same way
  and re-run `install`. Because `~/.portname` config/registry are versioned
  and validated fail-closed, an older daemon refuses incompatible state
  instead of corrupting it. Rollback of the *background service* alone works
  the same way without touching the app.
