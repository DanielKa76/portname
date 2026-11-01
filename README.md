# portname

Every local project gets a real, stable address — whatever port it landed on.

```
proj.localhost        this Mac
proj.local            your Wi-Fi (one switch per project)
https://…/token/      anyone, for one hour
```

macOS 14+ (developed on macOS 26) · Node ≥ 22 · no runtime dependencies · CLI first.

The one shipped component beyond Node: **public links** use the `cloudflared`
binary (Quick Tunnel). If it is missing, everything local keeps working and
only `share` says so; `portname doctor` reports it.

## Install from source

Requirements: macOS 14+ and a Node version listed under `engines` in
`package.json`. There are no npm dependencies to install.

```bash
git clone https://github.com/DanielKa76/portname.git
cd portname
npm test                # optional: unit + integration suite
npm link                # puts `portname` on your PATH
```

The menubar app is optional; it is a pure client of the daemon and needs a
Swift toolchain (Xcode or the Command Line Tools):

```bash
scripts/build-macos-app.sh      # -> dist/Portname.app (ad-hoc signed, for this Mac)
scripts/install-macos-app.sh    # -> ~/Applications, no root
```

`scripts/bundle-macos.sh` builds the self-contained app with its own pinned
Node runtime and `cloudflared`; see `docs/macos-bundle.md`.

## Quick start

```bash
portname install        # LaunchAgent; the daemon now runs at login
portname                # every named project it can see right now
```

Start any dev server. It gets its folder's name:

```
shop.localhost   -> :3000   node
api.localhost    -> :8000   uvicorn
```

No DNS setup, no hosts file, no admin password. Your normal `localhost:3000`
URLs keep working — portname only adds names.

```bash
portname rename shop boutique   # one click, no config file
portname add db 55432           # register anything lsof cannot attribute
portname expose shop            # shop.local answers on your Wi-Fi
portname unexpose shop          # off again
portname share shop             # public demo link, 1 h, secret key
portname unshare shop           # dead the moment you switch it off
portname unshare-all            # revoke every public link at once
portname doctor                 # read-only checks with concrete remedies
portname status --json          # machine-readable diagnosis (no secrets, no project paths)
portname uninstall
```

## How it works

- **Names.** The daemon watches TCP listeners (`lsof` machine format), reads
  each process's working directory, walks to the project root and keeps a
  persistent identity per root — so `web-2` stays `web-2` across scans, and
  when a framework auto-increments its port, the name follows the newest
  listener of that project (older ones are listed as stale). A stopped
  project keeps its name reserved, but not forever. On start and then
  hourly, the daemon drops the reservations of folders that no longer exist
  (throwaway temp dirs from test runs, deleted worktrees) and of projects
  that have not run for 90 days, and keeps at most 500, dropping the
  longest-unused first. Folders under `/Volumes`, `/net` and `/Network` are
  never treated as deleted, since the volume may just be unmounted. Renamed
  projects, a chosen primary service and Wi-Fi exposures always keep their
  name.
- **HTTP only.** The gateway speaks HTTP, so discovery skips listeners that
  are known not to be HTTP services (PostgreSQL, MySQL, Redis, MongoDB,
  memcached, `limactl`, …) — a database port would only ever answer a
  browser with 502. Additional process commands can be ignored via
  `"ignoreCommands": ["somecommand"]` in `~/.portname/config.json`; manual
  registrations are never filtered (they are explicit decisions). `ssh`
  listeners stay visible on purpose: `ssh -L` port-forwards often carry a
  working web server.
- **`*.localhost`.** Browsers resolve these to your own machine (RFC 6761).
  The gateway listens on port 80, checks the Host header per request and
  streams HTTP/1.1, Server-Sent Events and WebSocket upgrades to the real
  port with sanitized hop-by-hop headers, trusted Forwarded metadata, and
  controlled upstream Host rewrites.
- **`*.local`.** Bonjour proxy registration (`dns-sd -P`) publishes a real
  `name.local` host record for the Mac's LAN address. Per project, off by
  default.
- **Public link.** `share` runs a `cloudflared` quick tunnel to a dedicated
  gate. Browser visits exchange the 32-byte secret token for an in-memory
  session cookie (HttpOnly, Secure, SameSite=Lax, expiring with the TTL) and
  redirect to clean paths — so SPAs, Vite, Next.js, and absolute asset URLs
  (`/assets/...`, `/_next/...`, `/api/...`) work cleanly. Webhooks can still
  authorize directly via the secret token in the path without cookies. The
  share is strictly bound to its specific target port and process generation;
  when the process or port changes, or when the TTL expires, all sessions,
  streams, WebSockets, and tunnel processes are terminated immediately.

## Security model, stated plainly

- **Zones.** The Host header decides *routing*, never *authorization*. A LAN
  client claiming `private.localhost` gets the same empty 404 as anything
  unknown. Only loopback connections reach local names; only explicitly
  exposed names answer on the LAN.
- **The port 80 tradeoff (macOS 26, measured).** Unprivileged binds to
  specific addresses like `127.0.0.1:80` fail with `EACCES`; wildcard binds
  (`0.0.0.0:80`, `:::80`) are allowed. "No root", "true loopback-only" and
  "portless URLs" cannot all three hold. Default is the wildcard on 80 with
  strict per-request zone gating; if you prefer maximum isolation, set
  `{"bind":"loopback","loopbackPort":7777}` in `~/.portname/config.json` and
  accept `:7777` URLs. Nothing switches modes silently. Measured probe:
  `docs/bind-probe.txt`.
- **status is honest.** If a dev server already listens on all interfaces on
  its own port, portname says so — turning expose off only removes portname's
  route, not your machine's other doors. First LAN use may trigger macOS's
  firewall prompt; portname never changes firewall or privacy settings.
- **Public links are demo-grade.** Cloudflare offers quick tunnels for
  testing and development: no SLA, at most 200 concurrent requests, no SSE.
  Treat them as a way to show someone a
  screen, not as ingress. Initial browser entry exchanges the secret token
  for an ephemeral in-memory session cookie so that assets load on clean paths;
  webhooks authorize directly with the secret token in the URL path. Tokens and
  sessions live solely in memory, are never logged in full, and are never
  persisted to disk. When a share expires, is stopped, or the underlying server
  port/process changes, the tunnel, gate, open WebSockets and streams are
  terminated actively. The upgrade path is a Cloudflare named tunnel with
  your own hostname — deliberately not built until needed.
- **No telemetry.** Everything stays local except the tunneled traffic
  itself, which runs Mac → Cloudflare.

## Development

```bash
npm test                  # node --test; unit + integration
cd macos && swift build   # the menubar app (pure control-socket client)
cd macos && swift test    # XCTest suite (needs a toolchain with XCTest)
```

Diagnostics are documented in `docs/diagnostics.md`, the control protocol in
`docs/control-protocol.md`, and the macOS manual smoke checklist in
`docs/macos-smoke-checklist.md`.

The test suite covers per-request re-routing on
one keep-alive connection, host split across TCP writes, defined refusals
(unknown/missing/duplicate Host, CONNECT), SSE arriving before response end,
bidirectional WebSocket bytes, and name stability across port switches.
Real-device smokes (Safari on `demo.localhost`, a second device on
`name.local`, LAN privacy under the LaunchAgent) are documented in
`docs/macos-smoke-checklist.md`, and the design decisions behind the
daemon, discovery, shares, and the menubar app are re-stated factually in
`docs/architecture-notes.md`.

## Status

v0.1.0 — gateway core, discovery + Wi-Fi and public sharing, followed by
hardening: bounded discovery, share freshness/revocation, daemon lifecycle
states, and the native menubar app in `macos/` — a pure client of the same
control socket, never a second daemon.

## License

MIT, see `LICENSE`. portname is a free spare-time project and comes without
warranty or support commitment. Security reports: see `SECURITY.md`.
