# Architecture notes (public re-statement)

These notes restate, factually and for the public candidate, the design
decisions behind portname. They intentionally carry no chat or review
history; the private development record stays out of the release tree.

## Name-to-HTTP gateway

- One HTTP/1.1 gateway on port 80 (wildcard bind) routes by Host header.
  Routing and authorization are separate: the Host header only selects a
  route; zone (loopback / LAN / public) plus exposure state authorize each
  request. Unknown names answer with a name-less 404; missing or duplicate
  Host headers are refused (400); CONNECT is refused (405).
- Connections are admitted per zone before a byte is parsed. Loopback
  clients have 512 slots per listener; LAN peers share a separate budget
  of 128, at most 32 per address, so a busy or hostile network can never
  take the local developer's slots. A non-loopback peer that is not an
  authorized LAN client (accepted on the LAN address, from the LAN subnet)
  is dropped at connect. Request headers must arrive within 15 s (enforced
  every second); there is deliberately no whole-request timeout, so SSE,
  HMR and long uploads keep working; a client that stalls mid-body holds
  just its own slot in these budgets and the one upstream request tied to
  it.
- Requests and responses stream unbuffered. Upstream requests carry
  hop-by-hop-sanitized headers, trusted `X-Forwarded-*`/`Forwarded`
  metadata and a controlled Host rewrite (`localhost:<port>`). Client-sent
  forwarding and client-address headers (`Forwarded`,
  `X-Forwarded-For`/`-Host`/`-Proto`, `Client-Ip`, `X-Real-Ip`, …) are
  dropped in every spelling that differs only in case or separator — `_`,
  `.` or any other punctuation for `-` — since CGI-style servers read `-`
  and `_` (PHP also `.`) as the same variable; the trusted values follow
  all client headers. Other headers with `_` or `.` pass unchanged. Body
  framing is re-established explicitly: a chunked request goes upstream
  chunked whatever its method, and `Connection` cannot nominate
  `Content-Length` away. Upstream keep-alive pools are separate per client zone, so a
  desynchronized upstream connection never hands one zone's response to
  the other. No upstream connection within 10 s, no upstream response
  headers within 15 s after the complete request body (the time a client
  takes to upload never counts), or a status outside 100–999 answer 502;
  an upstream that dies mid-body aborts the client response instead of
  ending it as if complete. When an upstream answers before it has the
  whole request body (an early 401/404/413 to an upload), its connection
  is closed once the answer is relayed, never pooled or left open.
- Only `GET` with `Upgrade: websocket` is treated as an upgrade. The
  handshake runs over a dedicated upstream connection (connect within 10 s,
  answer within 15 s), and the sockets are spliced only after the upstream
  answered `101 Switching Protocols`; client bytes beyond the request head
  are forwarded only then. Any other answer is relayed once, sanitized,
  with `connection: close`; no or a broken answer becomes 502. Other
  upgrade offers (h2c) are served as plain HTTP/1.1 with `Upgrade`
  stripped, so no raw channel past the sanitization ever opens.
- Connections (upgraded sockets and in-flight requests) carry their
  authorized target state; after every scan pass a pure policy check tears
  down connections whose route, identity, or target changed, and
  non-loopback `*.local` connections when LAN exposure is withdrawn.
- Bind tradeoff (measured, `docs/bind-probe.txt`): on macOS, unprivileged
  binds below port 1024 are only possible on wildcard addresses; specific
  loopback binds like `127.0.0.1:80` fail with EACCES. Default is the
  wildcard bind with strict per-request zone gating; a loopback-only mode
  with a non-privileged port is available via configuration. Nothing
  switches modes silently.

## WLAN exposure

- An exposure is a decision about one endpoint on one network:
  `portname expose <name>` confirms the route's current port and command
  and the current network — the LAN subnet plus, when it can be
  identified, the router (the MAC address of the LAN interface's default
  gateway, read without privileges from the routing table and the ARP
  cache, stored only as a truncated hash and never reported).
- When the name moves to another port or command (a newer dev server, a
  debug or admin endpoint, `set-primary`, a repointed manual entry) or the
  Mac joins another network, the exposure pauses (`target-changed`,
  `network-changed`; one stored before endpoint binding existed reports
  `target-unconfirmed`): no Bonjour advertisement, LAN requests refused,
  until it is confirmed again. A restart of the same command on the same
  port, or a new address in the same subnet behind the same router, stays
  exposed. `target-not-verified` (no fresh discovery) heals with the next
  successful scan. Networks with the same subnet and no identifiable
  router cannot be told apart.
- Exposure decisions take effect in arrival order: an activation still
  waiting for its bounded router lookup fails with `STALE_TARGET` when a
  later `expose off` or `remove` of the same project, or a target change,
  landed meanwhile. Revocations always apply immediately.

## Discovery

- Listeners come from `lsof` machine format (`-F0pcn`): fields are
  NUL-terminated, records newline-terminated; the parser is fail-closed —
  timeouts, truncation, and partial output surface as a diagnosable scan
  error and the previous routes are kept (a failed scan never looks like an
  empty one). `lsof` runs in a UTF-8 locale; escapes it still prints are
  decoded before a path is used.
- Project identity is the canonical project root: walk up to `.git`,
  bounded by `$HOME`; outside `$HOME` the working directory itself. The
  filesystem root and `$HOME` are never an identity (also not with a
  dotfiles `~/.git`); such listeners get no automatic route, `portname add`
  still works. `$HOME` counts as configured and with symlinks resolved,
  the form `lsof` reports. Names persist per identity. When a framework
  increments its port, the newest listener of the same identity wins and
  older listeners are listed as stale; the name never migrates across
  identities.
- Process identity is pid plus `ps -o lstart`, read with `LC_ALL=C` and
  `TZ=UTC0`, so it does not depend on the user's locale or time zone. Every
  pass reads the start time of every pid it saw, in one batched `ps`, so a
  process that takes over a pid and port between two passes is a new
  generation in the very next pass (and loses the old one's share). A failed
  lookup for a live pid degrades the pass: it neither creates a new
  generation nor keeps the old one, and it verifies nothing.
- Debug endpoints never become a route's primary, for any runtime: Node,
  Deno and Bun inspectors, Chromium/Electron DevTools, the Firefox Remote
  Agent and debugger server, and debugpy. They are recognized from the
  command line (`--inspect*`, without a port the runtime's default: 6499
  for Bun, 9229 for node and deno; `--remote-debugging-port`, debugpy's
  `--listen` and adapter processes; browser debug flags without a usable
  port mark every listener of the process) or from one `GET /json/version`
  per process generation and port (200 ms, 4 KiB cap). Answers are cached
  for the generation; a
  listener that does not answer is retried with a backoff of 5 s up to
  5 minutes. Only listeners with a project root are examined; the others
  never become routes, so apps running in `/` or `$HOME` get neither an
  args lookup nor a request. A debugger that announces nothing on its
  command line and does not answer HTTP is not recognized; `set-primary`
  (control protocol) or `portname add` pins the intended listener.
- Non-HTTP commands (PostgreSQL, MySQL, Redis, MongoDB, memcached,
  `limactl`, …) are skipped by an exact command match; `ssh` stays visible
  because port forwards often carry working web servers; user additions via
  `ignoreCommands` in `~/.portname/config.json`. WebDriver servers
  (chromedriver, geckodriver, msedgedriver, safaridriver) are never
  discovered automatically. Manual registrations are never filtered.
- Scan work is bounded: parallel subprocess caps, wall-clock probe and scan
  budgets, TTL-bound negative caches, and pruning of dead generations.
  Every subprocess has a timeout, is escalated to SIGKILL after a grace
  period and settles on its own timer even if the child never exits; while
  two children of a command are stuck, further runs of it fail fast and
  the pass degrades. `scripts/bench-discovery.js` +
  `docs/bench-discovery.md` document the measurement path.

## Shares (public demo links)

- One tunnel mode: `cloudflared` Quick Tunnel to a dedicated gate (never
  pointed at the general router). Initial entry exchanges a 32-byte CSPRNG
  path token for an in-memory session cookie (HttpOnly, Secure, SameSite=Lax,
  TTL-bounded) with a redirect to the clean path; webhooks may authorize
  directly via the token path. Token redemption collapses leading slashes so
  a token can never redirect to a cross-origin host.
- cloudflared runs with a portname-owned config file
  (`<state dir>/cloudflared.yml`, no ingress) and an allowlisted
  environment (`HOME`, `LOGNAME`, `PATH`, `TMPDIR`, `USER`): a user's
  `~/.cloudflared/config.yml`, `/etc/cloudflared` or `TUNNEL_*` variables
  can never route a public link past the gate. The tunnel URL is taken
  only where it stands alone (whitespace or the banner bar on both sides),
  never the API host; an offline or failed start reports cloudflared's
  error instead of a link.
- The gate presents the public visitor upstream: the address Cloudflare
  sends in `Cf-Connecting-Ip` goes into `X-Forwarded-For` and `Forwarded`.
  A forwarded request without exactly one valid address that is neither
  loopback nor unspecified is refused (400) — never presented as a local
  client. Visitor-settable
  `Client-Ip`, `X-Real-Ip` and `True-Client-Ip` are stripped, also when
  spelled with `_`, `.` or any other punctuation for `-`. The TCP peer
  the dev server sees is still the gate (127.0.0.1), and Host is rewritten
  to `localhost:<port>`.
- Share WebSockets are spliced only after the dev server confirmed 101,
  other upgrade offers (h2c) are served as plain HTTP/1.1, an upstream
  status below 100 becomes 502, an upstream that aborts mid-response is
  passed on as an aborted response, never as a complete one, and an early
  answer to an unfinished upload closes that upstream connection. The gate
  bounds the upstream connect (10 s) and response headers (15 s after the
  complete request body) like the gateway.
- Shares bind to port and process generation; expiry/stop/port change/
  generation change actively terminate tunnel, gate, streams, and WebSockets.
  Freshness policy: shares need recent verified discovery, are revoked when
  verification stays impossible beyond `shareVerifyGraceMs`, and never
  silently reactivate. The documented detection window is one scan period.
- `unshare-all` and daemon shutdown stop all tunnels in parallel (each stop
  waits about 1.5 s before SIGKILL); a tunnel still running when the
  shutdown backstop fires is killed, not orphaned.
- Tokens and sessions are memory-only; never logged in full, never persisted.
- Orphan tunnel cleanup verifies PID + process start time + executable
  before signaling, so PID reuse cannot kill an unrelated process.

## Native menubar app

- `macos/` is a SwiftPM package: `PortnameCore` (models, Unix-socket
  transport, typed client, state store) plus the SwiftUI `MenuBarExtra`
  executable. It is a **pure client** of the daemon's control socket
  (`~/.portname/daemon.sock`, JSON per line) — no second daemon, no second
  discovery, no GUI-side business logic; only harmless UI preferences are
  persisted.
- All daemon-owned invariants (routing, naming, Bonjour, shares, TTLs)
  stay with the daemon; the protocol is versioned and additively evolved
  (`docs/control-protocol.md`), with optimistic-concurrency guards on
  mutations.
- URLs are validated before hand-off to the system (only expected
  `*.localhost`/`*.local` http or the expected tunnel https host); no shell
  command strings are constructed anywhere in the app.

## Daemon lifecycle

- One daemon instance per machine, exclusive ownership via an instance lock
  with lifecycle states; the CLI and GUI are clients. The LaunchAgent runs
  an absolute, upgrade-stable Node path, unprivileged. It is `KeepAlive`
  with a `ThrottleInterval` of 30 s: a daemon that dies right after
  starting is restarted at most every 30 s, one that ran longer restarts
  at once.
- SIGINT, SIGTERM and SIGHUP run the orderly teardown under a 5 s backstop;
  an uncaught exception kills the tunnel children synchronously before the
  process exits.
- The daemon log (`~/.portname/daemon.log`) is bounded: at most 1 MiB plus
  one predecessor, rotated at start when over the cap and whenever it
  reaches the cap, the same event
  at most 20 times per minute, control characters escaped and long
  letter/digit runs redacted. Details: `docs/diagnostics.md`.
