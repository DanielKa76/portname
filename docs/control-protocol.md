# portname Control Protocol (v1)

The daemon exposes one local control channel: a Unix domain socket at
`$PORTNAME_DIR/daemon.sock` (default `~/.portname/daemon.sock`), created with
mode `0600`: the daemon binds it under a private temporary name in the same
directory, restricts it, and renames it into place. On stop it removes the
path only while it is still the socket it published (same device and inode),
never a socket another daemon put there. The socket path must fit the macOS
limit of 103 bytes; a longer `PORTNAME_DIR` is refused by `daemon` start and by `install` with a concrete
message (never silently truncated). Every request is a single JSON object followed by `\n`; every
response is a single JSON object followed by `\n`. **One request per
connection is enforced server-side**: the first complete line is the whole
request; the connection answers once and ends. A second line sent on the
same connection causes the daemon to close it without dispatching.

Framing is byte-exact: a request line may be up to 64 KiB (65536 bytes,
**excluding** the terminating `\n`; 65537 bytes on the wire). The line is
UTF-8-decoded only after it is complete, so a multibyte character split
across transport chunks is never corrupted.

This document describes protocol **version 1**. It is additive-only relative
to the pre-GUI MVP protocol: every field and command that existed before is
unchanged, and old clients (the CLI without the new fields) keep working.

## Response envelope

```json
{ "ok": true,  "...": "command-specific fields" }
{ "ok": false, "error": "human-readable message", "code": "STABLE_CODE" }
```

`error` is always present on failures and keeps the exact legacy wording.
`code` is optional and machine-readable. Current codes:

| Code | Meaning |
| --- | --- |
| `STALE_TARGET` | The client's view is outdated (route revision or share id mismatch), or an `expose { on: true }` was overtaken while it waited for its router lookup — by a later `expose { on: false }`/`remove` of the same project, a target change, or a network change; this one needs no expectation field (see `expose`). Re-read status and let the user act again; never retry blindly. |
| `SHARE_NOT_ACTIVE` | No active, unexpired share exists for that name (`share-link`). |
| `NAME_CONFLICT` | Name (or port) collision: rename/add was refused. |
| `INVALID_NAME` | Name failed DNS-label validation. |
| `INVALID_PORT` | Port out of range 1–65535. |
| `LAN_UNAVAILABLE` | LAN exposure impossible right now (loopback bind or no physical LAN interface). |
| `NETWORK_UNIDENTIFIED` | An `expose { on: true }` would replace the router binding of an exposure with the subnet alone: the Mac is in the confirmed subnet, but its router cannot be identified right now (e.g. just after wake). Nothing changed; the exposure resumes by itself once the router is identified (`network-unidentified`). Retry later; this is not a confirmation to offer. |
| `NO_ROUTE` | No running project under that name. |
| `SHARE_TARGET_UNVERIFIED` | A public share start was refused because the target is not freshly verified (last successful discovery scan too old or failed), because nothing was observed listening on a manual target's port, or because the target was just changed by an accepted mutation (remove, repoint, primary port switch) that no completed scan has re-verified yet. The displayed routes may still be shown (display state), but no new public share decision is taken from stale verification. |
| `REQUEST_TOO_LARGE` | Control request exceeded the 64 KiB line limit; the connection is closed afterwards. |
| `INVALID_REQUEST` | Malformed v1 request: a required guard field is missing (e.g. `share-link` without `expectedShareId`), or a request the command never accepts (e.g. `set-primary` for a manual entry, `rename` of a project whose root would be the filesystem root or the home folder). |
| `UNSUPPORTED_PROTOCOL` | Reserved: a client explicitly requires protocol features the daemon does not provide. |

## Versioning

`status` answers carry `protocolVersion` (currently `1`) and
`daemonInstanceId` (a fresh UUID per daemon run). A status answer without
`protocolVersion` comes from an **older daemon**: clients must degrade
gracefully — display is fine, new protocol-guarded mutations are not offered
against it. A changed `daemonInstanceId` means the daemon restarted; clients
must discard cached target bindings and any in-memory secret links.

Forward policy (fixed in v1, before any v2 exists): protocol evolution is
**additive-only**. A client that speaks v1 accepts any non-nil
`protocolVersion >= 1` and keeps working against it; a future daemon that
breaks additivity must bump the version, and v1 clients are expected to
degrade (unknown fields ignored, unknown commands answered with the legacy
`unknown command` error) rather than misbehave.

## `status`

All legacy fields are preserved (`proxyPort`, `bind`, `routes`, `stale`,
`exposed`, `shares`). Additions:

- `protocolVersion: 1`, `daemonInstanceId: "<uuid>"`
- `daemonVersion`, `runtimeVersion`, `payloadId` — additive v1 fields: the
  build identity of the running daemon (package version, the Node.js
  runtime actually serving the gateway, and the payload manifest id when it
  runs from the installed app payload, else `null`). Replacing the app does
  not update the LaunchAgent's payload; clients compare these against their
  own build to flag a stale background service (`portname doctor`:
  `daemon-build`, `node-runtime`).
- `lan: { available: boolean, reason: string|null }` — reason is e.g.
  `loopback-bind` or `no-lan-interface`.
- every route gains:
  - `id` — stable identity. Auto-discovered projects use the canonical
    project root path (same identity the exposure config uses); manual
    registrations use `manual:<name>`.
  - `revision` — 16 hex chars hashing daemon instance, identity, name,
    upstream host, port and the known process generation (PID/start time).
    Stable across identical polls; changes when the concrete target changes.
    Manual entries have no process generation, so none is invented.
  - `localUrl` — browser URL on this Mac, e.g. `http://name.localhost/` at
    gateway port 80 or `http://name.localhost:7777/` otherwise. Built by
    `lib/urls.js` from the *gateway* port; the upstream port never appears.
  - `lanUrl` — `http://name.local[:port]/` when exposure is requested **and**
    a LAN is currently available, else `null`. Offering a URL is not proof of
    end-to-end reachability from another device (see `exposureEffective` and
    `lanRegistration`).
  - `exposureRequested` — the stored per-project wish, independent of current
    LAN availability.
  - `exposureEffective` — additive v1 field: the **effective** WLAN exposure,
    derived from the SAME decision the gateway applies to every WLAN request
    (the desired flag AND the confirmed endpoint AND a fresh, tuple-bound
    target verification — never a recomputed lookalike). One of:
    - `"active"` — the gateway currently grants WLAN access to this target;
    - `"paused"` — the wish is set but access is currently withheld (see
      `exposurePauseReason`);
    - `"off"` — no exposure wish for this route.
    The advertised address (`lanUrl`) and the Bonjour advertisement keep
    reflecting the *desired* state (exceptions: Bonjour is withdrawn for
    `target-unconfirmed`, `target-changed`, `network-changed` and
    `network-unidentified`, see below): a findable address is not an active
    access grant — clients must gate any "reachable" claim on
    `exposureEffective`, not on `lanUrl`.
  - `exposurePauseReason` — additive v1 field, non-null only while
    `exposureEffective` is `"paused"`. Current values:
    - `target-not-verified` — the gateway would refuse WLAN requests: the
      target's tuple-bound verification is missing or older than
      `lanVerifyGraceMs` (sustained discovery failure). A fresh successful
      scan flips the route back to `"active"` without a new `expose`
      command.
    - `target-changed` — the route's current, verified primary is not the
      endpoint (port + command) confirmed by the last `expose` of this
      project: the name moved to another listener of the same tree (a newer
      dev server on another port, a debug/admin endpoint, a `set-primary`
      switch, a repointed manual entry). WLAN requests are refused and the
      Bonjour advertisement is **withdrawn**; `lanUrl` keeps showing the
      desired address. No scan heals it — only a new `expose { on: true }`
      confirms the current endpoint (`exposureTarget` names the confirmed
      one, the route's own `port`/`command` the one a confirmation would
      expose). A restart of the same command on the same port stays
      `"active"`. Reported only while the target is freshly verified
      (otherwise `target-not-verified` wins), i.e. exactly when `expose` can
      succeed.
    - `target-unconfirmed` — like `target-changed` (refused, withdrawn from
      Bonjour, healed only by `expose { on: true }`), but nothing moved: the
      wish was stored by an older daemon that recorded no endpoint
      (`exposureTarget` is `null`), so the endpoint it reaches now was never
      confirmed for the WLAN. Every exposure that predates endpoint binding
      reports this once after the update; clients should ask for a one-time
      confirmation rather than report a change. Same freshness precondition
      as `target-changed`.
    - `network-changed` — the exposure was confirmed on another network
      than the current one (the Mac joined another network: café,
      conference, hotel Wi-Fi). A network is the LAN subnet **and**, when it
      could be identified at confirmation time, its router: the MAC address
      of the LAN interface's default gateway, read without privileges from
      the routing table and the ARP cache (`route -n get -ifscope <if>
      default`, `arp -n <gateway>`; stored only as a truncated hash, never
      reported). So a network with the same default range behind another
      router (every Fritz!Box uses 192.168.178.0/24, every iPhone hotspot
      172.20.10.0/28) or a rogue AP that hands out the home range pauses
      too. Refused and withdrawn from Bonjour like `target-changed`; a new
      DHCP address in the same subnet, or Wi-Fi vs. Ethernet of the same LAN
      (same router), does not pause. Only a new `expose { on: true }`
      confirms another network. A router that cannot be identified right
      now is `network-unidentified`, not this reason. Limits: an exposure
      confirmed while no router could be identified (no default route on
      the LAN interface, not macOS) is bound to the subnet only, and a
      network that clones the confirmed router's MAC address is not told
      apart. The SSID is not used — reading it requires Location
      permission.
    - `network-unidentified` (additive) — the Mac is in the subnet a
      router-bound exposure was confirmed in, but no router can be
      identified right now (just after wake, before the ARP cache knows it
      again; a single failed lookup within `lanVerifyGraceMs` does not
      count). Refused and withdrawn from Bonjour like `network-changed`,
      but it heals by itself: the exposure resumes once the confirmed
      router is identified again, and turns into `network-changed` once
      another router is identified. Clients offer **no** confirmation for
      it — `expose { on: true }` is refused meanwhile with
      `NETWORK_UNIDENTIFIED`, so a confirmation can never replace the
      router binding with the subnet alone.
    - `no-lan-interface` / `loopback-bind` — mirrors `lan.reason`: no WLAN
      path exists at all right now.
    Clients must treat an unknown reason as "paused, reason unknown" — new
    reasons are additive.
  - `exposureTarget` — additive v1 field: `{ port, command, network,
    subnetOnly }` — the endpoint the exposure is bound to and the subnet it
    was confirmed on (`"192.168.1.0/24"`, `null` when unknown; compare with
    `lan.network`), or `null` (no exposure requested, or none confirmed yet —
    see `target-unconfirmed`). `subnetOnly` (additive) is `true` when no
    router could be identified at confirmation time: the binding is then the
    address range alone, and any network using that range counts as the
    confirmed one (see `network-changed`). The router identity is never
    reported.
  - `exposureVerifiedAt` — additive v1 field: the unix-ms timestamp the
    effective decision is actually based on (the endpoint-tuple verification
    record), or `null` when the target has no verification record. Clients
    may display the verification age; enforcement stays daemon-side.
  - `lanRegistration` — additive v1 field: the Bonjour registration of the
    `lanUrl` name (`<name>.local`) as far as the daemon knows it — `dns-sd`
    reports no success back — or `null` while the name is not advertised
    (no exposure requested, no LAN, withdrawn for one of the pause reasons
    above). One of:
    - `"registering"` — the registration was started moments ago;
    - `"registered"` — the registration has been running for a while;
    - `"conflict"` — `dns-sd` ended right after the start with "name in
      use": another device on the network already answers for
      `<name>.local`, so `lanUrl` leads other devices there, not to this
      Mac. The name is retried with a growing backoff; another project name
      avoids the clash. Clients must not present `lanUrl` as reachable
      while this lasts (the CLI marks it as "name in use");
    - `"retrying"` — the registration ended right after the start for
      another reason and is retried with a backoff.
    It does not change `exposureEffective` (the gateway's access decision is
    the same; only the name may lead elsewhere). Clients treat an unknown
    value like `null` — new values are additive.
- every share gains `shareId` — a random, **non-secret**, non-persisted
  identifier of this share instance, renewed for every new share. `url` in
  status remains the public origin **without** the secret token.
- every share gains `lastVerifiedAt` — the timestamp of the last successful
  discovery pass that confirmed the share's binding (port, upstream host,
  process generation). The age is **honest**: a share inherits the timestamp
  of the scan that passed its start freshness gate, and becoming `ACTIVE`
  (tunnel ready) never stamps a fresh one. Daemon-side policy: a share whose
  verification is older than the grace window because discovery kept failing
  is revoked (bounded, currently 20 s) — this includes a share still
  `STARTING` whose slow tunnel boot outlives the window — and a startup that
  would only complete after its verification expired is refused with a
  defined error instead of activated. A single failed scan defers
  revocation. A later successful scan never re-activates a revoked share —
  only an explicit `share` command starts a share.
- every auto-discovered route gains:
  - `services` — every usable listener of the winning process generation
    (`{port, upstreamHost, command, pid, processKey, since, primary}`),
    primary first. A project with a frontend AND a backend is the normal
    multi-service case; extra services are not "overhauled".
  - `preferredPort` — the stored per-root user preference (null if none).
  - `preferredMissing` — true when the preference points at no living
    listener: the route fell back to the default rule and the UI should say
    so instead of implying the user's choice is active.
- **Service identity model** (three separate identities):
  - *Project/worktree identity* — the canonical root directory (`route.id`);
    two parallel worktrees of one repository are two different projects and
    never inherit each other's names, LAN exposure or public shares.
  - *Service identity (role)* — the port inside a project, surfaced as
    `serviceId` = `<project root>#<port>` on every `services` and `stale`
    entry. A port change of the same role is a new `serviceId` under the
    same project identity; it never lets one project take over another.
  - *Process generation* — `processKey` (PID + start time) on every service
    entry and on the route (the primary's generation).
  - Consequently `services` may contain listeners of **other living process
    generations** of the same project: a frontend (PID A, :5173) and a
    backend (PID B, :3333) are simultaneously valid services. Such entries
    carry `crossGeneration: true`; entries of the primary's own generation
    carry `crossGeneration: false`.
- `scanError` — string when the last discovery scan failed. Routes shown are
  the previous scan's result (possibly outdated); a failed scan never looks
  like "all projects stopped".
- `lastGoodScanAt` — unix-ms timestamp of the last successful discovery pass
  (null before the first one). Display/diagnostic metadata; the enforcement
  of share freshness windows happens daemon-side.
- `lanVerifyGraceMs` — additive v1 field: the WLAN exposure continuation
  grace (currently 20000 ms). WLAN access to an exposed project is bounded
  by target-verification freshness: new WLAN requests are refused and
  established WLAN streams (WebSocket/SSE) torn down once the exposing
  target has not been verified by a successful scan for this long (clients
  can derive the remaining window from `lastGoodScanAt`). Revocation runs on
  the next refresh pass after the deadline, so the teardown latency is
  bounded by roughly one scan period (`REFRESH_MS` + scan budget), never
  0 ms. The persisted `exposureRequested` wish is unaffected — a fresh
  successful scan re-enables access without a new `expose` command.
- `state` — daemon lifecycle: `STARTING`, `RUNNING`, `STOPPING`, `STOPPED`.
  After `STOPPING` begins the daemon answers only read-only commands
  (`status`, `share-link`, `unshare`, `unshare-all`) and refuses everything
  that publishes or starts resources with error code `DAEMON_STOPPING`. A
  second daemon started against the same state directory fails with error
  code `DAEMON_ALREADY_RUNNING` before touching the socket or any child
  process. So does a start while a daemon that holds no instance lock (an
  older version, or a lock file removed by hand) still answers on
  `daemon.sock`; a socket file nobody serves (left by a crash) is replaced.
- `lan` additionally carries `interfaceName` (BSD name of the selected
  LAN/Wi-Fi interface, e.g. `"en0"`), `address` (its IPv4 address) and
  `network` (its subnet, e.g. `"192.168.1.0/24"`, comparable with
  `exposureTarget.network`), all nullable and additive for clients: a
  change of interface and address between polls
  means the machine changed networks, and UIs must re-label accordingly
  instead of continuing to present the same trusted Wi-Fi. The CLI's
  `status --json` export deliberately drops `address` (see
  docs/diagnostics.md, redaction rules).

`stale` entries stay diagnostic-only. A listener is listed there only when it
is genuinely not a service of the routed project: an inspector/debug port (in
any generation) or a listener of another living generation whose **port**
(i.e. service role) the winning generation also serves. A different port of
another generation is a different, simultaneously valid role and appears in
`route.services` with `crossGeneration: true` instead — a different PID alone
never means "stale server". Stale entries carry `serviceId` and the `name` of
their own project; they are never valid `set-primary` targets for a different
project.

## Commands

Legacy commands keep their request shape: `refresh`, `rename {name,newName}`,
`add {name,port}`, `remove {name}`, `expose {name,on}`,
`share {name,ttlMinutes}`, `unshare {name}`.

Additions:

- **`remove { name }`** — the name is canonicalized the way `add` stores
  it (lower case, surrounding spaces trimmed: `"Shop"` and `" shop "`
  remove the entry `shop`), and the answer `{ removed, existed }` carries
  the canonical name. `existed` (additive) is `false` when no manual entry
  had that name: the remove was a no-op — nothing was removed and no share
  invalidated — not a success to report. Older daemons send no
  `existed`; clients then keep the legacy reading.

- **`share-link { name, expectedShareId }`** — read-only. Returns
  `{ url, expiresAt, shareId }` (the full secret link) only when the active,
  unexpired share for `name` still has exactly `expectedShareId`.
  `expectedShareId` is **required and server-enforced** since this hardening
  round: a request without a non-empty value fails with `INVALID_REQUEST`
  before anything is looked up (fail-closed — a caller that never learned the
  current shareId can never pull the secret link). A non-empty but wrong
  value fails with `STALE_TARGET`, an inactive share with
  `SHARE_NOT_ACTIVE`. It never starts a tunnel, mints a token or touches a
  timer. This is the only sanctioned way for a *running* client to obtain a
  secret link after the creating action; see the security note below.
- **`expectedRouteRevision`** — optional field on `rename`, `add`-adjacent
  mutations (`remove`), `expose`, `share`, `unshare`. When present it is
  validated strictly *before* any effect; a mismatch fails with
  `STALE_TARGET`. When absent (old CLI) the client's view is not compared;
  the arrival-order checks of `expose { on: true }` still apply and can fail
  with `STALE_TARGET` without any expectation field (see `expose`).
  (`unshare` validates both guards when present: route revision first, then
  share id.)
- **`expectedShareId`** — optional field on `unshare` and **required** on
  `share-link`. Binds the action to one share instance so a stale view can
  never stop or read a *newer* share. A targeted stop with the matching id
  also works while the share is `STARTING`.
- **`createOnly`** — optional flag on `add`. With `createOnly: true` an
  existing manual name fails with `NAME_CONFLICT` instead of the legacy
  upsert. The GUI's add form always sends it; the CLI keeps the upsert.
- **`set-primary { name, port, expectedRouteRevision? }`** — chooses which
  living service of a project carries the name (e.g. the frontend instead of
  the API). The port must belong to the project — to its winning generation
  or a cross-generation service (`route.services`, including the
  `crossGeneration: true` entries) **or** to one of its superseded
  same-role listeners (`stale` entries with the same name) — pointing the
  name at an older frontend is the canonical use; the preference then
  resolves to the newest *living* generation carrying that port. The
  preference is stored per project root, honours future generations carrying
  the same port, and survives daemon restarts.
  Manual registrations are not applicable (`INVALID_REQUEST`).
- **`unshare-all`** — revokes **every** live public link
  (`ACTIVE`, `STARTING`, and already `STOPPING` instances are awaited);
  answers `{ stopped: [names] }` and is idempotent (`stopped: []`). It uses
  the same per-share stop path as a targeted `unshare` — no shortcut that
  could skip the bounded teardown — and stays available while the daemon is
  stopping (revocation is never scan-bound). This is the daemon side of the
  GUI's distinctly labeled "end all public links" action and the CLI's
  `portname unshare-all`. Revocation safety: the sweep advances a
  revocation generation *before* stopping anything, so a `share` (re)start
  that was already accepted and is still waiting on another share's teardown
  is cancelled with a defined error instead of silently starting its public
  link after the revocation; new `share` starts are refused with a plain
  error while the sweep is running. The same generation guard covers the
  daemon shutdown sweep, so no waiting start can outlive `stop()`.
- **`expose { name, on }`** — desired vs. allowed exposure are separated.
  Activation (`on: true`) is a decision like a `share` start and requires the
  target to have been verified by a successful scan within the share
  freshness window; otherwise it fails with `LAN_TARGET_UNVERIFIED` (after
  the existing `LAN_UNAVAILABLE` checks). Activation binds the exposure to
  the endpoint it verified — the route's current port and command — and to
  the current network (subnet and, when identified, router; see
  `network-changed`), and is persisted with them (config.json
  `exposedTargets`); the answer gains `target: { port, command, network,
  subnetOnly }` (additive; `subnetOnly: true` means the router could not be
  identified and the binding is the address range alone — the CLI says so).
  Sending `on: true` again for an exposure paused with
  `target-unconfirmed`, `target-changed` or `network-changed` confirms the
  current endpoint/network. In the subnet of a router-bound exposure it
  fails with `NETWORK_UNIDENTIFIED` (whatever the pause reason) while no
  router can be identified: a confirmation never weakens a router binding
  to the subnet alone. `exposureRequested` stays `true` throughout, so
  clients must offer this confirmation for such a paused route — a toggle
  that only offers `on: false` for a requested exposure cannot resume it. GUI
  clients send `expectedRouteRevision` so the confirmation binds exactly the
  target the user saw. If the activation cannot be persisted it is rolled
  back and the error is returned — nothing answers on the LAN. Revocation
  (`on: false`) is scan-independent: the project's established WLAN streams
  (WebSocket/SSE) are closed immediately in the handler, never held open
  until the next (possibly blocked or failing) scan pass — also when
  persisting the switch-off fails (it stays in effect; the error is
  returned). Loopback traffic is never touched.

  Exposure decisions take effect in arrival order. An activation looks up
  the current router first (bounded: about 3.5 s per lookup at most, also
  when `route` or `arp` hangs — such a lookup identifies no router); the route it
  confirms and the network the Mac is on are taken when the request
  arrives. `expose { on: true }` therefore fails with `STALE_TARGET` — also
  without `expectedRouteRevision`, i.e. from the CLI — when, during that
  lookup:
  - a later `expose { on: false }` or `remove` of the same project was
    applied (the revocation stays in effect);
  - the name came to denote another target (route revision) than on
    arrival, e.g. a newer listener took it over;
  - the Mac moved to another network: another subnet, or the same subnet
    behind another router (compared where both routers are identified).
    Nothing is bound to a network the user did not confirm. A new address
    in the same subnet (a DHCP renewal) is the same network: the router is
    looked up once more for it, and the activation proceeds.
  With `expectedRouteRevision`, the route must in addition still carry the
  revision the client saw. Concurrent activations of the same project share
  one router lookup and both succeed in arrival order; decisions about other
  projects never affect a waiting activation. Revocations (`on: false`, `remove`)
  always apply immediately. On `STALE_TARGET` clients re-read `status` and
  let the user decide again; they never retry blindly.

Timeout note: a mutation request that times out on the client side may still
have taken effect daemon-side. Clients reconcile via `status` instead of
blindly retrying. The reconciliation must verify the *effect*, not a
lookalike: the same display name alone proves neither a successful rename,
add, set-primary nor share. Clients tie the check to the stable route `id`
(plus `daemonInstanceId` — a restart voids everything), and for the actual
expected properties: rename → the route with that `id` now carries the new
name; add → a *manual* route (`root: null`) with that name; set-primary → the
route's stored `preferredPort`; share → a live share for that name pinned to
the intended target port; Wi-Fi confirmation (`expose` on while the exposure
is already requested) → the route's `exposureTarget` now names exactly the
endpoint (port, command) and the `lan.network` the client showed when the
user confirmed, and the route no longer awaits a confirmation — another pause
reason or a return to the previous binding proves nothing, and when that
tuple equals the binding before the request (same address range, another
router) the outcome stays unclear. A poll that cannot reconstruct the outcome
must be shown as "unclear", never as a fabricated confirmation.

Client reconciliation honesty for shares (additive guidance): state
observation ("a share is visible") and operation proof ("your request
produced this share") are different claims. A share `STARTING` after a lost
start response is *accepted, in progress* — clients keep waiting instead of
confirming an activation that has not happened yet; a poll that finds the
share gone later reports an unclear outcome, never success. A confirmation
of activation additionally requires the proof fields to be present and
matching (target port, requested ttl, the expiry window derived from the
issue time): a snapshot missing any of them degrades to "unclear" — a time
window alone is not attribution. An add whose target entry may predate the
request (created concurrently, e.g. via the CLI) can only ever be confirmed
as "the entry is now visible", not as "your request created it".

## Security note (deliberate decision)

Share tokens were previously described as "only echoed to the CLI that
requested the share". With the GUI the wording is intentionally narrowed to
"only echoed to an explicitly requesting local client": the full secret link
is returned (a) by `share` to the client that created it, and (b) by
`share-link` to a client that explicitly asks for it **and** proves it knows
the current non-secret `shareId`. Tokens still never appear in `status`,
poll responses, logs or persisted state. No other part of the security model
was relaxed.
