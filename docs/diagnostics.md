# portname Diagnostics: `status --json` and `doctor`

Both commands are **strictly read-only**: they collect facts, print them and
exit. They repair nothing, restart nothing, open no tunnel and touch no
setting. This documents the machine-readable contract; the daemon-side
protocol additions are in `docs/control-protocol.md`.

## Redaction rules (apply to every machine-readable output)

- **No tokens, no cookies.** The daemon never puts share tokens or session
  cookies into status answers; the CLI adds nothing of that kind.
- **No share origins and no share ids.** An exported report must not contain
  a working demo link or the id that guards it. Shares appear only as
  `name`, `state`, `expired`, `expiresAt`, `ttlMinutes`.
- **No project paths.** Route fields `root`, `cwd`, `id` (identity carries
  the canonical root), `pid`, `processKey` and `upstreamHost` are dropped.
- **No LAN IP address.** The interface *name* (e.g. `en0`) is kept because it
  explains Wi-Fi reach; the address itself stays private.
- The state directory is referenced in remedies only where the fix needs it
  (`chmod 700 <dir>`); it is never dumped as a field.
- **No home path in check details.** Paths under the home directory (the
  LaunchAgent plist, a bundled `cloudflared`) are shown home-relative
  (`~/Library/…`), so a pasted report does not carry the account name.
  Paths inside daemon free text (`scanError`, `daemonError`) are masked to
  `[path]`, including paths with spaces (`/Volumes/Kunde Müller GmbH/…`).

## `portname status --json`

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | The daemon answered; the snapshot was printed. |
| `1` | The daemon was unreachable or answered with an error (message on stderr, no JSON body). |

Schema `portname.status/1` (fields may grow additively; nothing is removed):

```json
{
  "schema": "portname.status/1",
  "generatedAt": 1780000000000,
  "versions": { "cli": "0.1.0", "node": "v26.12.1", "protocol": 1,
                "daemonInstanceId": "…", "daemon": "0.1.0",
                "daemonRuntime": "v26.12.1" },
  "daemon": { "reachable": true, "state": "RUNNING", "bind": "wildcard",
              "bindPort": 80, "scanError": null, "lastGoodScanAt": 1779999998000 },
  "lan": { "available": true, "reason": null, "interfaceName": "en0" },
  "installation": { "stateDirPrivate": true, "launchAgentInstalled": true,
                    "cloudflaredFound": true },
  "routes": [ { "name": "shop", "port": 3000, "command": "node",
                "manual": false, "external": false,
                "exposureRequested": false, "localUrl": "http://shop.localhost/" } ],
  "staleCount": 0,
  "shares": [ { "name": "shop", "state": "ACTIVE", "expired": false,
                "expiresAt": 1780003600000, "ttlMinutes": 60 } ],
  "remedies": []
}
```

`versions.node` is the runtime of the CLI process; `versions.daemon` and
`versions.daemonRuntime` come from the running daemon (`null` from daemons
that predate build reporting).

`remedies` lists one concrete next action per detectable problem (daemon not
`RUNNING`, legacy protocol, failed scan, missing LaunchAgent, state dir
permissions, missing `cloudflared`, a background service that runs another
build than this CLI/app, a Node.js runtime below the security floor). An empty array means the snapshot found
no problem.

## `portname doctor`

Human-readable by default, `--json` for machines (schema
`portname.doctor/1`: `{ schema, generatedAt, summary: {ok,warn,fail,skip},
checks: [...], remedies: [...] }`). Every check is
`{ id, severity, detail, remedy? }` with severity `ok | warn | fail | skip`;
`skip` marks what could not be judged (daemon unreachable) and is never
presented as a pass.

Checks:

| id | judges |
| --- | --- |
| `daemon-socket` | the control socket answers (`fail` + remedy when not) |
| `protocol-version` | daemon speaks protocol v1 (`warn` for pre-v1 daemons) |
| `daemon-state` | lifecycle state is `RUNNING` (`warn` for `STARTING`/`STOPPING`/`STOPPED`) |
| `discovery` | last scan succeeded and when (`warn` on `scanError` / no successful scan yet) |
| `gateway-port` | the bound gateway port answers on loopback (bounded TCP probe, no HTTP request sent) |
| `launch-agent` | the `dev.portname.daemon` LaunchAgent is installed (`warn`) |
| `state-dir` | state dir exists and has mode 700 (`fail` with `chmod 700` remedy when too open) |
| `cloudflared` | the binary a share start would use resolves (config override → bundled payload binary → Homebrew → PATH) (`warn`; only needed for public links) |
| `shares` | informational count of active/starting public links |
| `daemon-build` | the running daemon is the build this CLI expects: inside the app, the payload id matches the app's `MANIFEST.json`; otherwise the daemon version equals the CLI version (`warn` with the reinstall remedy; `skip` when unreachable or pre-v1) |
| `node-runtime` | the runtime serving the gateway (the daemon's, else this CLI's) is at or above the security floor of its LTS line — currently 22.23.4 / 24.22.1 / 26.12.1, newer lines pass (`warn`; remedy depends on source install vs. bundled runtime) |

The text report ends with the state dir and the daemon log path (the
`discovery` remedy refers to it); the JSON report carries neither.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Daemon answered and no check failed (warnings possible). |
| `1` | At least one check failed (`state-dir` too open, gateway port dead, …). |
| `2` | The daemon did not answer; daemon-dependent checks are `skip`, local checks are still reported. |

## The daemon log

Under the LaunchAgent the daemon writes `daemon.log` in the state directory
(`~/.portname/daemon.log`, the file the menubar app reveals). One line per
event, ISO timestamp first: start and start failures, share starts (public
origin and `shareId` only), revocations with their reason, TTL expiry,
tunnel exits, orphan kills, lock takeovers, scan errors, Bonjour changes and
refused gateway requests. Discovery logs each change of its state, not every
failed pass: `discovery scan-failed <reason>` when scans start failing (or
fail for another reason, the `scanError` of `status`) and
`discovery recovered` with the previous error once a pass succeeds again.

- **Bounded.** At most 1 MiB per file plus one predecessor
  (`daemon.log.1`); the log is rotated at start when it is over the cap,
  and whenever it reaches the cap, so a permanent start failure under
  `KeepAlive` (respawned at most every 30 s via `ThrottleInterval`) or a
  request flood cannot fill the disk.
- **Rate-limited.** The same event (first two fields, e.g. `reject 404`)
  is written at most 20 times per minute; the rest is summarized as
  `log suppressed N similar line(s): …`.
- **No secrets.** Call sites never pass share tokens; as a second line of
  defense every long mixed letter/digit run is replaced by `[redacted]`.
  Control characters are escaped, so a hostile `Host` header or process
  name cannot forge log lines. The log is local and private (state dir
  `0700`); it may contain project names, local paths and the LAN address.

Run in a terminal (`portname daemon`), the same lines go to stderr.
