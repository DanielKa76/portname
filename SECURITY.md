# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the
repository's Security tab and choose "Report a vulnerability". Do not open a
public issue for a security problem.

A useful report names the affected component (daemon and CLI, macOS app,
public-share gate), your macOS and Node versions, a minimal reproduction and
the impact. Never include real secrets or share tokens.

portname is a spare-time project without a support contract. Reports are
handled on a best-effort basis, usually acknowledged within 7 days. Fixes
are disclosed in coordination with the reporter, with credit on request.

## Supported versions

Security fixes go into the current `main` branch and the latest release
only.

Supported configuration: macOS 14 or later; the app bundle is built for
Apple silicon only. The CLI from source needs a Node version listed under
`engines` in `package.json`. The daemon runs unprivileged: no root, no
setuid, no privileged helper is required or supported. Forked or patched
builds are not supported configurations.

The app bundle ships its own pinned Node runtime and `cloudflared`
(`scripts/runtime-pin.env`). Keeping those copies current is this project's
job: a vendor security release that affects a pinned version leads to a
re-pin and a new release. There is no auto-update.

## Scope

In scope:

- the Node daemon and CLI (`lib/`, `bin/`) and the macOS app (`macos/`)
- the control socket protocol (`docs/control-protocol.md`) and the
  permissions of its Unix socket
- the local gateway: routing, zone gating (loopback, Wi-Fi, public) and
  header handling
- the public-share gate: token and session handling, revocation, and the
  binding of a share to its target port and process

Out of scope:

- vulnerabilities in third-party software itself (`cloudflared`, Node,
  macOS); please report those to the vendor
- local attacks by the same macOS user against their own daemon
- social engineering

## Known boundaries

These are documented design limits, not vulnerabilities by themselves. A
report that shows how one of them can be exploited is welcome.

- Public links run over Cloudflare quick tunnels: no SLA, a cap on
  concurrent requests, no Server-Sent Events. Tokens and sessions live in
  memory only and die with the share.
- A changed process or port behind a share is detected within one scan
  period; a share whose target cannot be verified is revoked after the
  verification grace (`docs/architecture-notes.md`).
