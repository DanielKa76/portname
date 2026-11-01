'use strict';

// Read-only diagnosis support for `portname status --json` and
// `portname doctor` (docs/diagnostics.md). Both commands only read: nothing
// is repaired, no tunnel is started, no setting is touched.
//
// Redaction rules for every machine-readable output (docs/diagnostics.md):
// - no share tokens or session cookies (the daemon never puts them in
//   status answers in the first place),
// - no share origins or share ids (an exported report must not contain a
//   working demo link),
// - no project paths (route.root/cwd) and no process identities (pid,
//   processKey, upstream host),
// - paths reaching the export inside daemon free text (scanError,
//   daemonError) are masked to "[path]" — see maskPaths below,
// - no LAN IP address (the interface NAME is kept: it explains WLAN reach
//   without pinpointing a network).

const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

// Same resolver the daemon uses for share starts (lib/share.js) — doctor and
// status must report the tunnel binary that would ACTUALLY run.
const { resolveCloudflaredBin } = require('./share');
const { appBundleLayout, readManifest } = require('./bundleinstall');

const STATUS_SCHEMA = 'portname.status/1';
const DOCTOR_SCHEMA = 'portname.doctor/1';
const LAUNCH_AGENT_LABEL = 'dev.portname.daemon';

// Executable lookup along PATH (no subprocess, deterministic for tests).
function which(bin, { pathEnv = process.env.PATH || '', stat = fs.statSync } = {}) {
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, bin);
    try {
      const st = stat(candidate);
      if (st.isFile() && st.mode & 0o111) return candidate;
    } catch {
      // not present in this PATH entry
    }
  }
  return null;
}

// Minimum patch release per supported Node.js line: the newest security
// release fixing HTTP issues reachable through the gateway and share gate
// (Oct 2026: CVE-2026-105481; Jul 2026: CVE-2026-58044 request smuggling via
// header truncation; Jun 2026: CVE-2026-48931). package.json "engines"
// documents the same floor; engines is not enforced at runtime, this is.
// Raise it with every security release that touches node:http.
const NODE_RUNTIME_FLOORS = { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' };

// { ok, detail } for a Node.js version string ("v24.22.1"). Lines newer than
// every known floor pass; unknown older lines (odd/EOL majors) do not.
function nodeRuntimeVerdict(version) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(version ?? ''));
  if (!m) return { ok: false, detail: `unrecognized Node.js version ${version}` };
  const [major, minor, patch] = m.slice(1).map(Number);
  const floor = NODE_RUNTIME_FLOORS[major];
  if (!floor) {
    const newest = Math.max(...Object.keys(NODE_RUNTIME_FLOORS).map(Number));
    return major > newest
      ? { ok: true, detail: `Node.js ${version}` }
      : { ok: false, detail: `Node.js ${version} is not a supported LTS line (22, 24 or 26)` };
  }
  const [, fMinor, fPatch] = floor.split('.').map(Number);
  if (minor > fMinor || (minor === fMinor && patch >= fPatch)) {
    return { ok: true, detail: `Node.js ${version} (security floor v${floor})` };
  }
  return { ok: false, detail: `Node.js ${version} is older than the security floor v${floor} of its line (known node:http fixes missing)` };
}

function runtimeRemedy(status) {
  return status && status.payloadId
    ? 'The background service runs the runtime bundled with Portname: update the app, then run portname-cli install once.'
    : 'Update Node.js to the current 24 or 26 LTS release (Node 22 ends 2027-04-30), then restart the daemon: portname install';
}

// The app payload this CLI belongs to (null outside an app bundle).
function appBundleManifest(entryDir = __dirname) {
  const layout = appBundleLayout(entryDir);
  if (!layout.isBundle) return null;
  const manifest = readManifest(layout.resourcesDir);
  return manifest ? { ...manifest, appPath: layout.appPath } : null;
}

// Is the RUNNING daemon the build this CLI/app expects? Replacing the app
// does not update the LaunchAgent's payload (docs/macos-bundle.md), so a
// skipped `portname-cli install` would otherwise go unnoticed.
function buildVerdict({ status, cliVersion, bundleManifest }) {
  const daemon = `daemon ${status.daemonVersion ?? '?'} on node ${status.runtimeVersion ?? '?'}`;
  if (status.daemonVersion == null) {
    return { ok: false, detail: 'the daemon does not report its build (older than this CLI)',
      remedy: 'Restart the background service with this version: portname install (ends active public links).' };
  }
  if (bundleManifest && bundleManifest.payloadId && status.payloadId !== bundleManifest.payloadId) {
    return { ok: false, detail: `the background service runs a different payload than this app (${daemon})`,
      remedy: 'Run portname-cli install once (Portname.app/Contents/Resources/bin/portname-cli) — it updates and restarts the background service and ends active public links.' };
  }
  if (!bundleManifest && cliVersion && status.daemonVersion !== cliVersion) {
    return { ok: false, detail: `${daemon}, but this CLI is ${cliVersion}`,
      remedy: 'Restart the daemon so it runs this version: portname install (ends active public links).' };
  }
  return { ok: true, detail: daemon };
}

function launchAgentPath(home = os.homedir()) {
  return path.join(home, 'Library', 'LaunchAgents', `${LAUNCH_AGENT_LABEL}.plist`);
}

// Resolves the cloudflared binary the way a share start would (fixed
// precedence, docs/macos-bundle.md "cloudflared resolution"): an explicit
// `cloudflaredBin` override wins, then the bundled payload binary in payload
// operation, then Homebrew locations — and only the PATH fallback goes
// through `which`. Returns null when nothing resolves (the not-found case).
// home/isPayloadEntry are injectable for tests, as in lib/share.js.
function resolveCloudflared({
  override = 'cloudflared',
  home,
  isPayloadEntry,
  which: whichFn = which,
} = {}) {
  const resolved = resolveCloudflaredBin(override, { home, isPayloadEntry });
  if (resolved !== 'cloudflared') return resolved;
  return whichFn('cloudflared');
}

// Home-relative spelling for paths shown in doctor details: the account
// name in /Users/<name>/… is not needed to act on a check, and reports get
// pasted into public issues.
function tildify(p, home = os.homedir()) {
  const s = String(p);
  if (home && (s === home || s.startsWith(home + path.sep))) return '~' + s.slice(home.length);
  return s;
}

function dirMode(dir, stat = fs.statSync) {
  try {
    return stat(dir).mode & 0o777;
  } catch {
    return null;
  }
}

// Masks filesystem paths in daemon free text (defense in depth: a scan
// failure can embed lsof stderr, which quotes absolute paths such as
// /Users/<user>/…). A path is a token starting with `/`, or a home-relative
// `~/…`/`~name/…`, right after the start of the string, whitespace or an
// opening delimiter — mid-word slashes ("and/or") and rhetorical tildes
// ("~50ms") never match. A path with spaces ("/Volumes/Kunde Müller
// GmbH/Projekte") continues across up to three slash-less words when a
// later word continues it with a slash; plain prose after a path ("…:
// Permission denied (errno 13)") has none and is preserved.
const PATH_TOKEN = /(^|[\s(\['"=:])((?:\/|~(?:\/|[A-Za-z0-9._-]+\/))[^'"\s]*(?:(?:\s+[^\s'"/]+){0,3}\s+[^\s'"]*\/[^'"\s]*)*)/g;

function maskPaths(text) {
  if (typeof text !== 'string') return text;
  return text.replace(PATH_TOKEN, (_all, prefix) => `${prefix}[path]`);
}

// Builds the redacted, machine-readable status snapshot from a daemon
// `status` control answer. Everything here is display state; the caller's
// fs/environment facts come in as injectable values so the snapshot is
// testable without touching a real installation.
function statusSnapshot({
  status,
  dir,
  now = Date.now(),
  cliVersion,
  nodeVersion = process.version,
  launchAgentPath: agentPath = launchAgentPath(),
  exists = fs.existsSync,
  statMode: modeOf = dirMode,
  which: whichFn = which,
  resolveCloudflared: resolveCf = (opts = {}) => resolveCloudflared({ ...opts, which: whichFn }),
  cloudflaredBin,
  home,
  isPayloadEntry,
  bundleManifest = appBundleManifest(),
} = {}) {
  const mode = modeOf(dir);
  const launchAgentInstalled = exists(agentPath);
  const stateDirPrivate = mode === 0o700;
  const cloudflaredFound = Boolean(resolveCf({ override: cloudflaredBin, home, isPayloadEntry }));
  const protocol = status.protocolVersion ?? null;

  const remedies = [];
  if (protocol === null) {
    remedies.push('The daemon predates protocol v1 — update portname and restart the daemon (portname install).');
  }
  if (status.state && status.state !== 'RUNNING') {
    remedies.push(`The daemon is in state ${status.state}. "portname install" (re)starts the LaunchAgent.`);
  }
  if (status.scanError) {
    remedies.push(`The last discovery scan failed (${maskPaths(status.scanError)}) — projects shown may be outdated. Check the daemon log (daemon.log in the state directory; portname doctor prints its path).`);
  }
  if (!launchAgentInstalled) {
    remedies.push('No LaunchAgent is installed — the daemon will not start at login. Run: portname install');
  }
  if (!stateDirPrivate) {
    remedies.push(`The state directory permissions are too open (expected 700) — run: chmod 700 ${dir}`);
  }
  if (!cloudflaredFound) {
    remedies.push('cloudflared was not found — public demo links need it (e.g. brew install cloudflared). Everything else works without it.');
  }
  if (protocol !== null) {
    const build = buildVerdict({ status, cliVersion, bundleManifest });
    if (!build.ok) remedies.push(`${build.detail} — ${build.remedy}`);
  }
  const runtime = nodeRuntimeVerdict(status.runtimeVersion ?? nodeVersion);
  if (!runtime.ok) remedies.push(`${runtime.detail} — ${runtimeRemedy(status)}`);

  return {
    schema: STATUS_SCHEMA,
    generatedAt: now,
    versions: {
      cli: cliVersion,
      node: nodeVersion,
      protocol,
      daemonInstanceId: status.daemonInstanceId ?? null,
      // The running daemon's own build and runtime (null from older daemons);
      // `node` above is the runtime of this CLI process.
      daemon: status.daemonVersion ?? null,
      daemonRuntime: status.runtimeVersion ?? null,
    },
    daemon: {
      reachable: true,
      state: status.state ?? null,
      bind: status.bind ?? null,
      bindPort: status.proxyPort ?? null,
      scanError: maskPaths(status.scanError) ?? null,
      lastGoodScanAt: status.lastGoodScanAt ?? null,
    },
    lan: {
      available: Boolean(status.lan && status.lan.available),
      reason: (status.lan && status.lan.reason) || null,
      // The interface name explains WLAN reach; the address stays private.
      interfaceName: (status.lan && status.lan.interfaceName) || null,
    },
    installation: {
      stateDirPrivate,
      launchAgentInstalled,
      cloudflaredFound,
    },
    routes: (status.routes || []).map((r) => ({
      name: r.name,
      port: r.port,
      command: r.command ?? null,
      manual: Boolean(r.manual),
      external: Boolean(r.external),
      exposureRequested: Boolean(r.exposureRequested),
      // Effective WLAN exposure (daemon v1.x+): "active" / "paused" / "off",
      // with the machine-readable pause reason. An older daemon sends no
      // such fields — the export reports null (unknown), never an invented
      // state.
      exposureEffective: r.exposureEffective ?? null,
      exposurePauseReason: r.exposurePauseReason ?? null,
      localUrl: r.localUrl ?? null,
    })),
    staleCount: (status.stale || []).length,
    shares: (status.shares || []).map((s) => ({
      name: s.name,
      state: s.state,
      expired: Boolean(s.expired),
      expiresAt: s.expiresAt ?? null,
      ttlMinutes: s.ttlMinutes ?? null,
    })),
    remedies,
  };
}

// One doctor check: { id, severity: ok|warn|fail|skip, detail, remedy? }.
// `skip` means "cannot be judged right now" (the daemon did not answer) and
// is never presented as a pass.
function doctorChecks({
  status,
  daemonError = null,
  dir,
  launchAgentPath: agentPath = launchAgentPath(),
  gatewayProbe = null,
  exists = fs.existsSync,
  statMode: modeOf = dirMode,
  which: whichFn = which,
  resolveCloudflared: resolveCf = (opts = {}) => resolveCloudflared({ ...opts, which: whichFn }),
  cloudflaredBin,
  home,
  isPayloadEntry,
  cliVersion,
  nodeVersion = process.version,
  bundleManifest = appBundleManifest(),
} = {}) {
  const checks = [];
  const add = (id, severity, detail, remedy = undefined) =>
    checks.push(remedy === undefined ? { id, severity, detail } : { id, severity, detail, remedy });

  if (!status) {
    add('daemon-socket', 'fail', `daemon did not answer (${maskPaths(daemonError)})`,
      'Start the daemon: portname install');
    add('protocol-version', 'skip', 'daemon unreachable');
    add('daemon-state', 'skip', 'daemon unreachable');
    add('discovery', 'skip', 'daemon unreachable');
    add('gateway-port', 'skip', 'daemon unreachable');
    add('daemon-build', 'skip', 'daemon unreachable');
  } else {
    const protocol = status.protocolVersion ?? null;
    const daemonBuild = status.daemonVersion != null ? `daemon ${status.daemonVersion} on node ${status.runtimeVersion ?? '?'}, ` : '';
    add('daemon-socket', 'ok',
      `daemon reachable (protocol ${protocol ? 'v' + protocol : 'unversioned'}, state ${status.state ?? 'unknown'}, ${daemonBuild}cli ${cliVersion ?? '?'} on node ${nodeVersion})`);
    if (protocol === null || protocol < 1) {
      add('protocol-version', 'warn', 'daemon answers without a protocol version (pre-v1 build)',
        'Update portname and restart the daemon (portname install).');
    } else {
      add('protocol-version', 'ok', `protocol v${protocol}`);
    }
    if (status.state === 'RUNNING') {
      add('daemon-state', 'ok', 'daemon is RUNNING');
    } else {
      add('daemon-state', 'warn', `daemon is ${status.state} — display only, mutations are refused`,
        '"portname install" (re)starts the LaunchAgent.');
    }
    if (status.scanError) {
      add('discovery', 'warn', `last discovery scan failed (${maskPaths(status.scanError)}); the project list may be outdated`,
        'Check the daemon log (portname doctor prints its path) and retry once the machine is idle.');
    } else if (status.lastGoodScanAt == null) {
      add('discovery', 'warn', 'no successful discovery scan yet (daemon just started?)',
        'Wait a few seconds and run portname doctor again.');
    } else {
      add('discovery', 'ok', `last good scan ${Math.max(0, Math.round((Date.now() - status.lastGoodScanAt) / 1000))}s ago`);
    }
    if (!gatewayProbe) {
      add('gateway-port', 'skip', 'no probe result provided');
    } else if (gatewayProbe.ok) {
      add('gateway-port', 'ok', gatewayProbe.detail);
    } else {
      add('gateway-port', 'fail', gatewayProbe.detail,
        'The gateway port is not answering locally. Restart the daemon: launchctl kickstart -k gui/$UID/dev.portname.daemon (this ends active public links).');
    }
    if (protocol === null) {
      add('daemon-build', 'skip', 'pre-v1 daemon reports no build (see protocol-version)');
    } else {
      const build = buildVerdict({ status, cliVersion, bundleManifest });
      if (build.ok) add('daemon-build', 'ok', build.detail);
      else add('daemon-build', 'warn', build.detail, build.remedy);
    }
  }

  // The runtime that serves the gateway: the daemon's when it reports one,
  // otherwise this CLI's (a source install runs the daemon on the same node).
  const runtimeVersion = (status && status.runtimeVersion) || nodeVersion;
  const runtime = nodeRuntimeVerdict(runtimeVersion);
  if (runtime.ok) add('node-runtime', 'ok', runtime.detail);
  else add('node-runtime', 'warn', runtime.detail, runtimeRemedy(status));

  if (exists(agentPath)) {
    add('launch-agent', 'ok', `LaunchAgent installed (${tildify(agentPath, home ?? os.homedir())})`);
  } else {
    add('launch-agent', 'warn', 'no LaunchAgent installed — the daemon will not start at login',
      'Run: portname install');
  }

  const mode = modeOf(dir);
  if (mode === null) {
    add('state-dir', 'warn', `state directory does not exist yet (created on first daemon start)`,
      'Run: portname install');
  } else if (mode !== 0o700) {
    add('state-dir', 'fail', `state directory permissions are ${mode.toString(8)} (expected 700)`,
      `Run: chmod 700 ${dir}`);
  } else {
    add('state-dir', 'ok', 'state directory is private (mode 700)');
  }

  const cf = resolveCf({ override: cloudflaredBin, home, isPayloadEntry });
  if (cf) {
    add('cloudflared', 'ok', `cloudflared found (${tildify(cf, home ?? os.homedir())}) — public demo links available`);
  } else {
    add('cloudflared', 'warn', 'cloudflared not found — public demo links cannot start',
      'Install it, e.g. brew install cloudflared (or set "cloudflaredBin" in the config). Local names and WLAN exposure work without it.');
  }

  const shares = (status && status.shares) || [];
  const active = shares.filter((s) => s.state === 'ACTIVE' && !s.expired).length;
  const starting = shares.filter((s) => s.state === 'STARTING').length;
  add('shares', 'ok', `${active} active, ${starting} starting public link(s)`);

  return checks;
}

function doctorSummary(checks) {
  const summary = { ok: 0, warn: 0, fail: 0, skip: 0 };
  for (const c of checks) summary[c.severity] += 1;
  return summary;
}

// Exit code contract (docs/diagnostics.md):
//   0 — daemon answered, no check failed (warnings possible)
//   1 — at least one check failed
//   2 — the daemon did not answer (core checks could not run)
function doctorExitCode({ status, checks }) {
  if (!status) return 2;
  return checks.some((c) => c.severity === 'fail') ? 1 : 0;
}

// The text report names the state dir and the daemon log path (the remedies
// refer to it); the JSON report never carries either (redaction rules).
function formatDoctorText(checks, summary, { dir } = {}) {
  const lines = [];
  lines.push('portname doctor — read-only diagnosis (repairs nothing, opens no tunnels)');
  lines.push('');
  const pad = (s, n) => (s.length >= n ? s + ' ' : s + ' '.repeat(n - s.length + 1));
  for (const c of checks) {
    lines.push(`${pad(`[${c.severity}]`, 9)}${c.id}: ${c.detail}`);
    if (c.remedy) lines.push(`${pad('', 9)}-> ${c.remedy}`);
  }
  lines.push('');
  lines.push(
    `${summary.ok} ok, ${summary.warn} warning(s), ${summary.fail} problem(s), ${summary.skip} skipped` +
      (dir ? ` — state dir: ${dir}` : '')
  );
  if (dir) lines.push(`daemon log: ${path.join(dir, 'daemon.log')} (bounded; previous part in daemon.log.1)`);
  return lines.join('\n');
}

// Bounded, read-only probe: is the gateway port answering on loopback? A
// plain TCP connect — no HTTP request is sent, nothing is opened beyond the
// machine itself.
function probeGatewayPort(port, { timeoutMs = 1500, host = '127.0.0.1' } = {}) {
  return new Promise((resolve) => {
    if (!port) {
      resolve({ ok: false, detail: 'gateway port unknown (daemon never bound?)' });
      return;
    }
    const socket = net.connect({ host, port });
    let settled = false;
    const done = (ok, detail) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ ok, detail });
    };
    const timer = setTimeout(
      () => done(false, `gateway did not answer on ${host}:${port} within ${timeoutMs}ms`),
      timeoutMs
    );
    socket.on('connect', () => done(true, `gateway answers on ${host}:${port}`));
    socket.on('error', (err) => done(false, `gateway not reachable on ${host}:${port} (${err.code || err.message})`));
  });
}

// Wraps the CLI's send() so doctor keeps working (and keeps its report)
// when the daemon is down.
async function readDaemonStatus(sendFn, { timeoutMs = 8000 } = {}) {
  try {
    const res = await sendFn({ cmd: 'status' }, { timeoutMs });
    if (!res.ok) return { status: null, daemonError: res.error };
    return { status: res, daemonError: null };
  } catch (err) {
    return { status: null, daemonError: err.message };
  }
}

module.exports = {
  NODE_RUNTIME_FLOORS,
  nodeRuntimeVerdict,
  buildVerdict,
  appBundleManifest,
  STATUS_SCHEMA,
  DOCTOR_SCHEMA,
  LAUNCH_AGENT_LABEL,
  which,
  resolveCloudflared,
  launchAgentPath,
  dirMode,
  maskPaths,
  tildify,
  statusSnapshot,
  doctorChecks,
  doctorSummary,
  doctorExitCode,
  formatDoctorText,
  probeGatewayPort,
  readDaemonStatus,
};
