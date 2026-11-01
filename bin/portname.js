#!/usr/bin/env node
'use strict';

const net = require('net');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { browserHost } = require('../lib/urls');
const { readJsonObject, validateConfig, ensurePrivateDir, socketPathProblem } = require('../lib/config');
const bundleinstall = require('../lib/bundleinstall');

const DIR = process.env.PORTNAME_DIR || path.join(os.homedir(), '.portname');
const SOCK = path.join(DIR, 'daemon.sock');
const VERSION = require('../package.json').version;
const LAUNCH_AGENT_LABEL = 'dev.portname.daemon';
// PATH handed to the LaunchAgent; a bundled payload's runtime bin dir is
// prepended so the bundled cloudflared is found even without Homebrew.
const DAEMON_DEFAULT_PATH = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin';
// KeepAlive stays unconditional (the agent must heal itself once a broken
// config is fixed or a port frees up), but launchd may respawn the daemon at
// most once per this many seconds: a permanent start failure becomes a slow
// retry instead of a tight loop. launchd throttles only quick deaths — a
// daemon that ran longer than this restarts immediately after a crash.
const LAUNCHD_THROTTLE_SECONDS = 30;

// Framing invariants, identical to the Swift client (docs/control-protocol.md):
// collect bytes until the first newline, keep the response size bounded,
// UTF-8-decode only the complete frame, report EOF/close before a frame
// immediately, enforce a deadline, and settle the promise exactly once.
// Mutations are sent exactly once — an unclear outcome is surfaced as an
// error for the caller to inspect, never blindly retried.
const MAX_RESPONSE_BYTES = 1024 * 1024;

function send(msg, { timeoutMs = 45000, sockPath = SOCK } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(sockPath);
    let settled = false;
    let received = 0;
    let buf = Buffer.alloc(0);
    const settle = (ok, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      (ok ? resolve : reject)(value);
    };
    const timer = setTimeout(() => {
      settle(false, new Error(`timeout waiting for daemon (${timeoutMs}ms). Is it running? Try: portname install`));
    }, timeoutMs);
    socket.on('connect', () => socket.write(JSON.stringify(msg) + '\n'));
    socket.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_RESPONSE_BYTES) {
        settle(false, new Error(`daemon response exceeds ${MAX_RESPONSE_BYTES} bytes; refusing`));
        return;
      }
      buf = Buffer.concat([buf, chunk]);
      const nl = buf.indexOf(0x0a);
      if (nl === -1) return; // frame incomplete — keep collecting bytes
      const frame = buf.subarray(0, nl).toString('utf8'); // decode only the complete frame
      let parsed;
      try {
        parsed = JSON.parse(frame);
      } catch {
        settle(false, new Error('bad response from daemon'));
        return;
      }
      settle(true, parsed);
    });
    socket.on('close', () => {
      if (!settled) {
        settle(false, new Error('daemon closed the connection before sending a full response. Start it with: portname install'));
      }
    });
    socket.on('error', (err) => {
      settle(false, new Error(`cannot reach daemon (${err.message}). Start it with: portname install`));
    });
  });
}

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s + '  ' : s + ' '.repeat(n - s.length + 2);
}

// browserHost lives in lib/urls.js so the daemon and the CLI render identical
// browser URLs; re-exported here for compatibility.

function formatRemainingTtl(expiresAt, fallbackMinutes = 60) {
  const ms = expiresAt ? Math.max(1000, expiresAt - Date.now()) : Math.max(1000, fallbackMinutes * 60000);
  const totalSec = Math.round(ms / 1000);
  if (totalSec < 60) {
    return `${Math.max(1, totalSec)} sec`;
  }
  const min = ms / 60000;
  if (min < 10 && Math.abs(min - Math.round(min)) >= 0.05) {
    return `${min.toFixed(1)} min`;
  }
  return `${Math.max(1, Math.round(min))} min`;
}

// Human spellings of the daemon's machine-readable exposurePauseReason
// (docs/control-protocol.md). Unknown reasons pass through as-is.
const EXPOSURE_PAUSE_REASONS = {
  'target-not-verified': 'target not verified',
  'no-lan-interface': 'no LAN interface',
  'loopback-bind': 'loopback bind',
};

// The WLAN note under a route. The daemon reports the EFFECTIVE exposure
// (exposureEffective): "paused" means the wish is still set, but access is
// currently refused (e.g. the target's verification went stale). Routes from
// an older daemon without the field keep the legacy wording.
function wifiNote(route, lan = null) {
  const endpoint = (port, command) => `:${port}${command ? ' ' + command : ''}`;
  if (route.exposureEffective === 'paused' && route.exposurePauseReason === 'target-unconfirmed') {
    // A wish stored before exposures were bound to an endpoint: nothing
    // moved, the endpoint it reaches now only needs one confirmation.
    return `(on your Wi-Fi — paused: not confirmed since the update, now ${endpoint(route.port, route.command)}; confirm with: portname expose ${route.name})`;
  }
  if (route.exposureEffective === 'paused' && route.exposurePauseReason === 'target-changed') {
    // Never healed by a scan: the name now points at an endpoint nobody
    // confirmed for the Wi-Fi (another port or command of the project).
    const t = route.exposureTarget;
    const was = t ? `confirmed ${endpoint(t.port, t.command)}, ` : '';
    return `(on your Wi-Fi — paused: target changed (${was}now ${endpoint(route.port, route.command)}); confirm with: portname expose ${route.name})`;
  }
  if (route.exposureEffective === 'paused' && route.exposurePauseReason === 'network-unidentified') {
    // The confirmed address range, but its router is not identified yet
    // (just after wake): resumes by itself, nothing to confirm.
    return '(on your Wi-Fi — paused: the router of this network is not identified yet, e.g. just after wake; resumes by itself once the confirmed router is identified)';
  }
  if (route.exposureEffective === 'paused' && route.exposurePauseReason === 'network-changed') {
    // Exposures do not follow the Mac into another network on their own. A
    // network is the subnet plus its router: the same address range behind
    // another identified router is another network too. (A router that is
    // not identified yet is "network-unidentified" above: nothing to confirm.)
    const was = route.exposureTarget && route.exposureTarget.network;
    const now = lan && lan.network;
    let detail = '';
    if (was && now && was === now) detail = ` (same range ${was}, another router)`;
    else if (was && now) detail = ` (${was}, now ${now})`;
    return `(on your Wi-Fi — paused: exposed on another network${detail}; to expose it on this one: portname expose ${route.name})`;
  }
  if (route.exposureEffective === 'paused') {
    const reason = EXPOSURE_PAUSE_REASONS[route.exposurePauseReason] || route.exposurePauseReason || 'paused';
    return `(on your Wi-Fi — paused: ${reason})`;
  }
  if (route.lanRegistration === 'conflict') {
    // dns-sd refused the name: another device on the network already
    // answers for it, so the address leads there, not to this Mac. The
    // registration is retried with a backoff; another name avoids the clash.
    const rename = route.manual
      ? `portname remove ${route.name}, then portname add <new-name> ${route.port} and portname expose <new-name>`
      : `portname rename ${route.name} <new-name>`;
    return `(on your Wi-Fi — name in use: another device on this network answers for ${route.name}.local, so this address leads there; pick a free name: ${rename})`;
  }
  return '(on your Wi-Fi)';
}

// The answer to `portname expose|unexpose <name>`. The exposure is bound to
// the confirmed endpoint and network; if the name later moves to another
// port or command, or the Mac joins another network, it pauses until
// confirmed again. Without an identified router the network is the address
// range alone, and the user is told so.
function exposeMessage(name, res) {
  if (!res.exposed) return `${name}.local is no longer reachable.`;
  const t = res.target;
  if (!t) return `${name}.local now answers on your Wi-Fi.`;
  let where = '';
  if (t.network && t.subnetOnly) {
    where = `; this address range only: ${t.network} — the router could not be identified, so any network using this range counts as this one`;
  } else if (t.network) {
    where = `; this network only: ${t.network}`;
  }
  return `${name}.local now answers on your Wi-Fi (-> :${t.port}${t.command ? ' ' + t.command : ''}${where}).`;
}

// The Wi-Fi part of the reach column. Only the EFFECTIVE exposure
// (exposureEffective "active") is reachable; a wish the daemon currently
// refuses to serve is listed as paused, with the reason in the Wi-Fi line
// below. An older daemon without the field reports the wish alone. A name
// another device already answers for (lanRegistration "conflict") is not
// reachable by that name either.
function wifiReach(route, exposed) {
  if (!exposed.includes(route.name)) return null;
  if (route.exposureEffective === 'paused') return 'Wi-Fi (paused)';
  if (route.exposureEffective != null && route.exposureEffective !== 'active') return null;
  return route.lanRegistration === 'conflict' ? 'Wi-Fi (name in use)' : 'Wi-Fi';
}

function cmdStatus(data) {
  if (!data.routes.length && !data.stale.length) {
    console.log('No dev servers detected. Start one, then run portname again.');
    console.log('A server portname cannot attribute? Register it: portname add <name> <port>');
    return;
  }
  console.log(`portname — routing (${data.bind}) on port ${data.proxyPort}\n`);
  for (const r of data.routes) {
    const reach = ['Mac'];
    const wifi = wifiReach(r, data.exposed);
    if (wifi) reach.push(wifi);
    if (data.shares.some((s) => s.name === r.name && s.state === 'ACTIVE' && s.url && !s.expired)) {
      reach.push('Internet');
    }
    const warn = r.external ? '  (upstream already listens on all interfaces!)' : '';
    const localHost = browserHost(r.name, '.localhost', data.proxyPort);
    console.log(
      `${pad(localHost, 34)}${pad('-> :' + r.port, 12)}${pad(r.command, 12)}${reach.join('+')}${warn}`
    );
    if (data.exposed.includes(r.name)) {
      const lanHost = browserHost(r.name, '.local', data.proxyPort);
      console.log(`${pad(lanHost, 34)}${pad('-> :' + r.port, 12)}${wifiNote(r, data.lan)}`);
    }
    for (const s of data.shares) {
      if (s.name === r.name) {
        if (s.state === 'STARTING') {
          console.log(`${pad('(public link starting…)', 34)}${pad('', 12)}(public demo link)`);
        } else if (s.url) {
          const flag = s.expired ? ' (expired)' : '';
          console.log(`${pad(s.url + '/…/', 34)}${pad('', 12)}(public demo link${flag})`);
        }
      }
    }
  }
  if (data.stale.length) {
    console.log('\nAlso running, but not routed (debug/inspector port, or its port is now served by a newer generation of the same project):');
    for (const s of data.stale) {
      console.log(`  ${pad(s.name, 34)}${pad('-> :' + s.port, 12)}${s.command} (pid ${s.pid})`);
    }
  }
}

// The LaunchAgent must survive Homebrew upgrades: process.execPath resolves
// to the versioned Cellar binary (/opt/homebrew/Cellar/node/<ver>/bin/node),
// which disappears on every `brew upgrade node` and leaves the agent dying
// with EX_CONFIG after the next reboot. The stable <prefix>/bin/node symlink
// is preferred when it exists; anything else (nvm, asdf, system node) keeps
// the concrete path.
function stableNodePath(execPath = process.execPath, existsSync = fs.existsSync) {
  const marker = path.sep + 'Cellar' + path.sep;
  const i = execPath.indexOf(marker);
  if (i !== -1) {
    const stable = path.join(execPath.slice(0, i), 'bin', path.basename(execPath));
    if (existsSync(stable)) return stable;
  }
  return execPath;
}

// launchd plists are XML: any path (install dir, node binary, script entry)
// can contain &, <, >, quotes — all of them must be escaped or the agent
// silently fails to parse at boot.
function xmlEscape(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

// XML 1.0 cannot represent control characters (everything below 0x20 except
// tab, LF and CR) or lone surrogates — no escaping fixes that, so a path
// containing one would produce a plist launchd can never parse. `install`
// therefore rejects such paths up front with a concrete message instead of
// writing an agent that fails opaquely at boot.
function assertPlistSafePath(value, label, remedy) {
  const s = String(value);
  for (const ch of s) {
    const c = ch.codePointAt(0);
    const forbidden =
      (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) ||
      (c >= 0xd800 && c <= 0xdfff);
    if (forbidden) {
      throw new Error(
        `refusing to install: ${label} contains a character XML 1.0 forbids (U+${c.toString(16).padStart(4, '0')}); ${remedy}`
      );
    }
  }
}

function plist({ dir = DIR, nodePath = stableNodePath(), entryPath = path.resolve(__dirname, 'portname.js'), extraPath = '' } = {}) {
  const daemonPath = extraPath ? `${extraPath}:${DAEMON_DEFAULT_PATH}` : DAEMON_DEFAULT_PATH;
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.portname.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>${xmlEscape(nodePath)}</string>
    <string>${xmlEscape(entryPath)}</string>
    <string>daemon</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>${xmlEscape(daemonPath)}</string>
    <key>PORTNAME_DIR</key>
    <string>${xmlEscape(dir)}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>${LAUNCHD_THROTTLE_SECONDS}</integer>
  <key>StandardOutPath</key><string>${xmlEscape(path.join(dir, 'daemon.log'))}</string>
  <key>StandardErrorPath</key><string>${xmlEscape(path.join(dir, 'daemon.log'))}</string>
</dict>
</plist>
`;
}

async function cmdInstall(rest = []) {
  const dryRun = rest.includes('--dry-run');
  // Validated before anything is created or written: a path XML cannot
  // represent must fail visibly before the state dir or plist is touched.
  assertPlistSafePath(
    DIR,
    `the state directory ${JSON.stringify(DIR)}`,
    'set PORTNAME_DIR to a path without control characters'
  );
  // A state dir whose control socket path the OS would truncate yields an
  // agent that can never start: refuse before anything is written.
  const sockProblem = socketPathProblem(SOCK);
  if (sockProblem) throw new Error(`refusing to install: ${sockProblem}`);
  // Where the agent points depends on how this CLI runs:
  // - inside Portname.app/Contents/Resources → sync the payload (daemon +
  //   pinned node runtime) to the stable Application Support location first
  //   and reference only that location, so moving or deleting the .app never
  //   breaks the agent;
  // - already inside the stable payload → reference the payload itself;
  // - developer checkout → current behavior (stable node path, this entry).
  let nodePath = stableNodePath();
  let entryPath = path.resolve(__dirname, 'portname.js');
  let extraPath = '';
  const layout = bundleinstall.appBundleLayout(__dirname);
  if (layout.isBundle) {
    // The agent must never point into the .app: the stable-payload arguments
    // are computed deterministically. A dry-run only reports this plan — it
    // performs no payload sync and writes nothing at all (a ~130 MB copy
    // would be a permanent side effect, not a validation).
    ({ nodePath, entryPath, extraPath } = bundleinstall.payloadInstallArgs(bundleinstall.stablePayloadDir()));
    if (dryRun) {
      console.log(`dry-run: would sync the background service payload from ${layout.resourcesDir} to ${bundleinstall.stablePayloadDir()}.`);
    } else {
      const sync = bundleinstall.syncPayload({ sourceRoot: layout.resourcesDir, log: (m) => console.log(m) });
      console.log(
        sync.changed
          ? `Installed background service payload to ${sync.destDir}`
          : `Background service payload up to date at ${sync.destDir}`
      );
    }
  } else if (bundleinstall.isStablePayloadEntry(__dirname)) {
    nodePath = process.execPath;
    entryPath = path.resolve(__dirname, 'portname.js');
    extraPath = path.join(bundleinstall.stablePayloadDir(), 'runtime', 'bin');
  }
  assertPlistSafePath(
    nodePath,
    `the node binary path ${JSON.stringify(nodePath)}`,
    'install the CLI under a path without control characters'
  );
  assertPlistSafePath(
    entryPath,
    `the entry script path ${JSON.stringify(entryPath)}`,
    'install the CLI under a path without control characters'
  );
  const file = path.join(os.homedir(), 'Library', 'LaunchAgents', 'dev.portname.daemon.plist');
  // A source install runs the gateway on the CLI's own node. Not a hard stop
  // — but never a silent one either. (App installs run the runtime pinned
  // in the bundle; doctor's node-runtime check covers that case.)
  if (!layout.isBundle && !bundleinstall.isStablePayloadEntry(__dirname)) {
    const runtime = require('../lib/diagnose').nodeRuntimeVerdict(process.version);
    if (!runtime.ok) console.warn(`warning: ${runtime.detail}. Update Node.js (current 24 or 26 LTS) and run portname install again.`);
  }
  if (dryRun) {
    // Validation-only mode (used by automated checks): paths are validated
    // and the plan reported — no payload sync, no state dir, no plist,
    // launchctl never invoked, nothing loaded or unloaded.
    console.log(`dry-run: install validated; LaunchAgent plist would be written to ${file}, launchctl not invoked. Nothing was written.`);
    return;
  }
  ensurePrivateDir(DIR);
  // Normally present on every macOS account; created defensively so a missing
  // user template fails with a working install, not an opaque ENOENT.
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, plist({ nodePath, entryPath, extraPath }));
  const uid = process.getuid();
  runLaunchctl(['bootout', `gui/${uid}`, file], { ignoreFailure: true });
  runLaunchctl(['bootstrap', `gui/${uid}`, file], { ignoreFailure: false });
  console.log('Installed and started. The daemon runs at login and stays up.');
  console.log('Uninstall with: portname uninstall');
}

async function cmdUninstall(rest = []) {
  const dryRun = rest.includes('--dry-run');
  const file = path.join(os.homedir(), 'Library', 'LaunchAgents', 'dev.portname.daemon.plist');
  const uid = process.getuid();
  if (dryRun) {
    console.log(`dry-run: would bootout and remove ${file}, then remove the installed bundle payload if it is ours.`);
    return;
  }
  runLaunchctl(['bootout', `gui/${uid}`, file], { ignoreFailure: true });
  try {
    fs.unlinkSync(file);
  } catch (err) {
    // never installed
  }
  // The stable payload belongs to the background service, not to the app:
  // uninstall removes it too — but only when it is verifiably a portname
  // payload. User state (~/.portname: config, registry, logs) stays.
  if (bundleinstall.removePayloadIfOurs()) {
    console.log('Removed the installed background service payload.');
  }
  console.log('Uninstalled. Your normal localhost:port URLs keep working.');
  console.log('Note: the Portname.app GUI and your settings in ~/.portname are kept.');
}

// launchctl is exec'd as a fixed executable with an argument array — the
// plist path never passes through a shell, so spaces and shell
// metacharacters in allowed install paths stay plain data.
function runLaunchctl(args, { ignoreFailure }) {
  const { execFileSync } = require('child_process');
  try {
    execFileSync('launchctl', args, { stdio: 'ignore' });
  } catch (err) {
    if (!ignoreFailure) throw err;
  }
}

// Fail-closed config load for the daemon: a missing file is a fresh start;
// a damaged, unreadable or schema-invalid one aborts the start with a
// concrete repair message instead of silently enabling default binds.
function loadConfig() {
  return readJsonObject(path.join(DIR, 'config.json'), validateConfig) || {};
}

// The daemon log is BOUNDED: one file of at most LOG_MAX_BYTES plus one
// rotated predecessor (daemon.log.1), so a permanent start failure under
// KeepAlive or a flood of rejected LAN requests can never fill the disk.
const LOG_MAX_BYTES = 1024 * 1024;
const LOG_FIELD_MAX = 1000;
// Per-event rate limit (key = first two fields, e.g. "reject 404" for every
// refused gateway request — triggerable by any LAN peer): at most LOG_BURST
// lines per window, the rest is counted and summarized once.
const LOG_BURST = 20;
const LOG_WINDOW_MS = 60_000;
const LOG_MAX_KEYS = 256;

// Log hygiene: every field is rendered to one line, control
// characters (log injection via process/project/Host values) are escaped,
// overlong fields are cut, and anything shaped like a secret token (a long
// mixed letter/digit run, e.g. the 64-hex share token) is redacted as
// defense in depth — call sites already never pass tokens.
function formatLogField(value) {
  let s;
  if (typeof value === 'string') s = value;
  else if (value instanceof Error) s = value.message;
  else if (value !== null && typeof value === 'object') {
    try {
      s = JSON.stringify(value);
    } catch {
      s = String(value);
    }
  } else s = String(value);
  s = s.replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
  // 40+ chars: a share token is 64 hex chars; shareIds (16) and ordinary
  // project/path names stay readable.
  s = s.replace(/[A-Za-z0-9_-]{40,}/g, (run) => (/\d/.test(run) && /[A-Za-z]/.test(run) ? '[redacted]' : run));
  return s.length > LOG_FIELD_MAX ? `${s.slice(0, LOG_FIELD_MAX)}…` : s;
}

// Returns log(...fields). With `file`, lines are appended to that file via
// an own O_APPEND descriptor and the file is rotated (copied to `<file>.1`,
// then truncated in place) whenever it reaches maxBytes — including right
// at creation, so every (re)start trims an oversized log first. Truncating
// in place keeps launchd's own append-mode descriptor on the same file
// valid. Without `file`, lines go to `stream` (terminal or pipe).
function createDaemonLogger({
  file = null,
  stream = process.stderr,
  maxBytes = LOG_MAX_BYTES,
  burst = LOG_BURST,
  windowMs = LOG_WINDOW_MS,
  now = () => Date.now(),
} = {}) {
  let fd = null;
  if (file) {
    try {
      fd = fs.openSync(file, 'a', 0o600);
    } catch {
      fd = null; // fall back to the stream
    }
  }
  const rotate = () => {
    try {
      const { atomicWrite } = require('../lib/registry');
      atomicWrite(`${file}.1`, fs.readFileSync(file));
    } catch {
      // best effort: the bound matters more than the copy
    }
    try {
      fs.ftruncateSync(fd, 0);
    } catch {}
  };
  const write = (line) => {
    if (fd === null) {
      stream.write(line);
      return;
    }
    try {
      if (fs.fstatSync(fd).size + Buffer.byteLength(line) > maxBytes) rotate();
      fs.writeSync(fd, line);
    } catch {
      // logging must never take the daemon down
    }
  };
  const emit = (fields) => write(`${new Date(now()).toISOString()} ${fields.map(formatLogField).join(' ')}\n`);
  if (fd !== null) {
    try {
      if (fs.fstatSync(fd).size >= maxBytes) rotate();
    } catch {}
  }

  const buckets = new Map(); // key -> { start, count, suppressed }
  const flushExpired = (t) => {
    for (const [key, b] of buckets) {
      if (t - b.start < windowMs) continue;
      if (b.suppressed) emit(['log', `suppressed ${b.suppressed} similar line(s):`, key]);
      buckets.delete(key);
    }
  };
  return function log(...fields) {
    const t = now();
    flushExpired(t);
    const key = fields.slice(0, 2).map(formatLogField).join(' ');
    let b = buckets.get(key);
    if (!b) {
      if (buckets.size >= LOG_MAX_KEYS) buckets.clear();
      b = { start: t, count: 0, suppressed: 0 };
      buckets.set(key, b);
    }
    if (b.count >= burst) {
      b.suppressed += 1;
      return;
    }
    b.count += 1;
    emit(fields);
  };
}

// Under the LaunchAgent, stdout/stderr ARE <dir>/daemon.log (plist
// StandardOutPath/StandardErrorPath). Only then does the daemon write that
// file itself, bounded; run in a terminal it logs to stderr as usual.
function daemonLogFile(dir, fd = 2) {
  const file = path.join(dir, 'daemon.log');
  try {
    const st = fs.fstatSync(fd);
    const target = fs.statSync(file);
    if (st.isFile() && st.dev === target.dev && st.ino === target.ino) return file;
  } catch {
    // not a regular file, or no daemon.log: not the LaunchAgent layout
  }
  return null;
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === 'status') {
    const res = await send({ cmd: 'status' });
    if (!res.ok) throw new Error(res.error);
    if (rest.includes('--json')) {
      // Read-only machine snapshot: versioned schema, no tokens, no share
      // origins, no project paths (docs/diagnostics.md). Errors exit 1.
      const { statusSnapshot } = require('../lib/diagnose');
      // The config override feeds the same cloudflared resolution the daemon
      // uses, so `cloudflaredFound` reflects the binary a share would run.
      console.log(JSON.stringify(statusSnapshot({ status: res, dir: DIR, cliVersion: VERSION, cloudflaredBin: loadConfig().cloudflaredBin }), null, 2));
      return;
    }
    cmdStatus(res);
    return;
  }
  if (cmd === 'doctor') {
    // Read-only diagnosis: collects facts, prints checks with concrete
    // remedies, repairs nothing, opens no tunnels. Exit codes (documented in
    // docs/diagnostics.md): 0 ok/warnings only, 1 failed check, 2 daemon
    // unreachable.
    const diag = require('../lib/diagnose');
    const { status, daemonError } = await diag.readDaemonStatus(send);
    const gatewayProbe = status ? await diag.probeGatewayPort(status.proxyPort) : null;
    const checks = diag.doctorChecks({
      status,
      daemonError,
      dir: DIR,
      launchAgentPath: path.join(os.homedir(), 'Library', 'LaunchAgents', `${LAUNCH_AGENT_LABEL}.plist`),
      gatewayProbe,
      // Same cloudflared resolution as the daemon's share starts (config
      // override → bundled payload binary → Homebrew → PATH): doctor must
      // report the binary that would ACTUALLY run, not just PATH.
      cloudflaredBin: loadConfig().cloudflaredBin,
      cliVersion: VERSION,
    });
    const summary = diag.doctorSummary(checks);
    if (rest.includes('--json')) {
      console.log(JSON.stringify({
        schema: diag.DOCTOR_SCHEMA,
        generatedAt: Date.now(),
        summary,
        checks,
        remedies: checks.filter((c) => c.remedy).map((c) => c.remedy),
      }, null, 2));
    } else {
      console.log(diag.formatDoctorText(checks, summary, { dir: DIR }));
    }
    return diag.doctorExitCode({ status, checks });
  }
  if (cmd === 'unshare-all') {
    const res = await send({ cmd: 'unshare-all' }, { timeoutMs: 30000 });
    if (!res.ok) throw new Error(res.error);
    const stopped = res.stopped || [];
    if (!stopped.length) {
      console.log('No public links are active.');
    } else {
      console.log(`Revoked ${stopped.length} public link${stopped.length === 1 ? '' : 's'}: ${stopped.join(', ')}`);
    }
    return;
  }
  if (cmd === 'daemon') {
    const { Daemon } = require('../lib/daemon');
    // Every operational event — share revocations with their reason, TTL
    // expiry, tunnel exits, orphan kills, lock takeovers, scan errors — goes
    // to the bounded daemon log; production never runs with a no-op logger.
    // A start failure is logged the same way (timestamped, size-capped) and
    // ends with exit 1, so a KeepAlive respawn loop cannot grow the log.
    const log = createDaemonLogger({ file: daemonLogFile(DIR) });
    let daemon;
    try {
      daemon = new Daemon({ dir: DIR, config: loadConfig(), log });
    } catch (err) {
      log('daemon', 'start-failed', err.message);
      return 1;
    }

    let stopping = false;
    const stop = async () => {
      if (stopping) return;
      stopping = true;
      try {
        await daemon.stop();
      } finally {
        process.exit(0);
      }
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    // Node's default for SIGHUP is an immediate exit without teardown, which
    // would leave tunnels, Bonjour registrations, the lock and the socket
    // behind (`kill -HUP`, a closing terminal, supervisors that "reload").
    process.on('SIGHUP', stop);
    // A crash can no longer run the async teardown, but it must not leave
    // public tunnels running: children are killed synchronously before the
    // process exits with the usual crash code. Lock and socket are reclaimed
    // by the next start (dead-owner lock steal, socket unlink).
    process.on('uncaughtException', (err) => {
      daemon.killChildrenSync();
      log('daemon', 'fatal', (err && err.stack) || String(err));
      process.exit(1);
    });

    try {
      await daemon.start();
    } catch (err) {
      log('daemon', 'start-failed', err.message);
      return 1;
    }
    // A runtime below the security floor keeps running (no hard stop for an
    // existing install) but is recorded; doctor reports it with a remedy.
    const runtime = require('../lib/diagnose').nodeRuntimeVerdict(process.version);
    if (!runtime.ok) log('daemon', 'runtime-warning', runtime.detail);
    await new Promise(() => {}); // Hold process open until signal arrives
    return;
  }
  if (cmd === 'add') {
    const [name, port] = rest;
    if (!name || !port) throw new Error('usage: portname add <name> <port>');
    const res = await send({ cmd: 'add', name: name.replace(/\.localhost$/, ''), port: Number(port) });
    if (!res.ok) throw new Error(res.error);
    console.log(`Added: ${res.added}.localhost routes to port ${res.port}.`);
    return;
  }
  if (cmd === 'remove') {
    const name = (rest[0] || '').replace(/\.localhost$/, '').replace(/\.local$/, '');
    if (!name) throw new Error('usage: portname remove <name>');
    const res = await send({ cmd: 'remove', name });
    if (!res.ok) throw new Error(res.error);
    // An older daemon sends no `existed`: keep the legacy message then.
    console.log(res.existed === false ? `No manual entry named ${res.removed}; nothing removed.` : `Removed ${res.removed}.`);
    return;
  }
  if (cmd === 'rename') {
    const [oldName, newName] = rest;
    if (!oldName || !newName) throw new Error('usage: portname rename <old> <new>');
    const res = await send({ cmd: 'rename', name: oldName.replace(/\.localhost$/, ''), newName: newName.replace(/\.localhost$/, '') });
    if (!res.ok) throw new Error(res.error);
    console.log(`Renamed: ${res.renamed}.localhost is now ${res.to}.localhost`);
    return;
  }
  if (cmd === 'expose' || cmd === 'unexpose') {
    const name = (rest[0] || '').replace(/\.localhost$/, '').replace(/\.local$/, '');
    if (!name) throw new Error(`usage: portname ${cmd} <name>`);
    const res = await send({ cmd: 'expose', name, on: cmd === 'expose' });
    if (!res.ok) throw new Error(res.error);
    console.log(exposeMessage(name, res));
    return;
  }
  if (cmd === 'share') {
    const name = (rest[0] || '').replace(/\.localhost$/, '');
    const ttlIdx = rest.indexOf('--ttl');
    const rawTtl = ttlIdx !== -1 ? rest[ttlIdx + 1] : 60;
    if (!name) throw new Error('usage: portname share <name> [--ttl minutes]');
    if (rest.includes('--stop') || cmd === 'unshare') {
      const res = await send({ cmd: 'unshare', name });
      if (!res.ok) throw new Error(res.error);
      console.log(`Public link for ${name} is off.`);
      return;
    }
    const { validateTtlMinutes } = require('../lib/share');
    const ttlCheck = validateTtlMinutes(rawTtl);
    if (!ttlCheck.ok) {
      throw new Error(ttlCheck.reason);
    }
    const ttlMinutes = ttlCheck.minutes;
    const res = await send({ cmd: 'share', name, ttlMinutes }, { timeoutMs: 60000 });
    if (!res.ok) throw new Error(res.error);
    const remainingDesc = formatRemainingTtl(res.expiresAt, res.ttlMinutes || ttlMinutes);
    console.log(`Public link (expires in ${remainingDesc}, dies when you stop it):`);
    console.log('  ' + res.url);
    return;
  }
  if (cmd === 'unshare') {
    const name = (rest[0] || '').replace(/\.localhost$/, '');
    const res = await send({ cmd: 'unshare', name });
    if (!res.ok) throw new Error(res.error);
    console.log(`Public link for ${name} is off.`);
    return;
  }
  if (cmd === 'install') return cmdInstall(rest);
  if (cmd === 'uninstall') return cmdUninstall(rest);
  if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
    console.log(`portname — every local project gets a real address

  portname                 list every named project and where it reaches
  portname rename <a> <b>  rename a project
  portname add <n> <port>  register a server portname cannot attribute
  portname remove <n>      drop a manual registration
  portname expose <n>      answer as <n>.local on your Wi-Fi
  portname unexpose <n>    switch the Wi-Fi address off
  portname share <n>       public demo link (1 h, secret key; no SSE guarantee)
  portname share <n> --ttl 15
  portname unshare <n>     kill the public link now
  portname unshare-all     revoke EVERY public link now
  portname install         run the daemon at login (LaunchAgent)
  portname install --dry-run  validate the install (writes nothing), never launchctl
  portname uninstall [--dry-run]
                           remove the daemon (app and ~/.portname stay)
  portname doctor          read-only checks with concrete remedies (no repairs)
  portname status --json   machine-readable diagnosis (no secrets, no project paths)

No DNS setup, no admin password. Everything else keeps working.
The menubar app (portname.app) is a pure client of this daemon; quitting it
leaves the daemon and all public links running — revoke links explicitly.
Default bind is the wildcard on port 80 with per-request zone gating;
set {"bind":"loopback","loopbackPort":7777} in ~/.portname/config.json for
maximum isolation (URLs then need :7777). Hand edits to the settings in
config.json (bind, ports, ignoreCommands, cloudflaredBin) take effect after
a daemon restart (portname install); names, manual entries and Wi-Fi
exposures are changed with the commands above.`);
    return;
  }
  throw new Error(`unknown command: ${cmd}. Try: portname help`);
}

if (require.main === module) {
  main(process.argv.slice(2))
    .then((code) => process.exit(typeof code === 'number' ? code : 0))
    .catch((err) => {
      console.error('portname: ' + err.message);
      process.exit(1);
    });
}

module.exports = {
  main, cmdStatus, exposeMessage, cmdInstall, cmdUninstall, formatRemainingTtl, browserHost, stableNodePath, plist, xmlEscape,
  assertPlistSafePath, send, MAX_RESPONSE_BYTES, createDaemonLogger, formatLogField, daemonLogFile, LOG_MAX_BYTES,
};
