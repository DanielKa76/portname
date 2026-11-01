'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const { Daemon } = require('../lib/daemon');
const { BonjourAnnouncer } = require('../lib/expose');
const {
  statusSnapshot,
  doctorChecks,
  doctorSummary,
  doctorExitCode,
  formatDoctorText,
  probeGatewayPort,
  maskPaths,
  STATUS_SCHEMA,
  DOCTOR_SCHEMA,
} = require('../lib/diagnose');

const BIN_PATH = path.resolve(__dirname, '../bin/portname.js');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function deepStatus() {
  return {
    ok: true,
    protocolVersion: 1,
    daemonInstanceId: '11111111-2222-3333-4444-555555555555',
    daemonVersion: '0.1.0',
    runtimeVersion: 'v26.12.1',
    payloadId: null,
    state: 'RUNNING',
    proxyPort: 80,
    bind: 'wildcard',
    lastGoodScanAt: Date.now() - 2000,
    scanError: null,
    lan: { available: true, reason: null, interfaceName: 'en0', address: '192.168.1.42' },
    routes: [
      {
        name: 'shop',
        id: '/Users/demo/private/shop',
        root: '/Users/demo/private/shop',
        cwd: '/Users/demo/private/shop/sub',
        port: 3000,
        upstreamHost: '127.0.0.1',
        pid: 4242,
        processKey: '4242:abc',
        command: 'node',
        external: false,
        manual: false,
        localUrl: 'http://shop.localhost/',
        lanUrl: null,
        exposureRequested: false,
      },
      {
        name: 'db',
        id: 'manual:db',
        root: null,
        port: 55432,
        upstreamHost: '127.0.0.1',
        command: 'manual',
        external: false,
        manual: true,
        exposureRequested: false,
      },
    ],
    stale: [{ name: 'shop', port: 2999, pid: 4141 }],
    exposed: [],
    shares: [
      {
        name: 'shop',
        shareId: 'share-1',
        url: 'https://secret-origin.trycloudflare.com',
        state: 'ACTIVE',
        expiresAt: Date.now() + 60_000,
        expired: false,
        ttlMinutes: 60,
        pinnedPort: 3000,
        lastVerifiedAt: Date.now() - 1000,
      },
    ],
  };
}

const HEALTHY_ENV = () => ({
  dir: '/Users/demo/.portname',
  launchAgentPath: '/Users/demo/Library/LaunchAgents/dev.portname.daemon.plist',
  exists: () => true,
  statMode: () => 0o700,
  // Injected resolution outcome: deterministic on every machine (no real
  // Homebrew/payload lookup happens in the healthy-path tests).
  resolveCloudflared: () => '/opt/homebrew/bin/cloudflared',
  cliVersion: '0.1.0',
  nodeVersion: 'v26.12.1',
  // Outside an app bundle: no payload manifest to compare against.
  bundleManifest: null,
});

test('status --json: schema carries versions, bind port, discovery state and installation facts', () => {
  const now = 1_000;
  const lastGoodScanAt = now - 2_000;
  const status = deepStatus();
  status.lastGoodScanAt = lastGoodScanAt;
  const snap = statusSnapshot({ status, ...HEALTHY_ENV(), now });

  assert.strictEqual(snap.schema, STATUS_SCHEMA);
  assert.strictEqual(snap.generatedAt, 1_000);
  assert.deepStrictEqual(snap.versions, {
    cli: '0.1.0',
    node: 'v26.12.1',
    protocol: 1,
    daemonInstanceId: '11111111-2222-3333-4444-555555555555',
    daemon: '0.1.0',
    daemonRuntime: 'v26.12.1',
  });
  assert.strictEqual(snap.daemon.reachable, true);
  assert.strictEqual(snap.daemon.state, 'RUNNING');
  assert.strictEqual(snap.daemon.bind, 'wildcard');
  assert.strictEqual(snap.daemon.bindPort, 80);
  assert.strictEqual(snap.daemon.scanError, null);
  assert.strictEqual(snap.daemon.lastGoodScanAt, lastGoodScanAt);
  assert.strictEqual(snap.installation.launchAgentInstalled, true);
  assert.strictEqual(snap.installation.stateDirPrivate, true);
  assert.strictEqual(snap.installation.cloudflaredFound, true);
  assert.strictEqual(snap.routes.length, 2);
  assert.strictEqual(snap.staleCount, 1);
  assert.strictEqual(snap.shares.length, 1);
  assert.deepStrictEqual(snap.remedies, [], 'a healthy install produces no remedies');
});

test('status --json: routes carry the effective WLAN exposure, honestly unknown for old daemons', () => {
  const status = deepStatus();
  status.routes[0].exposureRequested = true;
  status.routes[0].lanUrl = 'http://shop.local:80/';
  status.routes[0].exposureEffective = 'paused';
  status.routes[0].exposurePauseReason = 'target-not-verified';
  status.routes[1].exposureEffective = 'off';
  const snap = statusSnapshot({ status, ...HEALTHY_ENV(), now: 1_000 });

  assert.strictEqual(snap.routes[0].exposureRequested, true);
  assert.strictEqual(snap.routes[0].exposureEffective, 'paused');
  assert.strictEqual(snap.routes[0].exposurePauseReason, 'target-not-verified');
  assert.strictEqual(snap.routes[1].exposureEffective, 'off', 'an unexposed route is off');

  // Old daemon: no effective fields — the export must say "unknown",
  // never invent an "off" that the daemon never stated.
  const legacy = deepStatus();
  delete legacy.routes[0].exposureRequested;
  const legacySnap = statusSnapshot({ status: legacy, ...HEALTHY_ENV(), now: 1_000 });
  assert.strictEqual(legacySnap.routes[0].exposureEffective, null);
  assert.strictEqual(legacySnap.routes[0].exposurePauseReason, null);
});

test('status --json redaction: no project paths, no pids, no share origins or ids, no LAN address', () => {
  const status = deepStatus();
  // Pin the time fields: real epoch milliseconds can coincidentally contain
  // digit runs like the pids pinned below ("4242") and would flake this test.
  status.lastGoodScanAt = 1_000;
  status.shares[0].expiresAt = 61_000;
  const snap = statusSnapshot({ status, ...HEALTHY_ENV(), now: 1_000 });
  const text = JSON.stringify(snap);

  for (const secret of [
    '/Users/demo',
    'trycloudflare.com',
    'share-1',
    '4242',
    '192.168.1.42',
    '127.0.0.1',
  ]) {
    assert.ok(!text.includes(secret), `exported status must not contain ${secret}`);
  }
  for (const r of snap.routes) {
    for (const field of ['root', 'cwd', 'pid', 'processKey', 'upstreamHost', 'id']) {
      assert.ok(!(field in r), `exported routes must omit ${field}`);
    }
  }
  for (const s of snap.shares) {
    for (const field of ['url', 'shareId', 'pinnedPort', 'lastVerifiedAt']) {
      assert.ok(!(field in s), `exported shares must omit ${field}`);
    }
    assert.strictEqual(typeof s.name, 'string');
    assert.strictEqual(s.state, 'ACTIVE');
  }
  assert.strictEqual(snap.lan.interfaceName, 'en0', 'interface name is kept (explains WLAN reach)');
  assert.strictEqual(snap.lan.address, undefined, 'the LAN IP itself stays out of exports');
});

test('status --json: concrete remedies for the problems it can see', () => {
  const status = deepStatus();
  status.protocolVersion = null; // legacy daemon
  status.state = 'STARTING';
  status.scanError = 'lsof timed out';
  const snap = statusSnapshot({
    status,
    dir: '/Users/demo/.portname',
    launchAgentPath: '/nope.plist',
    exists: () => false,
    statMode: () => 0o755,
    resolveCloudflared: () => null,
    cliVersion: '0.1.0',
    nodeVersion: 'v26.8.2',
    now: 1_000,
  });

  const joined = snap.remedies.join('\n');
  assert.ok(joined.includes('portname install'), 'missing LaunchAgent must name the remedy');
  assert.ok(joined.includes('chmod 700'), 'loose state dir must name the remedy');
  assert.ok(joined.includes('cloudflared'), 'missing cloudflared must name the remedy');
  assert.ok(joined.includes('daemon'), 'a non-RUNNING daemon must get a remedy');
});

test('status --json: scanError free text is path-masked, the reason stays visible', () => {
  const status = deepStatus();
  status.scanError = 'listener scan failed: /Users/demo/x';
  const snap = statusSnapshot({ status, ...HEALTHY_ENV(), now: 1_000 });
  const text = JSON.stringify(snap);

  assert.ok(!text.includes('/Users/demo'), 'a path from scanError must not reach the snapshot');
  assert.ok(snap.daemon.scanError.includes('listener scan failed:'), 'the failure reason is kept');
  assert.ok(snap.daemon.scanError.includes('[path]'), 'the path itself is masked');
  const remedy = snap.remedies.find((r) => r.includes('discovery scan failed'));
  assert.ok(remedy, 'a failed scan must still produce its remedy');
  assert.ok(remedy.includes('[path]'), 'the remedy carries the masked error, not the raw path');
});

test('doctor: scanError and daemonError free text are path-masked in the details', () => {
  const status = deepStatus();
  status.scanError = "lsof: /Users/demo/private: Permission denied (errno 13)";
  const checks = doctorChecks({ status, ...HEALTHY_ENV(), gatewayProbe: { ok: true, detail: 'gateway answers on 127.0.0.1:80' } });
  const discovery = checks.find((c) => c.id === 'discovery');
  assert.ok(!discovery.detail.includes('/Users/demo'), 'a path from scanError must not reach doctor output');
  assert.ok(discovery.detail.includes('[path]'), 'the scan error is masked, not dropped');
  assert.ok(discovery.detail.includes('Permission denied (errno 13)'), 'the reason/errno stays visible');

  const down = doctorChecks({
    status: null,
    daemonError: 'connect EACCES /Users/demo/.portname/control.sock',
    ...HEALTHY_ENV(),
  });
  const socket = down.find((c) => c.id === 'daemon-socket');
  assert.strictEqual(socket.severity, 'fail');
  assert.ok(!socket.detail.includes('/Users/demo'), 'a path from daemonError must not reach doctor output');
  assert.ok(socket.detail.includes('[path]'), 'the daemon error is masked, not dropped');
  assert.ok(socket.detail.includes('EACCES'), 'the errno stays visible');
});

test('maskPaths: masks /… and ~/… tokens, keeps mid-word slashes and prose tildes', () => {
  assert.strictEqual(maskPaths('listener scan failed: /Users/demo/x'), 'listener scan failed: [path]');
  assert.strictEqual(maskPaths("open '/Users/demo/file' denied"), "open '[path]' denied");
  assert.strictEqual(maskPaths('cannot read ~/Library/Caches'), 'cannot read [path]');
  assert.strictEqual(maskPaths('scan ~demo/work died'), 'scan [path] died');
  assert.strictEqual(maskPaths('and/or ~50ms kept'), 'and/or ~50ms kept');
  assert.strictEqual(maskPaths('lsof timed out'), 'lsof timed out');
  assert.strictEqual(maskPaths(null), null);
});

test('doctor: unreachable daemon is the only failure, remedy points at install, exit code 2', () => {
  const checks = doctorChecks({ status: null, daemonError: 'cannot reach daemon (ENOENT)', ...HEALTHY_ENV() });
  const socket = checks.find((c) => c.id === 'daemon-socket');
  assert.strictEqual(socket.severity, 'fail');
  assert.ok(socket.remedy.includes('portname install'));

  // Everything that depends on the daemon is skipped, not faked as "ok".
  for (const id of ['protocol-version', 'daemon-state', 'discovery', 'gateway-port']) {
    assert.strictEqual(checks.find((c) => c.id === id).severity, 'skip', `${id} must be skipped`);
  }
  // Local facts are still reported.
  assert.ok(checks.find((c) => c.id === 'launch-agent'));
  assert.strictEqual(doctorExitCode({ status: null, checks }), 2);

  const report = formatDoctorText(checks, doctorSummary(checks));
  assert.ok(report.includes('repairs nothing') || report.includes('read-only'), 'report must state it is read-only');
});

test('doctor: healthy daemon passes every check (exit 0)', () => {
  const checks = doctorChecks({
    status: deepStatus(),
    gatewayProbe: { ok: true, detail: 'gateway answers on 127.0.0.1:80' },
    ...HEALTHY_ENV(),
  });
  assert.deepStrictEqual(doctorSummary(checks), { ok: checks.length, warn: 0, fail: 0, skip: 0 });
  assert.strictEqual(doctorExitCode({ status: deepStatus(), checks }), 0);
  for (const c of checks) {
    assert.strictEqual(c.severity, 'ok', `check ${c.id} must pass`);
    assert.ok(c.detail, 'every check explains itself');
  }
});

// Doctor must go through the SAME cloudflared resolution as a
// share start — in payload operation the bundled binary satisfies the check
// even when nothing is on PATH (the default resolver runs over a fixture
// payload home; bundled takes precedence over any Homebrew binary).
test('doctor: payload context with only the bundled binary reports found (bundled path)', () => {
  const home = tmpDir('pn-diag-bundled-');
  const bundled = path.join(home, 'Library', 'Application Support', 'Portname', 'runtime', 'bin', 'cloudflared');
  fs.mkdirSync(path.dirname(bundled), { recursive: true });
  fs.writeFileSync(bundled, '#!/bin/sh\n');
  fs.chmodSync(bundled, 0o755);
  try {
    const checks = doctorChecks({
      status: deepStatus(),
      gatewayProbe: { ok: true, detail: 'gateway answers on 127.0.0.1:80' },
      dir: '/Users/demo/.portname',
      launchAgentPath: '/Users/demo/Library/LaunchAgents/dev.portname.daemon.plist',
      exists: () => true,
      statMode: () => 0o700,
      which: () => null,
      home,
      isPayloadEntry: true,
      cliVersion: '0.1.0',
      nodeVersion: 'v26.8.2',
    });
    const cf = checks.find((c) => c.id === 'cloudflared');
    assert.strictEqual(cf.severity, 'ok', `the bundled binary must satisfy the check: ${cf.detail}`);
    // Reported home-relative (no account name in a pasted report).
    const shown = '~' + bundled.slice(home.length);
    assert.ok(cf.detail.includes(shown), `the bundled path must be reported: ${cf.detail}`);
    assert.ok(!cf.detail.includes(home), 'the home path itself is not reported');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('doctor: an explicit cloudflaredBin override is reported by its path', () => {
  const checks = doctorChecks({
    status: deepStatus(),
    gatewayProbe: { ok: true, detail: 'gateway answers on 127.0.0.1:80' },
    dir: '/Users/demo/.portname',
    launchAgentPath: '/Users/demo/Library/LaunchAgents/dev.portname.daemon.plist',
    exists: () => true,
    statMode: () => 0o700,
    which: () => null,
    cloudflaredBin: '/usr/local/bin/special-cloudflared',
    cliVersion: '0.1.0',
    nodeVersion: 'v26.8.2',
  });
  const cf = checks.find((c) => c.id === 'cloudflared');
  assert.strictEqual(cf.severity, 'ok', `the override must satisfy the check: ${cf.detail}`);
  assert.ok(cf.detail.includes('/usr/local/bin/special-cloudflared'), `the override path must be reported: ${cf.detail}`);
});

test('doctor: failed scan, dead gateway, loose permissions and missing pieces produce remedies (exit 1)', () => {
  const status = deepStatus();
  status.scanError = 'lsof timed out';
  status.lastGoodScanAt = null;
  const checks = doctorChecks({
    status,
    daemonError: null,
    gatewayProbe: { ok: false, detail: 'connect ECONNREFUSED' },
    dir: '/Users/demo/.portname',
    launchAgentPath: '/nope.plist',
    exists: () => false,
    statMode: () => 0o755,
    resolveCloudflared: () => null,
    cliVersion: '0.1.0',
    nodeVersion: 'v26.8.2',
  });

  const byId = Object.fromEntries(checks.map((c) => [c.id, c]));
  assert.strictEqual(byId['discovery'].severity, 'warn');
  assert.ok(byId['discovery'].detail.includes('lsof timed out'));
  assert.strictEqual(byId['gateway-port'].severity, 'fail');
  assert.strictEqual(byId['state-dir'].severity, 'fail');
  assert.ok(byId['state-dir'].remedy.includes('chmod 700'));
  assert.strictEqual(byId['launch-agent'].severity, 'warn');
  assert.ok(byId['launch-agent'].remedy.includes('portname install'));
  assert.strictEqual(byId['cloudflared'].severity, 'warn');
  assert.ok(byId['cloudflared'].remedy.includes('cloudflared'));
  assert.strictEqual(doctorExitCode({ status, checks }), 1, 'any fail must yield exit code 1');
});

test('doctor --json is parseable, versioned and free of secrets even on a broken install', async () => {
  const dir = tmpDir('pn-diag-doctor-');
  // No daemon on this dir: doctor must still emit its JSON report and exit 2.
  const proc = spawn(process.execPath, [BIN_PATH, 'doctor', '--json'], {
    env: { ...process.env, PORTNAME_DIR: dir },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  proc.stdout.on('data', (d) => (stdout += d));
  const exitCode = await new Promise((resolve) => proc.on('close', resolve));
  assert.strictEqual(exitCode, 2);
  const report = JSON.parse(stdout);
  assert.strictEqual(report.schema, DOCTOR_SCHEMA);
  assert.ok(Array.isArray(report.checks) && report.checks.length >= 5);
  assert.ok(report.checks.every((c) => c.id && c.severity));
  assert.ok(!stdout.includes('token'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('status --json over a running daemon: parseable, reachable, remedies absent, no tmp paths leaked', async () => {
  const dir = tmpDir('pn-diag-status-');
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', port: 0, fallbackPort: 0, loopbackPort: 0, control: true },
    listListeners: async () => [],
  });
  let proc;
  try {
    await daemon.start();
    proc = spawn(process.execPath, [BIN_PATH, 'status', '--json'], {
      env: { ...process.env, PORTNAME_DIR: dir },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    proc.stdout.on('data', (d) => (stdout += d));
    const exitCode = await new Promise((resolve) => proc.on('close', resolve));
    assert.strictEqual(exitCode, 0);
    const snap = JSON.parse(stdout);
    assert.strictEqual(snap.schema, STATUS_SCHEMA);
    assert.strictEqual(snap.daemon.reachable, true);
    assert.strictEqual(typeof snap.daemon.bindPort, 'number');
    assert.ok(Array.isArray(snap.routes));
    assert.ok(!stdout.includes(dir), 'the (tmp) state dir is a private path — never leaked');
    assert.ok(!stdout.includes('root') && !stdout.includes('cwd'), 'no path fields in exported routes');
    // Remedies depend on the host installation (LaunchAgent, cloudflared);
    // only the shape is contract here.
    assert.ok(Array.isArray(snap.remedies));
  } finally {
    if (proc && proc.exitCode === null) proc.kill('SIGKILL');
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('probeGatewayPort: reports a listening gateway and a dead port, read-only', async () => {
  const server = net.createServer(() => {});
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const good = await probeGatewayPort(port);
  assert.strictEqual(good.ok, true);

  server.close();
  const bad = await probeGatewayPort(port);
  assert.strictEqual(bad.ok, false);
  assert.ok(bad.detail);
});

test('daemon: status exposes lan interface name and the last good scan time (additive v1 fields)', async () => {
  const dir = tmpDir('pn-diag-lan-');
  const announcer = {
    cleanupOrphans() {},
    childPids() { return []; },
    lanAddress() { return '192.168.1.50'; },
    lanInterfaceName() { return 'en0'; },
    stopAll() {},
    sync() { return { ok: true }; },
  };
  const daemon = new Daemon({
    dir,
    announcer,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => [],
  });
  try {
    await daemon.start();
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.lan.interfaceName, 'en0');
    assert.strictEqual(status.lan.address, '192.168.1.50');
    assert.strictEqual(typeof status.lastGoodScanAt, 'number');

    // An older-style announcer mock without the new method must not crash.
    delete announcer.lanInterfaceName;
    const status2 = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status2.lan.interfaceName, null);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: unshare-all revokes every live share through the normal stop path', async () => {
  const dir = tmpDir('pn-diag-unshare-all-');
  const script = path.join(dir, 'cf-ok.js');
  fs.writeFileSync(script, '#!/usr/bin/env node\nconsole.log("https://all.trycloudflare.com");\nsetInterval(() => {}, 1000);\n');
  fs.chmodSync(script, 0o755);

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    // The shares below have no route (the scan is empty), so a correctly
    // working periodic refresh would revoke them — under load the 3 s timer
    // fired before the assertions. unshare-all is exercised explicitly.
    refreshMs: 3_600_000,
    listListeners: async () => [],
  });
  try {
    await daemon.start();
    await daemon.shares.start({ name: 'a', targetPort: 5151, ttlMinutes: 60, cloudflaredBin: script, timeoutMs: 5000 });
    await daemon.shares.start({ name: 'b', targetPort: 5152, ttlMinutes: 60, cloudflaredBin: script, timeoutMs: 5000 });
    assert.strictEqual(daemon.shares.isShared('a'), true);
    assert.strictEqual(daemon.shares.isShared('b'), true);
    const childPids = daemon.shares.childPids();
    assert.ok(childPids.length >= 2);

    const res = await daemon.dispatchControl({ cmd: 'unshare-all' });
    assert.deepStrictEqual([...res.stopped].sort(), ['a', 'b']);
    assert.strictEqual(daemon.shares.isShared('a'), false);
    assert.strictEqual(daemon.shares.isShared('b'), false);
    for (const pid of childPids) {
      let alive = true;
      try { process.kill(pid, 0); } catch { alive = false; }
      assert.strictEqual(alive, false, 'tunnel children must be torn down');
    }

    // Idempotent: nothing left to revoke.
    const res2 = await daemon.dispatchControl({ cmd: 'unshare-all' });
    assert.deepStrictEqual(res2.stopped, []);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: unshare-all stays available while stopping (revocation is never scan-bound)', async (t) => {
  const dir = tmpDir('pn-diag-unshare-stopping-');
  const script = path.join(dir, 'cf-hang.js');
  fs.writeFileSync(
    script,
    '#!/usr/bin/env node\nconsole.log("https://hang.trycloudflare.com");\nprocess.on("SIGTERM", () => {});\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(script, 0o755);

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    // The share below has no route (the scan is empty), so a correctly
    // working periodic refresh would revoke it — under load the 3 s timer
    // fired before the share reached the stop() gate. unshare-all is
    // exercised explicitly.
    refreshMs: 3_600_000,
    listListeners: async () => [],
  });
  try {
    await daemon.start();
    await daemon.shares.start({ name: 'a', targetPort: 5151, ttlMinutes: 60, cloudflaredBin: script, timeoutMs: 5000 });
    const stopPromise = daemon.stop();
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(daemon.state, 'STOPPING');

    const res = await daemon.dispatchControl({ cmd: 'unshare-all' });
    assert.deepStrictEqual(res.stopped, ['a'], 'unshare-all must pass the lifecycle gate like unshare');
    await stopPromise;
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('BonjourAnnouncer.lanInterfaceName reports the selected interface name', () => {
  const dir = tmpDir('pn-diag-ann-');
  const announcer = new BonjourAnnouncer({
    port: 80,
    dir,
    getLan: () => ({ name: 'en0', address: '10.1.2.3', netmask: '255.255.255.0', family: 'IPv4' }),
  });
  assert.strictEqual(announcer.lanInterfaceName(), 'en0');
  announcer.getLan = () => null;
  assert.strictEqual(announcer.lanInterfaceName(), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CLI: status --json without a daemon exits 1 with a plain stderr message', async () => {
  const dir = tmpDir('pn-diag-cli-status-');
  const proc = spawn(process.execPath, [BIN_PATH, 'status', '--json'], {
    env: { ...process.env, PORTNAME_DIR: dir },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  proc.stderr.on('data', (d) => (stderr += d));
  const exitCode = await new Promise((resolve) => proc.on('close', resolve));
  assert.strictEqual(exitCode, 1);
  assert.ok(stderr.includes('portname:'));
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Build identity and runtime floor
// ---------------------------------------------------------------------------

const { nodeRuntimeVerdict, buildVerdict, NODE_RUNTIME_FLOORS } = require('../lib/diagnose');
const { readBuildInfo } = require('../lib/daemon');

test('runtime floor: security patch releases per LTS line; older patches and EOL lines warn', () => {
  assert.deepStrictEqual(NODE_RUNTIME_FLOORS, { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' });
  for (const v of ['v22.23.4', 'v22.24.0', 'v24.22.1', 'v24.23.0', 'v26.12.1', 'v27.1.0']) {
    assert.strictEqual(nodeRuntimeVerdict(v).ok, true, `${v} must pass`);
  }
  for (const v of ['v22.22.0', 'v24.21.0', 'v26.8.2', 'v25.9.0', 'v20.18.0', 'garbage']) {
    assert.strictEqual(nodeRuntimeVerdict(v).ok, false, `${v} must warn`);
  }
  const pkg = require('../package.json');
  assert.strictEqual(pkg.engines.node, '^22.23.4 || ^24.22.1 || >=26.12.1', 'engines documents the same floor');
});

test('doctor/status: a daemon runtime below the floor warns with the matching remedy', () => {
  const status = { ...deepStatus(), runtimeVersion: 'v22.22.0' };
  const checks = doctorChecks({ status, ...HEALTHY_ENV(), gatewayProbe: { ok: true, detail: 'ok' } });
  const runtime = checks.find((c) => c.id === 'node-runtime');
  assert.strictEqual(runtime.severity, 'warn');
  assert.match(runtime.detail, /v22\.22\.0.*security floor v22\.23\.4/);
  assert.match(runtime.remedy, /Update Node\.js/);
  assert.strictEqual(doctorExitCode({ status, checks }), 0, 'a warning, not a failure');

  const bundled = { ...status, payloadId: 'a'.repeat(64) };
  const bundledCheck = doctorChecks({ status: bundled, ...HEALTHY_ENV() }).find((c) => c.id === 'node-runtime');
  assert.match(bundledCheck.remedy, /update the app/, 'a bundled runtime is fixed by updating Portname');

  const snap = statusSnapshot({ status, ...HEALTHY_ENV(), now: 1_000 });
  assert.ok(snap.remedies.some((r) => /security floor/.test(r)));
  assert.strictEqual(snap.versions.daemonRuntime, 'v22.22.0', 'the daemon runtime is reported, not only the CLI node');
});

test('doctor: a stale background service is detected (payload, version, pre-build daemons)', () => {
  const manifest = { payloadId: 'b'.repeat(64), appPath: '/Applications/Portname.app' };
  const stale = { ...deepStatus(), payloadId: 'a'.repeat(64) };
  let v = buildVerdict({ status: stale, cliVersion: '0.1.0', bundleManifest: manifest });
  assert.strictEqual(v.ok, false);
  assert.match(v.remedy, /portname-cli install/);
  v = buildVerdict({ status: { ...stale, payloadId: manifest.payloadId }, cliVersion: '0.1.0', bundleManifest: manifest });
  assert.strictEqual(v.ok, true);
  v = buildVerdict({ status: { ...deepStatus(), daemonVersion: '0.0.9' }, cliVersion: '0.1.0', bundleManifest: null });
  assert.strictEqual(v.ok, false, 'a daemon older than the CLI must not look current');
  const older = { ...deepStatus() };
  delete older.daemonVersion;
  const checks = doctorChecks({ status: older, ...HEALTHY_ENV() });
  assert.strictEqual(checks.find((c) => c.id === 'daemon-build').severity, 'warn');
});

test('daemon status reports its own build and runtime; payloadId only from the installed payload', async () => {
  const dir = tmpDir('pn-diag-build-');
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', port: 0, fallbackPort: 0, loopbackPort: 0, control: false },
    listListeners: async () => [],
  });
  const oldHome = process.env.HOME;
  try {
    await daemon.start();
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.daemonVersion, require('../package.json').version);
    assert.strictEqual(status.runtimeVersion, process.version);
    assert.strictEqual(status.payloadId, null, 'a checkout is not the installed payload');

    process.env.HOME = dir;
    const payload = path.join(dir, 'Library', 'Application Support', 'Portname');
    fs.mkdirSync(path.join(payload, 'daemon', 'lib'), { recursive: true });
    fs.writeFileSync(path.join(payload, 'MANIFEST.json'),
      JSON.stringify({ schema: 'portname.payload-manifest/1', payloadId: 'c'.repeat(64), files: [] }));
    assert.strictEqual(readBuildInfo(path.join(payload, 'daemon', 'lib')).payloadId, 'c'.repeat(64));
  } finally {
    process.env.HOME = oldHome;
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('doctor details never carry the home path; maskPaths covers paths with spaces', () => {
  const checks = doctorChecks({
    status: deepStatus(),
    gatewayProbe: { ok: true, detail: 'gateway answers on 127.0.0.1:80' },
    ...HEALTHY_ENV(),
    home: '/Users/demo',
    launchAgentPath: '/Users/demo/Library/LaunchAgents/dev.portname.daemon.plist',
    resolveCloudflared: () => '/Users/demo/Library/Application Support/Portname/runtime/bin/cloudflared',
  });
  for (const c of checks) assert.ok(!c.detail.includes('/Users/demo'), `${c.id} leaks the home path: ${c.detail}`);
  assert.match(checks.find((c) => c.id === 'launch-agent').detail, /~\/Library\/LaunchAgents\/dev\.portname\.daemon\.plist/);

  assert.strictEqual(
    maskPaths("lsof: WARNING: can't stat() smbfs file system /Volumes/Kunde Müller GmbH/Projekte)"),
    "lsof: WARNING: can't stat() smbfs file system [path]"
  );
  assert.strictEqual(maskPaths('x /Users/Jane Doe/Library y'), 'x [path] y');
  assert.strictEqual(maskPaths('lsof: /a/b: Permission denied (errno 13)'), 'lsof: [path] Permission denied (errno 13)',
    'reason and errno prose after a path stays readable');
});
