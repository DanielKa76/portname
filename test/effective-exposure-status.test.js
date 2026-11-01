'use strict';

// The status surface must show the EFFECTIVE WLAN exposure, derived from the
// same decision that gates gateway access (tuple-bound freshness,
// #lanFreshRoute), not from the desired flag alone.
//
// Contract:
//   S1  exposureEffective mirrors the gateway's per-request authorization:
//       "active" (wish AND fresh tuple-bound verification), "paused" (wish
//       set, access currently withheld), "off" (no wish);
//   S2  paused carries a machine-readable exposurePauseReason:
//       "target-not-verified" (the gateway would refuse the request),
//       "no-lan-interface" / "loopback-bind" (no WLAN path at all) — the
//       situations must be distinguishable;
//   S3  the desired state stays visible and unchanged: exposureRequested,
//       lanUrl (advertised address) and the top-level `exposed` array keep
//       their legacy meaning (old clients see exactly what they saw);
//   S4  exposureVerifiedAt is the verification timestamp the decision is
//       actually based on (the tuple record), so clients can show the age;
//   S5  recovery: a fresh successful scan flips paused back to active —
//       exactly when the gateway starts granting access again;
//   S6  lanRegistration tells whether the advertised name is ours on the
//       network ("conflict": dns-sd found it in use) — additive, without
//       touching the fields above.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const { Daemon } = require('../lib/daemon');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => res.end('upstream:' + req.url));
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

function closeUpstream(u) {
  u.server.closeAllConnections();
  return new Promise((r) => u.server.close(r));
}

// Auto-discovered project listener fixture.
function autoListener(pid, port, root, processKey) {
  return {
    pid,
    port,
    processKey,
    command: 'node',
    cwd: root,
    root,
    external: false,
    suggestedName: path.basename(root),
  };
}

// Manual-target listener fixture (no project root; the observed listener is
// its process generation).
function manualListener(pid, port, processKey) {
  return {
    pid,
    port,
    processKey,
    command: 'postgres',
    cwd: null,
    root: null,
    external: false,
  };
}

function stubAnnouncer() {
  return {
    cleanupOrphans() {},
    childPids() { return []; },
    lanAddress() { return '192.168.1.50'; },
    lanInterfaceName() { return 'en0'; },
    stopAll() {},
    sync() { return { ok: true }; },
  };
}

// Plain HTTP status of a gateway request pretending to come from the WLAN
// (isLoopbackClient seam below classifies the socket as non-loopback).
function lanStatus(port, host) {
  return new Promise((resolve) => {
    const req = http.get(
      { host: '127.0.0.1', port, path: '/', headers: { host }, agent: false },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      }
    );
    req.on('error', () => resolve(0));
  });
}

// failScans: when true the scan itself fails (degraded pass: previous routes
// are kept, lanVerifiedAt is untouched and ages out).
//
// The grace is deliberately WIDE: "active" assertions must survive the real
// time between a fresh re-credit and the status/HTTP probes under parallel
// test load. The expiry deadline is exercised with an explicit time offset —
// the verification record is backdated past the deadline instead of sleeping
// real time — which is deterministic regardless of machine load.
function makeDaemon({ dir, listeners, announcer = stubAnnouncer(), lanVerifyGraceMs = 60_000 }) {
  return new Daemon({
    dir,
    announcer,
    routeFreshnessMs: 60000,
    lanVerifyGraceMs,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => listeners(),
  });
}

// Explicit time offset: age an identity's verification record past the
// deadline without waiting real time.
function expireLanVerification(daemon, identity) {
  const rec = daemon.lanVerifiedAt.get(identity);
  assert.ok(rec, 'the identity must carry a verification record to expire');
  rec.verifiedAt = Date.now() - (daemon.lanVerifyGraceMs + 1000);
}

async function startDaemon(daemon) {
  const gwPort = await daemon.start();
  // Simulated WLAN: every gateway socket is a non-loopback LAN client.
  daemon.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
  daemon.gateway.isLoopbackClient = () => false;
  return gwPort;
}

async function statusRoute(daemon, name) {
  const res = await daemon.dispatchControl({ cmd: 'status' });
  return res.routes.find((r) => r.name === name);
}

// ---------------------------------------------------------------------------

test('status: effective exposure follows the gateway decision (active, paused, recovery)', async () => {
  const dir = tmpDir('pn-eff-active-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const u = await startUpstream();
  let failScans = false;
  const listeners = [autoListener(7001, u.port, shopDir, '7001:a')];

  const daemon = makeDaemon({
    dir,
    listeners: () => {
      if (failScans) throw new Error('lsof exploded');
      return listeners;
    },
  });
  try {
    const gwPort = await startDaemon(daemon);
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });

    const active = await statusRoute(daemon, 'shop');
    assert.strictEqual(active.exposureRequested, true, 'the wish is reported as before');
    assert.strictEqual(active.exposureEffective, 'active', 'fresh verification: access is effective');
    assert.strictEqual(active.exposurePauseReason, null);
    assert.ok(Number.isFinite(active.exposureVerifiedAt), 'the verification age of the decision is exposed');
    assert.ok(active.lanUrl, 'the advertised address is unchanged');
    const topLevel = await daemon.dispatchControl({ cmd: 'status' });
    assert.ok(topLevel.exposed.includes('shop'), 'top-level exposed list keeps its legacy meaning');
    assert.strictEqual(await lanStatus(gwPort, 'shop.local'), 200);

    // Sustained discovery failure: a single failed scan defers revocation
    // (the last verification is still inside the grace window).
    failScans = true;
    await daemon.refresh();
    const deferred = await statusRoute(daemon, 'shop');
    assert.strictEqual(deferred.exposureEffective, 'active', 'one failed scan defers revocation');
    assert.strictEqual(await lanStatus(gwPort, 'shop.local'), 200);

    // Sustained failure past the deadline: the gateway refuses — and the
    // status must show exactly that instead of a live WLAN badge. The aging
    // is applied as an explicit time offset instead of sleeping real time,
    // so the deadline cannot elapse (or not elapse) between the assertions
    // depending on machine load.
    expireLanVerification(daemon, shopDir);
    await daemon.refresh();

    const paused = await statusRoute(daemon, 'shop');
    assert.strictEqual(paused.exposureRequested, true, 'the wish survives');
    assert.strictEqual(paused.exposureEffective, 'paused', 'the daemon withholds access: status must say so');
    assert.strictEqual(paused.exposurePauseReason, 'target-not-verified');
    assert.ok(paused.lanUrl, 'the advertised address stays advertised (Bonjour keeps the wish)');
    assert.strictEqual(await lanStatus(gwPort, 'shop.local'), 404, 'gateway and status must agree');
    const topLevel2 = await daemon.dispatchControl({ cmd: 'status' });
    assert.ok(topLevel2.exposed.includes('shop'), 'legacy contract: top-level exposed is the wish list');

    // Recovery: a fresh successful scan re-enables access and the status
    // flips back in the same instant the gateway starts granting it. The
    // wide grace makes both probes deterministic after the re-credit.
    failScans = false;
    await daemon.refresh();
    const recovered = await statusRoute(daemon, 'shop');
    assert.strictEqual(recovered.exposureEffective, 'active');
    assert.strictEqual(recovered.exposurePauseReason, null);
    assert.strictEqual(await lanStatus(gwPort, 'shop.local'), 200);
  } finally {
    await daemon.stop();
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('status: no LAN interface is a distinct pause reason, not target-not-verified', async () => {
  const dir = tmpDir('pn-eff-nolan-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const u = await startUpstream();
  const listeners = [autoListener(7002, u.port, shopDir, '7002:a')];

  const announcer = stubAnnouncer();
  const daemon = makeDaemon({ dir, listeners: () => listeners, announcer });
  try {
    await startDaemon(daemon);
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual((await statusRoute(daemon, 'shop')).exposureEffective, 'active');

    // The interface disappears (roaming/off): no WLAN path at all.
    announcer.lanAddress = () => null;
    const res = await daemon.dispatchControl({ cmd: 'status' });
    const paused = res.routes.find((r) => r.name === 'shop');
    assert.strictEqual(paused.exposureEffective, 'paused');
    assert.strictEqual(paused.exposurePauseReason, 'no-lan-interface');
    assert.strictEqual(paused.lanUrl, null, 'no advertised address without an interface');
    assert.strictEqual(paused.exposureRequested, true, 'wish still visible');
  } finally {
    await daemon.stop();
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('status: never-exposed routes are off with no pause reason', async () => {
  const dir = tmpDir('pn-eff-off-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const u = await startUpstream();
  const listeners = [autoListener(7003, u.port, shopDir, '7003:a')];

  const daemon = makeDaemon({ dir, listeners: () => listeners });
  try {
    await startDaemon(daemon);
    const off = await statusRoute(daemon, 'shop');
    assert.strictEqual(off.exposureEffective, 'off');
    assert.strictEqual(off.exposurePauseReason, null);
    assert.strictEqual(off.exposureVerifiedAt, null);
    assert.strictEqual(off.exposureRequested, false);
  } finally {
    await daemon.stop();
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('status: manual repoint to an unobserved target shows paused with the reason', async () => {
  const dir = tmpDir('pn-eff-manual-');
  const u1 = await startUpstream();
  const u3 = await startUpstream(); // never observed by any scan
  const listeners = [manualListener(7104, u1.port, '7104:m1')];

  const daemon = makeDaemon({ dir, listeners: () => listeners });
  try {
    const gwPort = await startDaemon(daemon);
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u1.port });
    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.strictEqual((await statusRoute(daemon, 'api')).exposureEffective, 'active');

    // Repoint to a port no scan has ever observed: the record dies with the
    // mutation, the gateway refuses, status agrees.
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u3.port });
    const paused = await statusRoute(daemon, 'api');
    assert.strictEqual(paused.exposureEffective, 'paused');
    assert.strictEqual(paused.exposurePauseReason, 'target-not-verified');
    assert.strictEqual(await lanStatus(gwPort, 'api.local'), 404);
  } finally {
    await daemon.stop();
    await closeUpstream(u1);
    await closeUpstream(u3);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// A dns-sd stand-in: a registration of a name listed in `inUse` ends at once
// with dns-sd's "name in use" exit code (255); every other one keeps running.
function fakeDnsSd(inUse) {
  const { EventEmitter } = require('events');
  let pid = 61000;
  return (cmd, args) => {
    const child = new EventEmitter();
    child.pid = ++pid;
    child.kill = () => true;
    if (inUse.has(args[1])) setImmediate(() => child.emit('exit', 255));
    return child;
  };
}

test('status: lanRegistration reports a name another device already answers for', async () => {
  const { BonjourAnnouncer } = require('../lib/expose');
  const dir = tmpDir('pn-eff-registration-');
  const shopDir = path.join(dir, 'shop');
  const blogDir = path.join(dir, 'blog');
  const docsDir = path.join(dir, 'docs');
  for (const d of [shopDir, blogDir, docsDir]) fs.mkdirSync(d);
  const shop = await startUpstream();
  const blog = await startUpstream();
  const docs = await startUpstream();
  const listeners = [
    autoListener(7201, shop.port, shopDir, '7201:a'),
    autoListener(7202, blog.port, blogDir, '7202:a'),
    autoListener(7203, docs.port, docsDir, '7203:a'),
  ];
  const announcer = new BonjourAnnouncer({
    port: 80,
    getLan: () => ({ name: 'en0', address: '192.168.1.50', netmask: '255.255.255.0' }),
    spawnFn: fakeDnsSd(new Set(['shop'])),
  });
  const daemon = makeDaemon({ dir, listeners: () => listeners, announcer });
  try {
    const gwPort = await startDaemon(daemon);
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    await daemon.dispatchControl({ cmd: 'expose', name: 'blog', on: true });
    await new Promise((r) => setImmediate(r));

    const conflict = await statusRoute(daemon, 'shop');
    assert.strictEqual(conflict.lanRegistration, 'conflict', 'dns-sd found shop.local in use on the network');
    // Additive: the access decision and the advertised address are unchanged.
    assert.strictEqual(conflict.exposureEffective, 'active');
    assert.ok(conflict.lanUrl);
    assert.strictEqual(await lanStatus(gwPort, 'shop.local'), 200);

    assert.strictEqual((await statusRoute(daemon, 'blog')).lanRegistration, 'registering');
    assert.strictEqual((await statusRoute(daemon, 'docs')).lanRegistration, null, 'not exposed: not advertised');

    // Switched off, the name is no longer advertised (and its backoff dropped).
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: false });
    assert.strictEqual((await statusRoute(daemon, 'shop')).lanRegistration, null);
  } finally {
    await daemon.stop();
    for (const u of [shop, blog, docs]) await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('status: lanRegistration is null for an announcer that cannot report it', async () => {
  const dir = tmpDir('pn-eff-registration-legacy-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const u = await startUpstream();
  const daemon = makeDaemon({ dir, listeners: () => [autoListener(7301, u.port, shopDir, '7301:a')] });
  try {
    await startDaemon(daemon);
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    const route = await statusRoute(daemon, 'shop');
    assert.strictEqual(route.exposureEffective, 'active');
    assert.ok(Object.hasOwn(route, 'lanRegistration'), 'the field is always present');
    assert.strictEqual(route.lanRegistration, null);
  } finally {
    await daemon.stop();
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
