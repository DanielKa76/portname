'use strict';

// Endpoint-bound LAN verification.
//
// The LAN verification bookkeeping (lanVerifiedAt) moves from a bare
// timestamp to one record per identity, bound to the exact endpoint tuple it
// was observed on: { host, port, processKey, verifiedAt } (I8). Contract:
//   I8   a record only vouches for a route whose tuple matches the record's
//        tuple, within lanVerifyGraceMs;
//   I9   known target mutations (add with changed port, remove, set-primary
//        with a port change) delete the record before the refresh pass; a
//        successful pass re-credits only when it observed the new tuple; a
//        port now served by a different upstream host invalidates the
//        credit outright; restarts start unverified (in-memory only);
//   I10  a successful scan that does not observe the tuple lets the record
//        age unrefreshed; failed/degraded passes never touch lanVerifiedAt;
//   I11  every freshness decision is tuple-bound: expose on, the gateway's
//        per-request isExposed (the gateway passes the route additively as a
//        second argument — the daemon fails closed without a route), and the
//        long-lived revoke (route via getRoute);
//   I12  shareVerifyGraceMs / lastVerifiedAt stamping (only surviving shares
//        actually binding-verified in this pass) unchanged.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const { Daemon } = require('../lib/daemon');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

// Manual-target listener fixture (no project root; the observed listener is
// its process generation). upstreamHost mirrors what lsof enrichment reports.
function manualListener(pid, port, processKey, upstreamHost) {
  return {
    pid,
    port,
    processKey,
    command: 'postgres',
    cwd: null,
    root: null,
    external: false,
    ...(upstreamHost ? { upstreamHost } : {}),
  };
}

// Auto-discovered project listener fixture.
function autoListener(pid, port, root, processKey, upstreamHost) {
  return {
    pid,
    port,
    processKey,
    command: 'node',
    cwd: root,
    root,
    external: false,
    suggestedName: path.basename(root),
    ...(upstreamHost ? { upstreamHost } : {}),
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

async function daemonWith({ dir, listeners }) {
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    // Generous windows: the tests assert tuple binding, never timestamp aging.
    routeFreshnessMs: 60000,
    lanVerifyGraceMs: 60000,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => listeners(),
  });
  const gwPort = await daemon.start();
  // Simulated WLAN: every gateway socket is a non-loopback LAN client.
  daemon.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
  daemon.gateway.isLoopbackClient = () => false;
  return { daemon, gwPort };
}

async function stopDaemon(daemon) {
  await daemon.stop();
}

// ---------------------------------------------------------------------------
// Manual targets: mutation-driven invalidation + observation-driven credit
// ---------------------------------------------------------------------------

test('LAN: repoint to unobserved port refuses expose and LAN requests', async () => {
  const dir = tmpDir('pn-lan-repoint-');
  const u1 = await startUpstream();
  const u2 = await startUpstream(); // its port exists, but is NOT observed yet
  let listeners = [manualListener(6001, u1.port, '6001:m1')];

  const { daemon, gwPort } = await daemonWith({ dir, listeners: () => listeners });
  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u1.port });
    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.strictEqual(daemon.registry.isExposed('manual:api'), true, 'precondition: exposure flag set');
    assert.strictEqual(
      await lanStatus(gwPort, 'api.local'), 200,
      'precondition: the verified target serves WLAN requests'
    );

    // Repoint the manual entry to the not-yet-observed port. The credit was
    // bound to (127.0.0.1, u1.port); the mutation must kill it immediately.
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u2.port });

    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true }),
      (err) => err.code === 'LAN_TARGET_UNVERIFIED',
      'expose must be refused while the new port is unobserved'
    );
    assert.strictEqual(
      await lanStatus(gwPort, 'api.local'), 404,
      'WLAN requests must be refused for the unobserved target'
    );
  } finally {
    await stopDaemon(daemon);
    await closeUpstream(u1);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('LAN: after the new target is observed, expose and access succeed', async () => {
  const dir = tmpDir('pn-lan-recredit-');
  const u1 = await startUpstream();
  const u2 = await startUpstream();
  let listeners = [manualListener(6002, u1.port, '6002:m1')];

  const { daemon, gwPort } = await daemonWith({ dir, listeners: () => listeners });
  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u1.port });
    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });

    // Repoint to u2's port, then let a successful pass observe it: access
    // must follow the newly observed tuple (refusal until observation is
    // covered by the repoint and remove+re-add tests).
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u2.port });
    listeners = [manualListener(6003, u2.port, '6003:m2')];
    await daemon.refresh();

    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.strictEqual(await lanStatus(gwPort, 'api.local'), 200, 'access must follow policy after re-verification');
  } finally {
    await stopDaemon(daemon);
    await closeUpstream(u1);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('LAN: the credit record carries the observed endpoint tuple', async () => {
  const dir = tmpDir('pn-lan-record-');
  const u2 = await startUpstream();
  let listeners = [manualListener(6012, u2.port, '6012:m2')];

  const { daemon } = await daemonWith({ dir, listeners: () => listeners });
  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u2.port });
    await daemon.refresh();
    const rec = daemon.lanVerifiedAt.get('manual:api');
    assert.ok(rec && typeof rec === 'object', 'the credit must be a tuple record, not a bare timestamp');
    assert.strictEqual(rec.host, '127.0.0.1');
    assert.strictEqual(rec.port, u2.port);
    assert.strictEqual(rec.processKey, '6012:m2', 'the record must carry the observed generation');
    assert.ok(Number.isFinite(rec.verifiedAt) && rec.verifiedAt <= Date.now());
  } finally {
    await stopDaemon(daemon);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('LAN: upstream host change invalidates the credit', async () => {
  const dir = tmpDir('pn-lan-hostswap-');
  const u2 = await startUpstream();
  let listeners = [manualListener(6004, u2.port, '6004:m1')];

  const { daemon, gwPort } = await daemonWith({ dir, listeners: () => listeners });
  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u2.port });
    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.strictEqual(await lanStatus(gwPort, 'api.local'), 200, 'precondition: access granted');

    // Same port, but the listener now reports a different upstream host
    // (IPv6 loopback): the pinned tuple is no longer what serves the port.
    listeners = [manualListener(6004, u2.port, '6004:m1', '::1')];
    await daemon.refresh();

    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true }),
      (err) => err.code === 'LAN_TARGET_UNVERIFIED',
      'a host change must invalidate the credit outright, not merely age it'
    );
    assert.strictEqual(await lanStatus(gwPort, 'api.local'), 404, 'requests must follow the invalidated credit');
  } finally {
    await stopDaemon(daemon);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('LAN: remove + re-add on another port requires fresh verification', async () => {
  const dir = tmpDir('pn-lan-remove-add-');
  const u1 = await startUpstream();
  const u2 = await startUpstream();
  let listeners = [manualListener(6005, u1.port, '6005:m1')];

  const { daemon, gwPort } = await daemonWith({ dir, listeners: () => listeners });
  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u1.port });
    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });

    // Removal is a known mutation: route gone, record gone.
    await daemon.dispatchControl({ cmd: 'remove', name: 'api' });
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true }),
      (err) => err.code === 'NO_ROUTE'
    );

    // Re-add on another port: refused until a pass observes that port.
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u2.port });
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true }),
      (err) => err.code === 'LAN_TARGET_UNVERIFIED'
    );
    assert.strictEqual(await lanStatus(gwPort, 'api.local'), 404);

    listeners = [manualListener(6006, u2.port, '6006:m2')];
    await daemon.refresh();
    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.strictEqual(await lanStatus(gwPort, 'api.local'), 200, 'fresh observation re-enables access');
  } finally {
    await stopDaemon(daemon);
    await closeUpstream(u1);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('LAN: failed scans preserve the grace (same target)', async () => {
  const dir = tmpDir('pn-lan-failgrace-');
  const u1 = await startUpstream();
  let failScans = false;
  const listeners = [manualListener(6007, u1.port, '6007:m1')];

  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    routeFreshnessMs: 60000,
    lanVerifyGraceMs: 60000,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      if (failScans) throw new Error('lsof exploded');
      return listeners;
    },
  });
  const gwPort = await daemon.start();
  daemon.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
  daemon.gateway.isLoopbackClient = () => false;

  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u1.port });
    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    // Shape-agnostic capture: holds whichever record type the daemon keeps.
    const before = daemon.lanVerifiedAt.get('manual:api');
    assert.ok(before, 'precondition: credit exists');

    failScans = true;
    await daemon.refresh();

    assert.deepStrictEqual(
      daemon.lanVerifiedAt.get('manual:api'), before,
      'a failed pass must not touch lanVerifiedAt at all'
    );
    assert.strictEqual(await lanStatus(gwPort, 'api.local'), 200, 'the grace must keep same-target access alive');
  } finally {
    await stopDaemon(daemon);
    await closeUpstream(u1);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('LAN: remove prunes the record; a restarted daemon starts unverified', async () => {
  const dir = tmpDir('pn-lan-restart-');
  const u1 = await startUpstream();
  const u2 = await startUpstream();
  let listeners = [manualListener(6008, u1.port, '6008:m1')];

  const first = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    routeFreshnessMs: 60000,
    lanVerifyGraceMs: 60000,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => listeners,
  });
  const gwPort1 = await first.start();
  first.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
  first.gateway.isLoopbackClient = () => false;
  try {
    await first.dispatchControl({ cmd: 'add', name: 'api', port: u1.port });
    await first.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.ok(first.lanVerifiedAt.has('manual:api'), 'precondition: record exists');

    // remove prunes the internal record, not only the route.
    await first.dispatchControl({ cmd: 'remove', name: 'api' });
    assert.strictEqual(
      first.lanVerifiedAt.has('manual:api'), false,
      'remove must delete the endpoint-bound record immediately'
    );

    // Re-add, observe, expose: the exposure flag is now persisted in the
    // registry on the second port.
    await first.dispatchControl({ cmd: 'add', name: 'api', port: u2.port });
    listeners = [manualListener(6009, u2.port, '6009:m2')];
    await first.refresh();
    await first.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.strictEqual(await lanStatus(gwPort1, 'api.local'), 200);
  } finally {
    await stopDaemon(first);
  }

  // Restart on the same dir with the target dark: in-memory records never
  // survive, and the persisted exposure flag must not resurrect access.
  listeners = [];
  const second = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    routeFreshnessMs: 60000,
    lanVerifyGraceMs: 60000,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => listeners,
  });
  const gwPort2 = await second.start();
  second.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
  second.gateway.isLoopbackClient = () => false;
  try {
    assert.strictEqual(second.lanVerifiedAt.size, 0, 'no record may survive a restart');
    await assert.rejects(
      () => second.dispatchControl({ cmd: 'expose', name: 'api', on: true }),
      (err) => err.code === 'LAN_TARGET_UNVERIFIED',
      'a restarted daemon must fail closed until a scan observes the target'
    );
    assert.strictEqual(await lanStatus(gwPort2, 'api.local'), 404);
  } finally {
    await stopDaemon(second);
    await closeUpstream(u1);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lastVerifiedAt stamped only on shares this pass verified', async () => {
  const dir = tmpDir('pn-lastverified-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const cf = path.join(dir, 'cf-stamp.js');
  fs.writeFileSync(cf, '#!/usr/bin/env node\nconsole.log("https://stamp.trycloudflare.com");\nsetInterval(() => {}, 1000);\n');
  fs.chmodSync(cf, 0o755);
  const u1 = await startUpstream();

  let listeners = [
    autoListener(6010, 6110, shopDir, '6010:a'),
    manualListener(6011, u1.port, '6011:m1'),
  ];
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'db', port: u1.port });
    await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
    await daemon.dispatchControl({ cmd: 'share', name: 'db', ttlMinutes: 60 });
    assert.strictEqual(daemon.shares.status().length, 2, 'precondition: both shares active');

    // The db target's port drifts away (nothing observes the pinned port
    // anymore); the shop target stays exactly as verified.
    listeners = [autoListener(6010, 6110, shopDir, '6010:a'), manualListener(6011, 6222, '6011:m1')];
    await daemon.refresh();

    const stamps = new Map(daemon.shares.status().map((s) => [s.name, s]));
    assert.strictEqual(daemon.shares.isShared('db'), false, 'the drifted target\'s share must be revoked');
    assert.strictEqual(
      stamps.get('shop').lastVerifiedAt, daemon.lastGoodScanAt,
      'the surviving share must carry exactly this pass\'s verification stamp'
    );
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
