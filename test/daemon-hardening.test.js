'use strict';

// Daemon hardening regressions:
//   H1  config.json hand edits made while the daemon runs survive every
//       registry save (lost-update guard); a damaged file is never
//       overwritten;
//   H2  registry mutations are transactional: a failed save rolls an
//       activation back (fail-closed) and keeps a revocation in effect.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const { Daemon } = require('../lib/daemon');
const { Registry } = require('../lib/registry');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function readConfig(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
}

function startUpstream(body = 'upstream') {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => res.end(body));
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

function closeUpstream(u) {
  u.server.closeAllConnections();
  return new Promise((r) => u.server.close(r));
}

function autoListener(pid, port, root, processKey, command = 'node') {
  return {
    pid,
    port,
    processKey,
    command,
    cwd: root,
    root,
    external: false,
    suggestedName: path.basename(root),
  };
}

function manualListener(pid, port, processKey) {
  return { pid, port, processKey, command: 'postgres', cwd: null, root: null, external: false };
}

// Records every Bonjour sync so tests can assert what is advertised.
function stubAnnouncer() {
  const syncs = [];
  return {
    syncs,
    cleanupOrphans() {},
    childPids() { return []; },
    lanAddress() { return '192.168.1.50'; },
    lanInterfaceName() { return 'en0'; },
    stopAll() {},
    sync(names) {
      syncs.push([...names]);
      return { ok: true };
    },
  };
}

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

async function startLanDaemon({ dir, listeners, announcer = stubAnnouncer(), options = {} }) {
  const daemon = new Daemon({
    dir,
    announcer,
    routeFreshnessMs: 60000,
    lanVerifyGraceMs: 60000,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => listeners(),
    ...options,
  });
  const gwPort = await daemon.start();
  // Simulated WLAN: every gateway socket is a non-loopback LAN client.
  daemon.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
  daemon.gateway.isLoopbackClient = () => false;
  return { daemon, gwPort, announcer };
}

// Simulated full disk: every write through a file descriptor (atomicWrite's
// data write) fails with ENOSPC until the returned restore() is called.
function failWrites() {
  const original = fs.writeFileSync;
  fs.writeFileSync = function patched(file, ...rest) {
    if (typeof file === 'number') {
      const err = new Error('ENOSPC: no space left on device, write');
      err.code = 'ENOSPC';
      throw err;
    }
    return original.call(this, file, ...rest);
  };
  return () => {
    fs.writeFileSync = original;
  };
}

// ---------------------------------------------------------------------------
// H1 — lost-update guard
// ---------------------------------------------------------------------------

test('H1: hand edits to config.json survive registry saves (mutations and auto-naming)', () => {
  const dir = tmpDir('pn-hard-lost-update-');
  try {
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ bind: 'wildcard', port: 80 }));
    const reg = new Registry(dir);

    // The user hardens the running installation by hand.
    const edited = {
      ...readConfig(dir),
      bind: 'loopback',
      loopbackPort: 7777,
      ignoreCommands: ['foo'],
      cloudflaredBin: '/opt/cf',
      futurePlugin: { on: true },
    };
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(edited));

    reg.setExposed('/p/shop', true);
    reg.rename('/p/shop', 'store');
    reg.addManual('db', 5432);
    reg.setPrimaryPort('/p/shop', 3000);
    // The scan path: resolveRoutes writes auto-names straight into the map.
    reg.config.names['/p/blog'] = 'blog';
    reg.saveConfig();

    const onDisk = readConfig(dir);
    assert.strictEqual(onDisk.bind, 'loopback', 'the hand-edited bind must not be reverted');
    assert.strictEqual(onDisk.loopbackPort, 7777);
    assert.deepStrictEqual(onDisk.ignoreCommands, ['foo']);
    assert.strictEqual(onDisk.cloudflaredBin, '/opt/cf');
    assert.deepStrictEqual(onDisk.futurePlugin, { on: true });
    assert.strictEqual(onDisk.port, 80, 'untouched user keys stay as they are on disk');
    // Registry-owned state is written from memory.
    assert.strictEqual(onDisk.exposed['/p/shop'], true);
    assert.strictEqual(onDisk.renames['/p/shop'], 'store');
    assert.strictEqual(onDisk.manual.db, 5432);
    assert.strictEqual(onDisk.primaryPorts['/p/shop'], 3000);
    assert.strictEqual(onDisk.names['/p/blog'], 'blog');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H1: a config.json damaged by a hand edit is never overwritten by a save', () => {
  const dir = tmpDir('pn-hard-damaged-');
  try {
    const reg = new Registry(dir);
    reg.setExposed('/p/shop', true);
    const damaged = '{"bind": "loopback", ';
    fs.writeFileSync(path.join(dir, 'config.json'), damaged);

    assert.throws(() => reg.addManual('db', 5432), /damaged/);
    assert.strictEqual(
      fs.readFileSync(path.join(dir, 'config.json'), 'utf8'), damaged,
      'the damaged file must stay exactly as the user left it'
    );
    assert.strictEqual(reg.config.manual.db, undefined, 'the refused mutation must not stay in effect');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H1: the daemon keeps a hand-edited bind when discovery names a new project', async () => {
  const dir = tmpDir('pn-hard-scan-save-');
  const shop = path.join(dir, 'shop');
  const blog = path.join(dir, 'blog');
  fs.mkdirSync(shop);
  fs.mkdirSync(blog);
  let listeners = [autoListener(8101, 41001, shop, '8101:a')];
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => listeners,
  });
  try {
    await daemon.start();
    fs.writeFileSync(
      path.join(dir, 'config.json'),
      JSON.stringify({ ...readConfig(dir), bind: 'loopback', loopbackPort: 7777 })
    );
    listeners = [...listeners, autoListener(8102, 41002, blog, '8102:a')];
    await daemon.refresh();
    const onDisk = readConfig(dir);
    assert.strictEqual(onDisk.names[blog], 'blog', 'precondition: the scan persisted the new name');
    assert.strictEqual(onDisk.bind, 'loopback', 'the scan-driven save must not revert the bind');
    assert.strictEqual(onDisk.loopbackPort, 7777);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H2 — transactional registry mutations
// ---------------------------------------------------------------------------

test('H2: expose on that cannot be persisted is rolled back — nothing answers on the LAN', async () => {
  const dir = tmpDir('pn-hard-expose-fail-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const u = await startUpstream();
  const { daemon, gwPort, announcer } = await startLanDaemon({
    dir,
    listeners: () => [autoListener(8201, u.port, shop, '8201:a')],
  });
  try {
    const restore = failWrites();
    try {
      await assert.rejects(
        () => daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true }),
        /ENOSPC/
      );
    } finally {
      restore();
    }
    assert.strictEqual(daemon.registry.isExposed(shop), false, 'a failed activation must not stay in effect');
    assert.strictEqual(await lanStatus(gwPort, 'shop.local'), 404, 'the LAN must not be served');
    await daemon.refresh();
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.deepStrictEqual(status.exposed, []);
    assert.deepStrictEqual(announcer.syncs.at(-1), [], 'nothing may be advertised via Bonjour');

    // A later, unrelated successful save must not persist the failed wish.
    daemon.registry.addManual('db', 5432);
    assert.strictEqual(readConfig(dir).exposed[shop], undefined);
  } finally {
    await daemon.stop();
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H2: a failed expose off stays in effect; a failed remove leaves no orphaned exposure flag', async () => {
  const dir = tmpDir('pn-hard-revoke-fail-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const u = await startUpstream();
  const db = await startUpstream();
  const db2 = await startUpstream();
  let listeners = [autoListener(8301, u.port, shop, '8301:a'), manualListener(8302, db.port, '8302:m')];
  const { daemon, gwPort } = await startLanDaemon({ dir, listeners: () => listeners });
  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'db', port: db.port });
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    await daemon.dispatchControl({ cmd: 'expose', name: 'db', on: true });
    assert.strictEqual(await lanStatus(gwPort, 'shop.local'), 200, 'precondition');
    assert.strictEqual(await lanStatus(gwPort, 'db.local'), 200, 'precondition');

    const restore = failWrites();
    try {
      await assert.rejects(() => daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: false }), /ENOSPC/);
      await assert.rejects(() => daemon.dispatchControl({ cmd: 'remove', name: 'db' }), /ENOSPC/);
    } finally {
      restore();
    }
    assert.strictEqual(daemon.registry.isExposed(shop), false, 'the switch-off stays in effect (fail-closed)');
    assert.strictEqual(await lanStatus(gwPort, 'shop.local'), 404);
    assert.strictEqual(daemon.registry.isExposed('manual:db'), false, 'no exposure flag may outlive its entry');
    assert.deepStrictEqual(daemon.registry.exposedIdentities(), []);

    // Re-adding the name on another port must not inherit the old exposure.
    listeners = [listeners[0], manualListener(8303, db2.port, '8303:m')];
    await daemon.dispatchControl({ cmd: 'add', name: 'db', port: db2.port });
    assert.strictEqual(daemon.registry.isExposed('manual:db'), false);
    assert.strictEqual(await lanStatus(gwPort, 'db.local'), 404);
  } finally {
    await daemon.stop();
    await closeUpstream(u);
    await closeUpstream(db);
    await closeUpstream(db2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H3 — a WLAN exposure is bound to the endpoint the user confirmed
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function lanGet(port, host, urlPath = '/') {
  return new Promise((resolve) => {
    const req = http.get(
      { host: '127.0.0.1', port, path: urlPath, headers: { host }, agent: false },
      (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }
    );
    req.on('error', () => resolve({ status: 0, body: '' }));
  });
}

async function routeStatus(daemon, name) {
  const res = await daemon.dispatchControl({ cmd: 'status' });
  return { route: res.routes.find((r) => r.name === name), status: res };
}

test('H3: a newer listener of the exposed tree (another command, another port) pauses the exposure', async () => {
  const dir = tmpDir('pn-hard-target-moved-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const debug = await startUpstream('debug endpoint (localhost only)');
  let listeners = [autoListener(8401, dev.port, shop, '8401:a')];
  const { daemon, gwPort, announcer } = await startLanDaemon({ dir, listeners: () => listeners });
  try {
    const res = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.deepStrictEqual(res.target, { port: dev.port, command: 'node', network: null, subnetOnly: false }, 'the confirmed endpoint is reported');
    assert.deepStrictEqual(await lanGet(gwPort, 'shop.local'), { status: 200, body: 'shop dev server' });

    // A debug/admin endpoint started from the same tree later wins the name.
    await sleep(5);
    listeners = [...listeners, autoListener(8402, debug.port, shop, '8402:b', 'python3')];
    await daemon.refresh();
    const { route, status } = await routeStatus(daemon, 'shop');
    assert.strictEqual(route.port, debug.port, 'precondition: the newer generation carries the name');

    const lan = await lanGet(gwPort, 'shop.local', '/json/version');
    assert.strictEqual(lan.status, 404, 'an endpoint nobody confirmed must not answer on the LAN');
    assert.ok(!lan.body.includes('debug endpoint'));
    assert.strictEqual(route.exposureEffective, 'paused');
    assert.strictEqual(route.exposurePauseReason, 'target-changed');
    assert.deepStrictEqual(route.exposureTarget, { port: dev.port, command: 'node', network: null, subnetOnly: false });
    assert.strictEqual(route.exposureRequested, true, 'the wish itself is kept');
    assert.deepStrictEqual(status.exposed, ['shop'], 'the legacy desired list keeps its meaning');
    assert.deepStrictEqual(announcer.syncs.at(-1), [], 'the Bonjour advertisement must be withdrawn');

    // Scans never heal it; only an explicit confirmation does.
    await daemon.refresh();
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.deepStrictEqual(await lanGet(gwPort, 'shop.local'), { status: 200, body: 'debug endpoint (localhost only)' });
    assert.deepStrictEqual(announcer.syncs.at(-1), ['shop']);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    await closeUpstream(debug);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H3: a restart on the same port stays exposed; a move to another port pauses', async () => {
  const dir = tmpDir('pn-hard-target-restart-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const moved = await startUpstream('shop on another port');
  let listeners = [autoListener(8501, dev.port, shop, '8501:a')];
  const { daemon, gwPort } = await startLanDaemon({ dir, listeners: () => listeners });
  try {
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });

    // Same command, same port, new process generation: a plain restart.
    listeners = [autoListener(8503, dev.port, shop, '8503:c')];
    await daemon.refresh();
    let { route } = await routeStatus(daemon, 'shop');
    assert.strictEqual(route.exposureEffective, 'active', 'a restart of the same service stays exposed');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);

    // Same command, different port (e.g. auto-increment): a different endpoint.
    listeners = [autoListener(8504, moved.port, shop, '8504:d')];
    await daemon.refresh();
    ({ route } = await routeStatus(daemon, 'shop'));
    assert.strictEqual(route.exposureEffective, 'paused');
    assert.strictEqual(route.exposurePauseReason, 'target-changed');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    await closeUpstream(moved);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H3: an exposure without a recorded endpoint (older daemon) stays paused until confirmed', async () => {
  const dir = tmpDir('pn-hard-target-legacy-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ exposed: { [shop]: true } }));
  const { daemon, gwPort, announcer } = await startLanDaemon({
    dir,
    listeners: () => [autoListener(8601, dev.port, shop, '8601:a')],
  });
  try {
    const { route } = await routeStatus(daemon, 'shop');
    assert.strictEqual(route.exposureEffective, 'paused');
    // Its own reason: nothing moved, so clients can ask for a one-time
    // confirmation instead of reporting a target change.
    assert.strictEqual(route.exposurePauseReason, 'target-unconfirmed');
    assert.strictEqual(route.exposureTarget, null);
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);
    assert.deepStrictEqual(announcer.syncs.at(-1), []);

    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);
    assert.deepStrictEqual(readConfig(dir).exposedTargets[shop], { port: dev.port, command: 'node', network: null, gateway: null },
      'the confirmed endpoint is persisted with the wish');
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H3: a repointed manual entry pauses its exposure until confirmed again', async () => {
  const dir = tmpDir('pn-hard-target-manual-');
  const a = await startUpstream('a');
  const b = await startUpstream('b');
  let listeners = [manualListener(8701, a.port, '8701:m')];
  const { daemon, gwPort } = await startLanDaemon({ dir, listeners: () => listeners });
  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: a.port });
    await daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.strictEqual((await lanGet(gwPort, 'api.local')).status, 200);

    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: b.port });
    listeners = [manualListener(8702, b.port, '8702:m')];
    await daemon.refresh();
    const { route } = await routeStatus(daemon, 'api');
    assert.strictEqual(route.exposurePauseReason, 'target-changed');
    assert.strictEqual((await lanGet(gwPort, 'api.local')).status, 404);
  } finally {
    await daemon.stop();
    await closeUpstream(a);
    await closeUpstream(b);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H4 — manual names: canonical lookups, own keys only
// ---------------------------------------------------------------------------

// Fake cloudflared that prints its URL at once and stays alive.
function writeCfScript(dir, name) {
  const script = path.join(dir, `cf-${name}.js`);
  fs.writeFileSync(
    script,
    `#!/usr/bin/env node\nconsole.log("https://${name}.trycloudflare.com");\nsetInterval(() => {}, 1000);\n`
  );
  fs.chmodSync(script, 0o755);
  return script;
}

test('H4: "constructor" is an ordinary name, not a prototype collision', () => {
  const dir = tmpDir('pn-hard-proto-');
  try {
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ exposed: { constructor: true } }));
    const reg = new Registry(dir);
    assert.deepStrictEqual(reg.exposedIdentities(), [],
      'a legacy name key without a matching entry is discarded, never migrated via the prototype');
    assert.deepStrictEqual(reg.rename('/p/a', 'constructor'), { ok: true, name: 'constructor' });
    assert.strictEqual(reg.addManual('tostring', 4000, { createOnly: true }).ok, true);
    assert.strictEqual(reg.hasManual('toString'), false);
    assert.strictEqual(reg.primaryPort('constructor'), null);
    reg.clearRename('/p/a');
    reg.config.names = {};
    assert.strictEqual(reg.addManual('constructor', 4001, { createOnly: true }).ok, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H4: a case/space variant repoint invalidates the share and LAN record at once; remove canonicalizes', async () => {
  const dir = tmpDir('pn-hard-canon-');
  const a = await startUpstream('a');
  const b = await startUpstream('b');
  let failScans = false;
  const listeners = [manualListener(8801, a.port, '8801:m')];
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: writeCfScript(dir, 'canon') },
    refreshMs: 3_600_000,
    routeFreshnessMs: 60_000,
    shareVerifyGraceMs: 60_000,
    lanVerifyGraceMs: 60_000,
    listListeners: async () => {
      if (failScans) throw new Error('lsof exploded');
      return listeners;
    },
  });
  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'shop', port: a.port });
    await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
    assert.strictEqual(daemon.shares.isShared('shop'), true, 'precondition: share active');
    assert.ok(daemon.lanVerifiedAt.has('manual:shop'), 'precondition: LAN record');

    // Discovery degrades: only the scan-independent invalidation can act.
    failScans = true;
    const res = await daemon.dispatchControl({ cmd: 'add', name: ' Shop ', port: b.port });
    assert.strictEqual(res.added, 'shop');
    assert.strictEqual(daemon.shares.isShared('shop'), false, 'the share on the old target must stop now');
    assert.strictEqual(daemon.lanVerifiedAt.has('manual:shop'), false, 'the old LAN record must die now');
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'shop' }),
      (err) => err.code === 'SHARE_TARGET_UNVERIFIED'
    );

    // remove with a variant removes the canonical entry and says so.
    failScans = false;
    const removed = await daemon.dispatchControl({ cmd: 'remove', name: 'SHOP' });
    assert.deepStrictEqual(removed, { removed: 'shop', existed: true });
    assert.strictEqual(daemon.registry.hasManual('shop'), false);

    // A prototype key is never an existing entry: nothing to remove, nothing invalidated.
    const noop = await daemon.dispatchControl({ cmd: 'remove', name: 'constructor' });
    assert.strictEqual(noop.existed, false);
    assert.strictEqual(daemon.publicVerifyInvalid.has('constructor'), false);
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(a);
    await closeUpstream(b);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H5 — control socket start failures reject start() cleanly
// ---------------------------------------------------------------------------

const { spawnSync } = require('child_process');
const net = require('net');

const BIN_PATH = path.resolve(__dirname, '../bin/portname.js');

function portRefuses(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    s.on('connect', () => { s.destroy(); resolve(false); });
    s.on('error', () => resolve(true));
  });
}

test('H5: a control socket path the OS would truncate is refused before anything is locked or bound', async () => {
  const outer = tmpDir('pn-hard-longsock-');
  // > 108 bytes: libuv would truncate it on Linux too (macOS limit is 103).
  const dir = path.join(outer, 'd'.repeat(120));
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'loopback', loopbackPort: 0, control: true },
    listListeners: async () => [],
  });
  try {
    await assert.rejects(() => daemon.start(), (err) => err.name === 'ConfigError' && /PORTNAME_DIR/.test(err.message));
    assert.strictEqual(daemon.state, 'STOPPED');
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.lock')), false, 'no lock may be left behind');
  } finally {
    await daemon.stop();
    fs.rmSync(outer, { recursive: true, force: true });
  }
});

test('H5: a control socket listen failure rejects start() and releases lock and gateway', async () => {
  const dir = tmpDir('pn-hard-sockfail-');
  // Something that is not a socket and cannot be unlinked occupies the path.
  fs.mkdirSync(path.join(dir, 'daemon.sock', 'occupied'), { recursive: true });
  let gwPort = null;
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'loopback', loopbackPort: 0, control: true },
    listListeners: async () => [],
  });
  try {
    await assert.rejects(() => daemon.start().then((p) => { gwPort = p; }), /EADDRINUSE|EISDIR|ENOTSOCK|EEXIST/);
    assert.strictEqual(daemon.state, 'STOPPED');
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.lock')), false, 'the lock must be released');
    assert.strictEqual(gwPort, null, 'start() must never report success');
    if (daemon.activePort) assert.strictEqual(await portRefuses(daemon.activePort), true, 'the gateway must be closed');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H5: install refuses a state dir whose control socket path is too long', () => {
  const outer = tmpDir('pn-hard-longinstall-');
  const dir = path.join(outer, 'd'.repeat(120));
  try {
    const res = spawnSync(process.execPath, [BIN_PATH, 'install', '--dry-run'], {
      env: { ...process.env, PORTNAME_DIR: dir, HOME: outer },
      encoding: 'utf8',
    });
    assert.strictEqual(res.status, 1);
    assert.match(res.stderr, /refusing to install: .*PORTNAME_DIR/);
  } finally {
    fs.rmSync(outer, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H6 — shutdown never leaves tunnels running
// ---------------------------------------------------------------------------

// Fake cloudflared that ignores SIGTERM (a slow graceful shutdown).
function writeCfHangScript(dir, name) {
  const script = path.join(dir, `cf-hang-${name}.js`);
  fs.writeFileSync(
    script,
    `#!/usr/bin/env node\nconsole.log("https://${name}.trycloudflare.com");\nprocess.on("SIGTERM", () => {});\nsetInterval(() => {}, 1000);\n`
  );
  fs.chmodSync(script, 0o755);
  return script;
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitUntil(condition, budgetMs = 3000) {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > budgetMs) return false;
    await sleep(20);
  }
  return true;
}

test('H6: tunnels still running when the stop backstop fires are killed, not orphaned', async () => {
  const dir = tmpDir('pn-hard-backstop-');
  const names = ['p1', 'p2', 'p3', 'p4', 'p5'];
  const roots = names.map((n) => path.join(dir, n));
  roots.forEach((r) => fs.mkdirSync(r));
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'loopback', loopbackPort: 0, control: false, cloudflaredBin: writeCfHangScript(dir, 'backstop') },
    stopTimeoutMs: 1000,
    listListeners: async () => roots.map((r, i) => autoListener(9001 + i, 42001 + i, r, `${9001 + i}:a`)),
  });
  let pids = [];
  try {
    await daemon.start();
    for (const n of names) await daemon.dispatchControl({ cmd: 'share', name: n, ttlMinutes: 60 });
    pids = daemon.shares.childPids();
    assert.strictEqual(pids.length, 5, 'precondition: five live tunnels');

    const started = Date.now();
    await daemon.stop();
    assert.ok(Date.now() - started < 4000, 'stop() stays bounded by the backstop');
    assert.strictEqual(
      await waitUntil(() => pids.every((p) => !pidAlive(p))), true,
      'no tunnel process may outlive stop()'
    );
  } finally {
    for (const p of pids) {
      try { process.kill(p, 'SIGKILL'); } catch {}
    }
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H6: SIGHUP runs the orderly teardown (lock and socket removed, exit 0)', async () => {
  const dir = tmpDir('pn-hard-sighup-');
  fs.writeFileSync(
    path.join(dir, 'config.json'),
    JSON.stringify({ bind: 'loopback', port: 0, fallbackPort: 0, loopbackPort: 0, control: true })
  );
  const proc = require('child_process').spawn(process.execPath, [BIN_PATH, 'daemon'], {
    env: { ...process.env, PORTNAME_DIR: dir },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  try {
    const sockFile = path.join(dir, 'daemon.sock');
    assert.strictEqual(await waitUntil(() => fs.existsSync(sockFile) || proc.exitCode !== null, 8000), true);
    assert.ok(fs.existsSync(path.join(dir, 'daemon.lock')), 'precondition: daemon running');
    proc.kill('SIGHUP');
    const [code, signal] = await new Promise((resolve) => proc.on('close', (c, s) => resolve([c, s])));
    assert.strictEqual(signal, null, 'SIGHUP must not kill the daemon without teardown');
    assert.strictEqual(code, 0);
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.lock')), false, 'the lock must be released');
    assert.strictEqual(fs.existsSync(sockFile), false, 'the socket must be removed');
  } finally {
    if (proc.exitCode === null) proc.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H7 — the production daemon logs, bounded and without secrets
// ---------------------------------------------------------------------------

const { createDaemonLogger, daemonLogFile, plist } = require('../bin/portname');
const { formatDoctorText } = require('../lib/diagnose');

test('H7: log lines are sanitized, secret-shaped runs redacted, floods rate-limited and summarized', () => {
  const dir = tmpDir('pn-hard-logfmt-');
  const file = path.join(dir, 'daemon.log');
  let t = 1_000_000;
  try {
    const log = createDaemonLogger({ file, now: () => t, burst: 3, windowMs: 1000 });
    const token = 'ab12'.repeat(16); // 64 hex chars, like a share token
    log('share', 'demo', `https://x.trycloudflare.com/${token}/`);
    log('reject', 404, 'evil.local\r\n2026-01-01T00:00:00.000Z share forged-line');
    log('daemon', 'listening (wildcard) on port', 80, { nested: true });
    for (let i = 0; i < 10; i++) log('reject', 404, `flood-${i}.local`);
    t += 1500;
    log('daemon', 'later', '/Users/x/my-app-2024-redesign-frontend-v2', 'shareId 0123456789abcdef');
    const lines = fs.readFileSync(file, 'utf8').trimEnd().split('\n');

    assert.ok(!lines.join('\n').includes(token), 'token material must never reach the log');
    assert.ok(lines[0].includes('[redacted]'));
    assert.ok(lines[1].includes('\\x0d\\x0a'), 'control characters are escaped, never a forged second line');
    assert.ok(!lines.some((l) => l.startsWith('2026-01-01')), 'no injected line');
    assert.ok(lines[2].endsWith('80 {"nested":true}'));
    const rejects = lines.filter((l) => / reject 404 /.test(l));
    assert.strictEqual(rejects.length, 3, 'a flood is cut at the burst size');
    assert.ok(lines.some((l) => l.includes('suppressed 8 similar line(s): reject 404')), 'the flood is summarized');
    assert.ok(lines.every((l) => /^\d{4}-\d\d-\d\dT[\d:.]+Z /.test(l)), 'every line is timestamped');
    assert.ok(lines.at(-1).includes('my-app-2024-redesign-frontend-v2') && lines.at(-1).includes('0123456789abcdef'),
      'ordinary names and shareIds stay readable');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H7: the log is bounded — rotated at start and whenever it reaches the cap', () => {
  const dir = tmpDir('pn-hard-logrot-');
  const file = path.join(dir, 'daemon.log');
  try {
    fs.writeFileSync(file, 'x'.repeat(5000) + '\n');
    const log = createDaemonLogger({ file, maxBytes: 4096, burst: 1000 });
    assert.ok(fs.statSync(file).size < 4096, 'an oversized log is rotated at start');
    assert.strictEqual(fs.statSync(`${file}.1`).size, 5001, 'the previous content moves to daemon.log.1');
    for (let i = 0; i < 400; i++) log('event', `n${i}`, 'y'.repeat(40));
    assert.ok(fs.statSync(file).size <= 4096, 'the live log never exceeds the cap');
    assert.ok(fs.statSync(`${file}.1`).size <= 4096, 'exactly one bounded predecessor is kept');
    assert.ok(fs.readFileSync(file, 'utf8').includes('n399'), 'the newest lines are kept');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Starts `portname daemon` the way the LaunchAgent does: stdout and stderr
// are <dir>/daemon.log, opened for appending.
function spawnAgentDaemon(dir) {
  const logFd = fs.openSync(path.join(dir, 'daemon.log'), 'a');
  try {
    return require('child_process').spawn(process.execPath, [BIN_PATH, 'daemon'], {
      env: { ...process.env, PORTNAME_DIR: dir },
      stdio: ['ignore', logFd, logFd],
    });
  } finally {
    fs.closeSync(logFd);
  }
}

test('H7: the LaunchAgent daemon writes a bounded, timestamped log (start trims an oversized one)', async () => {
  const dir = tmpDir('pn-hard-agentlog-');
  fs.chmodSync(dir, 0o700);
  fs.writeFileSync(
    path.join(dir, 'config.json'),
    JSON.stringify({ bind: 'loopback', port: 0, fallbackPort: 0, loopbackPort: 0, control: true })
  );
  fs.writeFileSync(path.join(dir, 'daemon.log'), 'old\n'.repeat(400_000)); // 1.6 MB
  const proc = spawnAgentDaemon(dir);
  try {
    const logFile = path.join(dir, 'daemon.log');
    assert.strictEqual(
      await waitUntil(() => fs.readFileSync(logFile, 'utf8').includes('listening'), 8000), true,
      'the start must be logged'
    );
    assert.ok(fs.statSync(logFile).size < 1024 * 1024, 'the oversized log was rotated at start');
    assert.ok(fs.existsSync(`${logFile}.1`));
    assert.match(fs.readFileSync(logFile, 'utf8'), /^\S+Z daemon listening \(loopback\) on port \d+/m);
    proc.kill('SIGTERM');
    assert.strictEqual(await new Promise((resolve) => proc.on('close', resolve)), 0);
  } finally {
    if (proc.exitCode === null) proc.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H7: a permanent start failure is logged once per attempt into the bounded log', async () => {
  const dir = tmpDir('pn-hard-agentfail-');
  fs.chmodSync(dir, 0o700);
  fs.writeFileSync(path.join(dir, 'config.json'), '{"bind": "loopback", ');
  for (let attempt = 0; attempt < 2; attempt++) {
    const proc = spawnAgentDaemon(dir);
    assert.strictEqual(await new Promise((resolve) => proc.on('close', resolve)), 1);
  }
  try {
    const lines = fs.readFileSync(path.join(dir, 'daemon.log'), 'utf8').trimEnd().split('\n');
    assert.strictEqual(lines.length, 2, 'exactly one line per failed start');
    for (const l of lines) assert.match(l, /^\S+Z daemon start-failed .*config\.json is damaged/);
    assert.strictEqual(daemonLogFile(dir, 2), null, 'outside the agent layout the daemon logs to stderr');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H7: the LaunchAgent stays KeepAlive but throttles quick respawns; doctor names the log path', () => {
  const generated = plist({ dir: '/Users/demo/.portname', nodePath: '/usr/bin/node', entryPath: '/x/portname.js' });
  assert.match(generated, /<key>KeepAlive<\/key><true\/>/, 'self-healing after a fix must stay');
  assert.match(generated, /<key>ThrottleInterval<\/key><integer>30<\/integer>/);
  const text = formatDoctorText([], { ok: 0, warn: 0, fail: 0, skip: 0 }, { dir: '/Users/demo/.portname' });
  assert.ok(text.includes('/Users/demo/.portname/daemon.log'), 'the remedies point at a path doctor prints');
});

// ---------------------------------------------------------------------------
// H8 — a WLAN exposure is bound to the network it was confirmed on
// ---------------------------------------------------------------------------

test('H8: joining another network pauses the exposure until confirmed there; same-subnet changes keep it', async () => {
  const dir = tmpDir('pn-hard-network-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  let lan = { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' };
  const announcer = stubAnnouncer();
  announcer.getLan = () => lan;
  announcer.lanAddress = () => (lan ? lan.address : null);
  const { daemon, gwPort } = await startLanDaemon({
    dir,
    announcer,
    listeners: () => [autoListener(8901, dev.port, shop, '8901:a')],
  });
  try {
    const res = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(res.target.network, '192.168.1.0/24', 'the confirming network is recorded');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);

    // New DHCP lease in the same LAN: still the confirmed network.
    lan = { name: 'en0', address: '192.168.1.77', netmask: '255.255.255.0' };
    await daemon.refresh();
    assert.strictEqual((await routeStatus(daemon, 'shop')).route.exposureEffective, 'active');

    // Conference Wi-Fi: nothing may be announced or served there.
    lan = { name: 'en0', address: '10.42.7.33', netmask: '255.255.248.0' };
    await daemon.refresh();
    const { route } = await routeStatus(daemon, 'shop');
    assert.strictEqual(route.exposureEffective, 'paused');
    assert.strictEqual(route.exposurePauseReason, 'network-changed');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);
    assert.deepStrictEqual(announcer.syncs.at(-1), [], 'no Bonjour announcement on the new network');

    // An explicit confirmation on the new network resumes it there.
    const again = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(again.target.network, '10.42.0.0/21');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);
    assert.deepStrictEqual(announcer.syncs.at(-1), ['shop']);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const { resolveGatewayMac } = require('../lib/daemon');

// A Mac on a LAN whose interface selection and router are both swappable.
function networkAnnouncer(state) {
  const announcer = stubAnnouncer();
  announcer.getLan = () => state.lan;
  announcer.lanAddress = () => (state.lan ? state.lan.address : null);
  announcer.lanInterfaceName = () => (state.lan ? state.lan.name : null);
  return announcer;
}

test('H8: the same subnet behind another router is another network; an unidentified router never counts', async () => {
  const dir = tmpDir('pn-hard-router-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const HOME_ROUTER = '3c:a6:2f:00:00:01';
  const CAFE_ROUTER = '3c:a6:2f:00:00:02';
  // Every Fritz!Box hands out 192.168.178.0/24.
  const state = { lan: { name: 'en0', address: '192.168.178.23', netmask: '255.255.255.0' }, router: HOME_ROUTER };
  const announcer = networkAnnouncer(state);
  const { daemon, gwPort } = await startLanDaemon({
    dir,
    announcer,
    listeners: () => [autoListener(9001, dev.port, shop, '9001:a')],
    options: { resolveGatewayMac: async () => state.router },
  });
  try {
    const res = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.deepStrictEqual(res.target, { port: dev.port, command: 'node', network: '192.168.178.0/24', subnetOnly: false },
      'clients see the subnet; the router identity stays internal');
    const stored = readConfig(dir).exposedTargets[shop];
    assert.match(stored.gateway, /^[0-9a-f]{16}$/, 'the router is recorded as a fingerprint');
    assert.ok(!JSON.stringify(readConfig(dir)).includes(HOME_ROUTER), 'the router MAC is never persisted in clear');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);

    // Same router, new lease or Ethernet instead of Wi-Fi: the same network.
    state.lan = { name: 'en7', address: '192.168.178.40', netmask: '255.255.255.0' };
    await daemon.refresh();
    let { route, status } = await routeStatus(daemon, 'shop');
    assert.strictEqual(route.exposureEffective, 'active');
    assert.strictEqual(status.lan.network, '192.168.178.0/24', 'status names the current subnet');
    assert.ok(!JSON.stringify(status).includes(stored.gateway), 'status never carries the router fingerprint');

    // Café (or a rogue AP) with the same default range: another router.
    state.lan = { name: 'en0', address: '192.168.178.45', netmask: '255.255.255.0' };
    state.router = CAFE_ROUTER;
    await daemon.refresh();
    ({ route } = await routeStatus(daemon, 'shop'));
    assert.strictEqual(route.exposureEffective, 'paused');
    assert.strictEqual(route.exposurePauseReason, 'network-changed');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404, 'nothing is served to that network');
    assert.deepStrictEqual(announcer.syncs.at(-1), [], 'nothing is announced there');

    // A router that does not reveal itself (no ARP answer) is not the home
    // one either — but nothing to confirm: it may still turn out to be.
    state.lan = { name: 'en0', address: '192.168.178.23', netmask: '255.255.255.0' };
    state.router = null;
    await daemon.refresh();
    ({ route } = await routeStatus(daemon, 'shop'));
    assert.strictEqual(route.exposurePauseReason, 'network-unidentified');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);

    // Confirming on the café network binds it there.
    state.lan = { name: 'en0', address: '192.168.178.45', netmask: '255.255.255.0' };
    state.router = CAFE_ROUTER;
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.notStrictEqual(readConfig(dir).exposedTargets[shop].gateway, stored.gateway);
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);
    assert.deepStrictEqual(announcer.syncs.at(-1), ['shop']);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H8: one failed router lookup does not flap the exposure; a lookup from before a sleep never vouches', async () => {
  const dir = tmpDir('pn-hard-router-grace-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: 'a:b:c:d:e:f' };
  let lookups = 0;
  const { daemon, gwPort, announcer } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9101, dev.port, shop, '9101:a')],
    options: { resolveGatewayMac: async () => { lookups++; return state.router; } },
  });
  try {
    assert.strictEqual(lookups, 0, 'no router lookups while nothing is exposed');
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.ok(lookups >= 1);

    // A single miss (ARP entry just expired) keeps the identity of the same address.
    state.router = null;
    await daemon.refresh();
    assert.strictEqual((await routeStatus(daemon, 'shop')).route.exposureEffective, 'active');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);

    // After a sleep the last identification is old: unknown until looked up again.
    daemon.lanGateway.at -= 61000;
    assert.strictEqual((await routeStatus(daemon, 'shop')).route.exposurePauseReason, 'network-unidentified');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);

    // The confirmed router is identified again: the same network, active.
    state.router = 'a:b:c:d:e:f';
    await daemon.refresh();
    assert.strictEqual((await routeStatus(daemon, 'shop')).route.exposureEffective, 'active');
    assert.deepStrictEqual(announcer.syncs.at(-1), ['shop']);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H8: a router not identified yet (after wake) heals by itself; a confirmation never drops the router binding', async () => {
  const dir = tmpDir('pn-hard-router-wake-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const HOME_ROUTER = '3c:a6:2f:00:00:01';
  const state = { lan: { name: 'en0', address: '192.168.178.23', netmask: '255.255.255.0' }, router: HOME_ROUTER };
  const { daemon, gwPort, announcer } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9151, dev.port, shop, '9151:a')],
    options: { resolveGatewayMac: async () => state.router },
  });
  try {
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    const homeBinding = readConfig(dir).exposedTargets[shop].gateway;
    assert.match(homeBinding, /^[0-9a-f]{16}$/, 'precondition: bound to the home router');

    // Wake: the last identification is old, and the ARP cache does not know
    // the router yet.
    state.router = null;
    daemon.lanGateway.at -= 61000;
    await daemon.refresh();
    let { route } = await routeStatus(daemon, 'shop');
    assert.strictEqual(route.exposureEffective, 'paused');
    assert.strictEqual(route.exposurePauseReason, 'network-unidentified', 'not "network-changed": nothing to confirm');
    assert.strictEqual(route.exposureTarget.subnetOnly, false);
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);
    assert.deepStrictEqual(announcer.syncs.at(-1), [], 'not announced meanwhile');

    // A confirmation in that window (CLI, or a client that offered one)
    // would bind the subnet alone: refused, the router binding stays.
    for (const msg of [
      { cmd: 'expose', name: 'shop', on: true },
      { cmd: 'expose', name: 'shop', on: true, expectedRouteRevision: route.revision },
    ]) {
      await assert.rejects(daemon.dispatchControl(msg),
        (err) => err.code === 'NETWORK_UNIDENTIFIED' && /not identified right now/.test(err.message));
    }
    assert.strictEqual(readConfig(dir).exposedTargets[shop].gateway, homeBinding, 'never weakened to subnet-only');
    assert.strictEqual(daemon.registry.isExposed(shop), true, 'the wish stays');

    // The home router answers again: active without any confirmation.
    state.router = HOME_ROUTER;
    await daemon.refresh();
    ({ route } = await routeStatus(daemon, 'shop'));
    assert.strictEqual(route.exposureEffective, 'active');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);
    assert.deepStrictEqual(announcer.syncs.at(-1), ['shop']);

    // Identified as another router in the same range: now that is a network
    // to confirm, and the confirmation binds that router.
    state.router = '3c:a6:2f:00:00:02';
    await daemon.refresh();
    assert.strictEqual((await routeStatus(daemon, 'shop')).route.exposurePauseReason, 'network-changed');
    const res = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(res.target.subnetOnly, false);
    assert.notStrictEqual(readConfig(dir).exposedTargets[shop].gateway, homeBinding);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H8: without an identified router the exposure is bound to the subnet only', async () => {
  const dir = tmpDir('pn-hard-router-none-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const state = { lan: { name: 'en0', address: '10.0.0.5', netmask: '255.255.255.0' }, router: null };
  const { daemon, gwPort } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9201, dev.port, shop, '9201:a')],
    options: { resolveGatewayMac: async () => state.router },
  });
  try {
    const res = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(readConfig(dir).exposedTargets[shop].gateway, null);
    assert.deepStrictEqual(res.target, { port: dev.port, command: 'node', network: '10.0.0.0/24', subnetOnly: true },
      'the answer says the binding is the address range alone');
    state.router = '00:11:22:33:44:55';
    await daemon.refresh();
    assert.strictEqual((await routeStatus(daemon, 'shop')).route.exposureEffective, 'active');
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H8: router lookup reads the scoped default route and the ARP cache, read-only, macOS only', async () => {
  const calls = [];
  const runner = (outputs) => async (cmd, args) => {
    calls.push([cmd, ...args].join(' '));
    return outputs[[cmd, ...args].join(' ')] ?? null;
  };
  const en0 = { name: 'en0', address: '192.168.178.23', netmask: '255.255.255.0' };
  const scoped = '/sbin/route -n get -ifscope en0 default';
  const unscoped = '/sbin/route -n get default';
  const routeOut = (iface) => [
    '   route to: default',
    'destination: default',
    '    gateway: 192.168.178.1',
    `  interface: ${iface}`,
    '      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,IFSCOPE>',
  ].join('\n');
  const arp = '/usr/sbin/arp -n 192.168.178.1';

  assert.strictEqual(await resolveGatewayMac(en0, { platform: 'linux', run: runner({}) }), null);
  assert.deepStrictEqual(calls, [], 'nothing is spawned off macOS');

  assert.strictEqual(await resolveGatewayMac(en0, {
    platform: 'darwin',
    run: runner({ [scoped]: routeOut('en0'), [arp]: '? (192.168.178.1) at 3c:a6:2f:1:2:a on en0 ifscope [ethernet]\n' }),
  }), '3c:a6:2f:01:02:0a', 'macOS prints octets without leading zeros');
  assert.deepStrictEqual(calls, [scoped, arp]);

  // Without a scoped route only an unscoped default on the LAN interface counts
  // (a VPN's default route is not the LAN's router).
  calls.length = 0;
  assert.strictEqual(await resolveGatewayMac(en0, { platform: 'darwin', run: runner({ [unscoped]: routeOut('utun3') }) }), null);
  assert.deepStrictEqual(calls, [scoped, unscoped], 'no ARP lookup without a LAN router');
  assert.strictEqual(await resolveGatewayMac(en0, {
    platform: 'darwin',
    run: runner({ [unscoped]: routeOut('en0'), [arp]: '? (192.168.178.1) at 0:1e:c2:aa:bb:cc on en0 ifscope [ethernet]\n' }),
  }), '00:1e:c2:aa:bb:cc');

  // Unresolved or foreign ARP entries identify nothing.
  for (const out of [
    '? (192.168.178.1) at (incomplete) on en0 ifscope [ethernet]\n',
    '192.168.178.1 (192.168.178.1) -- no entry\n',
    '? (192.168.178.1) at 3c:a6:2f:1:2:a on en7 ifscope [ethernet]\n',
  ]) {
    assert.strictEqual(await resolveGatewayMac(en0, { platform: 'darwin', run: runner({ [scoped]: routeOut('en0'), [arp]: out }) }), null, out);
  }
});

// ---------------------------------------------------------------------------
// H9 — exposure decisions take effect in arrival order
// ---------------------------------------------------------------------------

// Router lookup that can be held open: while held, every lookup waits until
// release() — the window in which an earlier `expose on` is still pending.
function heldRouterLookup(state) {
  let held = null;
  return {
    resolveGatewayMac: async () => {
      if (held) await new Promise((r) => held.push(r));
      return state.router;
    },
    hold() { held = []; },
    pending() { return held ? held.length : 0; },
    release() {
      const waiting = held || [];
      held = null;
      for (const r of waiting) r();
    },
  };
}

test('H9: an `expose off` that arrives during the router lookup of an earlier `expose on` wins', async () => {
  const dir = tmpDir('pn-hard-order-off-');
  const shop = path.join(dir, 'shop');
  const blog = path.join(dir, 'blog');
  fs.mkdirSync(shop);
  fs.mkdirSync(blog);
  const dev = await startUpstream('shop dev server');
  const other = await startUpstream('blog dev server');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: 'a:b:c:d:e:f' };
  const lookup = heldRouterLookup(state);
  const { daemon, gwPort, announcer } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9301, dev.port, shop, '9301:a'), autoListener(9302, other.port, blog, '9302:a')],
    options: { resolveGatewayMac: lookup.resolveGatewayMac },
  });
  try {
    lookup.hold();
    const on = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(lookup.pending(), 1, 'the activation waits for its router lookup');
    const off = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: false });
    assert.strictEqual(off.exposed, false, 'the CLI reports "no longer reachable"');
    lookup.release();
    await assert.rejects(on, (err) => err.code === 'STALE_TARGET', 'the earlier activation is superseded');
    assert.strictEqual(daemon.registry.isExposed(shop), false, 'the later revocation stays in effect');
    await daemon.refresh();
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);
    assert.deepStrictEqual(announcer.syncs.at(-1), []);
    assert.strictEqual((await routeStatus(daemon, 'shop')).route.exposureRequested, false);

    // In arrival order, without overlap: off, then on — the activation wins.
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);

    // Decisions about another project, or a repeated activation, never make
    // a pending activation stale.
    lookup.hold();
    const first = daemon.dispatchControl({ cmd: 'expose', name: 'blog', on: true });
    const second = daemon.dispatchControl({ cmd: 'expose', name: 'blog', on: true });
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: false });
    lookup.release();
    assert.strictEqual((await first).exposed, true);
    assert.strictEqual((await second).exposed, true);
    assert.strictEqual(daemon.registry.isExposed(blog), true);
    assert.strictEqual(daemon.registry.isExposed(shop), false);
  } finally {
    lookup.release();
    await daemon.stop();
    await closeUpstream(dev);
    await closeUpstream(other);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H9: a pending activation never re-exposes a removed (and re-added) manual entry', async () => {
  const dir = tmpDir('pn-hard-order-remove-');
  const api = await startUpstream('api');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: 'a:b:c:d:e:f' };
  const lookup = heldRouterLookup(state);
  const { daemon, gwPort, announcer } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [manualListener(8801, api.port, '8801:m')],
    options: { resolveGatewayMac: lookup.resolveGatewayMac },
  });
  try {
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: api.port });
    lookup.hold();
    const on = daemon.dispatchControl({ cmd: 'expose', name: 'api', on: true });
    assert.strictEqual(lookup.pending(), 1);
    await daemon.dispatchControl({ cmd: 'remove', name: 'api' });
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: api.port });
    lookup.release();
    await assert.rejects(on, (err) => err.code === 'STALE_TARGET');
    assert.strictEqual(daemon.registry.isExposed('manual:api'), false, 'the flag never resurfaces on the re-added entry');
    await daemon.refresh();
    assert.strictEqual((await lanGet(gwPort, 'api.local')).status, 404);
    assert.deepStrictEqual(announcer.syncs.at(-1), []);
  } finally {
    lookup.release();
    await daemon.stop();
    await closeUpstream(api);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H9: a pending activation never confirms a target the name moved to meanwhile', async () => {
  const dir = tmpDir('pn-hard-order-moved-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const debug = await startUpstream('debug endpoint (localhost only)');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: 'a:b:c:d:e:f' };
  const lookup = heldRouterLookup(state);
  let listeners = [autoListener(9401, dev.port, shop, '9401:a')];
  const { daemon, gwPort } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => listeners,
    options: { resolveGatewayMac: lookup.resolveGatewayMac },
  });
  try {
    await daemon.refresh();
    lookup.hold();
    const on = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(lookup.pending(), 1);
    // A newer process of the same tree takes the name before the lookup returns.
    await sleep(5);
    listeners = [...listeners, autoListener(9402, debug.port, shop, '9402:b', 'python3')];
    await daemon.refresh();
    assert.strictEqual(daemon.routesByName.get('shop').port, debug.port);
    lookup.release();
    await assert.rejects(on, (err) => err.code === 'STALE_TARGET');
    assert.strictEqual(daemon.registry.isExposed(shop), false);
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);
  } finally {
    lookup.release();
    await daemon.stop();
    await closeUpstream(dev);
    await closeUpstream(debug);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H9: concurrent activations of one project both succeed, whatever order their lookups would finish in', async () => {
  const dir = tmpDir('pn-hard-order-dup-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: 'a:b:c:d:e:f' };
  // The first lookup is slow, a second one would be fast: completion order
  // is the reverse of arrival order unless the lookups are shared.
  const delays = [];
  let lookups = 0;
  const { daemon, gwPort } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9501, dev.port, shop, '9501:a')],
    options: {
      resolveGatewayMac: async () => {
        lookups++;
        await sleep(delays.shift() ?? 0);
        return state.router;
      },
    },
  });
  try {
    delays.push(120, 10);
    const first = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    const second = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    const lookupsWhileConcurrent = lookups;
    const outcomes = await Promise.allSettled([first, second]);
    assert.deepStrictEqual(outcomes.map((o) => o.status), ['fulfilled', 'fulfilled'],
      outcomes.map((o) => (o.reason ? o.reason.code : 'ok')).join(', '));
    assert.strictEqual(outcomes[0].value.exposed, true);
    assert.strictEqual(outcomes[1].value.exposed, true);
    assert.strictEqual(lookupsWhileConcurrent, 1, 'concurrent confirmations share one router lookup');
    assert.strictEqual(daemon.registry.isExposed(shop), true);
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H9: a network switch during the router lookup fails the activation; nothing is bound to the new network', async () => {
  const dir = tmpDir('pn-hard-order-net-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const HOME = { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' };
  const CAFE = { name: 'en0', address: '10.9.8.7', netmask: '255.255.255.0' };
  const state = { lan: HOME, router: 'aa:aa:aa:00:00:01' };
  const lookup = heldRouterLookup(state);
  const { daemon, gwPort, announcer } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9601, dev.port, shop, '9601:a')],
    options: { resolveGatewayMac: lookup.resolveGatewayMac },
  });
  try {
    lookup.hold();
    const on = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(lookup.pending(), 1);
    // The Mac joins another network while the lookup for home runs.
    state.lan = CAFE;
    state.router = 'bb:bb:bb:00:00:02';
    lookup.release();
    await assert.rejects(on, (err) => err.code === 'STALE_TARGET' && /network changed/.test(err.message));
    assert.strictEqual(daemon.registry.isExposed(shop), false, 'nothing is exposed on the network nobody confirmed');
    assert.strictEqual(readConfig(dir).exposedTargets?.[shop], undefined);
    assert.strictEqual(daemon.lanGateway, null, 'a lookup for the old address records no router identity');
    await daemon.refresh();
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 404);
    assert.deepStrictEqual(announcer.syncs.at(-1), []);

    // A confirmation on the new network binds it there, with its router.
    const res = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.deepStrictEqual(res.target, { port: dev.port, command: 'node', network: '10.9.8.0/24', subnetOnly: false });
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);
  } finally {
    lookup.release();
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H9: a new DHCP address in the same subnet during the router lookup is the same network', async () => {
  const dir = tmpDir('pn-hard-order-dhcp-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const HOME_ROUTER = 'aa:aa:aa:00:00:01';
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: HOME_ROUTER };
  const lookup = heldRouterLookup(state);
  const { daemon, gwPort } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9651, dev.port, shop, '9651:a')],
    options: { resolveGatewayMac: lookup.resolveGatewayMac },
  });
  try {
    lookup.hold();
    const on = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(lookup.pending(), 1);
    // The lease is renewed to another address of the same LAN meanwhile.
    state.lan = { name: 'en0', address: '192.168.1.77', netmask: '255.255.255.0' };
    lookup.release();
    const res = await on;
    assert.deepStrictEqual(res.target, { port: dev.port, command: 'node', network: '192.168.1.0/24', subnetOnly: false },
      'confirmed, with the router looked up for the new address');
    const homeBinding = readConfig(dir).exposedTargets[shop].gateway;
    assert.match(homeBinding, /^[0-9a-f]{16}$/);
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);

    // Same range and a new address, but another router identified for it:
    // that is another network (a rogue AP handing out the home range).
    lookup.hold();
    const again = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    state.lan = { name: 'en0', address: '192.168.1.99', netmask: '255.255.255.0' };
    state.router = 'bb:bb:bb:00:00:02';
    lookup.release();
    await assert.rejects(again, (err) => err.code === 'STALE_TARGET' && /network changed/.test(err.message));
    assert.strictEqual(readConfig(dir).exposedTargets[shop].gateway, homeBinding, 'the binding stays with the home router');
  } finally {
    lookup.release();
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Heap in use after a full collection: what the daemon still retains.
function retainedHeap() {
  require('v8').setFlagsFromString('--expose-gc');
  require('vm').runInNewContext('gc')();
  return process.memoryUsage().heapUsed;
}

test('H9: activation bookkeeping stays bounded: revocations of unknown or invalid names record nothing', async () => {
  const dir = tmpDir('pn-hard-order-bounded-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: 'a:b:c:d:e:f' };
  const lookup = heldRouterLookup(state);
  const { daemon } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9701, dev.port, shop, '9701:a')],
    options: { resolveGatewayMac: lookup.resolveGatewayMac },
  });
  try {
    // Black box: a revocation of a name that never existed retains nothing
    // once it is answered — 128 distinct names of 64 KiB each would keep
    // 8 MiB alive in a per-name record.
    const unknownName = () => require('crypto').randomBytes(32 * 1024).toString('hex');
    await daemon.dispatchControl({ cmd: 'remove', name: unknownName() }); // warm-up
    const before = retainedHeap();
    for (let i = 0; i < 128; i++) await daemon.dispatchControl({ cmd: 'remove', name: unknownName() });
    const retained = retainedHeap() - before;
    assert.ok(retained < 2 * 1024 * 1024, `revocations of unknown names retained ${retained} bytes`);

    const long = 'x'.repeat(4096);
    for (let i = 0; i < 200; i++) {
      await daemon.dispatchControl({ cmd: 'remove', name: `${long}-${i}` });
      await daemon.dispatchControl({ cmd: 'remove', name: `unknown${i}` });
    }
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: false });
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(daemon.pendingActivations.size, 0, 'nothing is kept without a waiting activation');

    lookup.hold();
    const on = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(daemon.pendingActivations.size, 1, 'the waiting activation of an existing route');
    // Not awaited while held: its refresh pass shares the held router lookup.
    const removal = daemon.dispatchControl({ cmd: 'remove', name: `${long}-pending` });
    assert.strictEqual(daemon.pendingActivations.size, 1, 'a remove of an unknown name adds nothing');
    lookup.release();
    await removal;
    assert.strictEqual((await on).exposed, true, 'an unrelated remove never supersedes it');
    assert.strictEqual(daemon.pendingActivations.size, 0, 'the entry goes with its last waiting activation');
  } finally {
    lookup.release();
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H10 — the router lookup is safe to run alongside every pass
// ---------------------------------------------------------------------------

test('H10: a router lookup never rejects: an interface read that throws during a failing scan is no unhandled rejection', async () => {
  const dir = tmpDir('pn-hard-lookup-reject-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: 'a:b:c:d:e:f', lanError: false };
  const announcer = networkAnnouncer(state);
  // os.networkInterfaces() can throw (e.g. EMFILE); the real getLan reads it.
  announcer.getLan = () => {
    if (state.lanError) throw new Error('uv_interface_addresses returned Unknown system error 24');
    return state.lan;
  };
  let failScan = false;
  const { daemon } = await startLanDaemon({
    dir,
    announcer,
    listeners: () => {
      if (failScan) throw new Error('lsof timed out');
      return [autoListener(9801, dev.port, shop, '9801:a')];
    },
    options: { resolveGatewayMac: async () => state.router },
  });
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.match(readConfig(dir).exposedTargets[shop].gateway, /^[0-9a-f]{16}$/, 'precondition: a router-bound exposure');
    state.lanError = true;
    failScan = true;
    // The pass starts the lookup, then returns early on the failed scan.
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, 'lsof timed out');
    await sleep(20);
    assert.deepStrictEqual(unhandled.map(String), [], 'no unhandled rejection');
    assert.strictEqual(daemon.lanGateway, null, 'an unreadable interface identifies no router');
  } finally {
    state.lanError = false;
    failScan = false;
    process.removeListener('unhandledRejection', onUnhandled);
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H10: passes look up the router only while an exposure is bound to one', async () => {
  const dir = tmpDir('pn-hard-lookup-needed-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: null };
  let lookups = 0;
  const { daemon } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9901, dev.port, shop, '9901:a')],
    options: { resolveGatewayMac: async () => { lookups++; return state.router; } },
  });
  try {
    // Subnet-only binding (no router identified at confirmation).
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(readConfig(dir).exposedTargets[shop].gateway, null, 'precondition: bound to the subnet only');
    const afterConfirm = lookups;
    for (let i = 0; i < 3; i++) await daemon.refresh();
    assert.strictEqual(lookups, afterConfirm, 'no route/arp per pass for a subnet-only binding');

    // Router-bound binding: every pass re-identifies the router.
    state.router = 'a:b:c:d:e:f';
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    const bound = lookups;
    await daemon.refresh();
    await daemon.refresh();
    assert.ok(lookups >= bound + 2, `passes look the router up (${lookups - bound})`);
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H10: a wedged router lookup cannot hold `expose on` open: the lookup settles on its own bound', async () => {
  const dir = tmpDir('pn-hard-lookup-wedged-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const dev = await startUpstream('shop dev server');
  const state = { lan: { name: 'en0', address: '192.168.1.20', netmask: '255.255.255.0' }, router: 'a:b:c:d:e:f', wedged: true };
  let lookups = 0;
  const { daemon, gwPort } = await startLanDaemon({
    dir,
    announcer: networkAnnouncer(state),
    listeners: () => [autoListener(9951, dev.port, shop, '9951:a')],
    options: {
      gatewayLookupTimeoutMs: 200,
      // A route or arp child stuck in the kernel: the lookup never answers.
      resolveGatewayMac: () => {
        lookups++;
        return state.wedged ? new Promise(() => {}) : Promise.resolve(state.router);
      },
    },
  });
  try {
    const confirmations = Promise.all([
      daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true }),
      daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true }),
    ]);
    const outcome = await Promise.race([confirmations, sleep(5000).then(() => 'still waiting')]);
    assert.notStrictEqual(outcome, 'still waiting', 'every `expose on` sharing the wedged lookup answers');
    assert.strictEqual(lookups, 1, 'the confirmations shared one lookup');
    for (const res of outcome) {
      assert.strictEqual(res.exposed, true);
      assert.strictEqual(res.target.subnetOnly, true, 'no router identified within the bound');
    }
    assert.strictEqual((await lanGet(gwPort, 'shop.local')).status, 200);

    // The lookup slot is free again: the next confirmation looks up afresh.
    state.wedged = false;
    const res = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.ok(lookups >= 2, 'a new lookup ran');
    assert.strictEqual(res.target.subnetOnly, false, 'the router is identified by the next lookup');
  } finally {
    await daemon.stop();
    await closeUpstream(dev);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('H10: route/arp runs are bounded: a child that ignores SIGTERM is killed and the run settles', async () => {
  const { runRouterTool } = require('../lib/daemon');
  const dir = tmpDir('pn-hard-router-tool-');
  const pidFile = path.join(dir, 'pid');
  try {
    const started = Date.now();
    const out = await Promise.race([
      runRouterTool(process.execPath, ['-e',
        `require('fs').writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);`]),
      sleep(8000).then(() => 'still waiting'),
    ]);
    assert.strictEqual(out, null, 'a run that had to be killed reads as "no answer"');
    assert.ok(Date.now() - started < 4000, `settled after ${Date.now() - started}ms`);
    const pid = Number(fs.readFileSync(pidFile, 'utf8'));
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' }, 'the child was killed, not left running');
    assert.strictEqual(await runRouterTool(process.execPath, ['-e', 'process.stdout.write("gateway: 10.0.0.1")']), 'gateway: 10.0.0.1');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H11 — a refused state.json write never aborts a discovery pass
// ---------------------------------------------------------------------------

test('H11: with state.json writes refused and listeners churning, passes still publish, verify and revoke', async () => {
  const dir = tmpDir('pn-hard-state-save-');
  const shop = path.join(dir, 'shop');
  const runner = path.join(dir, 'runner');
  fs.mkdirSync(shop);
  fs.mkdirSync(runner);
  const logs = [];
  let shopListener = autoListener(9101, 41101, shop, '9101:a');
  let pass = 0;
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: writeCfScript(dir, 'statesave') },
    refreshMs: 3_600_000,
    routeFreshnessMs: 60_000,
    log: (...fields) => logs.push(fields.join(' ')),
    // A test runner's short-lived servers: every pass sees a listener (a
    // process generation and port) it never saw before, i.e. a birth that
    // observe() has to persist.
    listListeners: async () => {
      pass += 1;
      return [shopListener, autoListener(9200 + pass, 42000 + pass, runner, `${9200 + pass}:a`)];
    },
  });
  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
    assert.strictEqual(daemon.shares.isShared('shop'), true, 'precondition: share active');

    const restore = failWrites();
    try {
      for (let i = 0; i < 3; i++) {
        const before = daemon.lastGoodScanAt;
        await sleep(5);
        await daemon.refresh();
        assert.ok(daemon.lastGoodScanAt > before, `pass ${i + 1} completed as a good scan`);
        const { route, status } = await routeStatus(daemon, 'runner');
        assert.strictEqual(route.port, 42000 + pass, 'the routes of this pass are published');
        assert.strictEqual(status.scanError, null);
        assert.strictEqual(daemon.shares.status()[0].lastVerifiedAt, daemon.lastGoodScanAt, 'the share binding was verified by this pass');
      }
      assert.ok(daemon.registry.firstSeen[`${9200 + pass}:a:${42000 + pass}`], 'the birth stays in effect in memory');
      assert.ok(logs.some((l) => l.startsWith('registry state-save-failed') && l.includes('ENOSPC')), logs.join('\n'));

      // Another process generation takes over the shared port: revoked by
      // this very pass, not a pass after the disk recovered.
      shopListener = autoListener(9102, 41101, shop, '9102:b');
      await daemon.refresh();
      assert.strictEqual(daemon.shares.isShared('shop'), false, 'the binding check revokes the share');
      assert.ok(logs.some((l) => l.includes('revoked (process generation changed)')), logs.join('\n'));
    } finally {
      restore();
    }
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// H12 — discovery failures and the recovery reach the daemon log
// ---------------------------------------------------------------------------

test('H12: the daemon log records each change of the discovery state, not every failed pass', async () => {
  const dir = tmpDir('pn-hard-scan-log-');
  const shop = path.join(dir, 'shop');
  fs.mkdirSync(shop);
  const logs = [];
  let scanFailure = null;
  let enrichFailure = false;
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    refreshMs: 3_600_000,
    log: (...fields) => logs.push(fields.join(' ')),
    listListeners: async () => {
      if (scanFailure) throw new Error(scanFailure);
      // Without a process generation the pass looks up the start time.
      return enrichFailure
        ? [{ pid: 9301, port: 41301, command: 'node', cwd: shop, root: shop, external: false }]
        : [autoListener(9301, 41301, shop, '9301:a')];
    },
    getStartTime: async () => {
      throw new Error('ps timed out after 3000ms');
    },
  });
  const discoveryLines = () => logs.filter((l) => l.startsWith('discovery '));
  try {
    await daemon.start();
    assert.deepStrictEqual(discoveryLines(), [], 'a healthy start logs no discovery change');

    scanFailure = 'lsof timed out after 5000ms';
    for (let i = 0; i < 3; i++) await daemon.refresh();
    assert.strictEqual((await daemon.dispatchControl({ cmd: 'status' })).scanError, scanFailure);
    assert.deepStrictEqual(discoveryLines(), ['discovery scan-failed lsof timed out after 5000ms'],
      'the move into the degraded state is logged once, with its reason');

    // The scan works again, but a later stage keeps failing: still degraded,
    // with another reason — no recovery in between.
    scanFailure = null;
    enrichFailure = true;
    for (let i = 0; i < 3; i++) await daemon.refresh();
    assert.deepStrictEqual(discoveryLines().slice(1), ['discovery scan-failed ps timed out after 3000ms']);

    enrichFailure = false;
    await daemon.refresh();
    await daemon.refresh();
    assert.deepStrictEqual(discoveryLines().slice(2), ['discovery recovered previous error: ps timed out after 3000ms']);
    assert.strictEqual(daemon.lastScanError, null);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
