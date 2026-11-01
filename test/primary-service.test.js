'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { Daemon } = require('../lib/daemon');
const { resolveRoutes } = require('../lib/discover');
const { BonjourAnnouncer } = require('../lib/expose');

function listener(pid, port, root, command = 'node', processKey = `${pid}:gen`) {
  return {
    pid,
    port,
    command,
    processKey,
    cwd: root,
    root,
    external: false,
    suggestedName: path.basename(root),
  };
}

// blood-values live case: frontend :5173 (older generation) + backend :3333
// (newer generation). Default rule picks the newest; the stored preference
// must beat it.
test('resolveRoutes: preferred port wins across generations and reports all services', () => {
  const backend = listener(10, 3333, '/p/bv', 'node', '10:T2');
  const frontend = listener(20, 5173, '/p/bv', 'node', '20:T1');
  const firstSeen = { '10:T2:3333': 5000, '20:T1:5173': 1000 };

  const noPreference = resolveRoutes({ listeners: [backend, frontend], firstSeen });
  assert.strictEqual(noPreference.routes[0].port, 3333, 'default: newest generation wins the name');
  assert.strictEqual(noPreference.routes[0].services.length, 2,
    'frontend and backend are simultaneously valid services of the project');
  assert.strictEqual(noPreference.routes[0].services[0].port, 3333);
  assert.strictEqual(noPreference.routes[0].services[0].primary, true);
  assert.strictEqual(noPreference.routes[0].services[1].port, 5173);
  assert.strictEqual(noPreference.routes[0].services[1].primary, false);
  assert.strictEqual(noPreference.routes[0].services[1].crossGeneration, true,
    'the other PID is a different role, not a superseded server');
  assert.strictEqual(noPreference.stale.length, 0, 'nothing is stale: the ports (roles) differ');

  const preferred = resolveRoutes({
    listeners: [backend, frontend],
    firstSeen,
    preferredPorts: { '/p/bv': 5173 },
  });
  assert.strictEqual(preferred.routes[0].port, 5173, 'the stored preference beats the recency rule');
  assert.strictEqual(preferred.routes[0].preferredPort, 5173);
  assert.strictEqual(preferred.routes[0].preferredMissing, false);
  assert.strictEqual(preferred.routes[0].services.length, 2);
  assert.strictEqual(preferred.routes[0].services[0].primary, true);
  assert.strictEqual(preferred.routes[0].services[0].port, 5173);
  assert.strictEqual(preferred.routes[0].services[1].port, 3333, 'the unpreferred service stays listed');
  assert.strictEqual(preferred.routes[0].services[1].crossGeneration, true);
  assert.strictEqual(preferred.stale.length, 0,
    'the unpreferred generation is a valid service of another role, never stale');
});

test('resolveRoutes: two same-generation services both show up, primary flagged', () => {
  const api = listener(10, 3333, '/p/bv', 'node', '10:T1');
  const web = listener(10, 5173, '/p/bv', 'node', '10:T1');
  const firstSeen = { '10:T1:3333': 1000, '10:T1:5173': 2000 };

  const { routes } = resolveRoutes({ listeners: [api, web], firstSeen, preferredPorts: { '/p/bv': 5173 } });
  assert.strictEqual(routes[0].port, 5173);
  assert.strictEqual(routes[0].services.length, 2);
  assert.deepStrictEqual(routes[0].services.map((s) => s.port), [5173, 3333]);
  assert.deepStrictEqual(routes[0].services.map((s) => s.primary), [true, false]);
  assert.strictEqual(routes[0].stale, undefined);
  assert.strictEqual(routes[0].services.some((s) => !s.primary), true, 'the other service stays visible');
});

test('resolveRoutes: missing preferred port falls back and reports preferredMissing', () => {
  const l = listener(10, 3333, '/p/bv', 'node', '10:T1');
  const { routes } = resolveRoutes({ listeners: [l], preferredPorts: { '/p/bv': 5173 } });
  assert.strictEqual(routes[0].port, 3333, 'fallback uses the default rule');
  assert.strictEqual(routes[0].preferredMissing, true, 'the UI must see that the wish is unmet');
});

function startUpstream(port) {
  return port;
}

test('set-primary: switches the project primary, guards revisions, persists per root', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-primary-'));
  const root = path.join(dir, 'bv');
  fs.mkdirSync(root);
  // Deterministic births: backend :3333 is the NEWER generation, frontend
  // :5173 the older one — the default rule must pick 3333 first.
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({
    '10:T2:3333': 5000,
    '20:T1:5173': 1000,
  }));
  const backend = listener(10, 3333, root, 'node', '10:T2');
  const frontend = listener(20, 5173, root, 'node', '20:T1');

  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
    listListeners: () => [backend, frontend],
  });
  let daemon2 = null;

  try {
    await daemon.start();
    assert.strictEqual(daemon.routesByName.get('bv').port, 3333, 'default picks the newest generation');

    const status = await daemon.dispatchControl({ cmd: 'status' });
    const route = status.routes.find((r) => r.name === 'bv');
    // Cross-generation project: both PIDs are valid services of different
    // roles; the frontend is reported cross-generation, nothing is stale.
    assert.strictEqual(route.services.length, 2);
    assert.strictEqual(route.services[0].port, 3333);
    assert.ok(route.services.some((s) => s.port === 5173 && s.crossGeneration === true));
    assert.strictEqual(status.stale.length, 0);

    // Unknown port is refused without side effects.
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'set-primary', name: 'bv', port: 9999, expectedRouteRevision: route.revision }),
      (err) => err.code === 'INVALID_REQUEST'
    );

    // Stale revision fails closed.
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'set-primary', name: 'bv', port: 5173, expectedRouteRevision: 'bogus' }),
      (err) => err.code === 'STALE_TARGET'
    );

    const switched = await daemon.dispatchControl({
      cmd: 'set-primary', name: 'bv', port: 5173, expectedRouteRevision: route.revision,
    });
    assert.strictEqual(switched.primaryPort, 5173);
    assert.strictEqual(daemon.routesByName.get('bv').port, 5173);
    assert.strictEqual(daemon.routesByName.get('bv').preferredMissing, false);

    // The choice is stored per root and survives a daemon restart.
    await daemon.stop();
    daemon2 = new Daemon({
      dir,
      config: { bind: 'loopback', loopbackPort: 0, control: false },
      listListeners: () => [backend, frontend],
    });
    try {
      await daemon2.start();
      assert.strictEqual(daemon2.routesByName.get('bv').port, 5173, 'preference persists across daemon runs');
    } finally {
      await daemon2.stop();
    }
  } finally {
    if (!daemon2) await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('set-primary: manual routes are not applicable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-primary-manual-'));
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
    listListeners: () => [],
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'db', port: 5432 });
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'set-primary', name: 'db', port: 5432 }),
      (err) => err.code === 'INVALID_REQUEST' && /discovered projects/.test(err.message)
    );
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('failed scan keeps previous routes and reports scanError until recovery', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-scanfail-'));
  const root = path.join(dir, 'shop');
  fs.mkdirSync(root);
  let shouldFail = false;
  const listeners = [listener(10, 3000, root)];

  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
    listListeners: () => {
      if (shouldFail) throw new Error('lsof exploded');
      return listeners;
    },
  });

  try {
    await daemon.start();
    assert.strictEqual(daemon.routes.length, 1);
    assert.strictEqual(daemon.lastScanError, null);

    shouldFail = true;
    await daemon.refresh();
    assert.strictEqual(daemon.routes.length, 1, 'a failed scan must not look like "all projects stopped"');
    assert.match(daemon.lastScanError, /lsof exploded/);
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.match(status.scanError, /lsof exploded/);

    shouldFail = false;
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, null, 'a good scan clears the degraded flag');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('overlapping refresh passes coalesce into at most one follow-up scan', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-coalesce-'));
  let scanCount = 0;
  let slowScan = null;

  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
    listListeners: async () => {
      scanCount += 1;
      if (slowScan) await slowScan;
      return [];
    },
  });

  try {
    await daemon.start();
    const afterStart = scanCount;

    slowScan = new Promise((r) => setTimeout(r, 120));
    const first = daemon.refresh();
    await new Promise((r) => setTimeout(r, 20)); // first scan in flight
    const second = daemon.refresh();
    const third = daemon.refresh(); // arrives during the same scan
    await first;
    await second;
    await third;
    slowScan = null;

    assert.strictEqual(scanCount, afterStart + 2,
      'three overlapping requests = the running scan plus exactly one follow-up');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Bonjour: state file written only when the child set changes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-bonjour-'));
  const stateFile = path.join(dir, 'bonjour.state.json');

  const fsMod = require('node:fs');
  let writes = 0;
  // The state file is published via atomicWrite: open exclusive temp fd, then
  // renameSync onto the final path. Counting the rename counts the actual
  // write of the state file, independent of temp naming.
  const origRename = fsMod.renameSync;
  fsMod.renameSync = function (from, to, ...rest) {
    if (String(to).includes('bonjour.state')) writes += 1;
    return origRename.call(this, from, to, ...rest);
  };

  try {
    const announcer = new BonjourAnnouncer({
      port: 80,
      dir,
      getLan: () => ({ address: '10.0.0.9' }),
    });
    // Register without spawning dns-sd: plant the child directly.
    announcer.children.set('a', { pid: 424242, kill() {} });

    announcer.sync(['a']); // first record: writes the file
    assert.strictEqual(writes, 1);
    assert.ok(fs.existsSync(stateFile));

    announcer.sync(['a']); // unchanged set: no rewrite, no extra start-time reads
    assert.strictEqual(writes, 1, 'unchanged registrations must not rewrite the state file');

    announcer.sync([]); // withdrawal: unlink, not write
    assert.strictEqual(writes, 1);
    assert.ok(!fs.existsSync(stateFile), 'empty registration set removes the state file');
  } finally {
    fsMod.renameSync = origRename;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
