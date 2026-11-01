'use strict';

// Service identity model: project/worktree identity, service identity (role)
// and process generation are separate. These tests pin the corrected
// classification (a different PID is NOT automatically a stale server) and
// the identity guarantees the GUI's result verification relies on.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { Daemon } = require('../lib/daemon');
const { resolveRoutes } = require('../lib/discover');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function autoListener({ pid, port, root, processKey }) {
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

function writeCfScript(dir, host) {
  const script = path.join(dir, `cf-${host}.js`);
  fs.writeFileSync(
    script,
    `#!/usr/bin/env node\nconsole.log("https://${host}.trycloudflare.com");\nsetInterval(() => {}, 1000);\n`
  );
  fs.chmodSync(script, 0o755);
  return script;
}

// ---------------------------------------------------------------------------
// resolveRoutes level
// ---------------------------------------------------------------------------

test('resolveRoutes: two PIDs (frontend + API) of one project are simultaneously valid services', () => {
  const root = '/wt/main/proj';
  const api = autoListener({ pid: 10, port: 3333, root, processKey: '10:T2' });
  const web = autoListener({ pid: 20, port: 5173, root, processKey: '20:T1' });
  const firstSeen = { '10:T2:3333': 5000, '20:T1:5173': 1000 };

  const { routes, stale } = resolveRoutes({ listeners: [web, api], firstSeen });

  assert.strictEqual(routes.length, 1);
  assert.strictEqual(stale.length, 0, 'no generation is superseded: the roles (ports) differ');
  const services = routes[0].services;
  assert.deepStrictEqual(services.map((s) => s.port), [3333, 5173]);
  assert.deepStrictEqual(services.map((s) => s.primary), [true, false]);
  assert.deepStrictEqual(services.map((s) => s.crossGeneration), [false, true]);
  // Service identity = project + role (port), independent of the generation:
  assert.deepStrictEqual(services.map((s) => s.serviceId), [`${root}#3333`, `${root}#5173`]);
  assert.notStrictEqual(services[0].processKey, services[1].processKey, 'generations stay separate');
});

test('resolveRoutes: several services of the SAME pid keep crossGeneration false', () => {
  const root = '/p/app';
  const listeners = [
    autoListener({ pid: 10, port: 3000, root, processKey: '10:T1' }),
    autoListener({ pid: 10, port: 4000, root, processKey: '10:T1' }),
    autoListener({ pid: 10, port: 5000, root, processKey: '10:T1' }),
  ];
  const firstSeen = { '10:T1:3000': 1000, '10:T1:4000': 2000, '10:T1:5000': 3000 };

  const { routes, stale } = resolveRoutes({ listeners, firstSeen });
  assert.strictEqual(stale.length, 0);
  assert.strictEqual(routes[0].services.length, 3);
  assert.ok(routes[0].services.every((s) => s.crossGeneration === false));
  assert.ok(routes[0].services.every((s) => s.serviceId.startsWith(`${root}#`)));
});

// ---------------------------------------------------------------------------
// Daemon level (status/set-primary/identity across scans and restarts)
// ---------------------------------------------------------------------------

function loopbackDaemon(dir, listListeners, extra = {}) {
  return new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false, ...extra.config },
    listListeners,
    ...extra,
  });
}

// Wildcard daemon on an ephemeral port with a faked LAN address: needed for
// the exposure-wish tests (expose on:true is refused in loopback bind mode).
function wildcardDaemon(dir, listListeners) {
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners,
  });
  const realStart = daemon.start.bind(daemon);
  daemon.start = async () => {
    const port = await realStart();
    daemon.announcer.lanAddress = () => '192.168.1.20';
    return port;
  };
  return daemon;
}

test('daemon: frontend and API as two PIDs — set-primary switches roles, nothing is stale', async () => {
  const dir = tmpDir('pn-svc-two-pids-');
  const root = path.join(dir, 'proj');
  fs.mkdirSync(root);
  const state = {
    '10:T2:3333': 5000,
    '20:T1:5173': 1000,
  };
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify(state));
  const api = autoListener({ pid: 10, port: 3333, root, processKey: '10:T2' });
  const web = autoListener({ pid: 20, port: 5173, root, processKey: '20:T1' });

  const daemon = loopbackDaemon(dir, () => [api, web]);
  try {
    await daemon.start();
    const status = await daemon.dispatchControl({ cmd: 'status' });
    const route = status.routes.find((r) => r.name === 'proj');
    assert.strictEqual(route.port, 3333, 'default: newest generation carries the name');
    assert.strictEqual(route.services.length, 2);
    assert.strictEqual(status.stale.length, 0);

    // Switch the name to the frontend (older generation, different role).
    const switched = await daemon.dispatchControl({
      cmd: 'set-primary', name: 'proj', port: 5173, expectedRouteRevision: route.revision,
    });
    assert.strictEqual(switched.primaryPort, 5173);
    assert.strictEqual(daemon.routesByName.get('proj').port, 5173);

    // The revision guard is bound to the concrete target: after the switch,
    // the old revision must fail closed (a timed-out or repeated mutation
    // must never apply against a changed target).
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'set-primary', name: 'proj', port: 3333, expectedRouteRevision: route.revision }),
      (err) => err.code === 'STALE_TARGET'
    );
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: same-port replacement of one role — newer generation serves, older stays diagnostic', async () => {
  const dir = tmpDir('pn-svc-replace-');
  const root = path.join(dir, 'proj');
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({
    '30:T1:3000': 1000,
    '31:T2:3000': 5000,
  }));
  const oldGen = autoListener({ pid: 30, port: 3000, root, processKey: '30:T1' });
  const newGen = autoListener({ pid: 31, port: 3000, root, processKey: '31:T2' });

  const daemon = loopbackDaemon(dir, () => [oldGen, newGen]);
  try {
    await daemon.start();
    const route = daemon.routesByName.get('proj');
    assert.strictEqual(route.pid, 31, 'the newer generation fulfills the role');
    assert.strictEqual(route.services.length, 1);
    assert.strictEqual(daemon.stale.length, 1);
    assert.strictEqual(daemon.stale[0].pid, 30, 'the same-port loser is diagnostics, not a route');
    assert.strictEqual(daemon.stale[0].serviceId, `${root}#3000`);

    // Pointing the preference at the replaced generation's port is allowed,
    // but resolves to the LIVING generation of that role — the old process
    // is never revived or killed.
    await daemon.dispatchControl({ cmd: 'set-primary', name: 'proj', port: 3000 });
    assert.strictEqual(daemon.routesByName.get('proj').pid, 31);
    assert.strictEqual(daemon.routesByName.get('proj').preferredMissing, false);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: parallel worktrees are separate projects — names, services and exposure never cross', async () => {
  const dir = tmpDir('pn-svc-worktrees-');
  const mainRoot = path.join(dir, 'main', 'proj');
  const wtRoot = path.join(dir, 'wt', 'proj');
  fs.mkdirSync(mainRoot, { recursive: true });
  fs.mkdirSync(wtRoot, { recursive: true });
  const mainSrv = autoListener({ pid: 40, port: 4100, root: mainRoot, processKey: '40:T1' });
  const wtApi = autoListener({ pid: 41, port: 4200, root: wtRoot, processKey: '41:T1' });

  const daemon = wildcardDaemon(dir, () => [mainSrv, wtApi]);
  try {
    await daemon.start();
    const names = daemon.routes.map((r) => r.name).sort();
    assert.deepStrictEqual(names, ['proj', 'proj-2'],
      'same basename must not let one worktree take over the other');

    const byName = new Map(daemon.routes.map((r) => [r.name, r]));
    const mainRoute = byName.get('proj');
    const wtRoute = byName.get('proj-2');
    assert.strictEqual(mainRoute.root, mainRoot);
    assert.strictEqual(wtRoute.root, wtRoot);
    assert.deepStrictEqual(mainRoute.services.map((s) => s.serviceId), [`${mainRoot}#4100`],
      'services never leak across project identities');
    assert.deepStrictEqual(wtRoute.services.map((s) => s.serviceId), [`${wtRoot}#4200`]);

    // LAN exposure is a per-project wish: exposing main must not expose the
    // worktree, and a newly detected worktree inherits nothing.
    await daemon.dispatchControl({ cmd: 'expose', name: 'proj', on: true });
    const status = await daemon.dispatchControl({ cmd: 'status' });
    const again = new Map(status.routes.map((r) => [r.name, r]));
    assert.strictEqual(again.get('proj').exposureRequested, true);
    assert.strictEqual(again.get('proj-2').exposureRequested, false, 'new worktree inherits no LAN share');
    assert.deepStrictEqual(status.exposed, ['proj']);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: a new worktree inherits no public share; the shared project keeps its own', async () => {
  const dir = tmpDir('pn-svc-share-inherit-');
  const mainRoot = path.join(dir, 'main', 'proj');
  const wtRoot = path.join(dir, 'wt', 'proj');
  fs.mkdirSync(mainRoot, { recursive: true });
  fs.mkdirSync(wtRoot, { recursive: true });
  const cf = writeCfScript(dir, 'inherit');
  let listeners = [autoListener({ pid: 50, port: 5100, root: mainRoot, processKey: '50:T1' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'share', name: 'proj', ttlMinutes: 60 });
    assert.strictEqual(daemon.shares.isShared('proj'), true);

    // A second worktree appears while the share is active.
    listeners = [
      listeners[0],
      autoListener({ pid: 51, port: 5200, root: wtRoot, processKey: '51:T1' }),
    ];
    await daemon.refresh();

    assert.strictEqual(daemon.shares.isShared('proj'), true, 'the untouched project keeps its share');
    assert.strictEqual(daemon.shares.status().length, 1, 'the new worktree starts with no public share');
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.routes.find((r) => r.name === 'proj-2').exposureRequested, false,
      'the new worktree inherits no LAN share either');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: persisted primary choice with missing target falls back and reports preferredMissing', async () => {
  const dir = tmpDir('pn-svc-pref-missing-');
  const root = path.join(dir, 'proj');
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({
    '10:T1:3000': 1000,
    '20:T2:3001': 5000,
  }));
  const api = autoListener({ pid: 10, port: 3000, root, processKey: '10:T1' });
  const web = autoListener({ pid: 20, port: 3001, root, processKey: '20:T2' });
  let listeners = [api, web];

  const daemon = loopbackDaemon(dir, () => listeners);
  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'set-primary', name: 'proj', port: 3001 });
    assert.strictEqual(daemon.routesByName.get('proj').port, 3001);

    // The preferred service dies; the other role keeps the project alive.
    listeners = [api];
    await daemon.refresh();
    const route = daemon.routesByName.get('proj');
    assert.strictEqual(route.port, 3000, 'fallback keeps the project routed');
    assert.strictEqual(route.preferredMissing, true, 'the UI must see the wish is unmet');
    assert.strictEqual(route.preferredPort, 3001, 'the stored wish itself is kept');
    assert.strictEqual(route.services.length, 1);
    assert.strictEqual(daemon.stale.length, 0);

    // The wish survives and re-arms when the role comes back on its port.
    listeners = [api, web];
    await daemon.refresh();
    assert.strictEqual(daemon.routesByName.get('proj').port, 3001);
    assert.strictEqual(daemon.routesByName.get('proj').preferredMissing, false);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: a stale entry of project A is not usable as a set-primary target of project B', async () => {
  const dir = tmpDir('pn-svc-name-reuse-');
  const rootA = path.join(dir, 'alpha');
  const rootB = path.join(dir, 'beta');
  fs.mkdirSync(rootA);
  fs.mkdirSync(rootB);
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({
    '60:T1:3000': 1000,
    '61:T2:3000': 5000,
    '62:T1:6000': 2000,
  }));
  const alphaOld = autoListener({ pid: 60, port: 3000, root: rootA, processKey: '60:T1' });
  const alphaNew = autoListener({ pid: 61, port: 3000, root: rootA, processKey: '61:T2' });
  const beta = autoListener({ pid: 62, port: 6000, root: rootB, processKey: '62:T1' });

  const daemon = loopbackDaemon(dir, () => [alphaOld, alphaNew, beta]);
  try {
    await daemon.start();
    const status = await daemon.dispatchControl({ cmd: 'status' });
    const alpha = status.routes.find((r) => r.root === rootA);
    const betaRoute = status.routes.find((r) => r.root === rootB);
    assert.notStrictEqual(alpha.name, betaRoute.name, 'names stay unique per object');

    // Beta must not be steered onto alpha's superseded listener — the stale
    // entry belongs to alpha's identity even if a display name collides.
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'set-primary', name: betaRoute.name, port: 3000 }),
      (err) => err.code === 'INVALID_REQUEST'
    );
    // Alpha's own superseded port remains selectable for alpha.
    await daemon.dispatchControl({ cmd: 'set-primary', name: alpha.name, port: 3000 });
    assert.strictEqual(daemon.routesByName.get(alpha.name).pid, 61,
      'the preference resolves to the living generation of the role');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: daemon restart keeps service identity; a changed generation invalidates revisions', async () => {
  const dir = tmpDir('pn-svc-restart-');
  const root = path.join(dir, 'proj');
  fs.mkdirSync(root);
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({
    '70:T1:7000': 1000,
    '71:T2:7100': 5000,
  }));
  const api = autoListener({ pid: 70, port: 7000, root, processKey: '70:T1' });
  const web = autoListener({ pid: 71, port: 7100, root, processKey: '71:T2' });
  let listeners = [api, web];

  const daemon = wildcardDaemon(dir, () => listeners);
  let daemon2 = null;
  try {
    await daemon.start();
    const before = await daemon.dispatchControl({ cmd: 'status' });
    const routeBefore = before.routes.find((r) => r.name === 'proj');
    await daemon.dispatchControl({ cmd: 'expose', name: 'proj', on: true });
    await daemon.stop();

    // Restart with the SAME service landscape: identities are stable, the
    // exposure wish persists per project root.
    daemon2 = wildcardDaemon(dir, () => listeners);
    await daemon2.start();
    const after = await daemon2.dispatchControl({ cmd: 'status' });
    assert.notStrictEqual(after.daemonInstanceId, before.daemonInstanceId, 'clients can detect the restart');
    const routeAfter = after.routes.find((r) => r.name === 'proj');
    assert.deepStrictEqual(routeAfter.services.map((s) => s.serviceId),
      routeBefore.services.map((s) => s.serviceId));
    assert.strictEqual(routeAfter.exposureRequested, true);

    // Old-guard mutations from before the restart must fail closed.
    await assert.rejects(
      () => daemon2.dispatchControl({ cmd: 'set-primary', name: 'proj', port: 7000, expectedRouteRevision: routeBefore.revision }),
      (err) => err.code === 'STALE_TARGET'
    );

    // A new generation on the SAME port changes the revision (and the share
    // pinning), while the service identity (root#port) stays the same.
    const restartedApi = autoListener({ pid: 72, port: 7000, root, processKey: '72:T3' });
    listeners = [restartedApi, web];
    fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({
      '72:T3:7000': 9000,
      '71:T2:7100': 5000,
    }));
    await daemon2.refresh();
    const later = await daemon2.dispatchControl({ cmd: 'status' });
    const routeLater = later.routes.find((r) => r.name === 'proj');
    assert.notStrictEqual(routeLater.revision, routeAfter.revision, 'generation change must be visible');
    const apiSvc = routeLater.services.find((s) => s.port === 7000);
    assert.strictEqual(apiSvc.serviceId, `${root}#7000`, 'role identity survives the generation change');
    assert.strictEqual(apiSvc.processKey, '72:T3');
  } finally {
    if (daemon2) await daemon2.stop();
    else await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Late status overwrite is impossible daemon-side: status is always served
// from the current snapshot, and mutations observe their own refresh through
// the barrier (covered by the coalescing test in primary-service.test.js).
test('daemon: a mutation observes its own effect via the refresh barrier', async () => {
  const dir = tmpDir('pn-svc-barrier-');
  const root = path.join(dir, 'proj');
  fs.mkdirSync(root);
  const api = autoListener({ pid: 80, port: 8000, root, processKey: '80:T1' });
  const web = autoListener({ pid: 81, port: 8100, root, processKey: '81:T1' });

  const daemon = loopbackDaemon(dir, () => [api, web]);
  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'set-primary', name: 'proj', port: 8100 });
    // dispatchControl awaited its internal refresh: the status that any
    // client reads AFTER the mutation answered already shows the new state.
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.routes.find((r) => r.name === 'proj').port, 8100);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
