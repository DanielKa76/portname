'use strict';

// A KNOWN, accepted target mutation (manual entry remove, manual repoint,
// primary port switch) must invalidate the PUBLIC side immediately
// and scan-independently. The scan-driven revocation inside the refresh pass
// cannot act while discovery keeps failing (the verification grace window
// deliberately keeps the share alive), and the stale route snapshot stays
// DISPLAYED on purpose — but it must not stay STARTABLE, and no job accepted
// before the mutation may activate a public share for the removed or
// overridden target. This is a known mutation the daemon itself accepted,
// not the unavoidable poll window for unknown process changes.
//
// Contract:
//   M1  the mutation stops the affected share (held STARTING or active)
//       before its refresh pass, without waiting for any scan;
//   M2  the name's revocation epoch advances: a replacement start accepted
//       before the mutation aborts instead of starting with old arguments;
//   M3  a NEW share request for the mutated name is refused with
//       SHARE_TARGET_UNVERIFIED while scans keep failing (stale snapshot),
//       and works again after a completed successful scan re-verified the
//       post-mutation target;
//   M4  genuine no-ops (same-port upsert, remove of an unknown name) and
//       rejected mutations change nothing; other projects are untouched.
//
// Determinism: tunnel boots are held open with a flag-file-gated fake
// cloudflared; discovery failures are injected; the periodic refresh is
// disabled (only explicit refresh passes run); no real-time waits.

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

// Fake cloudflared that only prints its URL once the flag file exists and
// then stays alive: a deterministic hold point inside #startTunnel.
function writeFlagCfScript(dir, name, flagFile) {
  const script = path.join(dir, `cf-flag-${name}.js`);
  fs.writeFileSync(
    script,
    '#!/usr/bin/env node\n' +
    `const flag = ${JSON.stringify(flagFile)};\n` +
    'const t = setInterval(() => {\n' +
    '  if (require("fs").existsSync(flag)) {\n' +
    '    clearInterval(t);\n' +
    `    console.log("https://${name}.trycloudflare.com");\n` +
    '  }\n' +
    '}, 5);\n' +
    'setInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(script, 0o755);
  return script;
}

// Fake cloudflared that prints immediately and stays alive.
function writeCfScript(dir, name) {
  const script = path.join(dir, `cf-${name}.js`);
  fs.writeFileSync(
    script,
    `#!/usr/bin/env node\nconsole.log("https://${name}.trycloudflare.com");\nsetInterval(() => {}, 1000);\n`
  );
  fs.chmodSync(script, 0o755);
  return script;
}

function releaseFlag(flagFile) {
  fs.writeFileSync(flagFile, 'go\n');
}

async function waitFor(condition, { budgetMs = 3000, stepMs = 5 } = {}) {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > budgetMs) return false;
    await sleep(stepMs);
  }
  return true;
}

// Manual-target listener fixture (no project root: the observed listener is
// its process generation).
function manualListener(pid, port, processKey) {
  return { pid, port, processKey, command: 'postgres', cwd: null, root: null, external: false };
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

// Daemon with fully controlled discovery: the injected listener list is
// switched by the test, `failScans` makes every pass fail (degraded pass:
// previous routes stay displayed, verification-grace revocation only), and
// the periodic timer is disabled — the only passes are the ones the test and
// the control handlers trigger. The verification clocks are widened so the
// ONLY thing that can block or revoke a share here is the mutation
// invalidation under test, never a grace deadline.
function makeDaemon({ dir, cloudflaredBin }) {
  const state = { failScans: false, listeners: [] };
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin },
    refreshMs: 3_600_000, // only explicit refresh() passes in these tests
    routeFreshnessMs: 60_000,
    shareVerifyGraceMs: 60_000,
    listListeners: async () => {
      if (state.failScans) throw new Error('lsof exploded');
      return state.listeners;
    },
  });
  return { daemon, state };
}

// Held STARTING share A + pending replacement B (different TTL), both
// accepted BEFORE the mutation.
async function holdStartingShareWithPendingReplacement(daemon, name) {
  const startA = daemon.dispatchControl({ cmd: 'share', name, ttlMinutes: 60 })
    .then(() => null, (err) => err);
  assert.strictEqual(
    await waitFor(() => daemon.shares.childPids().length === 1), true, 'A must spawn while STARTING'
  );
  const startB = daemon.dispatchControl({ cmd: 'share', name, ttlMinutes: 30 })
    .then(() => null, (err) => err);
  return { startA, startB };
}

// ---------------------------------------------------------------------------

test('M1/M2: accepted remove revokes the held share and cancels the pending replacement while discovery is failing', async () => {
  const dir = tmpDir('pn-mut-remove-');
  const u1 = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cf = writeFlagCfScript(dir, 'mut-remove', flagFile);
  const { daemon, state } = makeDaemon({ dir, cloudflaredBin: cf });
  state.listeners = [manualListener(5101, u1.port, '5101:m1')];

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });

    const { startA, startB } = await holdStartingShareWithPendingReplacement(daemon, 'app');

    // Discovery fails from now on: the last verification is still inside the
    // grace window, so nothing scan-driven may be relied upon.
    state.failScans = true;

    // The known mutation, through the real control handler (response awaited).
    const removed = await daemon.dispatchControl({ cmd: 'remove', name: 'app' });
    assert.strictEqual(removed.removed, 'app');

    // Whatever was still booting must never reach activation after the
    // mutation: release the tunnel barrier and let every pre-mutation job
    // settle into its final outcome.
    releaseFlag(flagFile);

    // M2: the replacement accepted before the mutation must abort.
    const bOutcome = await startB;
    assert.ok(bOutcome instanceof Error, 'the pending replacement must be cancelled by the remove');
    assert.match(bOutcome.message, /cancelled/i);

    // M1: the held share must be gone — no scan needed.
    assert.strictEqual(daemon.shares.status().length, 0, 'no share may survive the remove');
    await startA.then(null, () => {});
    assert.strictEqual(daemon.shares.childPids().length, 0, 'no tunnel process may survive');

    // M3: no new share may start off the stale route snapshot.
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'app' }),
      (err) => err.code === 'SHARE_TARGET_UNVERIFIED',
      'the stale snapshot must not be startable while scans keep failing'
    );

    // Recovery: after a completed successful scan the world is re-verified.
    // The manual entry is gone, so the name resolves to a defined NO_ROUTE.
    state.failScans = false;
    await daemon.refresh();
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'app' }),
      (err) => err.code === 'NO_ROUTE'
    );
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('M1-M3: accepted repoint never activates the old target; new starts need re-verification and recover', async () => {
  const dir = tmpDir('pn-mut-repoint-');
  const u1 = await startUpstream();
  const u2 = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cf = writeFlagCfScript(dir, 'mut-repoint', flagFile);
  const { daemon, state } = makeDaemon({ dir, cloudflaredBin: cf });
  state.listeners = [manualListener(5102, u1.port, '5102:m1')];

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });

    const { startA, startB } = await holdStartingShareWithPendingReplacement(daemon, 'app');

    state.failScans = true;

    // Repoint to a different port through the real control handler.
    const repointed = await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u2.port });
    assert.strictEqual(repointed.port, u2.port);

    // Release the tunnel barrier: pre-mutation jobs must never activate the
    // overridden target.
    releaseFlag(flagFile);

    const bOutcome = await startB;
    assert.ok(bOutcome instanceof Error, 'the pending replacement must be cancelled by the repoint');
    assert.match(bOutcome.message, /cancelled/i);
    assert.strictEqual(daemon.shares.status().length, 0, 'no share may survive the repoint');
    await startA.then(null, () => {});
    assert.strictEqual(daemon.shares.childPids().length, 0, 'no tunnel process may survive');

    // M3: while scans fail, the stale snapshot (old port) must not be
    // startable — a share start is refused with a defined error instead of
    // pinning the overridden target.
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'app' }),
      (err) => err.code === 'SHARE_TARGET_UNVERIFIED',
      'the stale snapshot must not be startable while scans keep failing'
    );

    // Recovery: a fresh successful scan observes the NEW tuple; a share
    // requested deliberately AFTER the mutation now starts against it.
    state.failScans = false;
    state.listeners = [manualListener(5103, u2.port, '5103:m2')];
    await daemon.refresh();
    const recovered = await daemon.dispatchControl({ cmd: 'share', name: 'app' });
    assert.strictEqual(daemon.shares.status()[0].pinnedPort, u2.port, 'the new share must pin the repointed target');
    void recovered;
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('M1-M3: accepted primary port switch does the same for discovered projects', async () => {
  const dir = tmpDir('pn-mut-primary-');
  const uA = await startUpstream();
  const uB = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cf = writeFlagCfScript(dir, 'mut-primary', flagFile);
  const { daemon, state } = makeDaemon({ dir, cloudflaredBin: cf });
  const root = path.join(dir, 'shop');
  state.listeners = [
    autoListener(5201, uA.port, root, '5201:g1'),
    autoListener(5202, uB.port, root, '5202:g2'),
  ];

  try {
    await daemon.start();
    // Make the carried name explicit before anything is shared.
    await daemon.dispatchControl({ cmd: 'set-primary', name: 'shop', port: uA.port });
    assert.strictEqual(daemon.routesByName.get('shop').port, uA.port);

    const { startA, startB } = await holdStartingShareWithPendingReplacement(daemon, 'shop');

    state.failScans = true;

    // Primary switch to the other service of the same project.
    const switched = await daemon.dispatchControl({ cmd: 'set-primary', name: 'shop', port: uB.port });
    assert.strictEqual(switched.primaryPort, uB.port);

    // Release the tunnel barrier: pre-mutation jobs must never activate the
    // overridden target.
    releaseFlag(flagFile);

    const bOutcome = await startB;
    assert.ok(bOutcome instanceof Error, 'the pending replacement must be cancelled by the primary switch');
    assert.match(bOutcome.message, /cancelled/i);
    assert.strictEqual(daemon.shares.status().length, 0, 'no share may survive the primary switch');
    await startA.then(null, () => {});
    assert.strictEqual(daemon.shares.childPids().length, 0, 'no tunnel process may survive');

    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'shop' }),
      (err) => err.code === 'SHARE_TARGET_UNVERIFIED',
      'the stale snapshot must not be startable while scans keep failing'
    );

    // Recovery: the switch is verified by a fresh scan and the name carries
    // the new port; a new share pins it.
    state.failScans = false;
    await daemon.refresh();
    await daemon.dispatchControl({ cmd: 'share', name: 'shop' });
    assert.strictEqual(daemon.shares.status()[0].pinnedPort, uB.port, 'the new share must pin the switched target');
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(uA);
    await closeUpstream(uB);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('M4: mutations are name-scoped — the untouched project keeps its share and its startability', async () => {
  const dir = tmpDir('pn-mut-scoped-');
  const u1 = await startUpstream();
  const u2 = await startUpstream();
  const cf = writeCfScript(dir, 'mut-scoped');
  const { daemon, state } = makeDaemon({ dir, cloudflaredBin: cf });
  state.listeners = [
    manualListener(5301, u1.port, '5301:m1'),
    manualListener(5302, u2.port, '5302:m2'),
  ];

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });
    await daemon.dispatchControl({ cmd: 'add', name: 'api', port: u2.port });

    const sharedApp = await daemon.dispatchControl({ cmd: 'share', name: 'app' });
    const sharedApi = await daemon.dispatchControl({ cmd: 'share', name: 'api' });
    assert.strictEqual(daemon.shares.status().length, 2);

    state.failScans = true;
    await daemon.dispatchControl({ cmd: 'remove', name: 'app' });

    assert.strictEqual(daemon.shares.isShared('app'), false, 'the mutated name loses its share');
    assert.strictEqual(daemon.shares.isShared('api'), true, 'the untouched project keeps its share');

    // api is still startable: its request resolves to the SAME instance
    // instead of being refused with the mutated name.
    const againApi = await daemon.dispatchControl({ cmd: 'share', name: 'api' });
    assert.strictEqual(againApi.shareId, sharedApi.shareId, 'the untouched project must not be invalidated');
    void sharedApp;
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('M4: genuine no-ops change nothing — same-port upsert keeps the share startable', async () => {
  const dir = tmpDir('pn-mut-noop-');
  const u1 = await startUpstream();
  const cf = writeCfScript(dir, 'mut-noop');
  const { daemon, state } = makeDaemon({ dir, cloudflaredBin: cf });
  state.listeners = [manualListener(5401, u1.port, '5401:m1')];

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });
    const shared = await daemon.dispatchControl({ cmd: 'share', name: 'app' });

    state.failScans = true;
    // Same-port upsert: the target tuple is unchanged — a genuine no-op.
    const upsert = await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });
    assert.strictEqual(upsert.port, u1.port);

    assert.strictEqual(daemon.shares.isShared('app'), true, 'a no-op upsert must not stop the share');
    const again = await daemon.dispatchControl({ cmd: 'share', name: 'app' });
    assert.strictEqual(again.shareId, shared.shareId, 'a no-op upsert must not invalidate the name');
    void shared;
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('M4: rejected mutations change nothing — createOnly conflict keeps the share', async () => {
  const dir = tmpDir('pn-mut-rejected-');
  const u1 = await startUpstream();
  const u2 = await startUpstream();
  const cf = writeCfScript(dir, 'mut-rejected');
  const { daemon, state } = makeDaemon({ dir, cloudflaredBin: cf });
  state.listeners = [manualListener(5501, u1.port, '5501:m1')];

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });
    const shared = await daemon.dispatchControl({ cmd: 'share', name: 'app' });

    state.failScans = true;
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'add', name: 'app', port: u2.port, createOnly: true }),
      (err) => err.code === 'NAME_CONFLICT'
    );

    assert.strictEqual(daemon.shares.isShared('app'), true, 'a rejected mutation must not stop the share');
    const again = await daemon.dispatchControl({ cmd: 'share', name: 'app' });
    assert.strictEqual(again.shareId, shared.shareId, 'a rejected mutation must not invalidate the name');
    void shared;
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
