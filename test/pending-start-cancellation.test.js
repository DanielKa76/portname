'use strict';

// Order-of-operations hardening for pending start/replacement jobs.
//
// A start job that has been accepted and is still waiting on some teardown
// (the share it replaces, a global revocation sweep, a daemon shutdown) must
// be invalidated by every targeted revocation of that name — not only by the
// global ones. Contract (invariants I1-I7):
//   I1  monotonic per-name revocation epoch, bumped synchronously by every
//       stop() entry except a start job's own internal replacement stop;
//   I2  start() snapshots (global generation, name epoch, instance shareId)
//       at acceptance and re-checks them after every await;
//   I3  the internal replacement stop carries the expectedShareId of the
//       instance it replaces and never stops a newer instance;
//   I4  revoking events: targeted unshare, scan-driven binding revoke,
//       verification-stale revoke, TTL, tunnel child exit/error, stopAll/
//       shutdown;
//   I5  a fresh start after a revoke is accepted immediately (no lockout);
//   I6  name-scoped: other projects untouched;
//   I7  existing guards stay intact.
//
// Determinism: tunnel boots are held open with a flag-file-gated fake
// cloudflared script instead of sleeps; every wait polls with a bound.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const { ShareManager } = require('../lib/share');
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

// Stub announcer: no Bonjour children, fixed LAN address.
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

// Holds a share's gate teardown: the replacement start must wait inside
// stop() until the test releases it (same seam as revocation.test.js).
function holdGateClose(daemon, name) {
  const gate = daemon.shares.shares.get(name).gate;
  const origClose = gate.close.bind(gate);
  let releaseClose = null;
  gate.close = () => new Promise((resolve) => {
    releaseClose = () => resolve(origClose());
  });
  return { get release() { return releaseClose; } };
}

// ---------------------------------------------------------------------------
// ShareManager level
// ---------------------------------------------------------------------------

test('ShareManager: a targeted stop cancels a pending replacement start', async () => {
  const dir = tmpDir('pn-target-stop-');
  const mgr = new ShareManager({ dir });
  const u = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cf = writeFlagCfScript(dir, 'target-stop', flagFile);

  try {
    // A is held STARTING inside the flag-gated script.
    const startA = mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 60, cloudflaredBin: cf, timeoutMs: 5000,
    }).then(() => null, (err) => err);
    assert.strictEqual(await waitFor(() => mgr.childPids().length === 1), true, 'A must spawn while STARTING');

    // B (different TTL => replacement job) waits on A's startPromise.
    const startB = mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 30, cloudflaredBin: cf, timeoutMs: 5000,
    }).then(() => null, (err) => err);

    // Targeted revocation while B is waiting: the epoch bump happens
    // synchronously inside stop(), before B can resume anywhere.
    const stopP = mgr.stop('app');
    releaseFlag(flagFile);

    const bOutcome = await startB;
    assert.ok(bOutcome instanceof Error, 'the pending replacement start must be cancelled by the targeted stop');
    assert.match(bOutcome.message, /cancelled/i);

    const aOutcome = await startA; // A itself aborts mid-boot (pre-existing behavior)
    assert.ok(aOutcome instanceof Error, 'A must abort when targeted while STARTING');
    await stopP;

    assert.strictEqual(mgr.status().length, 0, 'no share may survive the targeted revoke');
    assert.strictEqual(mgr.childPids().length, 0, 'no tunnel process may survive');
  } finally {
    await mgr.stopAll().catch(() => {});
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('replacement stop binds to the expected instance (concurrent replacements)', async () => {
  const dir = tmpDir('pn-concurrent-repl-');
  const mgr = new ShareManager({ dir });
  const u = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cf = writeFlagCfScript(dir, 'concurrent-repl', flagFile);

  try {
    const startA = mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 60, cloudflaredBin: cf, timeoutMs: 5000,
    }).then(() => null, (err) => err);
    assert.strictEqual(await waitFor(() => mgr.childPids().length === 1), true);

    // B and C both wait on A's startPromise. Promise callbacks run FIFO, so
    // B (accepted first) performs the replacement; C must abort instead of
    // stopping B's newcomer instance.
    const startB = mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 30, cloudflaredBin: cf, timeoutMs: 5000,
    }).then(() => null, (err) => err);
    const startC = mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 45, cloudflaredBin: cf, timeoutMs: 5000,
    }).then(() => null, (err) => err);

    releaseFlag(flagFile); // A activates; B replaces it; C must be cancelled

    const [aOutcome, bOutcome, cOutcome] = await Promise.all([startA, startB, startC]);
    assert.ok(!(aOutcome instanceof Error), 'A must activate normally');
    assert.ok(!(bOutcome instanceof Error), 'the first replacement (B) must complete');
    assert.ok(cOutcome instanceof Error, 'the second replacement (C) must be cancelled');
    assert.match(cOutcome.message, /cancelled/i);

    assert.strictEqual(mgr.status().length, 1, 'exactly one share may survive');
    assert.strictEqual(mgr.status()[0].ttlMinutes, 30, 'B\'s instance must be the survivor');
    assert.strictEqual(mgr.childPids().length, 1, 'B\'s tunnel child must survive');
  } finally {
    await mgr.stopAll().catch(() => {});
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a fresh start after a targeted revoke is accepted immediately', async () => {
  const dir = tmpDir('pn-fresh-after-revoke-');
  const mgr = new ShareManager({ dir });
  const u = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cfFlagged = writeFlagCfScript(dir, 'fresh-after', flagFile);
  const cfPlain = writeCfScript(dir, 'fresh-after-plain');

  try {
    const startA = mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 60, cloudflaredBin: cfFlagged, timeoutMs: 5000,
    }).then(() => null, (err) => err);
    assert.strictEqual(await waitFor(() => mgr.childPids().length === 1), true);

    await mgr.stop('app'); // targeted revoke: bumps the name epoch
    await startA.catch(() => {});

    // No start lockout: the next start for the same name runs normally.
    const result = await mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 60, cloudflaredBin: cfPlain, timeoutMs: 5000,
    });
    assert.ok(String(result).includes('fresh-after-plain'));
    assert.strictEqual(mgr.status().length, 1);
    assert.strictEqual(mgr.status()[0].state, 'ACTIVE');
  } finally {
    await mgr.stopAll().catch(() => {});
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// A stop bound to an expectedShareId must validate the binding BEFORE it
// changes anything: a stale-rejected request (the id no longer owns the
// name) must leave the world untouched — in particular it must not advance
// the name's revocation epoch, which would improperly cancel pending
// replacement jobs of the newer, untouched instance. An unbound revocation
// without a visible share, by contrast, keeps working (epoch bump stands).
test('a stale-rejected stop changes nothing: the pending replacement still starts', async () => {
  const dir = tmpDir('pn-stale-stop-');
  const mgr = new ShareManager({ dir });
  const u = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cfFlagged = writeFlagCfScript(dir, 'stale-stop', flagFile);
  const cfPlain = writeCfScript(dir, 'stale-stop-plain');

  try {
    // A is held STARTING inside the flag-gated script.
    const startA = mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 60, cloudflaredBin: cfFlagged, timeoutMs: 5000,
    }).then(() => null, (err) => err);
    assert.strictEqual(await waitFor(() => mgr.childPids().length === 1), true, 'A must spawn while STARTING');

    // B (different TTL => replacement job) waits on A's startPromise.
    const startB = mgr.start({
      name: 'app', targetPort: u.port, ttlMinutes: 30, cloudflaredBin: cfPlain, timeoutMs: 5000,
    }).then(() => null, (err) => err);

    // Bound to an id that does not own the name: rejected stale, and it must
    // not invalidate B's acceptance snapshot.
    assert.strictEqual(await mgr.stop('app', { expectedShareId: 'not-the-current-id' }), 'stale');

    releaseFlag(flagFile); // A activates; B replaces it with its own arguments

    const bOutcome = await startB;
    assert.ok(!(bOutcome instanceof Error), 'the stale-rejected stop must not cancel the pending replacement');
    assert.strictEqual(mgr.status().length, 1, 'exactly one share may survive');
    assert.strictEqual(mgr.status()[0].ttlMinutes, 30, 'B must be the survivor, started with its own arguments');
    assert.strictEqual(mgr.childPids().length, 1, 'B\'s tunnel child must survive');
    await startA.then(null, () => {});
  } finally {
    await mgr.stopAll().catch(() => {});
    await closeUpstream(u);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('an unbound stop with no visible share still advances the name epoch', async () => {
  const dir = tmpDir('pn-unbound-no-share-');
  const mgr = new ShareManager({ dir });

  try {
    const before = mgr.nameEpochs.get('app') || 0;
    // Unbound revocation of a name with nothing shared: the epoch bump is
    // the invalidation itself and must keep happening (it cancels start jobs
    // accepted earlier and still waiting on a teardown).
    assert.strictEqual(await mgr.stop('app'), false);
    assert.strictEqual(mgr.nameEpochs.get('app') || 0, before + 1, 'unbound revoke without a share still invalidates');

    // A bound stop on a vanished share is not stale-rejected (nothing
    // contradicts the id) and is equally accepted as a revocation.
    assert.strictEqual(await mgr.stop('app', { expectedShareId: 'gone-id' }), false);
    assert.strictEqual(mgr.nameEpochs.get('app') || 0, before + 2, 'bound revoke on a vanished share still invalidates');
  } finally {
    await mgr.stopAll().catch(() => {});
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Daemon level: scan-driven revocation and shutdown must also cancel pending
// replacement jobs (they revoke through ShareManager.stop and stopAll).
// ---------------------------------------------------------------------------

test('Daemon: scan-driven target change cancels a pending replacement start', async () => {
  const dir = tmpDir('pn-scan-target-');
  const u1 = await startUpstream();
  const u2 = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cf = writeFlagCfScript(dir, 'scan-target', flagFile);
  let listeners = [manualListener(5001, u1.port, '5001:m1')];
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });
    // A is held STARTING inside the flag-gated script.
    const startA = daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 60 })
      .then(() => null, (err) => err);
    assert.strictEqual(
      await waitFor(() => daemon.shares.childPids().length === 1), true, 'A must spawn while STARTING'
    );

    // B waits on A's startPromise.
    const startB = daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 30 })
      .then(() => null, (err) => err);

    // Scan-driven repoint: the next pass revokes A ("port changed") through
    // ShareManager.stop — which must cancel the waiting replacement B.
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u2.port });
    releaseFlag(flagFile);

    const bOutcome = await startB;
    assert.ok(bOutcome instanceof Error, 'the pending replacement must be cancelled by the scan-driven revoke');
    assert.match(bOutcome.message, /cancelled/i);
    await startA.catch(() => {});
    assert.strictEqual(daemon.shares.status().length, 0, 'no share may start with the old arguments');
    assert.strictEqual(daemon.shares.childPids().length, 0, 'no tunnel process may survive');
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    await closeUpstream(u2);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon: route removal cancels a pending replacement start', async () => {
  const dir = tmpDir('pn-scan-remove-');
  const u1 = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cf = writeFlagCfScript(dir, 'scan-remove', flagFile);
  let listeners = [manualListener(5002, u1.port, '5002:m1')];
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });
    const startA = daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 60 })
      .then(() => null, (err) => err);
    assert.strictEqual(await waitFor(() => daemon.shares.childPids().length === 1), true);

    const startB = daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 30 })
      .then(() => null, (err) => err);

    await daemon.dispatchControl({ cmd: 'remove', name: 'app' });
    releaseFlag(flagFile);

    const bOutcome = await startB;
    assert.ok(bOutcome instanceof Error, 'the pending replacement must be cancelled by the route removal');
    assert.match(bOutcome.message, /cancelled/i);
    await startA.catch(() => {});
    assert.strictEqual(daemon.shares.status().length, 0);
    assert.strictEqual(daemon.shares.childPids().length, 0);
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon shutdown cancels a pending replacement start', async () => {
  const dir = tmpDir('pn-shutdown-starting-');
  const u1 = await startUpstream();
  const flagFile = path.join(dir, 'tunnel-flag');
  const cf = writeFlagCfScript(dir, 'shutdown-starting', flagFile);
  const listeners = [manualListener(5003, u1.port, '5003:m1')];
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });
    const startA = daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 60 })
      .then(() => null, (err) => err);
    assert.strictEqual(await waitFor(() => daemon.shares.childPids().length === 1), true);

    const startB = daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 30 })
      .then(() => null, (err) => err);

    const stopping = daemon.stop();
    releaseFlag(flagFile);

    const bOutcome = await startB;
    assert.ok(bOutcome instanceof Error, 'the pending replacement must be cancelled by the shutdown');
    assert.match(bOutcome.message, /revocation|cancelled/i);
    await startA.catch(() => {});
    await stopping;
    assert.strictEqual(daemon.shares.status().length, 0, 'no share may survive the shutdown');
    assert.strictEqual(daemon.shares.childPids().length, 0, 'no tunnel process may survive the shutdown');
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('revoke while replacement waits in its own stop (ACTIVE branch) cancels the replacement', async () => {
  const dir = tmpDir('pn-active-revoke-');
  const u1 = await startUpstream();
  const cf = writeCfScript(dir, 'active-revoke');
  const listeners = [manualListener(5004, u1.port, '5004:m1')];
  const daemon = new Daemon({
    dir,
    announcer: stubAnnouncer(),
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'app', port: u1.port });
    await daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 60 }); // A ACTIVE

    // B (changed descriptor) is held inside A's gate.close teardown seam.
    const hold = holdGateClose(daemon, 'app');
    const startB = daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 30 })
      .then(() => null, (err) => err);
    assert.strictEqual(
      await waitFor(() => daemon.shares.status()[0] && daemon.shares.status()[0].state === 'STOPPING'),
      true, 'B must be waiting inside A\'s teardown'
    );

    // Targeted unshare while B waits in its own replacement stop: the
    // unshare's stop() entry bumps the name epoch and must cancel B.
    const unshareP = daemon.dispatchControl({ cmd: 'unshare', name: 'app' });
    hold.release();

    const bOutcome = await startB;
    await unshareP.catch(() => {});
    assert.ok(bOutcome instanceof Error, 'the replacement waiting in its own stop must be cancelled by the unshare');
    assert.match(bOutcome.message, /cancelled/i);
    assert.strictEqual(daemon.shares.status().length, 0);
    assert.strictEqual(daemon.shares.childPids().length, 0);
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    await closeUpstream(u1);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
