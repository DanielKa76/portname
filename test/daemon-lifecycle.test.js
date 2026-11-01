'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const { Daemon } = require('../lib/daemon');
const { ShareManager } = require('../lib/share');
const { BonjourAnnouncer } = require('../lib/expose');
const { acquireInstanceLock } = require('../lib/instance-lock');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Executable mock cloudflared that prints its URL immediately and stays alive.
function writeCfScript(dir, name, host) {
  const script = path.join(dir, name);
  fs.writeFileSync(
    script,
    `#!/usr/bin/env node\nconsole.log("https://${host}.trycloudflare.com");\nsetInterval(() => {}, 1000);\n`
  );
  fs.chmodSync(script, 0o755);
  return script;
}

// Mock cloudflared that stays alive but ignores SIGTERM (forces the bounded
// force-kill path, which widens the STOPPING window deterministically).
function writeCfHangScript(dir, name, host) {
  const script = path.join(dir, name);
  fs.writeFileSync(
    script,
    `#!/usr/bin/env node\nconsole.log("https://${host}.trycloudflare.com");\nprocess.on("SIGTERM", () => {});\nsetInterval(() => {}, 1000);\n`
  );
  fs.chmodSync(script, 0o755);
  return script;
}

// Mock cloudflared that never prints a URL (share stays STARTING until timeout).
function writeCfSilentScript(dir, name) {
  const script = path.join(dir, name);
  fs.writeFileSync(script, '#!/usr/bin/env node\nsetInterval(() => {}, 1000);\n');
  fs.chmodSync(script, 0o755);
  return script;
}

function controlRequest(dir, msg, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const sockFile = path.join(dir, 'daemon.sock');
    const socket = net.connect(sockFile);
    let buf = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('control request timeout'));
    }, timeoutMs);
    socket.on('connect', () => socket.write(JSON.stringify(msg) + '\n'));
    socket.on('data', (d) => {
      buf += d.toString();
      if (buf.endsWith('\n')) {
        clearTimeout(timer);
        socket.end();
        resolve(JSON.parse(buf));
      }
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function isPidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

const SHOP_LISTENER = (dir) => ({
  pid: 42001,
  port: 4222,
  processKey: '42001:startShop',
  command: 'node',
  cwd: path.join(dir, 'shop'),
  root: path.join(dir, 'shop'),
  external: false,
  suggestedName: 'shop',
});

test('refresh barrier: two concurrent refresh callers each resolve after their own observed pass', async () => {
  const dir = tmpDir('pn-lc-refresh2-');
  const events = [];
  let holdScans = false;
  const heldResolvers = [];
  let scanCount = 0;

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async ({ excludePids }) => {
      scanCount += 1;
      events.push(`scan-start-${scanCount}`);
      if (holdScans) {
        await new Promise((resolve) => heldResolvers.push(resolve));
      }
      return [];
    },
  });

  try {
    await daemon.start();
    // The initial start() pass already consumed one scan; measure from here.
    scanCount = 0;
    events.length = 0;

    // Pass 1 starts and blocks inside the scan.
    holdScans = true;
    const p1 = daemon.refresh();
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(scanCount, 1, 'pass 1 scan must be in flight');

    // A mutation arrives while pass 1 is in flight, then a second refresh caller.
    daemon.registry.addManual('app', 4711);
    const p2 = daemon.refresh();

    // p2 must not settle before a follow-up pass that observed the mutation.
    let p2Settled = false;
    p2.then(() => { p2Settled = true; }, () => { p2Settled = true; });
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(p2Settled, false, 'refresh must not resolve before a pass started after the caller');

    // Release pass 1; the serialized follow-up pass must run after it.
    p1.then(() => events.push('p1-resolved'));
    holdScans = false;
    for (const resolve of heldResolvers.splice(0)) resolve();
    await p1;
    await p2;

    assert.strictEqual(scanCount, 2, 'exactly one follow-up pass must have run');
    assert.ok(
      events.indexOf('p1-resolved') !== -1 &&
        events.indexOf('p1-resolved') < events.lastIndexOf('scan-start-2'),
      'follow-up pass must start only after pass 1 finished'
    );
    assert.strictEqual(daemon.routesByName.get('app').port, 4711,
      'the awaited pass must reflect the mutation that happened before the refresh call');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('refresh barrier: mutation confirmed during an in-flight scan waits for its derived route', async () => {
  const dir = tmpDir('pn-lc-mutation-');
  let holdScans = false;
  const heldResolvers = [];

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      if (holdScans) {
        await new Promise((resolve) => heldResolvers.push(resolve));
      }
      return [];
    },
  });

  try {
    await daemon.start();

    holdScans = true;
    const scanPass = daemon.refresh();
    await new Promise((r) => setTimeout(r, 30));

    // The mutation handler awaits refresh(); with the premature coalescing bug
    // it would resolve even though no pass observed the new entry yet.
    const mutation = daemon.dispatchControl({ cmd: 'add', name: 'api', port: 5151 });
    let mutationSettled = false;
    mutation.then(() => { mutationSettled = true; }, () => { mutationSettled = true; });
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(mutationSettled, false,
      'mutation must not be confirmed before a pass observed it');

    holdScans = false;
    for (const resolve of heldResolvers.splice(0)) resolve();
    await scanPass;
    await mutation;

    assert.strictEqual(daemon.routesByName.get('api').port, 5151,
      'confirmed mutation must see its derived route');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('refresh barrier: a rejected pass still drains the follow-up slot', async (t) => {
  const dir = tmpDir('pn-lc-reject-');
  let holdScans = false;
  const heldResolvers = [];
  let scanCount = 0;
  let syncCalls = 0;
  // The pass whose sync() call is number syncFailOnCall rejects: call 1 is
  // the start pass, call 2 the doomed pass, call 3 the healed follow-up.
  let syncFailOnCall = 0;

  // Injected announcer whose sync() fails on exactly one numbered call —
  // the throw happens inside #runRefreshPass and rejects the whole pass.
  const announcer = {
    cleanupOrphans() {},
    childPids() { return []; },
    lanAddress() { return null; },
    stopAll() {},
    sync() {
      syncCalls += 1;
      if (syncCalls === syncFailOnCall) throw new Error('announcer sync exploded');
      return { ok: true };
    },
  };

  const daemon = new Daemon({
    dir,
    announcer,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      scanCount += 1;
      if (holdScans) await new Promise((resolve) => heldResolvers.push(resolve));
      return [];
    },
  });

  try {
    await daemon.start();
    scanCount = 0;

    // Pass 1 runs into a failing announcer.sync and holds inside the scan
    // until released, so it is deterministically still in flight below.
    syncFailOnCall = 2;
    holdScans = true;
    const failing = daemon.refresh();
    failing.catch(() => {});
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(scanCount, 1, 'failing pass must be in flight');

    // A mutation arrives while the doomed pass runs; its caller must be
    // served by a follow-up pass, not by the old pass's rejection.
    daemon.registry.addManual('app', 4711);
    const p2 = daemon.refresh();
    let p2Settled = false;
    p2.then(() => { p2Settled = true; }, () => { p2Settled = true; });
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(p2Settled, false, 'follow-up caller must wait for a pass of its own');

    // Release the doomed pass: it rejects at announcer.sync, and the
    // follow-up (sync call 3, healthy) must still run and confirm the
    // mutation with its own outcome.
    holdScans = false;
    for (const resolve of heldResolvers.splice(0)) resolve();
    await t.assert.rejects(() => failing, /announcer sync exploded/,
      'the rejected pass must report its own failure');
    await p2;

    assert.strictEqual(scanCount, 2, 'the follow-up pass must have run after the rejection');
    assert.strictEqual(syncCalls, 3,
      'follow-up pass must have synced with the healed announcer');
    assert.strictEqual(daemon.routesByName.get('app').port, 4711,
      'the follow-up pass must observe the mutation made during the rejected pass');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lifecycle: stop during an in-flight scan publishes nothing and is idempotent', async (t) => {
  const dir = tmpDir('pn-lc-stop-scan-');
  writeCfHangScript(dir, 'cf-ignore.js', 'stop-scan-hang');

  let scanMode = 'shop'; // 'shop' -> deliver listener; 'held-empty' -> block, then deliver []
  const heldResolvers = [];
  let syncCalls = 0;

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      if (scanMode === 'held-empty') {
        await new Promise((resolve) => heldResolvers.push(resolve));
        return [];
      }
      return [SHOP_LISTENER(dir)];
    },
  });

  try {
    await daemon.start();
    assert.strictEqual(daemon.state, 'RUNNING', 'daemon must report RUNNING after start');
    assert.strictEqual(daemon.routesByName.has('shop'), true, 'route published by the start pass');
    daemon.announcer.sync = () => { syncCalls += 1; return { ok: true }; };

    // The scan started now would observe "shop stopped" (empty listener list)
    // — if it were ever allowed to publish.
    scanMode = 'held-empty';
    const scanPass = daemon.refresh();
    await new Promise((r) => setTimeout(r, 30));

    // Active share with a SIGTERM-ignoring child keeps stop() in STOPPING long
    // enough to observe the window deterministically.
    await daemon.shares.start({
      name: 'shop',
      targetPort: 4222,
      pinnedPid: 42001,
      pinnedProcessKey: '42001:startShop',
      ttlMinutes: 60,
      cloudflaredBin: path.join(dir, 'cf-ignore.js'),
      timeoutMs: 5000,
    });
    assert.strictEqual(daemon.shares.isShared('shop'), true);

    const stopPromise = daemon.stop();
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(daemon.state, 'STOPPING', 'state must be STOPPING while resources tear down');

    // Idempotent stop: a second call joins the same teardown.
    const secondStop = daemon.stop();

    // Mutations that publish must be refused while stopping...
    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'add', name: 'nope', port: 1234 }),
      (err) => err.code === 'DAEMON_STOPPING',
      'mutations must be refused with DAEMON_STOPPING while stopping'
    );
    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 }),
      (err) => err.code === 'DAEMON_STOPPING',
      'share activations must be refused with DAEMON_STOPPING while stopping'
    );
    // ...read-only status still answers.
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.state, 'STOPPING', 'status must report the STOPPING state');

    // Commands on the during-stop allow list must pass the lifecycle gate:
    // they may fail with their own domain error, but never with DAEMON_STOPPING.
    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share-link', name: 'nope' }),
      (err) => err.code === 'INVALID_REQUEST',
      'share-link must pass the state gate while stopping'
    );
    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'unshare', name: 'nope' }),
      (err) => !err.code && /no active share/.test(err.message),
      'unshare must pass the state gate while stopping'
    );

    // The held scan (observing an empty listener list) may not publish
    // anything anymore: routes must keep their pre-stop snapshot.
    const syncCallsAtRelease = syncCalls;
    for (const resolve of heldResolvers.splice(0)) resolve();
    await scanPass;
    await stopPromise;
    await secondStop;

    assert.strictEqual(daemon.state, 'STOPPED', 'state must be STOPPED after stop()');
    assert.strictEqual(syncCalls, syncCallsAtRelease,
      'a scan that outlives stop() must not publish Bonjour registrations');
    assert.strictEqual(daemon.shares.isShared('shop'), false, 'stop must tear down shares');
    assert.strictEqual(daemon.routesByName.has('shop'), true,
      'a post-stop scan must not publish routes (the "shop stopped" observation is discarded)');

    // A third stop call is a no-op.
    await daemon.stop();
    assert.strictEqual(daemon.state, 'STOPPED');

    // Publishing mutations stay refused also in the terminal STOPPED state.
    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'add', name: 'late', port: 1234 }),
      (err) => err.code === 'DAEMON_STOPPING',
      'mutations must be refused with DAEMON_STOPPING also when stopped'
    );
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lifecycle: a failing resource teardown still releases lock and socket', async (t) => {
  const dir = tmpDir('pn-lc-teardown-');
  const logs = [];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0 },
    listListeners: async () => [],
    log: (...args) => logs.push(args.join(' ')),
  });

  try {
    await daemon.start();
    // Resource teardown explodes: stop() must still close the control
    // socket, unlink it and release the instance lock.
    daemon.shares.stopAll = async () => { throw new Error('shares stopAll exploded'); };
    await daemon.stop();

    assert.strictEqual(daemon.state, 'STOPPED', 'stop() must reach STOPPED despite teardown failure');
    assert.ok(logs.some((l) => l.includes('teardown-error')), 'the teardown failure must be logged');
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.lock')), false,
      'lock must be released despite a failing resource teardown');
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.sock')), false,
      'control socket must be unlinked despite a failing resource teardown');

    // The released lock must allow a restart against the same state dir.
    const daemon2 = new Daemon({
      dir,
      config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
      listListeners: async () => [],
    });
    await daemon2.start();
    assert.strictEqual(daemon2.state, 'RUNNING', 'restart must not hit DAEMON_ALREADY_RUNNING');
    await daemon2.stop();
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lifecycle: stop during STARTING aborts startup defined and releases the lock', async (t) => {
  const dir = tmpDir('pn-lc-stop-starting-');
  let releaseScans = false;
  const heldResolvers = [];

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      if (!releaseScans) await new Promise((resolve) => heldResolvers.push(resolve));
      return [];
    },
  });

  try {
    const startPromise = daemon.start();
    startPromise.catch(() => {});
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(daemon.state, 'STARTING', 'held first scan keeps the daemon STARTING');

    // stop() while the initial scan is in flight must complete in bounded
    // time and release the lock, even though start() has not finished.
    await daemon.stop();
    assert.strictEqual(daemon.state, 'STOPPED');
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.lock')), false,
      'stop during STARTING must release the lock');

    releaseScans = true;
    for (const resolve of heldResolvers.splice(0)) resolve();
    await t.assert.rejects(() => startPromise, /stopped during startup/,
      'start() must fail defined when stopped during startup');

    // A fresh daemon can take over the same dir afterwards.
    const daemon2 = new Daemon({
      dir,
      config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
      listListeners: async () => [],
    });
    await daemon2.start();
    assert.strictEqual(daemon2.state, 'RUNNING');
    await daemon2.stop();
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('lifecycle: start during running, stop during tunnel start, and restart after stop', async (t) => {
  const dir = tmpDir('pn-lc-startstop-');
  const silentScript = writeCfSilentScript(dir, 'cf-silent.js');
  const cfScript = writeCfScript(dir, 'cf-ok.js', 'startstop');

  let listenersServed = false;
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      listenersServed = true;
      return [];
    },
  });

  try {
    await daemon.start();

    await t.assert.rejects(
      () => daemon.start(),
      /already running/,
      'a second start() on the same instance must fail with a defined error'
    );

    // Tunnel start in flight when the daemon stops: the share must be aborted
    // atomically and stop() must complete in bounded time.
    const startPromise = daemon.shares.start({
      name: 'app',
      targetPort: 5151,
      ttlMinutes: 60,
      cloudflaredBin: silentScript,
      timeoutMs: 30000,
    });
    await new Promise((r) => setTimeout(r, 80));
    assert.strictEqual(daemon.shares.isShared('app'), true, 'share must be STARTING');
    const childPid = daemon.shares.childPids()[0];
    assert.ok(childPid, 'tunnel child must exist during STARTING');

    await daemon.stop();

    await t.assert.rejects(() => startPromise, /aborted|stopped/,
      'share start must reject when the daemon stops during tunnel startup');
    assert.strictEqual(daemon.shares.isShared('app'), false);
    assert.strictEqual(isPidAlive(childPid), false, 'tunnel child must not survive daemon stop');
    assert.strictEqual(daemon.state, 'STOPPED');

    // Restart in the same state dir must re-acquire the instance lock.
    listenersServed = false;
    const daemon2 = new Daemon({
      dir,
      config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
      listListeners: async () => {
        listenersServed = true;
        return [];
      },
    });
    await daemon2.start();
    assert.strictEqual(daemon2.state, 'RUNNING', 'restart after stop must reach RUNNING');
    assert.strictEqual(listenersServed, true);
    await daemon2.stop();
    void cfScript;
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('share instance barrier: stale child-exit callback must not stop a newer share with the same name', async () => {
  const dir = tmpDir('pn-lc-stale-cb-');
  const cfScript = writeCfScript(dir, 'cf-stay.js', 'stale-cb');

  // Manager-level invariant, isolated from the daemon on purpose: a real
  // daemon's periodic refresh correctly revokes a share that has no route
  // (the scan is empty here), which made this test load-dependent — the
  // newer share could be revoked by a healthy refresh before the assertion.
  // The stale-callback barrier itself lives in the ShareManager.
  const shares = new ShareManager({ dir });

  try {
    // Generation A
    await shares.start({
      name: 'app',
      targetPort: 5151,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      // Generous: the fake tunnel is a node script, slow to start under load.
      timeoutMs: 20000,
    });
    const oldChild = shares.shares.get('app').cloudflared;

    // Replace with generation B under the same name.
    await shares.stop('app');
    await shares.start({
      name: 'app',
      targetPort: 5151,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 20000,
    });
    const newChild = shares.shares.get('app').cloudflared;
    assert.notStrictEqual(newChild.pid, oldChild.pid, 'a fresh tunnel child must be running');

    // Late delivery of generation A's exit event must be ignored: it belongs
    // to a share instance that no longer owns the name.
    oldChild.emit('exit', 1, 'SIGTERM');
    await new Promise((r) => setTimeout(r, 100));

    assert.strictEqual(shares.isShared('app'), true,
      'the newer share instance must survive a stale child-exit callback');
    assert.strictEqual(shares.shares.get('app').cloudflared.pid, newChild.pid,
      'the newer tunnel child must be untouched');
  } finally {
    await shares.stopAll();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('instance lock: second daemon on the same state dir fails defined and leaves the first untouched', async (t) => {
  const dir = tmpDir('pn-lc-lock-same-');
  const cfScript = writeCfScript(dir, 'cf-lock.js', 'lock-same');

  const daemon1 = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0 },
    listListeners: async () => [SHOP_LISTENER(dir)],
  });

  try {
    await daemon1.start();
    // Start the share through the manager with a MOCK tunnel binary: a share
    // started via dispatchControl would use the real cloudflared binary.
    await daemon1.shares.start({
      name: 'shop',
      targetPort: 4222,
      pinnedPid: 42001,
      pinnedProcessKey: '42001:startShop',
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });
    assert.strictEqual(daemon1.shares.isShared('shop'), true);
    const childPid = daemon1.shares.childPids()[0];

    // Second daemon on the SAME dir: must fail with a defined error, before
    // touching socket, orphans or anything else.
    const daemon2 = new Daemon({
      dir,
      config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
      listListeners: async () => [],
    });
    await t.assert.rejects(
      () => daemon2.start(),
      (err) => err.code === 'DAEMON_ALREADY_RUNNING' && /already managing/.test(err.message),
      'second daemon must fail with DAEMON_ALREADY_RUNNING'
    );
    assert.strictEqual(daemon2.state, 'STOPPED');

    // First instance is fully intact: real control socket answers, share and
    // its tunnel child are untouched (not treated as orphans).
    const res = await controlRequest(dir, { cmd: 'status' });
    assert.strictEqual(res.ok, true, 'first daemon control socket must still answer');
    assert.strictEqual(res.daemonInstanceId, daemon1.daemonInstanceId,
      'the socket must still belong to the first daemon instance');
    assert.strictEqual(res.state, 'RUNNING', 'status must report the RUNNING state');
    assert.strictEqual(daemon1.shares.isShared('shop'), true, 'first daemon share must survive');
    assert.strictEqual(isPidAlive(childPid), true, 'first daemon tunnel child must not be killed');
  } finally {
    await daemon1.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('instance lock: two daemons with separate state dirs run independently', async () => {
  const dirA = tmpDir('pn-lc-lock-a-');
  const dirB = tmpDir('pn-lc-lock-b-');
  const make = (dir) => new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0 },
    listListeners: async () => [],
  });
  const a = make(dirA);
  const b = make(dirB);

  try {
    await a.start();
    await b.start();
    assert.strictEqual(a.state, 'RUNNING');
    assert.strictEqual(b.state, 'RUNNING');
    assert.notStrictEqual(a.daemonInstanceId, b.daemonInstanceId);

    const resA = await controlRequest(dirA, { cmd: 'status' });
    const resB = await controlRequest(dirB, { cmd: 'status' });
    assert.strictEqual(resA.ok, true);
    assert.strictEqual(resB.ok, true);
    assert.strictEqual(resA.daemonInstanceId, a.daemonInstanceId);
    assert.strictEqual(resB.daemonInstanceId, b.daemonInstanceId);
  } finally {
    await a.stop();
    await b.stop();
    fs.rmSync(dirA, { recursive: true, force: true });
    fs.rmSync(dirB, { recursive: true, force: true });
  }
});

test('instance lock: stale lock from a crashed daemon is stolen via process identity', async () => {
  const dir = tmpDir('pn-lc-lock-stale-');

  // Produce a definitely dead PID for the stale lock entry.
  const dead = spawn(process.execPath, ['-e', 'process.exit(0)']);
  await new Promise((resolve) => dead.once('exit', resolve));

  fs.writeFileSync(
    path.join(dir, 'daemon.lock'),
    JSON.stringify({ pid: dead.pid, startTime: 'Mon Jan  1 00:00:00 2024', instanceId: 'dead-instance' })
  );

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => [],
  });

  try {
    await daemon.start();
    assert.strictEqual(daemon.state, 'RUNNING', 'a dead owner must allow lock takeover');
    const lock = JSON.parse(fs.readFileSync(path.join(dir, 'daemon.lock'), 'utf8'));
    assert.strictEqual(lock.instanceId, daemon.daemonInstanceId, 'lock must name the new instance');
    await daemon.stop();
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.lock')), false,
      'stop must release the lock');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('instance lock: live PID with mismatched start time (PID reuse) is treated as stale', async () => {
  const dir = tmpDir('pn-lc-lock-reuse-');

  // Live PID (this test process) but a start time that cannot match.
  fs.writeFileSync(
    path.join(dir, 'daemon.lock'),
    JSON.stringify({ pid: process.pid, startTime: 'definitely-not-the-real-start-time', instanceId: 'ghost' })
  );

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => [],
  });

  try {
    await daemon.start();
    assert.strictEqual(daemon.state, 'RUNNING', 'PID reuse must not block a fresh daemon forever');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('instance lock: transient ps failure must not steal the lock from a live owner', async () => {
  const dir = tmpDir('pn-lc-lock-psfail-');
  const lockFile = path.join(dir, 'daemon.lock');

  try {
    // Live owner (this test process), but getProcessInfo fails transiently:
    // the signal-0 probe must veto the wrongful "dead" verdict.
    fs.writeFileSync(lockFile, JSON.stringify({
      pid: process.pid, startTime: 'Mon Jan  1 00:00:00 2024', instanceId: 'live-owner',
    }));
    await assert.rejects(
      () => acquireInstanceLock({ dir, instanceId: 'new', getProcessInfo: () => null }),
      (err) => err.code === 'DAEMON_ALREADY_RUNNING',
      'a live owner must not be stolen just because ps failed'
    );
    assert.strictEqual(JSON.parse(fs.readFileSync(lockFile, 'utf8')).instanceId, 'live-owner',
      'the live owner claim must stay untouched');

    // Degraded claim (owner recorded a null start time because its own
    // start-time lookup failed while acquiring): the probe must protect it.
    fs.writeFileSync(lockFile, JSON.stringify({
      pid: process.pid, startTime: null, instanceId: 'live-owner-degraded',
    }));
    await assert.rejects(
      () => acquireInstanceLock({ dir, instanceId: 'new', getProcessInfo: () => null }),
      (err) => err.code === 'DAEMON_ALREADY_RUNNING',
      'a degraded but live claim must not be stolen either'
    );

    // The probe must not block crash recovery: a verifiably dead PID is
    // still stolen even while ps is failing.
    const dead = spawn(process.execPath, ['-e', 'process.exit(0)']);
    await new Promise((resolve) => dead.once('exit', resolve));
    fs.writeFileSync(lockFile, JSON.stringify({
      pid: dead.pid, startTime: 'Mon Jan  1 00:00:00 2024', instanceId: 'dead-owner',
    }));
    const lock = await acquireInstanceLock({ dir, instanceId: 'new', getProcessInfo: () => null });
    assert.strictEqual(lock.instanceId, 'new', 'a dead owner must be stealable despite ps failure');
    lock.release();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('BonjourAnnouncer: dns-sd spawn failure is handled defined instead of crashing the daemon', async () => {
  const dir = tmpDir('pn-lc-bonjour-spawn-');
  let spawnCalls = 0;
  const { EventEmitter } = require('events');

  // Deterministic fake dns-sd spawn that reports the async ENOENT-like
  // failure exactly like Node does for a missing binary.
  const failingSpawn = (cmd, args, opts) => {
    assert.strictEqual(cmd, 'dns-sd');
    spawnCalls += 1;
    const child = new EventEmitter();
    child.pid = 70000 + spawnCalls;
    child.kill = () => true;
    process.nextTick(() => child.emit('error', new Error('spawn dns-sd ENOENT')));
    return child;
  };

  const logs = [];
  const announcer = new BonjourAnnouncer({
    port: 80,
    dir,
    log: (...args) => logs.push(args.join(' ')),
    spawnFn: failingSpawn,
  });

  try {
    announcer.lanAddress = () => '192.168.1.50';
    const res = announcer.sync(['app']);
    assert.strictEqual(res.ok, true, 'sync must not throw on spawn failure');

    // Let the async spawn error surface.
    await new Promise((r) => setTimeout(r, 30));

    assert.ok(logs.some((l) => l.includes('spawn-error')), 'spawn failure must be logged, not thrown');
    assert.strictEqual(announcer.children.size, 0, 'failed registration must not stay tracked');

    // The retry loop must back off instead of spawning every sync tick.
    announcer.sync(['app']);
    await new Promise((r) => setTimeout(r, 30));
    assert.strictEqual(spawnCalls, 1, 'a failing spawn must not be retried immediately');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Control socket ownership: a daemon only ever removes the socket it bound.
// ---------------------------------------------------------------------------

// A daemon that serves the state dir's socket without holding the instance
// lock (an older version, or a lock file removed by hand).
function foreignSocketServer(sockFile) {
  return new Promise((resolve, reject) => {
    const server = net.createServer((s) => {
      s.on('error', () => {}); // probes hang up right away
      s.end('{"ok":true,"foreign":true}\n');
    });
    server.once('error', reject);
    server.listen(sockFile, () => resolve(server));
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

function socketAnswers(sockFile) {
  return new Promise((resolve) => {
    const s = net.connect(sockFile);
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => resolve(false));
  });
}

test('control socket: a live daemon without the lock keeps its socket; the new start fails defined', async () => {
  const dir = tmpDir('pn-lc-sock-live-');
  const sockFile = path.join(dir, 'daemon.sock');
  const foreign = await foreignSocketServer(sockFile);
  // Orphan cleanup would SIGTERM the live daemon's recorded tunnel and
  // Bonjour children (same start time and command): it must never run.
  const cleanups = [];
  const announcer = {
    cleanupOrphans() { cleanups.push('bonjour'); },
    childPids() { return []; },
    lanAddress() { return null; },
    stopAll() {},
    sync() { return { ok: true }; },
  };
  const daemon = new Daemon({
    dir,
    announcer,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0 },
    listListeners: async () => [],
  });
  daemon.shares.cleanupOrphans = () => cleanups.push('tunnels');
  try {
    await assert.rejects(() => daemon.start(), (err) => err.code === 'DAEMON_ALREADY_RUNNING');
    assert.strictEqual(daemon.state, 'STOPPED');
    assert.deepStrictEqual(cleanups, [], 'no orphan cleanup against the live daemon\'s children');
    assert.strictEqual(daemon.gateway, null, 'the gateway port is never bound');
    assert.strictEqual(daemon.registry, null, 'the live daemon\'s registry is never loaded or saved');
    assert.strictEqual(await socketAnswers(sockFile), true, 'the serving daemon keeps its socket');
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.lock')), false, 'no lock is left behind');
  } finally {
    await daemon.stop();
    await closeServer(foreign);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('control socket: a start that fails before binding never removes the socket at the path', async () => {
  const dir = tmpDir('pn-lc-sock-early-');
  const sockFile = path.join(dir, 'daemon.sock');
  // A socket file nobody serves (a live one fails the start before this
  // point): bound, hard-linked, then closed.
  const crashed = await foreignSocketServer(path.join(dir, 'crashed.sock'));
  fs.linkSync(path.join(dir, 'crashed.sock'), sockFile);
  await closeServer(crashed);
  // Damaged by a hand edit: the start fails after the lock, before the socket.
  fs.writeFileSync(path.join(dir, 'config.json'), '{ "bind": ');
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0 },
    listListeners: async () => [],
  });
  try {
    await assert.rejects(() => daemon.start(), (err) => err.name === 'ConfigError');
    assert.strictEqual(fs.lstatSync(sockFile).isSocket(), true, 'a socket this instance never bound is never removed');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('control socket: stop removes only the socket this instance published', async () => {
  const dir = tmpDir('pn-lc-sock-replaced-');
  const sockFile = path.join(dir, 'daemon.sock');
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0 },
    listListeners: async () => [],
  });
  let foreign = null;
  try {
    await daemon.start();
    assert.strictEqual((await controlRequest(dir, { cmd: 'status' })).daemonInstanceId, daemon.daemonInstanceId);
    assert.strictEqual(fs.statSync(sockFile).mode & 0o777, 0o600);
    assert.deepStrictEqual(fs.readdirSync(dir).filter((n) => n.startsWith('.ctl-')), [], 'only the published name remains');

    // Someone else takes the path over while this daemon runs.
    fs.unlinkSync(sockFile);
    foreign = await foreignSocketServer(sockFile);
    await daemon.stop();
    assert.strictEqual(await socketAnswers(sockFile), true, 'the other socket survives this daemon\'s stop');
    await closeServer(foreign);
    foreign = null;

    // The regular case: a daemon removes its own socket on stop.
    const again = new Daemon({ dir, config: { bind: 'wildcard', port: 0, fallbackPort: 0 }, listListeners: async () => [] });
    await again.start();
    assert.strictEqual(fs.existsSync(sockFile), true);
    await again.stop();
    assert.strictEqual(fs.existsSync(sockFile), false);
    assert.deepStrictEqual(fs.readdirSync(dir).filter((n) => n.startsWith('.ctl-')), []);
  } finally {
    await daemon.stop();
    if (foreign) await closeServer(foreign);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('control socket: a stale socket file of a crashed daemon is replaced', async () => {
  const dir = tmpDir('pn-lc-sock-stale-');
  const sockFile = path.join(dir, 'daemon.sock');
  // A socket inode nobody serves any more: bound, hard-linked, then closed.
  const crashed = await foreignSocketServer(path.join(dir, 'crashed.sock'));
  fs.linkSync(path.join(dir, 'crashed.sock'), sockFile);
  await closeServer(crashed);
  assert.strictEqual(fs.lstatSync(sockFile).isSocket(), true);
  assert.strictEqual(await socketAnswers(sockFile), false, 'precondition: nobody serves it');
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0 },
    listListeners: async () => [],
  });
  try {
    await daemon.start();
    assert.strictEqual((await controlRequest(dir, { cmd: 'status' })).daemonInstanceId, daemon.daemonInstanceId);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('inspector verdicts survive passes with many live listeners (no cache flush, no probe wave)', async () => {
  const dir = tmpDir('pn-lc-inspector-cache-');
  const root = path.join(dir, 'big');
  fs.mkdirSync(root);
  const listeners = Array.from({ length: 210 }, (_, i) => ({
    pid: 61000 + i,
    port: 41000 + i,
    processKey: `${61000 + i}:k`,
    command: 'node',
    cwd: root,
    root,
    external: false,
    suggestedName: 'big',
  }));
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => listeners.map((l) => ({ ...l })),
  });
  // Sticky verdicts from earlier passes: nothing needs probing again.
  for (const l of listeners) daemon.inspectorCache.set(`${l.processKey}:${l.port}`, { value: false, at: Date.now(), sticky: true });
  try {
    await daemon.start();
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, null);
    assert.strictEqual(daemon.inspectorCache.size, 210, 'every live verdict is kept');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
