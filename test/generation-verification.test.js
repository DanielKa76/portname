'use strict';

// A pass that verifies a public share must have read the process generation
// of its target in that very pass. Before, a start time was cached for 60 s
// and a failed re-read kept the last known identity, so a process that took
// over the same pid and port between two passes inherited the old share, and
// a broken `ps` renewed shares indefinitely. These tests drive the daemon
// with real start-time lookups replaced by an injected one; listeners carry
// no processKey, so the daemon's own enrichment resolves it.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { Daemon } = require('../lib/daemon');

function tmpDir(prefix) {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
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

// A live pid (this test process), so the daemon's alive probe says "alive".
function shopListener(shopDir) {
  return { pid: process.pid, port: 4855, command: 'node', cwd: shopDir, root: shopDir, external: false };
}

async function sharedShop(t, { prefix }) {
  const dir = tmpDir(prefix);
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const state = { generation: 'T1', lookups: 0 };
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: writeCfScript(dir, prefix.replace(/\W/g, '')) },
    // Passes run only when a test calls refresh(): no background pass may
    // verify or fail in between.
    refreshMs: 60_000,
    listListeners: () => [shopListener(shopDir)],
    getStartTime: async () => {
      state.lookups += 1;
      return state.generation;
    },
  });
  t.after(async () => {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  await daemon.start();
  daemon.announcer.lanAddress = () => null;
  await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
  assert.strictEqual(daemon.shares.isShared('shop'), true);
  return { daemon, state };
}

test('daemon: a new process on the same pid and port revokes the share in the very next pass', async (t) => {
  const { daemon, state } = await sharedShop(t, { prefix: 'pn-gen-share-' });
  const lookupsBefore = state.lookups;

  state.generation = 'T2'; // the old process died; a new one took its pid and port
  await daemon.refresh();

  assert.ok(state.lookups > lookupsBefore, 'the pass read the start time again');
  assert.strictEqual(daemon.shares.isShared('shop'), false, 'the share bound to the old generation is revoked');
});

test('daemon: start times that cannot be read degrade the pass and never renew a share', async (t) => {
  const { daemon, state } = await sharedShop(t, { prefix: 'pn-gen-fail-' });
  // A good pass right before the failures, then a short grace: the share
  // start itself (fake tunnel boot) needed the default one.
  await daemon.refresh();
  daemon.shareVerifyGraceMs = 2000;
  const verifiedBefore = daemon.shares.shares.get('shop').lastVerifiedAt;
  const goodScanBefore = daemon.lastGoodScanAt;

  state.generation = null; // ps keeps failing for this live pid
  await daemon.refresh();

  assert.match(String(daemon.lastScanError), /start time lookup failed/);
  assert.strictEqual(daemon.lastGoodScanAt, goodScanBefore, 'a pass without verified generations is no good scan');
  assert.strictEqual(daemon.shares.shares.get('shop').lastVerifiedAt, verifiedBefore, 'the share is not renewed');
  assert.strictEqual(daemon.shares.isShared('shop'), true, 'one failed pass stays within the grace window');

  await new Promise((r) => setTimeout(r, 2200));
  await daemon.refresh();
  assert.strictEqual(daemon.shares.isShared('shop'), false, 'sustained failures past the grace window revoke the share');
});

test('daemon: by default one batched start-time lookup per pass covers every pid', async (t) => {
  const dir = tmpDir('pn-gen-batch-');
  const pids = [41001, 41002, 41003, 41004, 41005, 41006];
  const calls = [];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    refreshMs: 60_000,
    listListeners: () => pids.map((pid, i) => ({ pid, port: 42000 + i, command: 'node', cwd: dir, root: dir, external: false })),
    getStartTimes: async (wanted) => {
      calls.push([...wanted].sort());
      return new Map(wanted.map((pid) => [pid, 'T1']));
    },
  });
  t.after(async () => {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  await daemon.start();
  daemon.announcer.lanAddress = () => null;
  await daemon.refresh();

  assert.strictEqual(calls.length, 2, 'one lookup for the start pass, one for the next pass');
  for (const call of calls) assert.deepStrictEqual(call, pids, 'every pid of the pass in that one lookup');
});
