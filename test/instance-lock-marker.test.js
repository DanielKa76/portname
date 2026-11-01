'use strict';

// Removing a takeover marker left behind by a contender that died is bound
// to the marker that was judged stale: a fresh marker that replaced it in the
// meantime — another contender inside its takeover — is never deleted, so
// takeovers stay serialized. The interleavings are injected deterministically
// by wrapping fs calls of this process; all state lives in temp dirs.

const test = require('node:test');
const assert = require('node:assert');
const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { acquireInstanceLock } = require('../lib/instance-lock');

async function deadPid() {
  const dead = childProcess.spawn(process.execPath, ['-e', 'process.exit(0)']);
  await new Promise((r) => dead.once('exit', r));
  return dead.pid;
}

// A state dir as a crash in the middle of a takeover leaves it: the claim of
// a dead owner and a takeover marker well past the stale threshold.
async function crashedTakeover() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-lock-marker-'));
  const lockFile = path.join(dir, 'daemon.lock');
  const marker = `${lockFile}.takeover`;
  const claim = JSON.stringify({ pid: await deadPid(), startTime: 'Mon Jan  1 00:00:00 2024', instanceId: 'crashed' });
  fs.writeFileSync(lockFile, claim);
  fs.writeFileSync(marker, '');
  const old = Date.now() / 1000 - 60;
  fs.utimesSync(marker, old, old);
  return { dir, lockFile, marker, claim };
}

// What a faster contender does meanwhile: it removes the stale marker and
// claims a fresh one — it is now inside its takeover.
// (fstat: the stat functions may be wrapped by the test itself.)
function replaceWithFreshMarker(marker) {
  fs.unlinkSync(marker);
  const fd = fs.openSync(marker, 'wx', 0o600);
  try {
    return fs.fstatSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

// Replaces fs[name] for the duration of a test; returns the restore function.
function wrap(name, make) {
  const original = fs[name];
  fs[name] = make(original);
  return () => { fs[name] = original; };
}

// The contender judged dead; its ps entry is gone.
const deadOwner = { getProcessInfo: () => null };

async function assertMarkerKept({ dir, lockFile, marker, claim }, fresh, attempt) {
  await assert.rejects(attempt, (err) => err.code === 'DAEMON_ALREADY_RUNNING' && err.owner === null);
  assert.ok(fresh(), 'the interleaving was injected');
  const st = fs.lstatSync(marker);
  assert.strictEqual(st.ino, fresh().ino, "the other contender's marker is still in place");
  assert.strictEqual(st.mtimeMs, fresh().mtimeMs);
  assert.strictEqual(fs.readFileSync(lockFile, 'utf8'), claim, 'the judged claim is left to the marker holder');
  assert.deepStrictEqual(fs.readdirSync(dir).sort(), ['daemon.lock', 'daemon.lock.takeover'],
    'nothing set aside is left behind');
}

test('instance lock: a fresh marker that replaced the stale one after the staleness check is never removed', async () => {
  const state = await crashedTakeover();
  let fresh = null;
  // The swap lands right after the stat that judged the marker stale.
  const after = (original) => function statThenSwap(p, ...rest) {
    const st = original.call(fs, p, ...rest);
    if (p === state.marker && !fresh) fresh = replaceWithFreshMarker(state.marker);
    return st;
  };
  const restores = [wrap('statSync', after), wrap('lstatSync', after)];
  try {
    await assertMarkerKept(state, () => fresh,
      () => acquireInstanceLock({ dir: state.dir, instanceId: 'late', ...deadOwner }));
  } finally {
    for (const restore of restores) restore();
    fs.rmSync(state.dir, { recursive: true, force: true });
  }
});

test('instance lock: a marker swapped in right before the stale one is moved away is put back', async () => {
  const state = await crashedTakeover();
  let fresh = null;
  // The swap lands between the last identity check and the removal itself:
  // the entry captured for removal is checked, not the one judged earlier.
  const restore = wrap('renameSync', (original) => function swapThenRename(from, to) {
    if (from === state.marker && !fresh) fresh = replaceWithFreshMarker(state.marker);
    return original.call(fs, from, to);
  });
  try {
    await assertMarkerKept(state, () => fresh,
      () => acquireInstanceLock({ dir: state.dir, instanceId: 'late', ...deadOwner }));
  } finally {
    restore();
    fs.rmSync(state.dir, { recursive: true, force: true });
  }
});

test('instance lock: a stale marker is removed and the marker is claimed again through O_EXCL', async () => {
  const state = await crashedTakeover();
  const exclusiveOpens = [];
  const restore = wrap('openSync', (original) => function recordOpen(p, flags, ...rest) {
    if (p === state.marker && flags === 'wx') {
      try {
        const fd = original.call(fs, p, flags, ...rest);
        exclusiveOpens.push('created');
        return fd;
      } catch (err) {
        exclusiveOpens.push(err.code);
        throw err;
      }
    }
    return original.call(fs, p, flags, ...rest);
  });
  const events = [];
  try {
    const lock = await acquireInstanceLock({
      dir: state.dir,
      instanceId: 'next',
      log: (_scope, event) => events.push(event),
      ...deadOwner,
    });
    assert.ok(events.includes('lock-takeover-marker-stale'));
    assert.deepStrictEqual(exclusiveOpens, ['EEXIST', 'created'],
      'the stale marker is removed in one attempt and claimed through O_EXCL in a later one');
    assert.strictEqual(JSON.parse(fs.readFileSync(state.lockFile, 'utf8')).instanceId, 'next');
    lock.release();
    assert.deepStrictEqual(fs.readdirSync(state.dir), [], 'no marker, temp or set-aside file is left behind');
  } finally {
    restore();
    fs.rmSync(state.dir, { recursive: true, force: true });
  }
});
