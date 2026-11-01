'use strict';

// Auto-name reservations (config.names) must not grow without bound:
// reservations of deleted directories and of projects unused for a long time
// are dropped, the rest is capped, and nothing the user decided about or that
// is live right now is ever touched.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { Registry, dayNumber, MAX_NAME_ENTRIES, NAME_RESERVATION_TTL_DAYS } = require('../lib/registry');
const { validateConfig } = require('../lib/config');
const { resolveRoutes } = require('../lib/discover');
const { Daemon } = require('../lib/daemon');

const TODAY = 20_000;

function tmpDir(prefix) {
  // realpath: project roots are canonical paths (/private/var/... on macOS).
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function registryWith(dir, config) {
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(config, null, 2));
  return new Registry(dir);
}

function projectDirs(base, ...names) {
  return names.map((n) => {
    const p = path.join(base, n);
    fs.mkdirSync(p);
    return p;
  });
}

async function prune(reg, opts = {}) {
  const gone = await reg.findGoneNameRoots({ liveRoots: opts.liveRoots });
  return reg.pruneNames({ today: TODAY, ...opts, gone });
}

test('pruneNames: drops reservations of deleted directories, keeps existing, pinned, live and volume roots', async () => {
  const dir = tmpDir('pn-names-');
  try {
    const [kept, live] = projectDirs(dir, 'kept', 'live');
    const gone = (n) => path.join(dir, 'gone', n);
    const reg = registryWith(dir, {
      names: {
        [kept]: 'kept',
        [live]: 'live',
        [gone('a')]: 'tree',
        [gone('b')]: 'tree-2',
        [gone('renamed')]: 'mine',
        [gone('primary')]: 'primary',
        [gone('exposed')]: 'exposed',
        [gone('target')]: 'target',
        '/Volumes/Unplugged/app': 'app',
      },
      namesSeen: { [gone('a')]: TODAY },
      renames: { [gone('renamed')]: 'mine' },
      primaryPorts: { [gone('primary')]: 5173 },
      exposed: { [gone('exposed')]: true },
      exposedTargets: { [gone('target')]: { port: 3000, command: 'node' } },
    });

    const { dropped, changed } = await prune(reg, { liveRoots: new Set([live]) });

    assert.strictEqual(dropped, 2);
    assert.strictEqual(changed, true);
    assert.deepStrictEqual(Object.keys(reg.config.names).sort(), [
      '/Volumes/Unplugged/app',
      gone('exposed'),
      gone('primary'),
      gone('renamed'),
      gone('target'),
      kept,
      live,
    ].sort());
    assert.ok(!Object.hasOwn(reg.config.namesSeen, gone('a')), 'the day of a dropped reservation goes with it');
    // Memory only: the caller decides when to persist.
    const onDisk = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
    assert.ok(Object.hasOwn(onDisk.names, gone('a')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('findGoneNameRoots: a directory that cannot be checked is never judged gone', { skip: process.getuid && process.getuid() === 0 }, async () => {
  const dir = tmpDir('pn-names-eacces-');
  const locked = path.join(dir, 'locked');
  const inside = path.join(locked, 'app');
  fs.mkdirSync(inside, { recursive: true });
  try {
    fs.chmodSync(locked, 0o000);
    const reg = registryWith(dir, { names: { [inside]: 'app' } });
    assert.strictEqual((await reg.findGoneNameRoots()).size, 0);
  } finally {
    fs.chmodSync(locked, 0o700);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('pruneNames: reservations unused for longer than the TTL expire; legacy ones start their TTL now', async () => {
  const dir = tmpDir('pn-names-ttl-');
  try {
    const [old, recent, legacy, future] = projectDirs(dir, 'old', 'recent', 'legacy', 'future');
    const reg = registryWith(dir, {
      names: { [old]: 'old', [recent]: 'recent', [legacy]: 'legacy', [future]: 'future' },
      namesSeen: {
        [old]: TODAY - NAME_RESERVATION_TTL_DAYS - 1,
        [recent]: TODAY - NAME_RESERVATION_TTL_DAYS,
        // A clock that went backwards must not expire anything.
        [future]: TODAY + 400,
      },
    });

    const { dropped } = await prune(reg);

    assert.strictEqual(dropped, 1);
    assert.deepStrictEqual(Object.keys(reg.config.names).sort(), [future, legacy, recent].sort());
    assert.strictEqual(reg.config.namesSeen[legacy], TODAY, 'a reservation from before namesSeen gets today');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('pruneNames: the cap counts unpinned reservations only and drops the least recently live first', async () => {
  const dir = tmpDir('pn-names-cap-');
  try {
    const [a, b, c, d, e, p1, p2, p3] = projectDirs(dir, 'a', 'b', 'c', 'd', 'e', 'p1', 'p2', 'p3');
    const reg = registryWith(dir, {
      names: { [a]: 'a', [b]: 'b', [c]: 'c', [d]: 'd', [e]: 'e', [p1]: 'p1', [p2]: 'p2', [p3]: 'p3' },
      namesSeen: { [a]: TODAY - 1, [b]: TODAY - 5, [c]: TODAY - 5, [d]: TODAY - 2, [e]: TODAY },
      // Three pinned roots: they must not push unpinned ones out.
      renames: { [p1]: 'p1' },
      primaryPorts: { [p2]: 3000 },
      exposed: { [p3]: true },
    });

    const { dropped } = await prune(reg, { maxEntries: 3 });

    // Unpinned a, b, c, d, e: the two oldest (b, c; tie kept in map order) go.
    assert.strictEqual(dropped, 2);
    assert.deepStrictEqual(Object.keys(reg.config.names), [a, d, e, p1, p2, p3]);
    assert.ok(MAX_NAME_ENTRIES >= 100, 'the default cap leaves room for real projects');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('noteNamesSeen: stamps live reservations once per day', () => {
  const dir = tmpDir('pn-names-seen-');
  try {
    const [shop, other] = projectDirs(dir, 'shop', 'other');
    const reg = registryWith(dir, { names: { [shop]: 'shop' } });
    assert.strictEqual(reg.noteNamesSeen(new Set([shop, other]), TODAY), true);
    assert.deepStrictEqual(reg.config.namesSeen, { [shop]: TODAY }, 'only roots holding a reservation');
    assert.strictEqual(reg.noteNamesSeen(new Set([shop]), TODAY), false, 'no second write the same day');
    assert.strictEqual(reg.noteNamesSeen(new Set([shop]), TODAY + 1), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('pruneNames: a freed name goes to the next project with that folder name, without a suffix', async () => {
  const dir = tmpDir('pn-names-free-');
  try {
    const [fresh] = projectDirs(dir, 'fresh');
    const names = {};
    for (let i = 0; i < 50; i += 1) names[path.join(dir, 'deleted', String(i))] = i === 0 ? 'tree' : `tree-${i + 1}`;
    const reg = registryWith(dir, { names });

    assert.strictEqual((await prune(reg)).dropped, 50);

    const listener = { pid: 7, port: 4000, root: fresh, processKey: '7:T', command: 'node', suggestedName: 'tree' };
    const { routes } = resolveRoutes({ listeners: [listener], names: reg.config.names });
    assert.strictEqual(routes[0].name, 'tree');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('config: namesSeen must map roots to day numbers', () => {
  assert.doesNotThrow(() => validateConfig({ namesSeen: { '/p/app': 20000 } }));
  for (const bad of [[], { '/p/app': -1 }, { '/p/app': 1.5 }, { '/p/app': '20000' }]) {
    assert.throws(() => validateConfig({ namesSeen: bad }), /namesSeen must map roots to day numbers/);
  }
});

function shopDaemon(dir, shop, logged) {
  return new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => [{ pid: 1001, port: 3000, processKey: '1001:sA', command: 'node', cwd: shop, root: shop, external: false, suggestedName: 'shop' }],
    log: (...fields) => logged.push(fields),
  });
}

test('daemon: the first successful scan prunes in the background and persists; later scans wait for the interval', async () => {
  const dir = tmpDir('pn-names-daemon-');
  const [shop, idle] = projectDirs(dir, 'shop', 'idle');
  const deleted = (n) => path.join(dir, 'deleted', n);
  fs.writeFileSync(
    path.join(dir, 'config.json'),
    JSON.stringify({ names: { [deleted('old')]: 'old', [idle]: 'idle', [shop]: 'shop' } }, null, 2)
  );
  const logged = [];
  const daemon = shopDaemon(dir, shop, logged);
  try {
    await daemon.start();
    daemon.announcer.lanAddress = () => null;
    await daemon.namesPrune;

    const onDisk = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
    assert.deepStrictEqual(Object.keys(onDisk.names).sort(), [idle, shop].sort(), 'the deleted root is dropped on disk');
    assert.deepStrictEqual(onDisk.namesSeen, { [shop]: dayNumber(), [idle]: dayNumber() });
    assert.ok(logged.some((f) => f[0] === 'registry' && f[1] === 'names-pruned' && f[2] === 1));

    // Within the interval a newly stale reservation stays until the next prune.
    daemon.registry.config.names[deleted('later')] = 'later';
    daemon.registry.saveConfig();
    const pruneBefore = daemon.namesPrune;
    await daemon.refresh();
    assert.strictEqual(daemon.namesPrune, pruneBefore, 'no new prune within the interval');
    assert.ok(Object.hasOwn(daemon.registry.config.names, deleted('later')));

    // Stop and start the same instance: the fresh registry is pruned at once.
    await daemon.stop();
    await daemon.start();
    daemon.announcer.lanAddress = () => null;
    await daemon.namesPrune;
    assert.ok(!Object.hasOwn(daemon.registry.config.names, deleted('later')));
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: a directory check that never returns blocks neither scans nor a second prune start', async () => {
  const dir = tmpDir('pn-names-hang-');
  const [shop] = projectDirs(dir, 'shop');
  const daemon = shopDaemon(dir, shop, []);
  try {
    await daemon.start();
    daemon.announcer.lanAddress = () => null;
    await daemon.namesPrune;

    let calls = 0;
    daemon.registry.findGoneNameRoots = () => {
      calls += 1;
      return new Promise(() => {}); // a stat on a dead network mount
    };
    daemon.namesPruneIntervalMs = 0;
    await daemon.refresh();
    await daemon.refresh();
    assert.strictEqual(calls, 1, 'one hanging prune at a time');
    assert.strictEqual(daemon.routes.find((r) => r.root === shop).name, 'shop', 'scans keep working');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
