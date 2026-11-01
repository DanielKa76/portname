'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { Daemon } = require('../lib/daemon');
const { NON_HTTP_COMMANDS, ignoredCommandsFilter } = require('../lib/discover');

function listener({ pid, port, root, command }) {
  return {
    pid,
    port,
    processKey: `${pid}:s`,
    command,
    cwd: root,
    root,
    external: false,
    suggestedName: path.basename(root),
  };
}

function mkDaemon(dir, { ignoreCommands } = {}) {
  return new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false, ignoreCommands },
    listListeners: () => [
      // Real dev server: must stay a route.
      listener({ pid: 1101, port: 3000, root: path.join(dir, 'shop'), command: 'node' }),
      // Known non-HTTP services: must never become routes (the live case:
      // data.localhost/postgresql-16 = postgres, main = limactl).
      listener({ pid: 1102, port: 5432, root: path.join(dir, 'data'), command: 'postgres' }),
      listener({ pid: 1104, port: 2223, root: path.join(dir, 'main'), command: 'limactl' }),
      // Case-insensitive match.
      listener({ pid: 1105, port: 62549, root: path.join(dir, 'legacy'), command: 'Postgres' }),
      // An ssh listener must STAY: ssh -L port-forwards are indistinguishable
      // by command name and often carry HTTP (live evidence: project.localhost
      // -> ssh :3010 answering HTTP 200).
      listener({ pid: 1103, port: 3010, root: path.join(dir, 'project'), command: 'ssh' }),
    ],
  });
}

test('discovery filter: known non-HTTP commands never become routes or stale entries', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-filter-'));
  for (const name of ['shop', 'data', 'project', 'main', 'legacy']) fs.mkdirSync(path.join(dir, name));
  const daemon = mkDaemon(dir);

  try {
    await daemon.start();
    // shop (node) and project (ssh port-forward) stay, the rest is filtered.
    const names = daemon.routes.map((r) => r.name).sort();
    assert.deepStrictEqual(names, ['project', 'shop']);

    const routedPorts = daemon.routes.map((r) => r.port);
    assert.ok(routedPorts.includes(3010), 'ssh port-forward listeners stay visible');
    assert.ok(!routedPorts.includes(5432) && !routedPorts.includes(2223) && !routedPorts.includes(62549));

    // Ignored listeners are not diagnostics either — they would only re-create
    // the confusing 502 entries under a different label.
    assert.strictEqual(daemon.stale.length, 0, 'ignored listeners must not leak into stale');
    assert.strictEqual(daemon.registry.config.names['legacy'], undefined,
      'ignored projects must not reserve an auto name');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('discovery filter: config.ignoreCommands extends the built-in set', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-filter2-'));
  for (const name of ['shop', 'macos']) fs.mkdirSync(path.join(dir, name));

  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false, ignoreCommands: ['EABackgroundAgent'] },
    listListeners: () => [
      listener({ pid: 1201, port: 3000, root: path.join(dir, 'shop'), command: 'node' }),
      // Not in the built-in list — only ignored via config.
      listener({ pid: 1202, port: 63645, root: path.join(dir, 'macos'), command: 'EABackgroundAgent' }),
    ],
  });

  try {
    await daemon.start();
    assert.deepStrictEqual(daemon.routes.map((r) => r.name), ['shop']);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('discovery filter: manual registrations deliberately bypass the ignore list', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-filter3-'));
  const daemon = mkDaemon(dir);

  try {
    await daemon.start();
    // An explicit human decision to route a database port stays possible.
    const added = await daemon.dispatchControl({ cmd: 'add', name: 'db', port: 5432 });
    assert.strictEqual(added.added, 'db');
    assert.ok(daemon.routesByName.has('db'), 'manual entries ignore the command filter');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('discovery filter: helper matches exactly, case-insensitively, and tolerates junk', () => {
  const filter = ignoredCommandsFilter(['MyAgent']);
  assert.strictEqual(filter({ command: 'postgres' }), false);
  assert.strictEqual(filter({ command: 'POSTGRES' }), false);
  assert.strictEqual(filter({ command: 'postgres-server' }), true, 'no substring matches');
  assert.strictEqual(filter({ command: 'MyAgent' }), false);
  assert.strictEqual(filter({ command: 'node' }), true);
  assert.strictEqual(filter({ command: undefined }), true);
  assert.strictEqual(filter({}), true);
  assert.ok(NON_HTTP_COMMANDS.has('postgres') && NON_HTTP_COMMANDS.has('limactl'));
  assert.ok(!NON_HTTP_COMMANDS.has('ssh'), 'ssh stays visible: -L forwards can carry HTTP');
});
