'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const { Daemon } = require('../lib/daemon');
const { Registry } = require('../lib/registry');

function startUpstream(port) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => res.end('upstream:' + req.url));
    server.listen(port || 0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

test('Daemon.refresh: changing manual route port immediately revokes public share', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-manual-'));
  const u1 = await startUpstream();
  const u2 = await startUpstream();

  // Executable mock cloudflared script
  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://demo-manual.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  // Hermetic discovery: the injected listeners replace a real lsof scan,
  // whose duration (budget-bounded) is load-dependent — under parallel test
  // load the real scan degraded the pass, the route never appeared and the
  // assertions below ran against a missing route. The behavior under test is
  // the refresh-driven revocation, not the scan itself.
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => [
      { pid: 41001, port: u1.port, processKey: '41001:u1', command: 'node', cwd: null, root: null, external: false },
      { pid: 41002, port: u2.port, processKey: '41002:u2', command: 'node', cwd: null, root: null, external: false },
    ],
  });

  try {
    await daemon.start();

    // 1. portname add app <u1.port>
    daemon.registry.addManual('app', u1.port);
    await daemon.refresh();
    assert.strictEqual(daemon.routesByName.get('app').port, u1.port);

    // 2. portname share app
    await daemon.shares.start({
      name: 'app',
      targetPort: u1.port,
      pinnedPid: null,
      pinnedProcessKey: null,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
    });
    assert.strictEqual(daemon.shares.isShared('app'), true);

    // 3. portname add app <u2.port> (port changed!)
    daemon.registry.addManual('app', u2.port);
    await daemon.refresh();

    // Verification: old share must be immediately revoked!
    assert.strictEqual(daemon.shares.isShared('app'), false, 'share must be revoked when target port changes');
  } finally {
    await daemon.stop();
    u1.server.closeAllConnections();
    u2.server.closeAllConnections();
    await new Promise((r) => u1.server.close(r));
    await new Promise((r) => u2.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon.refresh: upstreamHost change revokes public share', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-host-'));

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://demo-host.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  let currentListeners = [];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => currentListeners,
  });

  try {
    await daemon.start();

    // Listener on 127.0.0.1
    currentListeners = [
      {
        pid: 2001,
        port: 3000,
        processKey: '2001:startA',
        command: 'node',
        cwd: path.join(dir, 'shop'),
        root: path.join(dir, 'shop'),
        upstreamHost: '127.0.0.1',
        external: false,
      },
    ];
    await daemon.refresh();
    assert.strictEqual(daemon.routesByName.get('shop').upstreamHost, '127.0.0.1');

    await daemon.shares.start({
      name: 'shop',
      targetPort: 3000,
      targetHost: '127.0.0.1',
      pinnedPid: 2001,
      pinnedProcessKey: '2001:startA',
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
    });
    assert.strictEqual(daemon.shares.isShared('shop'), true);

    // Now same process switches upstreamHost to ::1
    currentListeners = [
      {
        pid: 2001,
        port: 3000,
        processKey: '2001:startA',
        command: 'node',
        cwd: path.join(dir, 'shop'),
        root: path.join(dir, 'shop'),
        upstreamHost: '::1',
        external: false,
      },
    ];
    await daemon.refresh();

    assert.strictEqual(daemon.shares.isShared('shop'), false, 'share must be revoked when upstream host changes');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon.refresh: process generation change revokes public share (generation A -> B)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-auto-'));

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://demo-gen.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  let currentListeners = [];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => currentListeners,
  });

  try {
    await daemon.start();

    // Generation A on port 3000
    currentListeners = [
      {
        pid: 1001,
        port: 3000,
        processKey: '1001:startA',
        command: 'node',
        cwd: path.join(dir, 'shop'),
        root: path.join(dir, 'shop'),
        external: false,
        suggestedName: 'shop',
      },
    ];

    await daemon.refresh();
    assert.strictEqual(daemon.routesByName.has('shop'), true);
    assert.strictEqual(daemon.routesByName.get('shop').port, 3000);

    // Start share for generation A
    await daemon.shares.start({
      name: 'shop',
      targetPort: 3000,
      pinnedPid: 1001,
      pinnedProcessKey: '1001:startA',
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
    });
    assert.strictEqual(daemon.shares.isShared('shop'), true);

    // Generation B takes over on port 3001
    currentListeners = [
      {
        pid: 2002,
        port: 3001,
        processKey: '2002:startB',
        command: 'node',
        cwd: path.join(dir, 'shop'),
        root: path.join(dir, 'shop'),
        external: false,
        suggestedName: 'shop',
      },
    ];

    // CALL REAL DAEMON.REFRESH()
    await daemon.refresh();

    // Share must be revoked by real daemon.refresh()!
    assert.strictEqual(daemon.shares.isShared('shop'), false, 'real daemon.refresh() must revoke share on process generation change');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon: cloudflared child PID is passed to listListeners excludePids during refresh', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-exclude-'));
  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://demo-pid.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  let passedExcludePids = null;
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    // The share below has no route (the scan is empty), so a correctly
    // working periodic refresh would revoke it — under load the 3 s timer
    // fired between the share start and the assertion. Only the explicit
    // refresh below is needed to capture the exclude list.
    refreshMs: 3_600_000,
    listListeners: ({ excludePids }) => {
      passedExcludePids = excludePids;
      return [];
    },
  });

  try {
    await daemon.start();
    await daemon.shares.start({
      name: 'dummy',
      targetPort: 9999,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
    });

    const activeChildPid = daemon.shares.shares.get('dummy').cloudflared.pid;
    assert.ok(typeof activeChildPid === 'number');

    // Call real refresh
    await daemon.refresh();

    // Child PID must be passed in exclude list during real refresh
    assert.ok(Array.isArray(passedExcludePids));
    assert.ok(passedExcludePids.includes(activeChildPid), 'listListeners must receive active cloudflared child PID');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon: refuses expose in loopback bind mode', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-loopback-'));
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
  });

  try {
    await daemon.start();
    daemon.routesByName.set('app', { name: 'app', port: 3000 });

    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'expose', name: 'app', on: true }),
      /loopback-only bind mode/
    );

    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.deepStrictEqual(status.exposed, [], 'exposed list must be empty in loopback mode');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon: refuses expose when no physical LAN interface is found', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-nolan-'));
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
  });

  try {
    await daemon.start();
    // Simulate no LAN interface
    daemon.announcer.lanAddress = () => null;
    daemon.routesByName.set('app', { name: 'app', port: 3000 });

    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'expose', name: 'app', on: true }),
      /no active physical Wi-Fi\/LAN interface found/
    );

    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.deepStrictEqual(status.exposed, [], 'exposed list must be empty when no LAN interface');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon / Registry: exposure is bound to project identity across renames and prevents reuse theft', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-ident-'));
  const shopDir = path.join(dir, 'shop');
  const otherDir = path.join(dir, 'other');
  fs.mkdirSync(shopDir);
  fs.mkdirSync(otherDir);
  fs.mkdirSync(path.join(shopDir, '.git'));
  fs.mkdirSync(path.join(otherDir, '.git'));

  let currentListeners = [
    { pid: 101, port: 3000, processKey: '101:start', command: 'node', cwd: shopDir, external: false },
  ];

  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => currentListeners,
  });

  try {
    await daemon.start();
    daemon.announcer.lanAddress = () => '192.168.1.50';

    // 1. "shop" is running from shopDir
    assert.strictEqual(daemon.routesByName.get('shop').root, shopDir);

    // Expose "shop"
    const expRes = await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    assert.strictEqual(expRes.exposed, true);
    assert.strictEqual(daemon.registry.isExposed(shopDir), true);

    // 2. Rename /projects/shop to "super-shop"
    const renRes = await daemon.dispatchControl({ cmd: 'rename', name: 'shop', newName: 'super-shop' });
    assert.strictEqual(renRes.to, 'super-shop');

    // "super-shop" must still be exposed because its root (shopDir) was exposed!
    assert.strictEqual(daemon.registry.isExposed(shopDir), true);
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.deepStrictEqual(status.exposed, ['super-shop']);

    // 3. New unrelated project in otherDir starts up and claims name "shop"
    currentListeners.push({
      pid: 202,
      port: 4000,
      processKey: '202:start',
      command: 'node',
      cwd: otherDir,
      external: false,
    });
    daemon.registry.config.renames[otherDir] = 'shop';
    await daemon.refresh();

    // The other project is at route "shop", but must NOT be exposed!
    assert.strictEqual(daemon.routesByName.get('shop').root, otherDir);
    assert.strictEqual(daemon.registry.isExposed(otherDir), false);
    const status2 = await daemon.dispatchControl({ cmd: 'status' });
    assert.deepStrictEqual(status2.exposed, ['super-shop'], 'other project must not inherit exposure by reusing old name');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('BonjourAnnouncer: safe orphan cleanup verifies PID and process start time before killing', () => {
  const { BonjourAnnouncer } = require('../lib/expose');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-bonjour-orphan-'));
  const stateFile = path.join(dir, 'bonjour.state.json');

  let killedPids = [];
  const fakeKill = (pid) => killedPids.push(pid);
  const originalKill = process.kill;
  process.kill = fakeKill;

  try {
    fs.writeFileSync(
      stateFile,
      JSON.stringify({
        children: [
          { pid: 1111, startTime: 'Old Start Time', command: 'dns-sd' },
          { pid: 2222, startTime: 'Match Start Time', command: 'dns-sd' },
        ],
      })
    );

    const mockGetProcessInfo = (pid) => {
      if (pid === 1111) {
        return { pid: 1111, startTime: 'Different Time (PID Reused)', command: 'bash' };
      }
      if (pid === 2222) {
        return { pid: 2222, startTime: 'Match Start Time', command: 'dns-sd' };
      }
      return null;
    };

    const announcer = new BonjourAnnouncer({
      port: 80,
      dir,
      getProcessInfo: mockGetProcessInfo,
    });
    announcer.cleanupOrphans();

    assert.ok(!killedPids.includes(1111), 'PID-reused process must NOT be killed');
    assert.ok(killedPids.includes(2222), 'matching orphan process must be killed');
    assert.strictEqual(fs.existsSync(stateFile), false, 'bonjour state file must be removed after cleanup');
  } finally {
    process.kill = originalKill;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon: rejects share command with invalid ttlMinutes', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-ttl-'));
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
  });

  try {
    await daemon.start();
    daemon.routesByName.set('app', { name: 'app', port: 3000 });

    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 0 }),
      /invalid ttlMinutes/
    );

    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: -10 }),
      /invalid ttlMinutes/
    );

    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 'not-a-number' }),
      /invalid ttlMinutes/
    );

    await t.assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'app', ttlMinutes: 5000 }),
      /invalid ttlMinutes/
    );
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Registry / Daemon: rename refuses stealing an auto-discovered project name', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-rename-steal-'));
  const reg = new Registry(dir);

  // Auto-assigned names in config.names
  reg.config.names['/projects/shop'] = 'shop';
  reg.config.names['/projects/api'] = 'api';
  reg.saveConfig();

  // /projects/api tries to rename to "shop"
  const res = reg.rename('/projects/api', 'shop');
  assert.strictEqual(res.ok, false);
  assert.match(res.reason, /already used by \/projects\/shop/);

  // Check live auto names collision
  const res2 = reg.rename('/projects/api', 'blog', { liveAutoNames: new Set(['blog']) });
  assert.strictEqual(res2.ok, false);
  assert.match(res2.reason, /already used by an automatically discovered project/);

  fs.rmSync(dir, { recursive: true, force: true });
});

