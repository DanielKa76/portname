'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const http = require('http');

const { Daemon } = require('../lib/daemon');
const { browserHost, localBrowserUrl, lanBrowserUrl } = require('../lib/urls');

// The daemon subprocess launch itself is covered by cli.test.js ("daemon
// stays alive until SIGTERM"); the socket tests below run the daemon
// in-process with HERMETIC discovery so the wire contract is not subject to
// real lsof scan durations under parallel test load (the historical 10 s
// socket timeouts). The control socket, its envelope and its framing are
// the daemon's real #startControl code path either way.

function fakeCloudflared(dir, urlHost) {
  const script = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    script,
    `#!/usr/bin/env node\nconsole.log("https://${urlHost}.trycloudflare.com");\nsetInterval(() => {}, 1000);\n`
  );
  fs.chmodSync(script, 0o755);
  return script;
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

function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => res.end('upstream:' + req.url));
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

// Send one newline-delimited JSON request over the real control socket.
function sendToSocket(sockFile, msg, { timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(sockFile);
    let buf = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`timeout waiting for daemon socket (${timeoutMs}ms)`));
    }, timeoutMs);
    socket.on('connect', () => socket.write(JSON.stringify(msg) + '\n'));
    socket.on('data', (d) => {
      buf += d.toString();
      if (buf.endsWith('\n')) {
        clearTimeout(timer);
        socket.end();
        try {
          resolve(JSON.parse(buf));
        } catch (err) {
          reject(new Error('bad response: ' + buf.slice(0, 200)));
        }
      }
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// Send pre-encoded bytes (optionally in several writes on the same
// connection) and collect the single response line plus whether the daemon
// closed its side afterwards (end/half-close or destroy).
function sendRawBytes(sockFile, payload, { timeoutMs = 10000, secondWrite = null, gapMs = 100 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(sockFile);
    let buf = Buffer.alloc(0);
    let closed = false;
    let answered = false;
    const finish = (fn, arg) => {
      if (!answered) {
        answered = true;
        clearTimeout(timer);
        socket.destroy();
        fn(arg);
      }
    };
    const timer = setTimeout(() => finish(reject, new Error(`timeout (${timeoutMs}ms)`)), timeoutMs);
    socket.on('connect', () => {
      socket.write(payload);
      if (secondWrite) {
        setTimeout(() => socket.write(secondWrite), gapMs);
      }
    });
    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      const nl = buf.indexOf(0x0a);
      if (nl !== -1) {
        let parsed;
        try {
          parsed = JSON.parse(buf.subarray(0, nl).toString('utf8'));
        } catch (err) {
          finish(reject, new Error('bad response: ' + buf.subarray(0, 200).toString('utf8')));
          return;
        }
        // Give the daemon a moment to close its side, then resolve.
        setTimeout(() => finish(resolve, { response: parsed, closedByDaemon: closed }), 150);
      }
    });
    socket.on('close', () => (closed = true));
    socket.on('error', (err) => finish(reject, err));
  });
}

async function waitForFile(file, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`file never appeared: ${file}`);
}

test('urls: browser hosts at gateway port 80 and non-80', () => {
  assert.strictEqual(browserHost('shop', '.localhost', 80), 'shop.localhost');
  assert.strictEqual(browserHost('shop', '.localhost', 7777), 'shop.localhost:7777');
  assert.strictEqual(browserHost('shop', '.localhost', 0), 'shop.localhost');
  assert.strictEqual(browserHost('shop', '.local', 7777), 'shop.local:7777');
  assert.strictEqual(localBrowserUrl('shop', 80), 'http://shop.localhost/');
  assert.strictEqual(localBrowserUrl('shop', 7777), 'http://shop.localhost:7777/');
  assert.strictEqual(lanBrowserUrl('shop', 80), 'http://shop.local/');
  assert.strictEqual(lanBrowserUrl('shop', 7777), 'http://shop.local:7777/');
});

test('status: protocol metadata, route identity, revision stability, and URLs', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-status-'));
  const root = path.join(dir, 'shop');
  fs.mkdirSync(root);
  const listeners = [autoListener({ pid: 1001, port: 3000, root, processKey: '1001:sA' })];

  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 7777, control: false },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    daemon.announcer.lanAddress = () => null;

    const s1 = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(s1.protocolVersion, 1);
    assert.ok(typeof s1.daemonInstanceId === 'string' && s1.daemonInstanceId.length > 10);

    // Loopback never offers LAN metadata (additive v1 fields, fixed shape).
    assert.deepStrictEqual(s1.lan, { available: false, reason: 'loopback-bind', interfaceName: null, address: null, network: null });

    assert.strictEqual(s1.routes.length, 1);
    const r1 = s1.routes[0];
    assert.strictEqual(r1.id, root, 'auto route identity is the canonical root');
    assert.strictEqual(r1.name, 'shop');
    assert.strictEqual(r1.localUrl, 'http://shop.localhost:7777/');
    assert.strictEqual(r1.lanUrl, null);
    assert.strictEqual(r1.exposureRequested, false);
    // Upstream port (3000) must never masquerade as the gateway port.
    assert.strictEqual(r1.port, 3000);
    assert.ok(!r1.localUrl.includes(':3000'), 'upstream port must not leak into the browser URL');

    // Identical polls keep id and revision stable.
    const s2 = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(s2.routes[0].id, r1.id);
    assert.strictEqual(s2.routes[0].revision, r1.revision);

    // A target change (process generation) changes the revision, not the id.
    listeners[0] = autoListener({ pid: 1002, port: 3001, root, processKey: '1002:sB' });
    await daemon.refresh();
    const s3 = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(s3.routes[0].id, r1.id);
    assert.notStrictEqual(s3.routes[0].revision, r1.revision);

    // Exposure wish survives a missing LAN and is reported separately.
    daemon.registry.setExposed(root, true);
    const s4 = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(s4.routes[0].exposureRequested, true);
    assert.strictEqual(s4.routes[0].lanUrl, null, 'no lanUrl while no physical LAN exists');
    assert.strictEqual(s4.exposed.length, 0);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('status: loopback bind reports LAN unavailable with reason and hides lanUrl', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-loop-'));
  const root = path.join(dir, 'api');
  fs.mkdirSync(root);
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 7777, control: false },
    listListeners: () => [autoListener({ pid: 3001, port: 4000, root, processKey: '3001:s' })],
  });

  try {
    await daemon.start();
    daemon.announcer.lanAddress = () => '192.168.1.20';
    daemon.registry.setExposed(root, true);
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.deepStrictEqual(status.lan, { available: false, reason: 'loopback-bind', interfaceName: null, address: null, network: null });
    assert.strictEqual(status.routes[0].lanUrl, null);
    assert.strictEqual(status.exposed.length, 0, 'loopback mode exposes nothing');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('status: exposed route with available LAN carries a lanUrl', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-lan-'));
  const root = path.join(dir, 'shop');
  fs.mkdirSync(root);
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => [autoListener({ pid: 4001, port: 3000, root, processKey: '4001:s' })],
  });

  try {
    await daemon.start();
    // No physical LAN first: exposure wish is kept, but nothing is offered.
    // (interfaceName stays display metadata from the real announcer; the
    // address must be null whenever nothing is available.)
    daemon.announcer.lanAddress = () => null;
    let status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.lan.available, false);
    assert.strictEqual(status.lan.reason, 'no-lan-interface');
    assert.strictEqual(status.lan.address, null);

    daemon.announcer.lanAddress = () => '192.168.1.50';
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.lan.available, true);
    assert.strictEqual(status.routes[0].exposureRequested, true);
    assert.strictEqual(status.routes[0].lanUrl, `http://shop.local:${status.proxyPort}/`);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('revision: changes across daemon restarts and on manual target change', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-rev-'));
  const root = path.join(dir, 'app');
  fs.mkdirSync(root);
  const listeners = [autoListener({ pid: 5001, port: 3000, root, processKey: '5001:s' })];

  const mkDaemon = () => new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => listeners,
  });

  const d1 = mkDaemon();
  await d1.start();
  await d1.dispatchControl({ cmd: 'add', name: 'manual1', port: 9100 });
  const s1 = await d1.dispatchControl({ cmd: 'status' });
  const auto1 = s1.routes.find((r) => r.id === root);
  const manual1 = s1.routes.find((r) => r.id === 'manual:manual1');
  await d1.stop();

  // New daemon run: new instance id and therefore new revisions.
  const d2 = mkDaemon();
  await d2.start();
  const s2 = await d2.dispatchControl({ cmd: 'status' });
  const auto2 = s2.routes.find((r) => r.id === root);
  const manual2 = s2.routes.find((r) => r.id === 'manual:manual1');
  assert.notStrictEqual(s2.daemonInstanceId, s1.daemonInstanceId);
  assert.notStrictEqual(auto2.revision, auto1.revision, 'revision must change across daemon restarts');
  assert.notStrictEqual(manual2.revision, manual1.revision);
  await d2.stop();

  // Manual target change (port) changes the revision; identity stays.
  listeners.push(autoListener({ pid: 5002, port: 3000, root, processKey: '5001:s' }));
  listeners.pop();
  const d3 = mkDaemon();
  await d3.start();
  await d3.dispatchControl({ cmd: 'add', name: 'manual1', port: 9200 });
  const s3 = await d3.dispatchControl({ cmd: 'status' });
  const manual3 = s3.routes.find((r) => r.id === 'manual:manual1');
  assert.strictEqual(manual3.port, 9200);
  assert.notStrictEqual(manual3.revision, manual2.revision, 'port change must change the revision');
  await d3.stop();

  fs.rmSync(dir, { recursive: true, force: true });
});

test('expectedRouteRevision: stale guards reject rename, expose, share, and remove', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-guard-'));
  const root = path.join(dir, 'shop');
  fs.mkdirSync(root);
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => [autoListener({ pid: 6001, port: 3000, root, processKey: '6001:s' })],
  });

  try {
    await daemon.start();
    const status = await daemon.dispatchControl({ cmd: 'status' });
    const rev = status.routes[0].revision;

    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'rename', name: 'shop', newName: 'other', expectedRouteRevision: 'bogus' }),
      (err) => err.code === 'STALE_TARGET' && /changed/.test(err.message)
    );
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true, expectedRouteRevision: 'bogus' }),
      (err) => err.code === 'STALE_TARGET'
    );
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 15, expectedRouteRevision: 'bogus' }),
      (err) => err.code === 'STALE_TARGET'
    );
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'remove', name: 'shop', expectedRouteRevision: 'bogus' }),
      (err) => err.code === 'STALE_TARGET'
    );

    // Nothing above may have had an effect.
    assert.strictEqual(daemon.registry.config.renames[root], undefined);
    assert.strictEqual(daemon.registry.isExposed(root), false);

    // With the correct revision the mutation goes through.
    const renamed = await daemon.dispatchControl({
      cmd: 'rename', name: 'shop', newName: 'boutique', expectedRouteRevision: rev,
    });
    assert.strictEqual(renamed.to, 'boutique');

    // Old CLI shape (no expectation field) stays unguarded.
    const exposed = await daemon.dispatchControl({ cmd: 'expose', name: 'boutique', on: true });
    assert.strictEqual(exposed.exposed, true);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rename: conflict failures keep legacy message and gain a NAME_CONFLICT code', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-conflict-'));
  const shopDir = path.join(dir, 'shop');
  const apiDir = path.join(dir, 'api');
  fs.mkdirSync(shopDir);
  fs.mkdirSync(apiDir);
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => [
      autoListener({ pid: 7001, port: 3000, root: shopDir, processKey: '7001:s' }),
      autoListener({ pid: 7002, port: 4000, root: apiDir, processKey: '7002:s' }),
    ],
  });

  try {
    await daemon.start();
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'rename', name: 'api', newName: 'shop' }),
      (err) => err.code === 'NAME_CONFLICT' && err.message === `name "shop" is already used by ${shopDir}`
    );
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('add: createOnly rejects an existing manual entry without repointing it', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-create-'));
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => [],
  });

  try {
    await daemon.start();
    const added = await daemon.dispatchControl({ cmd: 'add', name: 'db', port: 55432, createOnly: true });
    assert.strictEqual(added.added, 'db');

    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'add', name: 'db', port: 55433, createOnly: true }),
      (err) => err.code === 'NAME_CONFLICT' && err.message === 'name "db" is already manually registered'
    );
    assert.strictEqual(daemon.registry.config.manual.db, 55432, 'createOnly must not change the target port');

    // Legacy upsert behavior without createOnly remains available to the CLI.
    const updated = await daemon.dispatchControl({ cmd: 'add', name: 'db', port: 55433 });
    assert.strictEqual(updated.added, 'db');
    assert.strictEqual(daemon.registry.config.manual.db, 55433);

    // A fresh create with createOnly still succeeds.
    const second = await daemon.dispatchControl({ cmd: 'add', name: 'cache', port: 56379, createOnly: true });
    assert.strictEqual(second.added, 'cache');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('add: auto-name collisions carry a NAME_CONFLICT code', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-autoname-'));
  const root = path.join(dir, 'shop');
  fs.mkdirSync(root);
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => [autoListener({ pid: 8001, port: 3000, root, processKey: '8001:s' })],
  });

  try {
    await daemon.start();
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'add', name: 'shop', port: 5000, createOnly: true }),
      (err) => err.code === 'NAME_CONFLICT' && /automatically discovered/.test(err.message)
    );
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('expose: LAN failures carry a LAN_UNAVAILABLE code with legacy messages', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-lanerr-'));
  const root = path.join(dir, 'app');
  fs.mkdirSync(root);
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => [autoListener({ pid: 9001, port: 3000, root, processKey: '9001:s' })],
  });

  try {
    await daemon.start();
    daemon.announcer.lanAddress = () => null;
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'expose', name: 'app', on: true }),
      (err) =>
        err.code === 'LAN_UNAVAILABLE' &&
        err.message === 'cannot expose project on LAN: no active physical Wi-Fi/LAN interface found'
    );
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('share lifecycle: shareId, read-only share-link, and targeted unshare guards', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-share-'));
  const cfScript = fakeCloudflared(dir, 'proto-share');
  // A listener on the shared port: public share starts require the manual
  // target to be verified by an observed listener (a port alone is no
  // identity).
  const listener = { pid: 32001, port: 3200, processKey: '32001:s', command: 'node', cwd: null, root: null, external: false };
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cfScript },
    listListeners: () => [listener],
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'demo', port: 3200 });

    const status0 = await daemon.dispatchControl({ cmd: 'status' });
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share-link', name: 'demo', expectedShareId: 'whatever' }),
      (err) =>
        err.code === 'SHARE_NOT_ACTIVE' &&
        err.message === 'no active share for "demo"'
    );

    const started = await daemon.dispatchControl({ cmd: 'share', name: 'demo', ttlMinutes: 60 });
    assert.ok(typeof started.shareId === 'string' && started.shareId.length >= 8);
    assert.ok(started.url.includes('/'), 'share response contains the full secret link for the requester');
    const token = started.url.split('/')[3];
    assert.ok(token && token.length === 64, 'token must be 64 hex chars');

    // Normal status must never contain the token, but does carry the shareId.
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.ok(!JSON.stringify(status).includes(token), 'status must not leak the secret token');
    assert.strictEqual(status.shares.length, 1);
    assert.strictEqual(status.shares[0].shareId, started.shareId);
    assert.strictEqual(status.shares[0].url, 'https://proto-share.trycloudflare.com', 'status url is the origin without secret');

    // share-link with a wrong id is rejected without handing out the link.
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share-link', name: 'demo', expectedShareId: 'stale-view-id' }),
      (err) => err.code === 'STALE_TARGET'
    );

    // Regression: a share-link without the guard must never return the secret
    // link — fail-closed with INVALID_REQUEST (empty string counts as missing).
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share-link', name: 'demo' }),
      (err) => err.code === 'INVALID_REQUEST' && !/https:/.test(err.message)
    );
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share-link', name: 'demo', expectedShareId: '' }),
      (err) => err.code === 'INVALID_REQUEST'
    );

    // The exact match returns the full link, read-only.
    const link = await daemon.dispatchControl({ cmd: 'share-link', name: 'demo', expectedShareId: started.shareId });
    assert.strictEqual(link.url, started.url);
    assert.strictEqual(link.expiresAt, status.shares[0].expiresAt);
    assert.strictEqual(link.shareId, started.shareId);
    assert.strictEqual(daemon.shares.status().length, 1, 'share-link must not start or replace shares');

    // Targeted unshare with a stale id must not stop the running share.
    const staleStop = await daemon.dispatchControl({ cmd: 'unshare', name: 'demo', expectedShareId: 'stale-view-id' }).then(
      () => null,
      (err) => err
    );
    assert.ok(staleStop && staleStop.code === 'STALE_TARGET');
    assert.strictEqual(daemon.shares.isShared('demo'), true, 'stale expectation must not stop the active share');

    // Regression: unshare also honours the route revision guard — correct
    // share id but stale revision must fail closed and keep the share running.
    await assert.rejects(
      () => daemon.dispatchControl({
        cmd: 'unshare',
        name: 'demo',
        expectedShareId: started.shareId,
        expectedRouteRevision: 'bogus',
      }),
      (err) => err.code === 'STALE_TARGET'
    );
    assert.strictEqual(daemon.shares.isShared('demo'), true, 'wrong revision must not stop the active share');

    // Matching id stops exactly that share.
    const stopped = await daemon.dispatchControl({ cmd: 'unshare', name: 'demo', expectedShareId: started.shareId });
    assert.strictEqual(stopped.stopped, 'demo');
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share-link', name: 'demo', expectedShareId: started.shareId }),
      (err) => err.code === 'SHARE_NOT_ACTIVE'
    );

    // A new share instance gets a new shareId.
    const again = await daemon.dispatchControl({ cmd: 'share', name: 'demo', ttlMinutes: 60 });
    assert.notStrictEqual(again.shareId, started.shareId, 'every new share instance must get a fresh shareId');

    // Legacy unshare without expectedShareId still works (CLI contract).
    const legacyStop = await daemon.dispatchControl({ cmd: 'unshare', name: 'demo' });
    assert.strictEqual(legacyStop.stopped, 'demo');
    await assert.rejects(() => daemon.dispatchControl({ cmd: 'unshare', name: 'demo' }), /no active share/);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('share-link: expired share no longer hands out the secret link', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-expired-'));
  const cfScript = fakeCloudflared(dir, 'proto-expired');
  // Observed listener on the shared port: public share starts require a
  // verified target (see share lifecycle test).
  const listener = { pid: 33001, port: 3300, processKey: '33001:s', command: 'node', cwd: null, root: null, external: false };
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cfScript },
    listListeners: () => [listener],
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'demo', port: 3300 });
    const started = await daemon.dispatchControl({ cmd: 'share', name: 'demo', ttlMinutes: 0.1 });

    // Force expiry without waiting.
    const share = daemon.shares.shares.get('demo');
    share.gate.expiresAt = Date.now() - 1;
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share-link', name: 'demo', expectedShareId: started.shareId }),
      (err) => err.code === 'SHARE_NOT_ACTIVE'
    );
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('real control socket: envelope carries protocol fields and stable error codes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-sock-'));
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: true },
    listListeners: async () => [],
  });

  try {
    await daemon.start();
    await waitForFile(path.join(dir, 'daemon.sock'));

    const status = await sendToSocket(path.join(dir, 'daemon.sock'), { cmd: 'status' });
    assert.strictEqual(status.ok, true);
    assert.strictEqual(status.protocolVersion, 1);
    assert.ok(typeof status.daemonInstanceId === 'string');
    assert.ok(Array.isArray(status.routes));
    assert.ok(status.lan && typeof status.lan.available === 'boolean');

    const add = await sendToSocket(path.join(dir, 'daemon.sock'), { cmd: 'add', name: 'socktest', port: 59000, createOnly: true });
    assert.strictEqual(add.ok, true);

    const dup = await sendToSocket(path.join(dir, 'daemon.sock'), { cmd: 'add', name: 'socktest', port: 59001, createOnly: true });
    assert.strictEqual(dup.ok, false);
    assert.strictEqual(dup.code, 'NAME_CONFLICT');
    assert.strictEqual(dup.error, 'name "socktest" is already manually registered');

    const link = await sendToSocket(path.join(dir, 'daemon.sock'), { cmd: 'share-link', name: 'socktest', expectedShareId: 'x' });
    assert.strictEqual(link.ok, false);
    assert.strictEqual(link.code, 'SHARE_NOT_ACTIVE');

    const unknown = await sendToSocket(path.join(dir, 'daemon.sock'), { cmd: 'nope' });
    assert.strictEqual(unknown.ok, false);
    assert.strictEqual(unknown.code, undefined);
    assert.match(unknown.error, /unknown command/);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('control socket framing: byte-exact limit, split UTF-8 chunks, one request per connection', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-proto-frame-'));
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: true },
    listListeners: async () => [],
  });
  const sock = () => path.join(dir, 'daemon.sock');

  try {
    await daemon.start();
    await waitForFile(sock());

    // (a) A request line of exactly 65536 bytes (excluding the newline, so
    // 65537 wire bytes) must be accepted — the historical off-by-one
    // rejected exactly this shape.
    const probe = JSON.stringify({ cmd: 'status', pad: '' });
    const bigLine = JSON.stringify({ cmd: 'status', pad: 'x'.repeat(65536 - Buffer.byteLength(probe)) });
    assert.strictEqual(Buffer.byteLength(bigLine), 65536);
    const big = await sendRawBytes(sock(), Buffer.from(bigLine + '\n'));
    assert.strictEqual(big.response.ok, true, 'a full 64 KiB request line is valid');

    // (b) One byte over the line limit is refused and the connection closed.
    const overLine = JSON.stringify({ cmd: 'status', pad: 'x'.repeat(65537 - Buffer.byteLength(probe)) });
    assert.strictEqual(Buffer.byteLength(overLine), 65537);
    const over = await sendRawBytes(sock(), Buffer.from(overLine + '\n'));
    assert.strictEqual(over.response.ok, false);
    assert.strictEqual(over.response.code, 'REQUEST_TOO_LARGE');
    assert.strictEqual(over.closedByDaemon, true, 'daemon must close the socket after refusing');

    // (c) A multibyte UTF-8 character split across two socket chunks on the
    // SAME connection must survive byte-wise buffering (no per-chunk string
    // decoding) and still parse as one JSON line.
    const uniBytes = Buffer.from(JSON.stringify({ cmd: 'stäatus' }) + '\n', 'utf8');
    const splitAt = uniBytes.indexOf(Buffer.from('ä', 'utf8')) + 1; // inside the 2-byte sequence
    const uni = await sendRawBytes(sock(), uniBytes.subarray(0, splitAt), {
      secondWrite: uniBytes.subarray(splitAt),
      gapMs: 120,
    });
    assert.strictEqual(uni.response.ok, false);
    assert.match(uni.response.error, /unknown command: stäatus/);

    // (d) Two pipelined requests on one connection: only the first is
    // dispatched, the daemon answers once and closes its side.
    const two = await sendRawBytes(
      sock(),
      Buffer.from(
        JSON.stringify({ cmd: 'add', name: 'first', port: 59010, createOnly: true }) + '\n' +
        JSON.stringify({ cmd: 'add', name: 'second', port: 59011, createOnly: true }) + '\n'
      )
    );
    assert.strictEqual(two.response.ok, true);
    assert.strictEqual(two.response.added, 'first');
    assert.strictEqual(two.closedByDaemon, true, 'one request per connection: response is followed by close');

    const status = await sendToSocket(sock(), { cmd: 'status' });
    const names = status.routes.map((r) => r.name);
    assert.ok(names.includes('first'), 'the first pipelined request is dispatched');
    assert.ok(!names.includes('second'), 'the second pipelined request is never dispatched');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
