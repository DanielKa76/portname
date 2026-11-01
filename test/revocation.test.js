'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const http = require('http');

const { Daemon } = require('../lib/daemon');
const { createGateway, listenGateway } = require('../lib/proxy');
const { connectionPolicyViolation } = require('../lib/authorize');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A raw WebSocket echo upstream: answers the 101 handshake and echoes every
// byte afterwards (same pattern as proxy.test.js).
function wsEchoServer() {
  return new Promise((resolve) => {
    const server = net.createServer((sock) => {
      let handshaken = false;
      // A torn-down tunnel may reach the upstream as a RST (macOS sends one
      // when the gateway destroys a socket with unread echo data).
      sock.on('error', () => {});
      sock.on('data', (d) => {
        if (!handshaken && d.toString().toLowerCase().includes('upgrade: websocket')) {
          handshaken = true;
          sock.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: fake=\r\n\r\n');
          return;
        }
        sock.write(d);
      });
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

// Opens a WebSocket through a gateway/gate and resolves with observable
// state. Never rejects on close — the caller asserts on the state.
function wsConnect(port, host, { timeoutMs = 2000 } = {}) {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1');
    const state = { sock, upgraded: false, closed: false };
    sock.on('close', () => { state.closed = true; });
    sock.on('error', () => {});
    let data = '';
    sock.on('data', (d) => {
      data += d.toString();
      if (data.includes('101 Switching Protocols')) state.upgraded = true;
    });
    sock.on('connect', () => {
      sock.write(`GET /ws HTTP/1.1\r\nhost: ${host}\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: a==\r\nsec-websocket-version: 13\r\n\r\nPING`);
    });
    const start = Date.now();
    const poll = setInterval(() => {
      const echoed = data.indexOf('PING') !== -1 && data.indexOf('PING') !== data.lastIndexOf('PING');
      if (echoed || Date.now() - start > timeoutMs) {
        clearInterval(poll);
        resolve(state);
      }
    }, 10);
  });
}

// SSE-style upstream: first event immediately, then ticks; reports whether
// the upstream request side has been closed.
function sseServer() {
  const state = { server: null, port: null, upstreamClosed: false };
  return new Promise((resolve) => {
    state.server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
      res.write('data: hello\n\n');
      const t = setInterval(() => res.write('data: tick\n\n'), 20);
      req.on('close', () => {
        clearInterval(t);
        state.upstreamClosed = true;
      });
    });
    state.server.listen(0, '127.0.0.1', () => {
      state.port = state.server.address().port;
      resolve(state);
    });
  });
}

// Long-lived SSE client: resolves with { req, res, closed } after the first
// event; `closed` tracks the downstream response socket.
function sseRequest(port, host) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/', headers: { host }, agent: false }, (res) => {
      const state = { req, res, closed: false };
      res.on('close', () => { state.closed = true; });
      res.once('data', () => resolve(state));
    });
    req.on('error', () => {});
  });
}

async function waitFor(condition, { budgetMs = 2000, stepMs = 20 } = {}) {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > budgetMs) return false;
    await sleep(stepMs);
  }
  return true;
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
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
// Gateway-level: metadata tracking + revocation teardown mechanics.
// ---------------------------------------------------------------------------

test('gateway: exposure revocation tears down LAN websockets of that project, spares loopback and other projects', async () => {
  const app = await wsEchoServer();
  const other = await wsEchoServer();
  let loopbackMode = false; // test seam: classification of the next connections
  let appExposed = true;
  const gateway = createGateway({
    getRoute: (name) => {
      if (name === 'app') return { name: 'app', port: app.port, root: '/r/app' };
      if (name === 'other') return { name: 'other', port: other.port, root: '/r/other' };
      return null;
    },
    isExposed: (identity) => (identity === '/r/app' ? appExposed : identity === '/r/other'),
    // Simulated LAN: loopback-shaped sockets are treated as LAN clients.
    getLanInfo: () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' }),
    isLoopbackClient: () => loopbackMode,
    log: () => {},
  });
  const bind = await listenGateway(gateway, { mode: 'wildcard', port: 0, fallbackPort: 0 });

  let lanApp; let lanOther; let lbApp;
  try {
    loopbackMode = false; // act as LAN clients
    lanApp = await wsConnect(bind.primary, 'app.local');
    lanOther = await wsConnect(bind.primary, 'other.local');
    loopbackMode = true; // act as a loopback client
    lbApp = await wsConnect(bind.primary, 'app.local');

    assert.strictEqual(lanApp.upgraded, true, 'LAN websocket on exposed project must connect');
    assert.strictEqual(lanOther.upgraded, true, 'LAN websocket on other exposed project must connect');
    assert.strictEqual(lbApp.upgraded, true, 'loopback websocket must connect');
    assert.strictEqual(gateway.activeConnections.size, 3, 'all three connections tracked');

    appExposed = false; // LAN revocation for "app" only
    const revoked = [];
    gateway.revokeConnections((conn) => {
      const reason = connectionPolicyViolation(conn, {
        getRoute: gateway.getRoute,
        isExposedIdentity: gateway.isExposed,
      });
      if (reason) revoked.push({ name: conn.name, reason });
      return Boolean(reason);
    });

    assert.deepStrictEqual(revoked, [{ name: 'app', reason: 'exposure-revoked' }]);
    assert.strictEqual(await waitFor(() => lanApp.closed), true, 'LAN websocket of revoked project must be torn down');
    assert.strictEqual(lanOther.closed, false, 'other project must stay untouched');
    assert.strictEqual(lbApp.closed, false, 'loopback traffic must stay untouched');
  } finally {
    for (const c of [lanApp, lanOther, lbApp]) {
      if (c && !c.sock.destroyed) c.sock.destroy();
    }
    await gateway.close();
    await new Promise((r) => app.server.close(r));
    await new Promise((r) => other.server.close(r));
  }
});

test('gateway: exposure revocation tears down LAN SSE streams and their upstream requests', async () => {
  const sse = await sseServer();
  let loopbackMode = false;
  let appExposed = true;
  const gateway = createGateway({
    getRoute: (name) => (name === 'app' ? { name: 'app', port: sse.port, root: '/r/app' } : null),
    isExposed: (identity) => (identity === '/r/app' ? appExposed : false),
    getLanInfo: () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' }),
    isLoopbackClient: () => loopbackMode,
    log: () => {},
  });
  const bind = await listenGateway(gateway, { mode: 'wildcard', port: 0, fallbackPort: 0 });

  let lanSse; let lbSse;
  try {
    loopbackMode = false;
    lanSse = await sseRequest(bind.primary, 'app.local');
    loopbackMode = true;
    lbSse = await sseRequest(bind.primary, 'app.local');
    assert.strictEqual(sse.upstreamClosed, false, 'both upstream streams alive before revocation');

    appExposed = false;
    gateway.revokeConnections((conn) => Boolean(connectionPolicyViolation(conn, {
      getRoute: gateway.getRoute,
      isExposedIdentity: gateway.isExposed,
    })));

    assert.strictEqual(await waitFor(() => lanSse.closed), true, 'LAN SSE response must be torn down');
    assert.strictEqual(await waitFor(() => sse.upstreamClosed), true, 'both upstream requests must end');
    assert.strictEqual(lbSse.closed, false, 'loopback SSE must stay untouched');
  } finally {
    for (const c of [lanSse, lbSse]) {
      if (c) c.req.destroy();
    }
    await gateway.close();
    sse.server.closeAllConnections();
    await new Promise((r) => sse.server.close(r));
  }
});

test('gateway: per-request recheck — a keep-alive connection gets refused on the request after exposure revocation', async () => {
  const app = await wsEchoServer(); // any HTTP echo works; reuse pattern
  const httpUp = await new Promise((resolve) => {
    const server = http.createServer((req, res) => res.end('marker:' + req.url));
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
  let appExposed = true;
  const gateway = createGateway({
    getRoute: (name) => (name === 'app' ? { name: 'app', port: httpUp.port, root: '/r/app' } : null),
    isExposed: (identity) => (identity === '/r/app' ? appExposed : false),
    log: () => {},
  });
  const bind = await listenGateway(gateway, { mode: 'wildcard', port: 0, fallbackPort: 0 });

  const get = (path) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: bind.primary, path, headers: { host: 'app.local' }, agent: keepAlive }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode, body }));
    }).on('error', reject);
  });
  const keepAlive = new http.Agent({ keepAlive: true, maxSockets: 1 });

  try {
    const first = await get('/');
    assert.strictEqual(first.status, 200);

    appExposed = false;
    const second = await get('/again');
    assert.strictEqual(second.status, 404, 'revocation must apply per request, not per keep-alive connection');

    appExposed = true;
    const third = await get('/third');
    assert.strictEqual(third.status, 200, 're-exposure must serve again on the same connection');
  } finally {
    keepAlive.destroy();
    await gateway.close();
    httpUp.server.closeAllConnections();
    await new Promise((r) => httpUp.server.close(r));
    await new Promise((r) => app.server.close(r));
  }
});

test('gateway: unresponsive upstream is bounded by the response-header timeout and answered with no-store 502', async () => {
  const hang = await new Promise((resolve) => {
    const server = http.createServer(() => { /* never responds */ });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
  const gateway = createGateway({
    getRoute: () => ({ name: 'app', port: hang.port, root: '/r/app' }),
    isExposed: () => false,
    timeouts: { upstreamResponseHeaderTimeoutMs: 120 },
    log: () => {},
  });
  const bind = await listenGateway(gateway, { mode: 'wildcard', port: 0, fallbackPort: 0 });

  try {
    const started = Date.now();
    const res = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: bind.primary, path: '/', headers: { host: 'app.localhost' }, agent: false }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      }).on('error', reject);
    });
    assert.strictEqual(res.status, 502);
    assert.ok((res.headers['cache-control'] || '').includes('no-store'), 'error answers must be no-store');
    assert.ok(Date.now() - started < 5000, 'the wait must be bounded, not endless');
  } finally {
    await gateway.close();
    hang.server.closeAllConnections();
    await new Promise((r) => hang.server.close(r));
  }
});

// ---------------------------------------------------------------------------
// Daemon-level: enforcement wiring on refresh (route removal / target change /
// rename / exposure) and the discovery freshness policy for public shares.
// ---------------------------------------------------------------------------

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

test('daemon: route removal tears down established websockets of that project; other projects untouched', async () => {
  const dir = tmpDir('pn-revoke-route-');
  const shopDir = path.join(dir, 'shop');
  const apiDir = path.join(dir, 'api');
  fs.mkdirSync(shopDir);
  fs.mkdirSync(apiDir);
  const shopWs = await wsEchoServer();
  const apiWs = await wsEchoServer();

  let listeners = [
    autoListener({ pid: 4101, port: shopWs.port, root: shopDir, processKey: '4101:a' }),
    autoListener({ pid: 4102, port: apiWs.port, root: apiDir, processKey: '4102:b' }),
  ];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => listeners,
  });

  let c1; let c2;
  try {
    const gwPort = await daemon.start();
    c1 = await wsConnect(gwPort, 'shop.localhost');
    c2 = await wsConnect(gwPort, 'api.localhost');
    assert.strictEqual(c1.upgraded, true);
    assert.strictEqual(c2.upgraded, true);

    listeners = [autoListener({ pid: 4102, port: apiWs.port, root: apiDir, processKey: '4102:b' })];
    await daemon.refresh();

    assert.strictEqual(await waitFor(() => c1.closed), true, 'websocket of the removed route must be torn down');
    assert.strictEqual(c2.closed, false, 'websocket of the surviving project must stay untouched');
  } finally {
    for (const c of [c1, c2]) {
      if (c && !c.sock.destroyed) c.sock.destroy();
    }
    await daemon.stop();
    await new Promise((r) => shopWs.server.close(r));
    await new Promise((r) => apiWs.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: target port change tears down connections pinned to the old target generation', async () => {
  const dir = tmpDir('pn-revoke-target-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const wsA = await wsEchoServer();
  const wsB = await wsEchoServer();

  let listeners = [autoListener({ pid: 4201, port: wsA.port, root: shopDir, processKey: '4201:genA' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => listeners,
  });

  let conn;
  try {
    const gwPort = await daemon.start();
    conn = await wsConnect(gwPort, 'shop.localhost');
    assert.strictEqual(conn.upgraded, true);

    // Generation B takes over on a different port.
    listeners = [autoListener({ pid: 4202, port: wsB.port, root: shopDir, processKey: '4202:genB' })];
    await daemon.refresh();

    assert.strictEqual(await waitFor(() => conn.closed), true, 'connection pinned to the old target must be torn down');
  } finally {
    if (conn && !conn.sock.destroyed) conn.sock.destroy();
    await daemon.stop();
    await new Promise((r) => wsA.server.close(r));
    await new Promise((r) => wsB.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: exposure revocation leaves loopback connections alive but refuses new requests per request', async () => {
  const dir = tmpDir('pn-revoke-expose-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const shopWs = await wsEchoServer();

  const listeners = [autoListener({ pid: 4301, port: shopWs.port, root: shopDir, processKey: '4301:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: () => listeners,
  });

  let conn;
  try {
    const gwPort = await daemon.start();
    daemon.announcer.lanAddress = () => '192.168.1.50';

    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    conn = await wsConnect(gwPort, 'shop.local');
    assert.strictEqual(conn.upgraded, true, 'loopback client may use the exposed *.local name');

    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: false });

    assert.strictEqual(conn.closed, false, 'loopback traffic must not be torn down by a LAN revocation');
    assert.strictEqual(daemon.gateway.activeConnections.size, 1, 'connection stays tracked and alive');

    const refused = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: gwPort, path: '/', headers: { host: 'shop.local' }, agent: false }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      }).on('error', reject);
    });
    assert.strictEqual(refused, 404, 'new requests must be refused per request after revocation');
  } finally {
    if (conn && !conn.sock.destroyed) conn.sock.destroy();
    await daemon.stop();
    await new Promise((r) => shopWs.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: rename revokes the active public share of the renamed project', async () => {
  const dir = tmpDir('pn-revoke-rename-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const cf = writeCfScript(dir, 'revoke-rename');
  const listeners = [autoListener({ pid: 4401, port: 4444, root: shopDir, processKey: '4401:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
    assert.strictEqual(daemon.shares.isShared('shop'), true);

    await daemon.dispatchControl({ cmd: 'rename', name: 'shop', newName: 'boutique' });

    assert.strictEqual(daemon.shares.isShared('shop'), false, 'rename must revoke the share bound to the old name');
    assert.strictEqual(daemon.shares.status().length, 0);
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('freshness policy: public share start is refused while the discovery verification is stale, allowed again after recovery', async () => {
  const dir = tmpDir('pn-fresh-start-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const cf = writeCfScript(dir, 'fresh-start');
  let failScans = false;
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    routeFreshnessMs: 100,
    listListeners: async () => {
      if (failScans) throw new Error('lsof exploded');
      return [autoListener({ pid: 4501, port: 4555, root: shopDir, processKey: '4501:a' })];
    },
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
    await daemon.dispatchControl({ cmd: 'unshare', name: 'shop' });

    failScans = true;
    await daemon.refresh();

    // The displayed routes stay (a failed scan must not look like "all stopped"),
    // but the share DECISION is separated from that display state.
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.routes.length, 1, 'stale routes stay visible as display state');
    assert.ok(status.scanError, 'degraded scan is reported');

    await sleep(150); // exceed routeFreshnessMs
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 }),
      (err) => err.code === 'SHARE_TARGET_UNVERIFIED' && /verif/i.test(err.message)
    );

    failScans = false;
    await daemon.refresh();
    const again = await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
    assert.ok(again.url.includes('fresh-start'), 'a fresh successful scan re-enables public sharing');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('freshness policy: manual public share requires an observed listener and pins its process generation', async () => {
  const dir = tmpDir('pn-fresh-manual-');
  const cf = writeCfScript(dir, 'fresh-manual');
  let listeners = [];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'db', port: 4666 });

    // A port alone is not a verified target: nothing observed on 4666 yet.
    await assert.rejects(
      () => daemon.dispatchControl({ cmd: 'share', name: 'db', ttlMinutes: 60 }),
      (err) => err.code === 'SHARE_TARGET_UNVERIFIED' && /4666/.test(err.message)
    );

    listeners = [{ pid: 4601, port: 4666, processKey: '4601:pgA', command: 'postgres', cwd: null, root: null, external: false }];
    await daemon.refresh();
    const started = await daemon.dispatchControl({ cmd: 'share', name: 'db', ttlMinutes: 60 });
    assert.ok(String(started.url).includes('fresh-manual'));

    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.shares[0].pinnedPid, 4601, 'the observed listener pins the generation');
    assert.strictEqual(status.shares[0].pinnedProcessKey, '4601:pgA');

    // The port is manually reused by a different process: the public share dies.
    listeners = [{ pid: 4602, port: 4666, processKey: '4602:pgB', command: 'python3', cwd: null, root: null, external: false }];
    await daemon.refresh();
    assert.strictEqual(daemon.shares.isShared('db'), false, 'port reuse by another process must revoke the share');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('freshness policy: active share is revoked after sustained scan failures exceed the grace window and never silently re-activated', async () => {
  const dir = tmpDir('pn-fresh-grace-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const cf = writeCfScript(dir, 'fresh-grace');
  let failScans = false;
  const listeners = [autoListener({ pid: 4701, port: 4777, root: shopDir, processKey: '4701:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    // Wide grace (same approach as effective-exposure-status.test.js): the
    // healthy-phase assertions — share start incl. the fake tunnel's boot
    // and the deferred first failure — must survive real elapsed time under
    // parallel test load. A 1s grace here was tighter than a loaded tunnel
    // boot and tripped the honest activation guard on the start itself.
    // The deadline is instead exercised deterministically below by
    // backdating the share's verification timestamp past the grace window.
    shareVerifyGraceMs: 60_000,
    // No background passes: the deadline is driven by the explicit refresh()
    // calls, so a timer pass can never re-stamp the backdated verification.
    refreshMs: 60_000,
    listListeners: async () => {
      if (failScans) throw new Error('lsof exploded');
      return listeners;
    },
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
    assert.strictEqual(daemon.shares.isShared('shop'), true);
    const shareId = daemon.shares.status()[0].shareId;
    assert.ok(daemon.shares.status()[0].lastVerifiedAt > 0, 'share carries its last verification time');

    // One failed scan inside the grace window: deferred, not immediate.
    failScans = true;
    await daemon.refresh();
    assert.strictEqual(daemon.shares.isShared('shop'), true, 'a single failed scan must not revoke immediately');

    // Sustained failure beyond the grace window: bounded revoke. The aging
    // is applied as an explicit time offset on the share's honest
    // verification timestamp (same seam as the STARTING tests below)
    // instead of sleeping real time.
    daemon.shares.shares.get('shop').lastVerifiedAt = Date.now() - (daemon.shareVerifyGraceMs + 1000);
    await daemon.refresh();
    assert.strictEqual(daemon.shares.isShared('shop'), false, 'stale verification must not run indefinitely');

    // Recovery: a later successful scan must NOT silently re-activate the share.
    failScans = false;
    await daemon.refresh();
    await daemon.refresh();
    assert.strictEqual(daemon.shares.isShared('shop'), false, 'recovery must never resurrect a revoked share');
    const status = await daemon.dispatchControl({ cmd: 'status' });
    assert.strictEqual(status.shares.length, 0);
    assert.ok(shareId, 'shareId captured before revocation');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('daemon: exposure revocation tears down established LAN connections even while discovery keeps failing', async () => {
  const dir = tmpDir('pn-revoke-scanfail-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const shopWs = await wsEchoServer();

  let failScans = false;
  const listeners = [autoListener({ pid: 4801, port: shopWs.port, root: shopDir, processKey: '4801:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      if (failScans) throw new Error('lsof exploded');
      return listeners;
    },
  });

  let lanConn; let lbConn;
  let lanMode = false;
  try {
    const gwPort = await daemon.start();
    daemon.announcer.lanAddress = () => '192.168.1.50';
    // Simulated LAN: loopback-shaped sockets are classified per test flag
    // (same seam pattern as the gateway-level tests above).
    daemon.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
    daemon.gateway.isLoopbackClient = () => lanMode;

    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    lanMode = false; // act as a LAN client
    lanConn = await wsConnect(gwPort, 'shop.local');
    lanMode = true; // act as a loopback client
    lbConn = await wsConnect(gwPort, 'shop.local');
    assert.strictEqual(lanConn.upgraded, true, 'LAN websocket on the exposed project must connect');
    assert.strictEqual(lbConn.upgraded, true, 'loopback websocket must connect');

    // Sustained scan failure: every discovery pass now errors, so the
    // successful-pass revoke path never runs again.
    failScans = true;
    await daemon.refresh();

    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: false });

    assert.strictEqual(await waitFor(() => lanConn.closed), true, 'LAN websocket must be torn down even when scans keep failing');
    assert.strictEqual(lbConn.closed, false, 'loopback websocket must stay untouched');
  } finally {
    for (const c of [lanConn, lbConn]) {
      if (c && !c.sock.destroyed) c.sock.destroy();
    }
    await daemon.stop();
    await new Promise((r) => shopWs.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('freshness policy: a STARTING share carries its honest verification age and is revoked when booting past the grace window', async () => {
  const dir = tmpDir('pn-fresh-starting-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  // Mock cloudflared that prints its URL only after 5s: the share stays
  // STARTING well past the grace window of this test.
  const cf = path.join(dir, 'cf-slow-url.js');
  fs.writeFileSync(
    cf,
    '#!/usr/bin/env node\nsetTimeout(() => console.log("https://starting-scanfail.trycloudflare.com"), 5000);\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cf, 0o755);

  let failScans = false;
  const listeners = [autoListener({ pid: 4811, port: 4889, root: shopDir, processKey: '4811:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    shareVerifyGraceMs: 80,
    listListeners: async () => {
      if (failScans) throw new Error('lsof exploded');
      return listeners;
    },
  });

  try {
    await daemon.start();
    // Do not await: the start only resolves once the tunnel prints a URL.
    const starting = daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 }).then(
      () => null,
      (err) => err
    );
    for (let i = 0; i < 200 && daemon.shares.status().length === 0; i++) {
      await sleep(10);
    }
    assert.strictEqual(daemon.shares.status()[0].state, 'STARTING', 'share must be observed before its tunnel boots');
    // Honest verification age: the pre-start scan that passed the freshness
    // gate — not a stamp from the (much later) tunnel activation.
    assert.strictEqual(
      daemon.shares.status()[0].lastVerifiedAt, daemon.lastGoodScanAt,
      'the share must carry the real target verification time'
    );

    failScans = true;
    await daemon.refresh();
    assert.strictEqual(daemon.shares.isShared('shop'), true, 'a single failed scan must not revoke immediately');

    await sleep(120); // exceed the grace window while the tunnel is still booting
    await daemon.refresh();
    assert.strictEqual(
      daemon.shares.isShared('shop'), false,
      'a share booting past the grace window without new verification must be revoked — tunnel ready is not target verified'
    );

    // The revoked startup must surface as a visible refusal, not activate.
    const outcome = await starting;
    assert.ok(outcome instanceof Error, 'the delayed activation must be refused with a visible error');

    // Recovery must never resurrect the revoked share.
    failScans = false;
    await daemon.refresh();
    await daemon.refresh();
    assert.strictEqual(daemon.shares.status().length, 0, 'recovery must never resurrect a revoked share');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('freshness policy: a STARTING share without lastVerifiedAt survives a failed pass (boot protection) and is revoked once its timestamp ages past the grace window', async () => {
  const dir = tmpDir('pn-fresh-starting-raw-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  // Mock cloudflared that prints its URL only after 5s: the share stays
  // STARTING for the whole test.
  const cf = path.join(dir, 'cf-slow-url-raw.js');
  fs.writeFileSync(
    cf,
    '#!/usr/bin/env node\nsetTimeout(() => console.log("https://starting-raw.trycloudflare.com"), 5000);\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cf, 0o755);

  let failScans = false;
  const listeners = [autoListener({ pid: 4951, port: 4895, root: shopDir, processKey: '4951:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    shareVerifyGraceMs: 100,
    listListeners: async () => {
      if (failScans) throw new Error('lsof exploded');
      return listeners;
    },
  });

  try {
    await daemon.start();
    // Do not await: the start only resolves once the tunnel prints a URL.
    const starting = daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 }).then(
      () => null,
      (err) => err
    );
    for (let i = 0; i < 200 && daemon.shares.status().length === 0; i++) {
      await sleep(10);
    }
    assert.strictEqual(daemon.shares.status()[0].state, 'STARTING', 'share must be observed before its tunnel boots');

    // Wait until the boot phase has spawned the tunnel (the abort listener is
    // registered in the same synchronous block): the revoke below must hit a
    // STARTING share mid-boot, not the tiny listen-pending window in which a
    // start promise cannot be interrupted at all.
    for (let i = 0; i < 200; i++) {
      const booting = daemon.shares.shares.get('shop');
      if (booting && booting.cloudflared) break;
      await sleep(5);
    }
    assert.ok(daemon.shares.shares.get('shop').cloudflared, 'the tunnel must have spawned while the share is STARTING');

    // Only a direct ShareManager caller can produce this state: the control
    // handler always stamps verifiedAt from the scan that passed the start
    // freshness gate. Null it to model a caller that never verified.
    daemon.shares.shares.get('shop').lastVerifiedAt = null;

    // Boot protection: a STARTING share that has never been verified is not
    // staleness-killed mid-boot by a failed discovery pass.
    failScans = true;
    await daemon.refresh();
    assert.strictEqual(
      daemon.shares.isShared('shop'), true,
      'a STARTING share without a verification timestamp must survive a failed pass'
    );

    // Once a timestamp exists and ages past the grace window mid-boot, the
    // bounded revoke applies exactly as for every verified share.
    daemon.shares.shares.get('shop').lastVerifiedAt = Date.now() - 5000;
    await daemon.refresh();
    assert.strictEqual(
      daemon.shares.isShared('shop'), false,
      'a STARTING share whose verification aged past the grace window must be revoked'
    );

    // The revoked startup must surface as a visible refusal, not activate.
    const outcome = await starting;
    assert.ok(outcome instanceof Error, 'the delayed activation must be refused with a visible error');

    // Recovery must never resurrect the revoked share.
    failScans = false;
    await daemon.refresh();
    await daemon.refresh();
    assert.strictEqual(daemon.shares.status().length, 0, 'recovery must never resurrect a revoked share');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('freshness policy: manual share detects PID recycling through the pinned process generation', async () => {
  const dir = tmpDir('pn-fresh-pid-recycle-');
  const cf = writeCfScript(dir, 'fresh-recycle');
  let listeners = [{ pid: 4821, port: 4890, processKey: '4821:gen1', command: 'postgres', cwd: null, root: null, external: false }];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'add', name: 'db', port: 4890 });
    await daemon.refresh();
    await daemon.dispatchControl({ cmd: 'share', name: 'db', ttlMinutes: 60 });
    assert.strictEqual(daemon.shares.isShared('db'), true);

    // Same PID comes back with a new start time: recycled pid, new generation.
    listeners = [{ pid: 4821, port: 4890, processKey: '4821:gen2', command: 'postgres', cwd: null, root: null, external: false }];
    await daemon.refresh();

    assert.strictEqual(daemon.shares.isShared('db'), false, 'a recycled PID (new process generation) must revoke the share');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// LAN exposure freshness deadline: WLAN access (new requests AND
// established streams) is bounded by an honest target-verification window,
// exactly like public shares. An explicit expose-off closes streams directly,
// never via the next scan pass.
// ---------------------------------------------------------------------------

test('LAN freshness: sustained scan failure past the deadline tears down WLAN streams, refuses new WLAN requests, spares loopback', async () => {
  const dir = tmpDir('pn-lan-fresh-');
  const shopDir = path.join(dir, 'shop');
  const apiDir = path.join(dir, 'api');
  fs.mkdirSync(shopDir);
  fs.mkdirSync(apiDir);
  const shopWs = await wsEchoServer();
  const apiWs = await wsEchoServer();

  let failScans = false;
  const listeners = [
    autoListener({ pid: 4901, port: shopWs.port, root: shopDir, processKey: '4901:a' }),
    autoListener({ pid: 4902, port: apiWs.port, root: apiDir, processKey: '4902:b' }),
  ];
  // Stub announcer (no real Bonjour children) with a LAN address: keeps the
  // test free of spawned dns-sd processes despite the fast refresh polling.
  const announcer = {
    cleanupOrphans() {},
    childPids() { return []; },
    lanAddress() { return '192.168.1.50'; },
    lanInterfaceName() { return 'en0'; },
    stopAll() {},
    sync() { return { ok: true }; },
  };
  const daemon = new Daemon({
    dir,
    announcer,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    // Fast polling keeps the LAN verification fresh during the healthy
    // phase (like the real 3s period relative to the 20s grace); the short
    // grace makes the deadline phase fast.
    refreshMs: 50,
    lanVerifyGraceMs: 200,
    listListeners: async () => {
      if (failScans) throw new Error('lsof exploded');
      return listeners;
    },
  });

  let lanShop; let lbShop; let lbApi;
  let lanMode = false;
  try {
    const gwPort = await daemon.start();
    daemon.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
    daemon.gateway.isLoopbackClient = () => lanMode;

    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    lanMode = false; // act as a WLAN client
    lanShop = await wsConnect(gwPort, 'shop.local');
    lanMode = true; // act as a loopback client
    lbShop = await wsConnect(gwPort, 'shop.local');
    lbApi = await wsConnect(gwPort, 'api.localhost');
    assert.strictEqual(lanShop.upgraded, true, 'WLAN websocket on the exposed project must connect');
    assert.strictEqual(lbShop.upgraded, true);
    assert.strictEqual(lbApi.upgraded, true);

    // Sustained scan failure: no pass verifies the target anymore.
    failScans = true;
    await daemon.refresh();
    assert.strictEqual(lanShop.closed, false, 'a single failed scan must not revoke immediately');

    await sleep(320); // exceed lanVerifyGraceMs
    await daemon.refresh();

    assert.strictEqual(await waitFor(() => lanShop.closed), true, 'established WLAN stream must be torn down at the deadline');
    assert.strictEqual(lbShop.closed, false, 'loopback traffic must stay untouched');
    assert.strictEqual(lbApi.closed, false, 'other projects must stay untouched');

    lanMode = false;
    const refused = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: gwPort, path: '/', headers: { host: 'shop.local' }, agent: false }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      }).on('error', reject);
    });
    assert.strictEqual(refused, 404, 'new WLAN requests must be refused at the deadline');

    // Recovery: one successful scan re-verifies the target and re-enables.
    failScans = false;
    await daemon.refresh();
    const again = await wsConnect(gwPort, 'shop.local');
    assert.strictEqual(again.upgraded, true, 'a fresh successful scan re-enables WLAN access');
    again.sock.destroy();
  } finally {
    for (const c of [lanShop, lbShop, lbApi]) {
      if (c && !c.sock.destroyed) c.sock.destroy();
    }
    await daemon.stop();
    await new Promise((r) => shopWs.server.close(r));
    await new Promise((r) => apiWs.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('LAN freshness: explicit expose-off closes established WLAN streams immediately, without waiting for the blocked scan', async () => {
  const dir = tmpDir('pn-lan-off-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const shopWs = await wsEchoServer();

  let holdScans = false;
  let releaseScan = null;
  const listeners = [autoListener({ pid: 4921, port: shopWs.port, root: shopDir, processKey: '4921:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      // Hold exactly ONE pass: the expose handler's trailing refresh() must
      // still be able to drain as a follow-up once the barrier is released.
      if (holdScans) {
        holdScans = false;
        await new Promise((resolve) => { releaseScan = resolve; });
      }
      return listeners;
    },
  });

  let lanConn; let lbConn;
  let lanMode = false;
  try {
    const gwPort = await daemon.start();
    daemon.announcer.lanAddress = () => '192.168.1.50';
    daemon.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
    daemon.gateway.isLoopbackClient = () => lanMode;

    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    lanMode = false;
    lanConn = await wsConnect(gwPort, 'shop.local');
    lanMode = true;
    lbConn = await wsConnect(gwPort, 'shop.local');
    assert.strictEqual(lanConn.upgraded, true);

    // Block the in-flight scan: the expose handler's trailing refresh()
    // cannot finish, so scan-dependent teardown is unavailable.
    holdScans = true;
    const blockedPass = daemon.refresh();
    for (let i = 0; i < 200 && !releaseScan; i++) await sleep(5);
    assert.ok(releaseScan, 'the pass must be observed hanging inside the scan');

    const offPromise = daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: false });
    assert.strictEqual(
      await waitFor(() => lanConn.closed),
      true,
      'explicit revocation must close established WLAN streams directly, not via the blocked scan'
    );
    assert.strictEqual(lbConn.closed, false, 'loopback traffic must stay untouched');

    releaseScan();
    await blockedPass;
    await offPromise;
    assert.strictEqual(daemon.registry.isExposed(shopDir), false);
  } finally {
    for (const c of [lanConn, lbConn]) {
      if (c && !c.sock.destroyed) c.sock.destroy();
    }
    await daemon.stop();
    await new Promise((r) => shopWs.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('LAN freshness: removing an exposed manual project closes established WLAN streams immediately, without waiting for the blocked scan', async () => {
  const dir = tmpDir('pn-lan-remove-');
  const shopWs = await wsEchoServer();

  let holdScans = false;
  let releaseScan = null;
  // Manual target: the scan observes the listener on the pinned port (a
  // manual project has no process generation of its own — the observation
  // is its verification).
  const listeners = [{ pid: 4941, port: shopWs.port, processKey: '4941:m', command: 'postgres', cwd: null, root: null, external: false }];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    listListeners: async () => {
      // Hold exactly ONE pass: the remove handler's trailing refresh() must
      // still be able to drain as a follow-up once the barrier is released.
      if (holdScans) {
        holdScans = false;
        await new Promise((resolve) => { releaseScan = resolve; });
      }
      return listeners;
    },
  });

  let lanConn; let lbConn;
  let lanMode = false;
  try {
    const gwPort = await daemon.start();
    daemon.announcer.lanAddress = () => '192.168.1.50';
    daemon.gateway.getLanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
    daemon.gateway.isLoopbackClient = () => lanMode;

    await daemon.dispatchControl({ cmd: 'add', name: 'shop', port: shopWs.port });
    await daemon.refresh();
    await daemon.dispatchControl({ cmd: 'expose', name: 'shop', on: true });
    lanMode = false;
    lanConn = await wsConnect(gwPort, 'shop.local');
    lanMode = true;
    lbConn = await wsConnect(gwPort, 'shop.local');
    assert.strictEqual(lanConn.upgraded, true, 'the exposed manual project must serve the LAN websocket');

    // Block the in-flight scan: the remove handler's trailing refresh()
    // cannot finish, so scan-dependent teardown is unavailable.
    holdScans = true;
    const blockedPass = daemon.refresh();
    for (let i = 0; i < 200 && !releaseScan; i++) await sleep(5);
    assert.ok(releaseScan, 'the pass must be observed hanging inside the scan');

    const removePromise = daemon.dispatchControl({ cmd: 'remove', name: 'shop' });
    assert.strictEqual(
      await waitFor(() => lanConn.closed),
      true,
      'removing an exposed manual project must close established WLAN streams directly, not via the blocked scan'
    );
    assert.strictEqual(lbConn.closed, false, 'loopback traffic must stay untouched');

    releaseScan();
    await blockedPass;
    await removePromise;
    assert.strictEqual(daemon.registry.isExposed('manual:shop'), false);
  } finally {
    for (const c of [lanConn, lbConn]) {
      if (c && !c.sock.destroyed) c.sock.destroy();
    }
    await daemon.stop();
    await new Promise((r) => shopWs.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Revocation-safe pending starts: a start/replacement job waiting on a
// teardown must be cancelled by a global revocation (unshare-all, shutdown)
// instead of starting its share afterwards.
// ---------------------------------------------------------------------------

function holdGateClose(daemon, name) {
  const gate = daemon.shares.shares.get(name).gate;
  const origClose = gate.close.bind(gate);
  let releaseClose = null;
  gate.close = () => new Promise((resolve) => {
    releaseClose = () => resolve(origClose());
  });
  return { get release() { return releaseClose; } };
}

test('revocation safety: unshare-all cancels a pending replacement start so no tunnel survives the revocation', async () => {
  const dir = tmpDir('pn-revoke-pending-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const cf = writeCfScript(dir, 'pending-start');
  const listeners = [autoListener({ pid: 4931, port: 4991, root: shopDir, processKey: '4931:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });
    const firstChild = daemon.shares.childPids()[0];

    // Hold the old share's teardown: the replacement start must wait there.
    const hold = holdGateClose(daemon, 'shop');
    const replacement = daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 30 }).then(
      () => null,
      (err) => err
    );
    for (let i = 0; i < 200 && (!daemon.shares.status()[0] || daemon.shares.status()[0].state !== 'STOPPING'); i++) {
      await sleep(5);
    }
    assert.strictEqual(daemon.shares.status()[0].state, 'STOPPING', 'replacement must be waiting inside the teardown');

    // Global revocation while the replacement is still waiting.
    const unshared = daemon.dispatchControl({ cmd: 'unshare-all' });
    await sleep(30); // let unshare-all register its revocation generation
    hold.release();

    const outcome = await replacement;
    assert.ok(outcome instanceof Error, 'the pending replacement must be cancelled by the global revocation');
    assert.match(outcome.message, /revocation/i);
    await unshared;
    assert.strictEqual(daemon.shares.status().length, 0, 'no share may survive the revocation');
    assert.strictEqual(daemon.shares.childPids().length, 0, 'no tunnel process may survive');
    let firstChildAlive = true;
    try { process.kill(firstChild, 0); } catch { firstChildAlive = false; }
    assert.strictEqual(firstChildAlive, false, 'the old tunnel child must be gone');
  } finally {
    // Robust cleanup even on failure: a leaked replacement share (the bug
    // this test guards against) must never keep the event loop alive.
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('revocation safety: daemon shutdown cancels a pending replacement start', async () => {
  const dir = tmpDir('pn-revoke-shutdown-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const cf = writeCfScript(dir, 'pending-shutdown');
  const listeners = [autoListener({ pid: 4941, port: 4992, root: shopDir, processKey: '4941:a' })];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false, cloudflaredBin: cf },
    listListeners: () => listeners,
  });

  try {
    await daemon.start();
    await daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 60 });

    const hold = holdGateClose(daemon, 'shop');
    const replacement = daemon.dispatchControl({ cmd: 'share', name: 'shop', ttlMinutes: 30 }).then(
      () => null,
      (err) => err
    );
    for (let i = 0; i < 200 && (!daemon.shares.status()[0] || daemon.shares.status()[0].state !== 'STOPPING'); i++) {
      await sleep(5);
    }

    const stopping = daemon.stop();
    await sleep(30); // let the shutdown sweep register its revocation generation
    hold.release();

    const outcome = await replacement;
    assert.ok(outcome instanceof Error, 'the pending replacement must be cancelled by the shutdown');
    assert.match(outcome.message, /revocation/i);
    await stopping;
    assert.strictEqual(daemon.shares.status().length, 0, 'no share may survive the shutdown');
    assert.strictEqual(daemon.shares.childPids().length, 0, 'no tunnel process may survive the shutdown');
  } finally {
    await daemon.shares.stopAll().catch(() => {});
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
