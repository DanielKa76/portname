'use strict';

// Regression tests for gateway hardening: hostile peers and misbehaving
// upstreams must never crash the daemon, desynchronize pooled upstream
// connections, smuggle requests past header sanitization, or lock the
// loopback developer out.

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const { createGateway, listenGateway } = require('../lib/proxy');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tempHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'portname-gw-hardening-'));
}

function startUpstream(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

async function startGateway(routes, opts = {}) {
  const gateway = createGateway({
    getRoute: (name) => routes[name] || null,
    isExposed: opts.isExposed || (() => false),
    getLanInfo: opts.getLanInfo,
    isLoopbackClient: opts.isLoopbackClient || null,
    timeouts: opts.timeouts || {},
    log: () => {},
  });
  const bind = await listenGateway(gateway, { mode: 'wildcard', port: 0, fallbackPort: 0 });
  return { gateway, port: bind.primary };
}

async function stop(gateway, upstreams = []) {
  await gateway.close();
  for (const u of upstreams) {
    u.closeAllConnections();
    await new Promise((r) => u.close(r));
  }
}

function get(port, host, reqPath = '/') {
  return new Promise((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port, path: reqPath, headers: { host }, agent: false }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
      })
      .on('error', reject);
  });
}

// Sends raw bytes and collects everything until the peer closes (or a
// deadline passes, which is reported rather than thrown).
function rawExchange(port, payload, { timeoutMs = 2000, onConnect } = {}) {
  return new Promise((resolve) => {
    let data = '';
    let timer;
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write(payload);
      if (onConnect) onConnect(sock);
    });
    sock.on('data', (d) => (data += d.toString('latin1')));
    sock.on('error', () => {});
    sock.on('close', () => {
      clearTimeout(timer);
      resolve({ data, closed: true });
    });
    timer = setTimeout(() => {
      sock.destroy();
      resolve({ data, closed: false });
    }, timeoutMs);
  });
}

// ---------------------------------------------------------------------------
// CONNECT + peer reset (Node detaches its socket error handler before
// emitting 'connect'): the gateway process must survive.
// ---------------------------------------------------------------------------

const CHILD_GATEWAY = `
const { createGateway } = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'proxy.js'))});
const gateway = createGateway({ getRoute: () => null, log: () => {} });
const server = gateway._createServer();
server.listen(0, '127.0.0.1', () => process.stdout.write(server.address().port + '\\n'));
`;

function spawnGatewayProcess() {
  const home = tempHome();
  const child = spawn(process.execPath, ['-e', CHILD_GATEWAY], {
    env: { ...process.env, HOME: home },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (d) => (stderr += d));
  const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })));
  const port = new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (d) => {
      out += d;
      if (out.includes('\n')) resolve(Number(out.trim()));
    });
    child.on('exit', () => reject(new Error('gateway child exited early: ' + stderr)));
  });
  return {
    child,
    exited,
    port,
    stderr: () => stderr,
    cleanup: () => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      fs.rmSync(home, { recursive: true, force: true });
    },
  };
}

function connectThenReset(port, { afterResponse }) {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write('CONNECT x.example:443 HTTP/1.1\r\nHost: x.example:443\r\n\r\n');
      if (!afterResponse) sock.resetAndDestroy();
    });
    sock.on('data', () => {
      if (afterResponse && !sock.destroyed) sock.resetAndDestroy();
    });
    sock.on('error', () => {});
    sock.on('close', resolve);
  });
}

test('CONNECT followed by a TCP reset never crashes the gateway process', async () => {
  const gw = spawnGatewayProcess();
  try {
    const port = await gw.port;
    for (let i = 0; i < 5; i += 1) {
      await connectThenReset(port, { afterResponse: true });
      await connectThenReset(port, { afterResponse: false });
    }
    const died = await Promise.race([gw.exited, sleep(300).then(() => null)]);
    assert.strictEqual(died, null, 'gateway process must survive CONNECT + RST, stderr: ' + gw.stderr().slice(0, 400));

    // Still serving, and CONNECT is still refused with a clean 405.
    const res = await get(port, 'unknown.localhost');
    assert.strictEqual(res.status, 404);
    const connect = await rawExchange(port, 'CONNECT x.example:443 HTTP/1.1\r\nHost: x.example:443\r\n\r\n');
    assert.ok(connect.data.startsWith('HTTP/1.1 405'), 'CONNECT is refused with 405');
    assert.strictEqual(connect.closed, true, 'the CONNECT socket is closed after the 405');
  } finally {
    gw.cleanup();
  }
});

// ---------------------------------------------------------------------------
// Request framing: a body on GET/DELETE/OPTIONS (chunked, or with a
// Content-Length nominated in Connection) must reach the upstream as a body,
// never as a second, unsanitized request on a pooled connection.
// ---------------------------------------------------------------------------

const { prepareUpstreamRequestHeaders, sanitizeHeaders } = require('../lib/headers');

const SMUGGLED = 'GET /SMUGGLED HTTP/1.1\r\nHost: evil.example\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n';
const chunk = (s) => `${Buffer.byteLength(s).toString(16)}\r\n${s}\r\n`;

// Test upstreams are plain local Node listeners, so discovery passes of daemon
// tests running in parallel may probe them (e.g. GET /json/version).
// Assertions therefore only look at the paths a test itself uses.
const only = (seen, urls) => seen.filter((r) => urls.includes(r.url));

async function recordingUpstream() {
  const seen = [];
  const up = await startUpstream((req, res) => {
    let body = '';
    req.setEncoding('latin1');
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, host: req.headers.host, body, remotePort: req.socket.remotePort });
      res.end('resp:' + req.url);
    });
  });
  return { ...up, seen };
}

test('header sanitizing never drops request framing', () => {
  const opts = { originalHost: 'app.localhost', clientIp: '127.0.0.1', targetPort: 3000 };
  const te = prepareUpstreamRequestHeaders(
    { headers: { host: 'app.localhost', 'transfer-encoding': 'chunked', connection: 'keep-alive' } },
    opts
  );
  assert.strictEqual(te['transfer-encoding'], 'chunked', 'a chunked request body stays explicitly framed');
  assert.strictEqual(te['content-length'], undefined);

  const cl = prepareUpstreamRequestHeaders(
    { headers: { host: 'app.localhost', 'content-length': '12', connection: 'close, content-length' } },
    opts
  );
  assert.strictEqual(cl['content-length'], '12', 'Content-Length cannot be stripped by naming it in Connection');

  // Other Connection-nominated headers are still removed.
  assert.deepStrictEqual(
    sanitizeHeaders({ connection: 'x-hop, content-length', 'x-hop': '1', 'content-length': '3' }),
    { 'content-length': '3' }
  );
});

test('gateway: bodies on GET/DELETE/OPTIONS are framed upstream, never smuggled as a second request', async () => {
  const up = await recordingUpstream();
  const { gateway, port } = await startGateway({ app: { port: up.port } });
  const variants = [
    ['GET + chunked', `GET / HTTP/1.1\r\nHost: app.localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${chunk(SMUGGLED)}0\r\n\r\n`, 'GET'],
    ['DELETE + chunked', `DELETE / HTTP/1.1\r\nHost: app.localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${chunk(SMUGGLED)}0\r\n\r\n`, 'DELETE'],
    ['OPTIONS + chunked', `OPTIONS / HTTP/1.1\r\nHost: app.localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${chunk(SMUGGLED)}0\r\n\r\n`, 'OPTIONS'],
    ['GET + Connection: content-length', `GET / HTTP/1.1\r\nHost: app.localhost\r\nConnection: close, content-length\r\nContent-Length: ${Buffer.byteLength(SMUGGLED)}\r\n\r\n${SMUGGLED}`, 'GET'],
  ];
  try {
    for (const [label, payload, method] of variants) {
      up.seen.length = 0;
      const res = await rawExchange(port, payload);
      assert.match(res.data, /^HTTP\/1\.1 200/, `${label}: request is proxied`);
      await sleep(150); // a smuggled request would be parsed right behind the first one
      const seen = only(up.seen, ['/', '/SMUGGLED']);
      assert.strictEqual(seen.length, 1, `${label}: upstream must see exactly one request, saw ${JSON.stringify(seen.map((r) => r.url))}`);
      assert.strictEqual(seen[0].method, method);
      assert.strictEqual(seen[0].url, '/');
      assert.strictEqual(seen[0].body, SMUGGLED, `${label}: the body arrives as a body`);
    }
  } finally {
    await stop(gateway, [up.server]);
  }
});

test('share gate: a chunked DELETE body is framed upstream, never smuggled', async () => {
  const { ShareGate } = require('../lib/share');
  const up = await recordingUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  try {
    const res = await rawExchange(
      gatePort,
      `DELETE /${gate.token}/hook HTTP/1.1\r\nHost: demo.trycloudflare.com\r\nCf-Connecting-Ip: 203.0.113.7\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${chunk(SMUGGLED)}0\r\n\r\n`
    );
    assert.match(res.data, /^HTTP\/1\.1 200/);
    await sleep(150);
    assert.deepStrictEqual(
      only(up.seen, ['/hook', '/SMUGGLED']).map((r) => [r.method, r.url, r.body]),
      [['DELETE', '/hook', SMUGGLED]]
    );
  } finally {
    await gate.close();
    up.server.closeAllConnections();
    await new Promise((r) => up.server.close(r));
  }
});

test('gateway: LAN and loopback clients never share a pooled upstream connection', async () => {
  const up = await recordingUpstream();
  let loopback = true; // test seam: classification of the next connection/request
  const { gateway, port } = await startGateway({ app: { name: 'app', port: up.port, root: '/r/app' } }, {
    isExposed: () => true,
    getLanInfo: () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' }),
    isLoopbackClient: () => loopback,
  });
  try {
    loopback = true;
    assert.strictEqual((await get(port, 'app.localhost', '/dev-1')).status, 200);
    assert.strictEqual((await get(port, 'app.localhost', '/dev-2')).status, 200);
    loopback = false;
    assert.strictEqual((await get(port, 'app.local', '/lan')).status, 200);
    loopback = true;
    assert.strictEqual((await get(port, 'app.localhost', '/dev-3')).status, 200);

    const [dev1, dev2, lan, dev3] = only(up.seen, ['/dev-1', '/dev-2', '/lan', '/dev-3']);
    assert.strictEqual(dev2.remotePort, dev1.remotePort, 'loopback requests reuse their pooled upstream connection');
    assert.notStrictEqual(lan.remotePort, dev1.remotePort, 'a LAN request must not ride the loopback pool');
    assert.strictEqual(dev3.remotePort, dev1.remotePort, 'the loopback pool is untouched by LAN traffic');
  } finally {
    await stop(gateway, [up.server]);
  }
});

// ---------------------------------------------------------------------------
// Upstream status lines below 100 ("000", "099") parse fine but make
// writeHead throw: the gateway must answer 502 and keep running.
// ---------------------------------------------------------------------------

function rawStatusUpstream() {
  const state = { statusLine: 'HTTP/1.1 200 OK' };
  return new Promise((resolve) => {
    const server = net.createServer((sock) => {
      let buf = '';
      sock.on('error', () => {});
      sock.on('data', (d) => {
        buf += d;
        if (buf.includes('\r\n\r\n')) {
          buf = '';
          sock.write(`${state.statusLine}\r\ncontent-length: 2\r\n\r\nok`);
        }
      });
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, state }));
  });
}

test('gateway: an upstream status below 100 yields 502 and the gateway keeps serving', async () => {
  const bad = await rawStatusUpstream();
  const good = await startUpstream((req, res) => res.end('fine'));
  const { gateway, port } = await startGateway({ bad: { port: bad.port }, good: { port: good.port } });
  try {
    for (const line of ['HTTP/1.1 000 Zero', 'HTTP/1.1 099 Low', 'HTTP/1.0 050 Old']) {
      bad.state.statusLine = line;
      const res = await get(port, 'bad.localhost');
      assert.strictEqual(res.status, 502, `${line} must be answered with 502`);
      const ok = await get(port, 'good.localhost');
      assert.deepStrictEqual([ok.status, ok.body], [200, 'fine'], 'the gateway keeps serving');
    }
    bad.state.statusLine = 'HTTP/1.1 999 Odd';
    assert.strictEqual((await get(port, 'bad.localhost')).status, 999, 'valid unusual codes still pass through');
  } finally {
    await stop(gateway, [good.server]);
    await new Promise((r) => bad.server.close(r));
  }
});

// ---------------------------------------------------------------------------
// An upstream that dies mid-body (same process, FIN or RST after the headers)
// must surface as a broken response to the client, never as a hang.
// ---------------------------------------------------------------------------

function fetchOutcome(port, host, reqPath, timeoutMs = 3000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(v);
      }
    };
    const req = http.get({ host: '127.0.0.1', port, path: reqPath, headers: { host }, agent: false }, (res) => {
      res.on('data', () => {});
      res.on('error', () => {});
      res.on('close', () => done(res.complete ? 'complete' : 'incomplete'));
    });
    req.on('error', () => done('incomplete'));
    const timer = setTimeout(() => {
      done('hang');
      req.destroy();
    }, timeoutMs);
  });
}

test('gateway: an upstream dying mid-body ends the client response instead of hanging', async () => {
  const up = await startUpstream((req, res) => {
    if (req.url.startsWith('/chunked')) res.writeHead(200, { 'content-type': 'text/plain' });
    else res.writeHead(200, { 'content-length': '1000' });
    res.write('partial');
    setTimeout(() => (req.url.endsWith('-rst') ? req.socket.resetAndDestroy() : req.socket.destroy()), 50);
  });
  const { gateway, port } = await startGateway({ app: { port: up.port } });
  try {
    for (const p of ['/chunked', '/length', '/chunked-rst']) {
      const outcome = await fetchOutcome(port, 'app.localhost', p);
      assert.strictEqual(outcome, 'incomplete', `${p}: client must see a truncated response, got ${outcome}`);
    }
    for (let i = 0; i < 50 && gateway.activeRequests.size > 0; i += 1) await sleep(10);
    assert.strictEqual(gateway.activeRequests.size, 0, 'no in-flight request stays tracked');
  } finally {
    await stop(gateway, [up.server]);
  }
});

// ---------------------------------------------------------------------------
// Upgrade path: the client is spliced to the upstream only after a confirmed
// 101. Any other answer is relayed once, sanitized, and the connection closed
// — no raw keep-alive HTTP channel past Host/forwarding-header rewriting.
// ---------------------------------------------------------------------------

const WS_HANDSHAKE = (host, upgrade = 'websocket', reqPath = '/ws') =>
  `GET ${reqPath} HTTP/1.1\r\nHost: ${host}\r\nConnection: Upgrade\r\nUpgrade: ${upgrade}\r\n` +
  'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n';

test('upgrade: an upstream answering without 101 gets one sanitized response, then the connection closes', async () => {
  const seen = [];
  let upPort = 0;
  // A plain keep-alive HTTP server without an upgrade listener (Node treats
  // the handshake as an ordinary request), like many non-Node dev servers.
  const up = await startUpstream((req, res) => {
    seen.push({ url: req.url, host: req.headers.host, xff: req.headers['x-forwarded-for'] });
    res.writeHead(404, { location: `http://localhost:${upPort}/elsewhere`, 'content-length': '4' });
    res.end('nope');
  });
  upPort = up.port;
  const { gateway, port } = await startGateway({ app: { port: up.port } });
  try {
    const result = await new Promise((resolve) => {
      let data = '';
      let sentSecond = false;
      const sock = net.connect(port, '127.0.0.1', () => sock.write(WS_HANDSHAKE('app.localhost')));
      sock.on('error', () => {});
      sock.on('data', (d) => {
        data += d.toString('latin1');
        if (!sentSecond && data.includes('\r\n\r\nnope')) {
          sentSecond = true;
          // Second request on the same connection, with spoofed metadata.
          sock.write('GET /raw-after HTTP/1.1\r\nHost: private.localhost\r\nX-Forwarded-For: 127.0.0.1\r\nForwarded: for=127.0.0.1\r\n\r\n');
        }
      });
      sock.on('close', () => resolve({ data, closed: true }));
      setTimeout(() => {
        sock.destroy();
        resolve({ data, closed: false });
      }, 1500);
    });
    await sleep(100);
    const ours = only(seen, ['/ws', '/raw-after']);
    assert.deepStrictEqual(ours.map((r) => r.url), ['/ws'], 'the upstream never sees a request outside the sanitized handshake');
    assert.strictEqual(ours[0].host, `localhost:${up.port}`);
    // The verified socket peer; a dual-stack gateway sees the IPv4-mapped form.
    assert.match(ours[0].xff, /^(::ffff:)?127\.0\.0\.1$/);
    assert.strictEqual(result.closed, true, 'the gateway closes the connection after the non-101 answer');
    const responses = result.data.match(/HTTP\/1\.1 \d{3}/g) || [];
    assert.deepStrictEqual(responses, ['HTTP/1.1 404'], 'exactly one response reaches the client');
    const head = result.data.slice(0, result.data.indexOf('\r\n\r\n')).toLowerCase();
    assert.ok(head.includes('location: http://app.localhost/elsewhere'), 'Location is rewritten like any response: ' + head);
    assert.ok(head.includes('cache-control: no-store'));
    assert.ok(head.includes('connection: close'));
  } finally {
    await stop(gateway, [up.server]);
  }
});

// h2c offers as `curl --http2` and the JDK HttpClient send them on http://
// URLs. RFC 9110 §7.8 lets the gateway ignore the offer: the request must be
// served as plain HTTP/1.1, with Upgrade never reaching the upstream (which
// could otherwise answer 101 and get a raw channel).
const H2C_OFFER = 'Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n';

// An h2c-capable upstream: every Upgrade it sees is accepted with a 101.
async function h2cUpstream() {
  const seen = [];
  const upgrades = [];
  const up = await startUpstream((req, res) => {
    let body = '';
    req.setEncoding('latin1');
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      const h = req.headers;
      seen.push({ url: req.url, method: req.method, upgrade: h.upgrade, connection: h.connection, settings: h['http2-settings'], xff: h['x-forwarded-for'], body });
      res.end('dev:' + req.url);
    });
  });
  up.server.on('upgrade', (req, sock) => {
    upgrades.push(req.url);
    sock.on('error', () => {});
    sock.end('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\nRAW-H2C');
  });
  return { ...up, seen, upgrades };
}

function assertNoUpgradeUpstream(up, url) {
  const [r] = only(up.seen, [url]);
  assert.ok(r, `${url} reaches the upstream`);
  assert.strictEqual(r.upgrade, undefined, `${url}: the upstream never sees Upgrade`);
  assert.strictEqual(r.settings, undefined, `${url}: nor HTTP2-Settings`);
  assert.ok(!/upgrade/i.test(r.connection || ''), `${url}: nor an upgrade Connection token`);
  return r;
}

test('upgrade: an h2c offer is served as plain HTTP/1.1, body included; the upstream never sees Upgrade', async () => {
  const up = await h2cUpstream();
  const { gateway, port } = await startGateway({ app: { port: up.port } });
  try {
    // GET, then a follow-up request on the same connection: it is an
    // ordinary (sanitized) request, not a raw channel.
    let sentSecond = false;
    const get = await rawExchange(port, `GET /h2c-get HTTP/1.1\r\nHost: app.localhost\r\n${H2C_OFFER}\r\n`, {
      onConnect: (sock) =>
        sock.on('data', () => {
          if (sentSecond) return;
          sentSecond = true;
          sock.write('GET /h2c-after HTTP/1.1\r\nHost: app.localhost\r\nX-Forwarded-For: 6.6.6.6\r\nConnection: close\r\n\r\n');
        }),
    });
    assert.deepStrictEqual(get.data.match(/HTTP\/1\.1 \d{3}/g), ['HTTP/1.1 200', 'HTTP/1.1 200'], get.data);
    assert.ok(get.data.includes('dev:/h2c-get') && get.data.includes('dev:/h2c-after'));
    assert.ok(!get.data.includes('RAW-H2C'));
    assertNoUpgradeUpstream(up, '/h2c-get');
    assert.match(only(up.seen, ['/h2c-after'])[0].xff, /^(::ffff:)?127\.0\.0\.1$/, 'the follow-up request is sanitized');

    const offerClose = H2C_OFFER.replace('HTTP2-Settings\r\n', 'HTTP2-Settings, close\r\n');
    const post = await rawExchange(port, `POST /h2c-post HTTP/1.1\r\nHost: app.localhost\r\n${offerClose}Content-Length: 5\r\n\r\nhello`);
    assert.match(post.data, /^HTTP\/1\.1 200/);
    assert.strictEqual(assertNoUpgradeUpstream(up, '/h2c-post').body, 'hello');

    const chunked = await rawExchange(port, `POST /h2c-chunked HTTP/1.1\r\nHost: app.localhost\r\n${offerClose}Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n`);
    assert.match(chunked.data, /^HTTP\/1\.1 200/);
    assert.strictEqual(assertNoUpgradeUpstream(up, '/h2c-chunked').body, 'hello');

    assert.deepStrictEqual(up.upgrades, [], 'the upstream is never asked to switch protocols');
  } finally {
    await stop(gateway, [up.server]);
  }
});

test('upgrade fallback (runtime without shouldUpgradeCallback): an h2c offer gets one plain answer, then the connection closes', async () => {
  const up = await h2cUpstream();
  // Answers 101 to anything, upgrade offered or not.
  const bogus = net.createServer((sock) => {
    sock.on('error', () => {});
    sock.once('data', () => sock.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\nRAW-BOGUS'));
  });
  await new Promise((r) => bogus.listen(0, '127.0.0.1', r));
  const routes = { app: { port: up.port }, bogus: { port: bogus.address().port } };
  const gateway = createGateway({ getRoute: (name) => routes[name] || null, log: () => {} });
  // Built like _createServer on a runtime that ignores shouldUpgradeCallback:
  // every upgrade offer reaches _handleUpgrade.
  const server = http.createServer(gateway._handleRequest);
  server.on('upgrade', gateway._handleUpgrade);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const pipelined = 'GET /raw-after HTTP/1.1\r\nHost: private.localhost\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n';
    const get = await rawExchange(port, `GET /h2c-get HTTP/1.1\r\nHost: app.localhost\r\n${H2C_OFFER}\r\n${pipelined}`);
    assert.deepStrictEqual(get.data.match(/HTTP\/1\.1 \d{3}/g), ['HTTP/1.1 200'], 'exactly one response: ' + get.data);
    assert.ok(get.data.includes('dev:/h2c-get'));
    assert.ok(get.data.toLowerCase().includes('connection: close'));
    assert.strictEqual(get.closed, true, 'the connection closes after the answer');
    assertNoUpgradeUpstream(up, '/h2c-get');

    // Node leaves such a body unframed in `head`: refused, never forwarded.
    for (const [label, framing, body] of [
      ['Content-Length', 'Content-Length: 5\r\n', 'hello'],
      ['chunked', 'Transfer-Encoding: chunked\r\n', '5\r\nhello\r\n0\r\n\r\n'],
    ]) {
      const res = await rawExchange(port, `POST /h2c-post HTTP/1.1\r\nHost: app.localhost\r\n${H2C_OFFER}${framing}\r\n${body}`);
      assert.match(res.data, /^HTTP\/1\.1 400/, `${label} body is refused`);
    }

    const unsolicited = await rawExchange(port, `GET /x HTTP/1.1\r\nHost: bogus.localhost\r\n${H2C_OFFER}\r\n`);
    assert.match(unsolicited.data, /^HTTP\/1\.1 502/, 'a 101 nobody asked for is a broken upstream');
    assert.ok(!unsolicited.data.includes('RAW-BOGUS'));

    await sleep(100);
    assert.deepStrictEqual(only(up.seen, ['/h2c-get', '/raw-after', '/h2c-post']).map((r) => r.url), ['/h2c-get']);
    assert.deepStrictEqual(up.upgrades, [], 'the upstream is never asked to switch protocols');
    assert.strictEqual(gateway.activeConnections.size, 0, 'nothing stays tracked');
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    gateway.destroyUpstreamSockets();
    up.server.closeAllConnections();
    await new Promise((r) => up.server.close(r));
    await new Promise((r) => bogus.close(r));
  }
});

test('upgrade: unanswered or unreachable upstreams get 502', async () => {
  const silent = net.createServer((sock) => {
    sock.on('error', () => {});
    sock.on('data', () => {}); // reads the handshake, never answers
  });
  await new Promise((r) => silent.listen(0, '127.0.0.1', r));
  const closed = net.createServer();
  await new Promise((r) => closed.listen(0, '127.0.0.1', r));
  const closedPort = closed.address().port;
  await new Promise((r) => closed.close(r));

  const { gateway, port } = await startGateway(
    { app: { port: silent.address().port }, gone: { port: closedPort } },
    { timeouts: { upstreamResponseHeaderTimeoutMs: 200 } }
  );
  try {
    const unanswered = await rawExchange(port, WS_HANDSHAKE('app.localhost'));
    assert.ok(unanswered.data.startsWith('HTTP/1.1 502'), 'an upstream that never answers the handshake gets 502: ' + unanswered.data);
    assert.strictEqual(unanswered.closed, true);

    const unreachable = await rawExchange(port, WS_HANDSHAKE('gone.localhost'));
    assert.ok(unreachable.data.startsWith('HTTP/1.1 502'), 'an unreachable upstream gets 502');
    assert.strictEqual(gateway.activeConnections.size, 0, 'nothing stays tracked');
  } finally {
    await gateway.close();
    await new Promise((r) => silent.close(r));
  }
});

// ---------------------------------------------------------------------------
// Connection budgets: non-loopback peers must never be able to exhaust the
// listener and lock the loopback developer out. The isLoopbackClient seam
// classifies the (loopback-shaped) test sockets per phase.
// ---------------------------------------------------------------------------

// Opens `count` idle connections one after another (never sending a byte)
// and reports how many the gateway kept open.
async function holdIdleConnections(port, count) {
  const socks = [];
  for (let i = 0; i < count; i += 1) {
    await new Promise((resolve) => {
      const sock = net.connect(port, '127.0.0.1');
      const state = { sock, closed: false };
      socks.push(state);
      sock.on('data', () => {});
      sock.on('error', () => {});
      sock.on('close', () => {
        state.closed = true;
        resolve();
      });
      sock.on('connect', resolve);
    });
  }
  await sleep(150); // let the gateway admit or drop every one of them
  return {
    open: () => socks.filter((s) => !s.closed).length,
    destroy: () => socks.forEach((s) => s.sock.destroy()),
  };
}

test('connection admission: unauthorized non-loopback peers are dropped at once; loopback stays served', async () => {
  const up = await startUpstream((req, res) => res.end('dev'));
  let loopback = false;
  const { gateway, port } = await startGateway({ app: { port: up.port } }, {
    getLanInfo: () => null, // no LAN: a non-loopback peer can never be authorized
    isLoopbackClient: () => loopback,
    timeouts: { maxConnections: 4, maxLanConnections: 4 },
  });
  let idle;
  try {
    loopback = false;
    idle = await holdIdleConnections(port, 12);
    assert.strictEqual(idle.open(), 0, 'non-loopback peers without LAN authorization never hold a slot');
    loopback = true;
    const res = await get(port, 'app.localhost');
    assert.deepStrictEqual([res.status, res.body], [200, 'dev'], 'the loopback developer is still served');
  } finally {
    if (idle) idle.destroy();
    await stop(gateway, [up.server]);
  }
});

test('connection admission: LAN peers have their own budget and per-address cap; loopback is never locked out', async () => {
  const up = await startUpstream((req, res) => res.end('dev'));
  const lanInfo = () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' });
  const cases = [
    { timeouts: { maxConnections: 4, maxLanConnections: 6, maxLanConnectionsPerAddress: 3 }, held: 3 },
    { timeouts: { maxConnections: 4, maxLanConnections: 2, maxLanConnectionsPerAddress: 100 }, held: 2 },
  ];
  try {
    for (const { timeouts, held } of cases) {
      let loopback = false;
      const { gateway, port } = await startGateway({ app: { port: up.port } }, {
        getLanInfo: lanInfo,
        isLoopbackClient: () => loopback,
        timeouts,
      });
      let idle;
      try {
        loopback = false;
        idle = await holdIdleConnections(port, 10);
        assert.strictEqual(idle.open(), held, `LAN peers keep exactly ${held} slots (${JSON.stringify(timeouts)})`);
        assert.strictEqual(gateway.lanConnectionCount, held);

        loopback = true;
        const results = await Promise.all([1, 2, 3, 4].map(() => get(port, 'app.localhost')));
        assert.deepStrictEqual(results.map((r) => r.status), [200, 200, 200, 200], 'loopback keeps its full budget');

        idle.destroy();
        for (let i = 0; i < 50 && gateway.lanConnectionCount > 0; i += 1) await sleep(10);
        assert.strictEqual(gateway.lanConnectionCount, 0, 'LAN slots are released when peers close');
        assert.strictEqual(gateway.lanConnections.size, 0);
      } finally {
        if (idle) idle.destroy();
        await gateway.close();
      }
    }
  } finally {
    up.server.closeAllConnections();
    await new Promise((r) => up.server.close(r));
  }
});

test('connection admission: an idle connection is closed shortly after the header timeout', async () => {
  const { gateway, port } = await startGateway({}, {
    timeouts: { headerTimeoutMs: 300, connectionsCheckingIntervalMs: 100 },
  });
  try {
    const started = Date.now();
    const closedAfter = await new Promise((resolve) => {
      const sock = net.connect(port, '127.0.0.1');
      sock.on('data', () => {});
      sock.on('error', () => {});
      sock.on('close', () => resolve(Date.now() - started));
      setTimeout(() => {
        sock.destroy();
        resolve(null);
      }, 3000);
    });
    assert.ok(closedAfter !== null && closedAfter < 2000, `idle connection must be closed near the header timeout, got ${closedAfter}`);
  } finally {
    await gateway.close();
  }
});
