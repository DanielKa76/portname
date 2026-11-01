'use strict';

// Regression tests for the share path: the public visitor address the
// upstream sees, the isolation of the cloudflared child from user config
// and environment, the tunnel URL parser, broken upstream responses (status
// lines below 100, bodies cut off mid-stream), the parallel shutdown sweep
// and the WebSocket splice only after a confirmed 101.

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { ShareGate, ShareManager, randomToken } = require('../lib/share');

const VISITOR_IP = '203.0.113.9';

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function closeServer(server) {
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  return new Promise((r) => server.close(() => r()));
}

// HTTP upstream that records what it was sent.
async function recordingUpstream() {
  const seen = [];
  const server = http.createServer((req, res) => {
    const entry = { method: req.method, headers: req.headers, remote: req.socket.remoteAddress, url: req.url, body: '' };
    seen.push(entry);
    req.setEncoding('latin1');
    req.on('data', (d) => (entry.body += d));
    req.on('end', () => res.end('ok'));
  });
  const port = await listen(server);
  return { server, port, seen };
}

function request(port, path, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

// Raw request: lets a test send header shapes http.request would normalize.
function rawRequest(port, text) {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(text));
    let data = '';
    sock.on('data', (d) => (data += d));
    sock.on('close', () => resolve(data));
    sock.on('error', () => resolve(data));
    setTimeout(() => sock.destroy(), 3000).unref();
  });
}

function assertNoLoopback(value, label) {
  assert.ok(typeof value === 'string' && value.length > 0, `${label} must be present`);
  assert.ok(!/127\.\d+\.\d+\.\d+|::1\b|localhost/i.test(value), `${label} must never carry a loopback client: ${value}`);
}

// ---------------------------------------------------------------------------
// Visitor address: the gate presents the public visitor, never loopback.
// ---------------------------------------------------------------------------

test('share gate: upstream sees the Cf-Connecting-Ip visitor in X-Forwarded-For and Forwarded, never loopback', async () => {
  const up = await recordingUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);

  // Visitor-controlled headers trying to look local; only Cf-Connecting-Ip
  // is set by the Cloudflare edge.
  const spoofed = {
    host: 'abc-def.trycloudflare.com',
    'cf-connecting-ip': VISITOR_IP,
    'x-forwarded-for': `127.0.0.1, ${VISITOR_IP}`,
    forwarded: 'for=127.0.0.1',
    'client-ip': '127.0.0.1',
    'x-real-ip': '127.0.0.1',
    'true-client-ip': '127.0.0.1',
  };
  try {
    const viaToken = await request(gatePort, `/${gate.token}/hook`, { method: 'POST', headers: spoofed });
    assert.strictEqual(viaToken.status, 200);
    const viaCookie = await request(gatePort, '/page', {
      headers: { ...spoofed, cookie: `pn_share=${sessionId}` },
    });
    assert.strictEqual(viaCookie.status, 200);

    assert.strictEqual(up.seen.length, 2);
    for (const { headers } of up.seen) {
      assert.strictEqual(headers['x-forwarded-for'], VISITOR_IP, 'XFF must be exactly the visitor address');
      assert.ok(headers.forwarded.startsWith(`for=${VISITOR_IP};`), `Forwarded must name the visitor: ${headers.forwarded}`);
      assertNoLoopback(headers['x-forwarded-for'], 'X-Forwarded-For');
      assertNoLoopback(headers.forwarded.split(';')[0], 'Forwarded for=');
      assert.strictEqual(headers['client-ip'], undefined, 'spoofable Client-Ip must not reach the upstream');
      assert.strictEqual(headers['x-real-ip'], undefined, 'spoofable X-Real-Ip must not reach the upstream');
      assert.strictEqual(headers['true-client-ip'], undefined, 'spoofable True-Client-Ip must not reach the upstream');
    }

    // IPv6 visitors are quoted per RFC 7239.
    await request(gatePort, '/v6', {
      headers: { host: 'abc-def.trycloudflare.com', 'cf-connecting-ip': '2001:db8::7', cookie: `pn_share=${sessionId}` },
    });
    const v6 = up.seen[2].headers;
    assert.strictEqual(v6['x-forwarded-for'], '2001:db8::7');
    assert.ok(v6.forwarded.startsWith('for="[2001:db8::7]";'), v6.forwarded);
  } finally {
    await gate.close();
    await closeServer(up.server);
  }
});

test('share gate: a forwarded request without a valid public visitor address fails closed (400, upstream untouched)', async () => {
  const up = await recordingUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);
  const cookie = `pn_share=${sessionId}`;

  try {
    const missing = await request(gatePort, '/page', { headers: { cookie } });
    assert.strictEqual(missing.status, 400, 'no Cf-Connecting-Ip: refuse, never fall back to the loopback peer');
    assert.strictEqual(missing.body, '');
    assert.ok(missing.headers['cache-control'].includes('no-store'));

    for (const bad of ['127.0.0.1', '127.8.8.8', '::1', '::ffff:127.0.0.1', '0.0.0.0', '::', 'unknown', '203.0.113.9 x', 'fe80::1%lo0']) {
      const res = await request(gatePort, '/page', { headers: { cookie, 'cf-connecting-ip': bad } });
      assert.strictEqual(res.status, 400, `Cf-Connecting-Ip ${JSON.stringify(bad)} must be refused`);
    }
    const webhook = await request(gatePort, `/${gate.token}/hook`, { method: 'POST' });
    assert.strictEqual(webhook.status, 400, 'token-direct (webhook) requests follow the same rule');

    // Two Cf-Connecting-Ip headers are not one visitor address.
    const dup = await rawRequest(
      gatePort,
      `GET /page HTTP/1.1\r\nHost: x\r\nCookie: ${cookie}\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\nCf-Connecting-Ip: 127.0.0.1\r\nConnection: close\r\n\r\n`
    );
    assert.ok(dup.startsWith('HTTP/1.1 400'), dup.split('\r\n')[0]);

    assert.strictEqual(up.seen.length, 0, 'the upstream must never see a request without a visitor address');
  } finally {
    await gate.close();
    await closeServer(up.server);
  }
});

test('share gate: a refused request body is discarded in frame, never parsed as the next request', async () => {
  // The fail-closed 400 answers before the body is read. On the keep-alive
  // cloudflared connection that body must still be consumed as a body: a
  // chunked payload shaped like another token request is never parsed by the
  // gate, and the real next request is framed at its own boundary.
  const up = await recordingUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const host = 'Host: demo.trycloudflare.com\r\n';
  const smuggled = `POST /${gate.token}/SMUGGLED HTTP/1.1\r\n${host}Cf-Connecting-Ip: ${VISITOR_IP}\r\nContent-Length: 0\r\n\r\n`;
  const chunk = (s) => `${Buffer.byteLength(s).toString(16)}\r\n${s}\r\n`;

  try {
    const data = await rawRequest(
      gatePort,
      `POST /${gate.token}/hook HTTP/1.1\r\n${host}Transfer-Encoding: chunked\r\n\r\n${chunk(smuggled)}0\r\n\r\n` +
        `POST /${gate.token}/after HTTP/1.1\r\n${host}Cf-Connecting-Ip: ${VISITOR_IP}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok`
    );
    assert.deepStrictEqual(data.match(/^HTTP\/1\.1 \d+/gm), ['HTTP/1.1 400', 'HTTP/1.1 200']);
    // Only the paths this test sends (parallel test files may probe local listeners).
    const ours = up.seen.filter((r) => ['/hook', '/SMUGGLED', '/after'].includes(r.url));
    assert.deepStrictEqual(
      ours.map((r) => [r.method, r.url, r.body, r.headers['x-forwarded-for']]),
      [['POST', '/after', 'ok', VISITOR_IP]]
    );
  } finally {
    await gate.close();
    await closeServer(up.server);
  }
});

test('share gate: WebSocket upgrade carries the visitor address, never loopback; without one it is refused', async () => {
  const handshakes = [];
  const ws = net.createServer((sock) => {
    let first = true;
    sock.on('data', (d) => {
      if (first) {
        first = false;
        handshakes.push(d.toString());
        sock.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n');
      }
    });
    sock.on('error', () => {});
  });
  const wsPort = await listen(ws);
  const gate = new ShareGate({ targetPort: wsPort, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);

  const upgrade = (extra) =>
    new Promise((resolve) => {
      const sock = net.connect(gatePort, '127.0.0.1', () => {
        sock.write(
          `GET /ws HTTP/1.1\r\nhost: abc-def.trycloudflare.com\r\nupgrade: websocket\r\nconnection: Upgrade\r\n` +
            `cookie: pn_share=${sessionId}\r\nsec-websocket-key: a==\r\nsec-websocket-version: 13\r\n${extra}\r\n`
        );
      });
      let data = '';
      sock.on('data', (d) => {
        data += d;
        if (data.includes('\r\n\r\n')) {
          sock.destroy();
          resolve(data);
        }
      });
      sock.on('close', () => resolve(data));
      sock.on('error', () => resolve(data));
    });

  try {
    const ok = await upgrade(
      `cf-connecting-ip: ${VISITOR_IP}\r\nx-forwarded-for: 127.0.0.1\r\nforwarded: for=127.0.0.1\r\n` +
        'client-ip: 127.0.0.1\r\nx-real-ip: 127.0.0.1\r\ntrue-client-ip: 127.0.0.1\r\n'
    );
    assert.ok(ok.startsWith('HTTP/1.1 101'), ok.split('\r\n')[0]);
    assert.strictEqual(handshakes.length, 1);
    const lines = handshakes[0].split('\r\n');
    const header = (name) => lines.filter((l) => l.toLowerCase().startsWith(name + ':')).map((l) => l.slice(name.length + 1).trim());
    assert.deepStrictEqual(header('x-forwarded-for'), [VISITOR_IP]);
    assert.strictEqual(header('forwarded').length, 1);
    assert.ok(header('forwarded')[0].startsWith(`for=${VISITOR_IP};`), header('forwarded')[0]);
    assert.deepStrictEqual(header('client-ip'), []);
    assert.deepStrictEqual(header('x-real-ip'), []);
    assert.deepStrictEqual(header('true-client-ip'), []);

    for (const extra of ['', 'cf-connecting-ip: 127.0.0.1\r\n', 'cf-connecting-ip: ::1\r\n']) {
      const refused = await upgrade(extra);
      assert.ok(refused.startsWith('HTTP/1.1 400'), `upgrade with ${JSON.stringify(extra)} must be refused: ${refused.split('\r\n')[0]}`);
    }
    assert.strictEqual(handshakes.length, 1, 'refused upgrades must never reach the upstream');
  } finally {
    await gate.close();
    await closeServer(ws);
  }
});

// ---------------------------------------------------------------------------
// WebSocket splice: only after the upstream confirmed 101. A dev server
// without a WebSocket handler answers 404 keep-alive; a raw splice then left
// cloudflared a pooled channel past the gate.
// ---------------------------------------------------------------------------

// Raw client: sends `first`, and once `ready(data)` holds sends `second` on
// the same socket (cloudflared reusing its pooled origin connection).
// Resolves with everything received and whether the gate closed the socket.
function rawFollowUp(port, first, ready, second, timeoutMs = 2000) {
  return new Promise((resolve) => {
    let data = '';
    let sent = false;
    const sock = net.connect(port, '127.0.0.1', () => sock.write(first));
    const timer = setTimeout(() => {
      resolve({ data, closed: false });
      sock.destroy();
    }, timeoutMs);
    sock.on('data', (d) => {
      data += d;
      if (!sent && ready(data)) {
        sent = true;
        sock.write(second, () => {});
      }
    });
    sock.on('error', () => {});
    sock.on('close', () => {
      clearTimeout(timer);
      resolve({ data, closed: true });
    });
  });
}

test('share gate: an upgrade the upstream answers without 101 is relayed once and closed; no later request rides the connection', async () => {
  // A plain Node server without an 'upgrade' listener (Express without ws):
  // it answers the handshake like any request, 404 keep-alive.
  const seen = [];
  const plain = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    res.writeHead(404, { 'content-type': 'text/plain', 'content-length': 4 });
    res.end('nope');
  });
  const upPort = await listen(plain);
  const gate = new ShareGate({ targetPort: upPort, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const host = 'Host: demo.trycloudflare.com\r\n';
  const handshake =
    `GET /${gate.token}/ws HTTP/1.1\r\n${host}Cf-Connecting-Ip: ${VISITOR_IP}\r\nUpgrade: websocket\r\n` +
    'Connection: Upgrade\r\nSec-WebSocket-Key: a==\r\nSec-WebSocket-Version: 13\r\n\r\n';
  // No token, no valid session, no visitor address: the gate answers this
  // with nothing but a closed socket — it must never reach the upstream.
  const intruder = `GET /admin/secret HTTP/1.1\r\n${host}Upgrade: websocket\r\nConnection: Upgrade\r\nCookie: pn_share=deadbeef\r\n\r\n`;
  const ours = () => seen.filter((r) => ['/ws', '/admin/secret'].includes(r.url));

  try {
    for (const mode of ['after the answer', 'pipelined']) {
      seen.length = 0;
      const { data, closed } =
        mode === 'pipelined'
          ? await rawFollowUp(gatePort, handshake + intruder, () => false, '')
          : await rawFollowUp(gatePort, handshake, (d) => d.includes('\r\n\r\nnope'), intruder);
      await new Promise((r) => setTimeout(r, 150)); // a spliced follow-up would arrive by now

      assert.deepStrictEqual(ours().map((r) => r.url), ['/ws'], `${mode}: only the authorized handshake may reach the upstream`);
      assert.strictEqual(closed, true, `${mode}: the gate must close the connection after a non-101 answer`);
      assert.strictEqual(ours()[0].headers.host, `localhost:${upPort}`);
      assert.strictEqual(ours()[0].headers['x-forwarded-for'], VISITOR_IP);

      const [head, body] = data.split('\r\n\r\n');
      const lines = head.split('\r\n');
      assert.strictEqual(lines[0], 'HTTP/1.1 404 Not Found', `${mode}: ${lines[0]}`);
      assert.ok(lines.includes('connection: close'), `${mode}: the answer must carry connection: close`);
      assert.ok(!lines.some((l) => /^connection: keep-alive$/i.test(l) || /^keep-alive:/i.test(l)));
      assert.ok(lines.includes('cache-control: no-store, no-cache, must-revalidate, max-age=0'));
      assert.ok(lines.includes('referrer-policy: no-referrer'));
      assert.strictEqual(body, 'nope', `${mode}: exactly one response, nothing after it`);
    }
    assert.strictEqual(gate.activeConnections.size, 0, 'a refused handshake leaves no tracked connection');
  } finally {
    await gate.close();
    await closeServer(plain);
  }
});

test('share gate: a confirmed 101 is relayed without a pn_share Set-Cookie and spliced; a bare 101 or an unreachable upstream gets 502', async () => {
  const ws = net.createServer((sock) => {
    let buf = '';
    let upgraded = false;
    sock.on('data', (d) => {
      if (upgraded) return void sock.write(d); // echo
      buf += d;
      const end = buf.indexOf('\r\n\r\n');
      if (end === -1) return;
      if (buf.startsWith('GET /bare ')) return void sock.write('HTTP/1.1 101 Switching Protocols\r\n\r\n');
      upgraded = true;
      sock.write(
        'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: fake=\r\n' +
          'Set-Cookie: pn_share=0000000000000000000000000000000000000000000000000000000000000000; Path=/\r\nSet-Cookie: app=1\r\n\r\n' +
          buf.slice(end + 4)
      );
    });
    sock.on('error', () => {});
  });
  const wsPort = await listen(ws);
  const gate = new ShareGate({ targetPort: wsPort, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);
  const handshake = (p) =>
    `GET ${p} HTTP/1.1\r\nHost: demo.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\nCookie: pn_share=${sessionId}\r\n` +
    'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: a==\r\nSec-WebSocket-Version: 13\r\n\r\n';

  let sock;
  try {
    const reply = await new Promise((resolve, reject) => {
      let data = '';
      sock = net.connect(gatePort, '127.0.0.1', () => sock.write(handshake('/ws') + 'HELLO'));
      sock.on('data', (d) => {
        data += d;
        if (data.includes('HELLO')) resolve(data);
      });
      sock.on('error', reject);
      setTimeout(() => reject(new Error(`no echo after the 101: ${JSON.stringify(data)}`)), 2000).unref();
    });
    const head = reply.split('\r\n\r\n')[0].split('\r\n');
    assert.strictEqual(head[0], 'HTTP/1.1 101 Switching Protocols');
    assert.ok(head.includes('Upgrade: websocket') && head.includes('Connection: Upgrade'));
    assert.ok(head.includes('Set-Cookie: app=1'), 'other upstream cookies are relayed');
    assert.ok(!reply.includes('pn_share'), 'the upstream must never set the gate session cookie');
    assert.strictEqual(gate.activeConnections.size, 1, 'the spliced pair is tracked');

    const bare = await rawRequest(gatePort, handshake('/bare'));
    assert.ok(bare.startsWith('HTTP/1.1 502 '), `a 101 without upgrade headers is no handshake: ${bare.split('\r\n')[0]}`);

    const closed = net.createServer();
    const deadPort = await listen(closed);
    await closeServer(closed);
    gate.targetPort = deadPort;
    const dead = await rawRequest(gatePort, handshake('/ws'));
    assert.ok(dead.startsWith('HTTP/1.1 502 '), `unreachable upstream: ${dead.split('\r\n')[0]}`);
    assert.strictEqual(gate.activeConnections.size, 1, 'failed handshakes leave no tracked connection (only the live splice)');
  } finally {
    if (sock) sock.destroy();
    await gate.close();
    await closeServer(ws);
  }
});

test('share gate: other upgrade offers (h2c) are served as plain HTTP, never switched; the fallback refuses them', async () => {
  // An h2c-capable upstream switches protocols for any Upgrade it sees.
  const seen = [];
  const h2c = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d;
      if (!buf.includes('\r\n\r\n')) return;
      const request = buf.split('\r\n\r\n')[0];
      buf = '';
      seen.push(request);
      if (/^upgrade:/im.test(request)) sock.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n');
      else sock.write('HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nplain');
    });
    sock.on('error', () => {});
  });
  const upPort = await listen(h2c);
  const gate = new ShareGate({ targetPort: upPort, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);
  const offer =
    `GET /h2c HTTP/1.1\r\nHost: demo.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\nCookie: pn_share=${sessionId}\r\n` +
    'Connection: Upgrade, HTTP2-Settings, close\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n';
  const ours = () => seen.filter((r) => r.startsWith('GET /h2c '));
  try {
    const plain = await rawRequest(gatePort, offer);
    assert.ok(plain.startsWith('HTTP/1.1 200 OK'), `the offer is ignored, the request served: ${plain.split('\r\n')[0]}`);
    assert.strictEqual(ours().length, 1);
    assert.ok(!/^(upgrade|http2-settings):/im.test(ours()[0]), `the upstream must never see the offer: ${ours()[0]}`);

    // Runtimes without shouldUpgradeCallback hand every offer to the
    // 'upgrade' path (Node's default callback): it refuses non-WebSocket ones.
    gate.server.shouldUpgradeCallback = function () {
      return this.listenerCount('upgrade') > 0;
    };
    const refused = await rawRequest(gatePort, offer);
    assert.ok(refused.startsWith('HTTP/1.1 400 '), `fallback: ${refused.split('\r\n')[0]}`);
    assert.strictEqual(ours().length, 1, 'a refused offer never reaches the upstream');
  } finally {
    await gate.close();
    await closeServer(h2c);
  }
});

// ---------------------------------------------------------------------------
// Tunnel isolation: cloudflared never sees the user's config or TUNNEL_* env.
// ---------------------------------------------------------------------------

test('share: cloudflared runs with a portname-owned config (no ingress) and an allowlisted environment', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cf-isolation-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cf-home-'));
  // A named-tunnel style user config whose ingress would win over --url.
  fs.mkdirSync(path.join(home, '.cloudflared'));
  fs.writeFileSync(
    path.join(home, '.cloudflared', 'config.yml'),
    'tunnel: 00000000-0000-0000-0000-000000000000\ningress:\n  - service: http://127.0.0.1:1\n'
  );
  const record = path.join(dir, 'argv-env.json');
  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\n' +
      `require('fs').writeFileSync(${JSON.stringify(record)}, JSON.stringify({ argv: process.argv.slice(2), env: process.env }));\n` +
      'console.log("https://isolated-tunnel.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  const injected = {
    HOME: home,
    TUNNEL_URL: 'http://127.0.0.1:1',
    TUNNEL_LOGLEVEL: 'debug',
    TUNNEL_LOGFILE: path.join(dir, 'leak.log'),
    TUNNEL_ORIGIN_CERT: path.join(home, 'cert.pem'),
    NO_TLS_VERIFY: 'true',
    CLOUDFLARED_TEST_MARKER: '1',
  };
  const saved = {};
  for (const [k, v] of Object.entries(injected)) {
    saved[k] = process.env[k];
    process.env[k] = v;
  }

  const up = await recordingUpstream();
  const mgr = new ShareManager({ dir });
  try {
    await mgr.start({ name: 'iso', targetPort: up.port, ttlMinutes: 60, cloudflaredBin: cfScript, timeoutMs: 5000 });
    const gatePort = mgr.shares.get('iso').gate.server.address().port;
    const { argv, env } = JSON.parse(fs.readFileSync(record, 'utf8'));

    const cfgIdx = argv.indexOf('--config');
    assert.ok(cfgIdx >= 0, `cloudflared must get an explicit --config: ${argv.join(' ')}`);
    const cfgPath = argv[cfgIdx + 1];
    assert.strictEqual(cfgPath, path.join(dir, 'cloudflared.yml'), 'the config must be portname-owned, in the state dir');
    assert.ok(!cfgPath.startsWith(path.join(home, '.cloudflared')));
    const cfgStat = fs.statSync(cfgPath);
    assert.strictEqual(cfgStat.mode & 0o777, 0o600, 'the config file must be private (0600)');
    assert.ok(!/ingress|service|url/i.test(fs.readFileSync(cfgPath, 'utf8').replace(/^#.*$/gm, '')), 'the config must not route anywhere');
    assert.strictEqual(argv[argv.indexOf('--url') + 1], `http://127.0.0.1:${gatePort}`, '--url must be the gate');
    assert.strictEqual(argv[0], 'tunnel');

    const leaked = Object.keys(env).filter((k) => /^(TUNNEL_|CLOUDFLARED_|NO_TLS_VERIFY$|NO_AUTOUPDATE$|NODE_OPTIONS$)/.test(k));
    assert.deepStrictEqual(leaked, [], 'no cloudflared-steering variables may reach the child');
    assert.strictEqual(env.HOME, home, 'HOME is kept (allowlisted)');
    assert.ok(env.PATH, 'PATH is kept (allowlisted)');
    assert.strictEqual(fs.existsSync(path.join(dir, 'leak.log')), false);
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await mgr.stopAll();
    await closeServer(up.server);
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Tunnel URL parsing: cloudflared's offline error names
// https://api.trycloudflare.com — that is never a tunnel URL.
// ---------------------------------------------------------------------------

const CF_DISCLAIMER =
  '2026-10-31T05:00:00Z INF Thank you for trying Cloudflare Tunnel. Doing so, without a Cloudflare account, is a quick way to experiment and try it out. ' +
  'However, be aware that these account-less Tunnels have no uptime guarantee, are subject to the Cloudflare Online Services Terms of Use ' +
  '(https://www.cloudflare.com/website-terms/), and Cloudflare reserves the right to investigate your use of Tunnels for violations of such terms. ' +
  'If you intend to use Tunnels in production you should use a pre-created named tunnel by following: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps\n' +
  '2026-10-31T05:00:00Z INF Requesting new quick Tunnel on trycloudflare.com...\n';
const CF_OFFLINE_ERROR =
  'failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel": dial tcp: lookup api.trycloudflare.com: no such host\n';

function writeFakeCf(dir, file, body) {
  const script = path.join(dir, file);
  fs.writeFileSync(script, '#!/usr/bin/env node\n' + body);
  fs.chmodSync(script, 0o755);
  return script;
}

test('share: an offline cloudflared error (api.trycloudflare.com) is a failed start, never a public link', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cf-offline-'));
  const logs = [];
  const mgr = new ShareManager({ dir, log: (...args) => logs.push(args.join(' ')) });
  const exits = writeFakeCf(
    dir,
    'cf-offline-exit.js',
    `process.stderr.write(${JSON.stringify(CF_DISCLAIMER)});\n` +
      `process.stderr.write(${JSON.stringify(CF_OFFLINE_ERROR)});\nprocess.exitCode = 1;\n`
  );
  const hangs = writeFakeCf(
    dir,
    'cf-offline-hang.js',
    `process.stderr.write(${JSON.stringify(CF_DISCLAIMER + CF_OFFLINE_ERROR)});\nsetInterval(() => {}, 1000);\n`
  );
  try {
    await assert.rejects(
      () => mgr.start({ name: 'offline', targetPort: 1, ttlMinutes: 60, cloudflaredBin: exits, timeoutMs: 5000 }),
      /exited early/
    );
    assert.strictEqual(mgr.isShared('offline'), false);

    await assert.rejects(
      () => mgr.start({ name: 'offline-hang', targetPort: 1, ttlMinutes: 60, cloudflaredBin: hangs, timeoutMs: 400 }),
      /did not produce a URL within 400ms/
    );
    assert.strictEqual(mgr.isShared('offline-hang'), false);
    assert.deepStrictEqual(mgr.status(), []);
    assert.ok(!logs.some((l) => l.startsWith('share ') && l.includes('api.trycloudflare.com')), 'no share may be announced on the API host');
  } finally {
    await mgr.stopAll();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('share: the tunnel URL is taken from cloudflared\'s real banner, also when split across output chunks', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cf-banner-'));
  const mgr = new ShareManager({ dir });
  const banner = writeFakeCf(
    dir,
    'cf-banner.js',
    `process.stderr.write(${JSON.stringify(CF_DISCLAIMER)});\n` +
      "const bar = '+' + '-'.repeat(90) + '+';\n" +
      "process.stderr.write('2026-10-31T05:00:03Z INF ' + bar + '\\n');\n" +
      "process.stderr.write('2026-10-31T05:00:03Z INF |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |\\n');\n" +
      // The URL line arrives in two chunks, cut inside the host name.
      "process.stderr.write('2026-10-31T05:00:03Z INF |  https://brave-quiet');\n" +
      "setTimeout(() => process.stderr.write('-river-lamp.trycloudflare.com' + ' '.repeat(42) + '|\\n2026-10-31T05:00:03Z INF ' + bar + '\\n'), 50);\n" +
      'setInterval(() => {}, 1000);\n'
  );
  try {
    const link = await mgr.start({ name: 'banner', targetPort: 1, ttlMinutes: 60, cloudflaredBin: banner, timeoutMs: 5000 });
    const token = mgr.shares.get('banner').gate.token;
    assert.strictEqual(String(link), `https://brave-quiet-river-lamp.trycloudflare.com/${token}/`);
    assert.strictEqual(mgr.status()[0].url, 'https://brave-quiet-river-lamp.trycloudflare.com');
  } finally {
    await mgr.stopAll();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Broken status lines: an upstream status below 100 must not crash the process.
// ---------------------------------------------------------------------------

// Raw upstream: GET /status/<code> answers with that literal status line,
// anything else with a normal 200.
async function rawStatusUpstream() {
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d;
      if (!buf.includes('\r\n\r\n')) return;
      const m = buf.match(/^GET \/status\/(\d+) /);
      const status = m ? `${m[1]} X` : '200 OK';
      sock.end(`HTTP/1.1 ${status}\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok`);
    });
    sock.on('error', () => {});
  });
  const port = await listen(server);
  return { server, port };
}

test('share gate: an upstream status below 100 (000-099) answers 502 and the gate keeps serving', async () => {
  const up = await rawStatusUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);
  const headers = { cookie: `pn_share=${sessionId}`, 'cf-connecting-ip': VISITOR_IP };
  try {
    for (const code of ['050', '000', '099']) {
      const res = await request(gatePort, `/status/${code}`, { headers });
      assert.strictEqual(res.status, 502, `upstream status ${code} must become a 502`);
      assert.ok(res.headers['cache-control'].includes('no-store'));
    }
    const ok = await request(gatePort, '/fine', { headers });
    assert.strictEqual(ok.status, 200, 'the gate (and the process) must survive');
    assert.strictEqual(ok.body, 'ok');
  } finally {
    await gate.close();
    await closeServer(up.server);
  }
});

// ---------------------------------------------------------------------------
// Truncated bodies: an upstream dying mid-body must reach the
// visitor as an aborted response — never a hang, never a "complete" body.
// ---------------------------------------------------------------------------

// Raw upstream: GET /<mode> sends headers plus a partial body, then ends the
// connection as the mode says. /close-delimited is a legitimate response
// whose end is the FIN itself.
async function truncatingUpstream() {
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d;
      if (!buf.includes('\r\n\r\n')) return;
      const mode = (buf.match(/^GET \/([a-z-]+) /) || [])[1];
      // node --test runs files in parallel: a client of another file can
      // reach this port after reuse. Its request is not ours to answer.
      if (!mode) {
        sock.destroy();
        return;
      }
      if (mode === 'close-delimited') {
        sock.end('HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nall-of-it');
        return;
      }
      const framing = mode.startsWith('chunked')
        ? 'transfer-encoding: chunked\r\n\r\n7\r\npartial\r\n'
        : 'content-length: 1000\r\n\r\npartial';
      sock.write(`HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n${framing}`);
      setTimeout(() => {
        if (mode.endsWith('-rst')) sock.resetAndDestroy();
        else sock.end();
      }, 50);
    });
    sock.on('error', () => {});
  });
  const port = await listen(server);
  return { server, port };
}

// Resolves with how the visitor experienced the response.
function responseOutcome(port, path, headers, timeoutMs = 3000) {
  return new Promise((resolve) => {
    let body = '';
    let done = false;
    const finish = (outcome) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ outcome, body });
    };
    const req = http.request({ host: '127.0.0.1', port, path, headers, agent: false }, (res) => {
      res.on('data', (d) => (body += d));
      res.on('end', () => finish(res.complete ? 'complete' : 'aborted'));
      res.on('aborted', () => finish('aborted'));
      res.on('error', () => finish('aborted'));
      res.on('close', () => finish('aborted'));
    });
    req.on('error', () => finish('aborted'));
    req.end();
    const timer = setTimeout(() => {
      finish('hang');
      req.destroy();
    }, timeoutMs);
  });
}

test('share gate: an upstream dying mid-body aborts the visitor response (no hang, no truncated "complete" body)', async () => {
  const up = await truncatingUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);
  const headers = { cookie: `pn_share=${sessionId}`, 'cf-connecting-ip': VISITOR_IP };
  try {
    for (const mode of ['chunked-fin', 'length-fin', 'chunked-rst', 'length-rst']) {
      const { outcome } = await responseOutcome(gatePort, `/${mode}`, headers);
      assert.strictEqual(outcome, 'aborted', `${mode}: the visitor must see an aborted response, got ${outcome}`);
    }
    // A close-delimited body legitimately ends with the FIN: still complete.
    const legit = await responseOutcome(gatePort, '/close-delimited', headers);
    assert.deepStrictEqual(legit, { outcome: 'complete', body: 'all-of-it' });
  } finally {
    await gate.close();
    await closeServer(up.server);
  }
});

// ---------------------------------------------------------------------------
// Shutdown sweep: stopAll must stop every tunnel within the daemon's 5s
// shutdown backstop, also when the children ignore SIGTERM.
// ---------------------------------------------------------------------------

test('share: stopAll tears down many SIGTERM-ignoring tunnels in parallel, well inside the shutdown backstop', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-stopall-parallel-'));
  const mgr = new ShareManager({ dir });
  const stubborn = writeFakeCf(
    dir,
    'cf-ignore-term.js',
    'console.log("https://stubborn-tunnel.trycloudflare.com");\nprocess.on("SIGTERM", () => {});\nsetInterval(() => {}, 1000);\n'
  );
  const names = ['s1', 's2', 's3', 's4', 's5'];
  let pids = [];
  try {
    for (const name of names) {
      await mgr.start({ name, targetPort: 1, ttlMinutes: 60, cloudflaredBin: stubborn, timeoutMs: 5000 });
    }
    pids = mgr.childPids();
    assert.strictEqual(pids.length, names.length);

    const t0 = Date.now();
    const stopped = await mgr.stopAll();
    const elapsed = Date.now() - t0;
    assert.deepStrictEqual(stopped, names, 'every share is reported, in order');
    // Sequentially this took 5 x 1.5s = 7.5s (past the 5s daemon backstop).
    assert.ok(elapsed < 4000, `stopAll must be bounded by the slowest single stop, took ${elapsed}ms`);
    assert.deepStrictEqual(mgr.status(), []);

    const alive = () => pids.filter((pid) => {
      try { process.kill(pid, 0); return true; } catch { return false; }
    });
    for (let i = 0; i < 200 && alive().length; i++) await new Promise((r) => setTimeout(r, 10));
    assert.deepStrictEqual(alive(), [], 'no tunnel child may survive the sweep');
  } finally {
    await mgr.stopAll();
    for (const pid of pids) {
      try { process.kill(pid, 'SIGKILL'); } catch {}
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
