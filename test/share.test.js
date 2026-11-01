'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { ShareGate, ShareManager, randomToken, resolveCloudflaredBin, validateTtlMinutes } = require('../lib/share');

function startUpstream(handler) {
  return new Promise((resolve) => {
    const defaultHandler = (req, res) => res.end('upstream:' + req.url);
    const server = http.createServer(handler || defaultHandler);
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Every request reaching a gate in production comes through cloudflared,
// which forwards the Cloudflare edge's Cf-Connecting-Ip (the public visitor
// address); the gate refuses to forward requests without one.
const VISITOR_IP = '203.0.113.10';

// What a browser sends on a top-level navigation; only such a request trades
// the token for a session cookie (other clients are served directly).
const NAVIGATE = {
  'sec-fetch-mode': 'navigate',
  'sec-fetch-dest': 'document',
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
};

function request(port, path, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method, headers: { 'cf-connecting-ip': VISITOR_IP, ...headers }, agent: false },
      (res) => {
        let resBody = '';
        res.on('data', (d) => (resBody += d));
        res.on('end', () => resolve({ status: res.statusCode, body: resBody, headers: res.headers }));
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('randomToken is 32 CSPRNG bytes, hex encoded', () => {
  assert.match(randomToken(), /^[0-9a-f]{64}$/);
});

test('browser token redemption: GET /<token>/ sets session cookie and redirects to clean path', async () => {
  const { server: upstream, port } = await startUpstream();
  const gate = new ShareGate({ targetPort: port, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  try {
    // 1. Browser initial navigation to /<token>/foo
    const res = await request(gatePort, `/${gate.token}/foo`, { headers: NAVIGATE });
    assert.strictEqual(res.status, 302);
    assert.strictEqual(res.headers['location'], '/foo');
    assert.ok(res.headers['set-cookie'], 'Set-Cookie header must be present');

    const setCookie = res.headers['set-cookie'][0];
    assert.match(setCookie, /pn_share=[0-9a-f]{64}/);
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /Secure/i);
    assert.match(setCookie, /SameSite=Lax/i);
    assert.match(setCookie, /Path=\//);

    const match = setCookie.match(/pn_share=([0-9a-f]{64})/);
    const sessionId = match[1];

    // 2. Follow-up asset request using the session cookie
    const assetRes = await request(gatePort, '/assets/app.js', {
      headers: { cookie: `pn_share=${sessionId}` },
    });
    assert.strictEqual(assetRes.status, 200);
    assert.strictEqual(assetRes.body, 'upstream:/assets/app.js');

    // 3. Request without cookie to /assets/app.js -> 404
    const unauthRes = await request(gatePort, '/assets/app.js');
    assert.strictEqual(unauthRes.status, 404);
    assert.strictEqual(unauthRes.body, '');
  } finally {
    await gate.close();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});

test('webhook: non-GET request with token in path authorizes directly without cookie', async () => {
  let receivedMethod = null;
  let receivedUrl = null;
  let receivedBody = '';
  let receivedHost = null;

  const { server: upstream, port } = await startUpstream((req, res) => {
    receivedMethod = req.method;
    receivedUrl = req.url;
    receivedHost = req.headers['host'];
    req.on('data', (d) => (receivedBody += d));
    req.on('end', () => res.end('webhook-ok'));
  });

  const gate = new ShareGate({ targetPort: port, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  try {
    const res = await request(gatePort, `/${gate.token}/webhooks/stripe`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: 'charge.succeeded' }),
    });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body, 'webhook-ok');
    assert.strictEqual(receivedMethod, 'POST');
    assert.strictEqual(receivedUrl, '/webhooks/stripe', 'token prefix must be stripped for upstream');
    assert.strictEqual(receivedHost, `localhost:${port}`, 'upstream sees internal localhost:<port>');
    assert.strictEqual(receivedBody, JSON.stringify({ event: 'charge.succeeded' }));
  } finally {
    await gate.close();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});

test('gate answers 410 per request once the ttl is over', async () => {
  const { server: upstream, port } = await startUpstream();
  const gate = new ShareGate({ targetPort: port, ttlMinutes: -1 });
  const gatePort = await gate.listen();
  try {
    const res = await request(gatePort, '/' + gate.token + '/');
    assert.strictEqual(res.status, 410);
  } finally {
    await gate.close();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});

test('revocation happens before closing: after close() the token is dead and sockets are torn down', async () => {
  const { server: upstream, port } = await startUpstream();
  const gate = new ShareGate({ targetPort: port, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  let wsUpstreamSock = null;
  const ws = net.createServer((sock) => {
    wsUpstreamSock = sock;
    let handshaken = false;
    sock.on('data', (d) => {
      if (!handshaken) {
        handshaken = true;
        sock.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: fake=\r\n\r\n');
      }
      sock.write(d);
    });
  });
  const wsPort = await new Promise((r) => ws.listen(0, '127.0.0.1', () => r(ws.address().port)));
  gate.targetPort = wsPort;

  let clientSock;
  try {
    await new Promise((resolve, reject) => {
      let timer;
      let data = '';
      clientSock = net.connect(gatePort, '127.0.0.1', () => {
        clientSock.write(
          `GET /${gate.token}/ws HTTP/1.1\r\nhost: x\r\ncf-connecting-ip: ${VISITOR_IP}\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: a==\r\nsec-websocket-version: 13\r\n\r\nHELLO`
        );
      });
      clientSock.on('data', (d) => {
        data += d.toString();
        if (data.includes('HELLO')) {
          clearTimeout(timer);
          resolve(data);
        }
      });
      clientSock.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      timer = setTimeout(() => reject(new Error('no upgrade echo')), 2000);
    });

    assert.strictEqual(gate.activeConnections.size, 1, 'upgraded socket pair is tracked');
    await gate.close();
    assert.strictEqual(gate.revoked, true);
    assert.strictEqual(gate.activeConnections.size, 0, 'all tracked connections destroyed on close');

    await assert.rejects(
      () => request(gatePort, '/' + gate.token + '/'),
      /ECONNREFUSED|ECONNRESET|socket hang up/,
      'server is closed'
    );
  } finally {
    if (clientSock && !clientSock.destroyed) clientSock.destroy();
    await gate.close();
    await new Promise((r) => ws.close(r));
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});

test('websocket upgrade works with valid session cookie and fails without', async () => {
  const ws = net.createServer((sock) => {
    let handshaken = false;
    sock.on('data', (d) => {
      if (!handshaken) {
        handshaken = true;
        sock.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: fake=\r\n\r\n');
      }
      sock.write(d);
    });
  });
  const wsPort = await new Promise((r) => ws.listen(0, '127.0.0.1', () => r(ws.address().port)));
  const gate = new ShareGate({ targetPort: wsPort, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  // Create a session in gate
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);

  let validSock;
  let invalidSock;
  try {
    // 1. Upgrade with session cookie -> succeeds
    const echo = await new Promise((resolve, reject) => {
      let timer;
      let data = '';
      validSock = net.connect(gatePort, '127.0.0.1', () => {
        validSock.write(
          `GET /ws HTTP/1.1\r\nhost: x\r\ncf-connecting-ip: ${VISITOR_IP}\r\nupgrade: websocket\r\nconnection: Upgrade\r\ncookie: pn_share=${sessionId}\r\nsec-websocket-key: b==\r\nsec-websocket-version: 13\r\n\r\nWS_COOKIE_OK`
        );
      });
      validSock.on('data', (d) => {
        data += d.toString();
        if (data.includes('WS_COOKIE_OK')) {
          clearTimeout(timer);
          resolve(data);
        }
      });
      validSock.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      timer = setTimeout(() => reject(new Error('timeout waiting for echo')), 2000);
    });
    assert.ok(echo.includes('101 Switching Protocols'));

    // 2. Upgrade without cookie or token -> rejected / closed immediately
    await new Promise((resolve) => {
      invalidSock = net.connect(gatePort, '127.0.0.1', () => {
        invalidSock.write('GET /ws HTTP/1.1\r\nhost: x\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n');
      });
      invalidSock.on('close', resolve);
      invalidSock.on('error', resolve);
    });
  } finally {
    if (validSock && !validSock.destroyed) validSock.destroy();
    if (invalidSock && !invalidSock.destroyed) invalidSock.destroy();
    await gate.close();
    await new Promise((r) => ws.close(r));
  }
});

test('ShareManager: active TTL expiry tears down share and removes from status', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-share-ttl-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  // Executable mock cloudflared script
  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://demo-ttl.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    // Start share with short test TTL (180ms)
    await mgr.start({
      name: 'app',
      targetPort: port,
      ttlMinutes: 0.1,
      _testTtlMs: 180,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });

    assert.strictEqual(mgr.isShared('app'), true);
    assert.strictEqual(mgr.status().length, 1);

    // Wait for the TTL timer to fire — poll with a generous upper bound
    // instead of racing a fixed sleep (deterministic under suite load).
    for (let i = 0; i < 500 && mgr.isShared('app'); i++) {
      await new Promise((r) => setTimeout(r, 10));
    }

    assert.strictEqual(mgr.isShared('app'), false, 'share must be removed from map on TTL expiry');
    assert.strictEqual(mgr.status().length, 0, 'status must not show expired share');
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareManager: unexpected child process exit automatically triggers share revocation', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-share-exit-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  // Executable mock cloudflared script that stays alive until killed
  const cfScript = path.join(dir, 'fake-cf-exit.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://demo-exit.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    await mgr.start({
      name: 'exiting-app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });

    assert.strictEqual(mgr.isShared('exiting-app'), true);
    const childPids = mgr.childPids();
    assert.strictEqual(childPids.length, 1);

    // Simulate child process unexpected death (SIGTERM)
    process.kill(childPids[0], 'SIGTERM');

    // Wait for the exit handler to clean up the share — polled, not a fixed
    // sleep (deterministic under suite load).
    for (let i = 0; i < 500 && mgr.isShared('exiting-app'); i++) {
      await new Promise((r) => setTimeout(r, 10));
    }

    assert.strictEqual(mgr.isShared('exiting-app'), false, 'share must be automatically cleaned up on child exit');
    assert.strictEqual(mgr.status().length, 0);
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareManager: safe orphan cleanup verifies PID and process start time before killing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-orphan-'));
  const stateFile = path.join(dir, 'shares.state.json');

  let killedPids = [];
  const fakeKill = (pid) => killedPids.push(pid);
  const originalKill = process.kill;
  process.kill = fakeKill;

  try {
    // 1. Case: PID reused! Current process start time differs from recorded start time
    fs.writeFileSync(
      stateFile,
      JSON.stringify({
        children: [
          { pid: 1234, startTime: 'Old Time 1', command: 'cloudflared' },
          { pid: 5678, startTime: 'Match Time 2', command: 'cloudflared' },
        ],
      })
    );

    const mockGetProcessInfo = (pid) => {
      if (pid === 1234) {
        // PID reused by another process with a different start time
        return { pid: 1234, startTime: 'New Time 1 (PID Reused)', command: 'node' };
      }
      if (pid === 5678) {
        // Real matching orphan cloudflared process
        return { pid: 5678, startTime: 'Match Time 2', command: 'cloudflared' };
      }
      return null;
    };

    const mgr = new ShareManager({ dir, getProcessInfo: mockGetProcessInfo });
    mgr.cleanupOrphans();

    assert.ok(!killedPids.includes(1234), 'PID-reused process must NOT be killed');
    assert.ok(killedPids.includes(5678), 'matching orphan process must be killed');
    assert.strictEqual(fs.existsSync(stateFile), false, 'state file must be cleaned up');
  } finally {
    process.kill = originalKill;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareManager: cleanup on failed tunnel start and no tokens in state file', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-fail-'));
  const mgr = new ShareManager({ dir });
  assert.strictEqual(mgr.isShared('x'), false);

  await t.assert.rejects(
    () =>
      mgr.start({
        name: 'x',
        targetPort: 59999,
        ttlMinutes: 1,
        cloudflaredBin: 'cloudflared-missing-binary',
        timeoutMs: 1500,
      }),
      /cloudflared/
  );

  assert.strictEqual(mgr.isShared('x'), false, 'failed share must be cleaned up');
  const stateFile = path.join(dir, 'shares.state.json');
  if (fs.existsSync(stateFile)) {
    const content = fs.readFileSync(stateFile, 'utf8');
    assert.ok(!content.includes('token'), 'tokens must never be persisted in state file');
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('ShareGate: capability isolation protects session cookie, Referer and Set-Cookie boundary', async () => {
  let receivedHeaders = null;
  const upstream = http.createServer((req, res) => {
    receivedHeaders = req.headers;
    res.writeHead(200, {
      'content-type': 'text/plain',
      'set-cookie': ['pn_share=malicious_upstream_cookie; Path=/', 'user_pref=dark; Path=/'],
      'cache-control': 'public, max-age=3600',
    });
    res.end('isolated');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const uPort = upstream.address().port;

  const gate = new ShareGate({ targetPort: uPort, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  try {
    // 1. Initial redemption
    const redeemRes = await request(gatePort, '/' + gate.token + '/', { headers: NAVIGATE });
    assert.strictEqual(redeemRes.status, 302);
    assert.strictEqual(redeemRes.headers['referrer-policy'], 'no-referrer');
    assert.ok(redeemRes.headers['cache-control'].includes('no-store'));

    const setCookieHeader = redeemRes.headers['set-cookie'];
    const setCookieStr = Array.isArray(setCookieHeader) ? setCookieHeader.join('; ') : String(setCookieHeader || '');
    assert.ok(setCookieStr.includes('pn_share='));
    const match = setCookieStr.match(/pn_share=([0-9a-f]{64})/);
    assert.ok(match, 'must match pn_share cookie');
    const sid = match[1];

    // 2. Client makes request carrying gate session cookie, dev cookie, and token in Referer
    const appRes = await new Promise((resolve, reject) => {
      http.get({
        host: '127.0.0.1',
        port: gatePort,
        path: '/',
        headers: {
          'cf-connecting-ip': VISITOR_IP,
          cookie: `user_id=42; pn_share=${sid}; lang=de`,
          referer: `https://trycloudflare.com/${gate.token}/dashboard`,
        },
      }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
      }).on('error', reject);
    });

    assert.strictEqual(appRes.status, 200);

    // Dev server must see other cookies, but NEVER pn_share!
    assert.ok(receivedHeaders['cookie'].includes('user_id=42'));
    assert.ok(receivedHeaders['cookie'].includes('lang=de'));
    assert.ok(!receivedHeaders['cookie'].includes('pn_share'), 'pn_share must be stripped before reaching dev server');

    // Dev server must NEVER receive token in Referer
    assert.strictEqual(receivedHeaders['referer'], undefined, 'token-bearing Referer must not be passed to dev server');

    // Dev server Set-Cookie: pn_share must be filtered out by gate
    const upstreamCookies = appRes.headers['set-cookie'] || [];
    const scString = Array.isArray(upstreamCookies) ? upstreamCookies.join(';') : String(upstreamCookies);
    assert.ok(!scString.includes('pn_share='), 'upstream must not set or collide with pn_share cookie');
    assert.ok(scString.includes('user_pref=dark'), 'legitimate upstream cookies must be preserved');

    // Gate must strictly enforce no-store even if upstream requested caching
    assert.ok(appRes.headers['cache-control'].includes('no-store'), 'no-store must be strictly enforced on public shares');
  } finally {
    await gate.close();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});

test('ShareManager: atomic cancellation of tunnel during STARTING state', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cancel-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  // Slow mock cloudflared script that stays in startup without printing URL
  const cfScript = path.join(dir, 'fake-slow-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    const startPromise = mgr.start({
      name: 'cancel-me',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 10000,
    });

    // Wait until child is spawned
    await new Promise((r) => setTimeout(r, 60));
    assert.strictEqual(mgr.isShared('cancel-me'), true);
    const childPids = mgr.childPids();
    assert.strictEqual(childPids.length, 1);
    const childPid = childPids[0];

    // Atomically stop while still STARTING
    const [, startResult] = await Promise.allSettled([
      mgr.stop('cancel-me'),
      startPromise,
    ]);

    assert.strictEqual(startResult.status, 'rejected');
    assert.match(startResult.reason.message, /aborted|stopped/);

    // Verify child process was killed
    let isAlive = true;
    try {
      process.kill(childPid, 0);
    } catch {
      isAlive = false;
    }
    assert.strictEqual(isAlive, false, 'child process must be killed when stopped during STARTING');
    assert.strictEqual(mgr.isShared('cancel-me'), false);
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareManager: safe orphan cleanup skips entries without verifiable startTime', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-orphan-fail-safe-'));
  const stateFile = path.join(dir, 'shares.state.json');

  let killedPids = [];
  const fakeKill = (pid) => killedPids.push(pid);
  const originalKill = process.kill;
  process.kill = fakeKill;

  try {
    // Unverifiable entry with missing startTime (e.g. legacy numeric entry or missing generation)
    fs.writeFileSync(
      stateFile,
      JSON.stringify({
        children: [
          { pid: 9999, command: 'cloudflared' }, // no startTime!
          9998, // numeric PID without startTime!
        ],
      })
    );

    const mockGetProcessInfo = (pid) => ({
      pid,
      startTime: 'Some Time',
      command: 'cloudflared',
    });

    const mgr = new ShareManager({ dir, getProcessInfo: mockGetProcessInfo });
    mgr.cleanupOrphans();

    assert.strictEqual(killedPids.length, 0, 'processes without verifiable generation must NOT be killed');
    assert.strictEqual(fs.existsSync(stateFile), false, 'state file should be cleaned up');
  } finally {
    process.kill = originalKill;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareManager: active WebSocket connection is torn down upon TTL expiration', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-ttl-stream-'));
  const mgr = new ShareManager({ dir });

  // WebSocket echo server
  const wsUpstream = net.createServer((socket) => {
    // The TTL teardown may reach the upstream as a RST (see revocation.test.js).
    socket.on('error', () => {});
    socket.on('data', (d) => {
      if (d.toString().includes('Upgrade: websocket')) {
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
      } else {
        socket.write(d);
      }
    });
  });
  await new Promise((r) => wsUpstream.listen(0, '127.0.0.1', r));
  const uPort = wsUpstream.address().port;

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://ttl-stream.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  let client = null;
  try {
    // Deterministic under load: the TTL (1s) is two orders of magnitude above
    // a localhost handshake, and every wait polls with a generous upper
    // bound instead of racing fixed sleeps. The teardown proof itself stays
    // strict: the client socket must really close and the share must vanish.
    const link = await mgr.start({
      name: 'ws-app',
      targetPort: uPort,
      ttlMinutes: 0.1,
      _testTtlMs: 1000,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });

    const share = mgr.shares.get('ws-app');
    const gatePort = share.gate.server.address().port;

    // Connect WebSocket through gate
    client = net.connect(gatePort, '127.0.0.1', () => {
      client.write(
        `GET /${share.token}/ HTTP/1.1\r\nHost: ttl-stream.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n`
      );
    });

    let clientClosed = false;
    let upgraded = false;
    client.on('data', (d) => {
      if (d.toString().includes('101 Switching Protocols')) {
        upgraded = true;
      }
    });
    client.on('close', () => {
      clientClosed = true;
    });
    client.on('error', () => {});

    // Wait until upgrade handshake completes (or the socket already died,
    // which must then fail the upgraded assertion below — never silently).
    for (let i = 0; i < 500 && !upgraded && !clientClosed; i++) {
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.strictEqual(upgraded, true, 'WebSocket upgrade must succeed before testing TTL teardown');

    // Wait for the TTL timer to fire and tear down the live connection.
    // Poll until BOTH the socket really closed AND the manager removed the
    // share: socket destruction happens synchronously in gate.close(), the
    // map removal only after the tunnel child confirmed its exit.
    for (let i = 0; i < 1000 && (!clientClosed || mgr.isShared('ws-app')); i++) {
      await new Promise((r) => setTimeout(r, 10));
    }

    assert.strictEqual(clientClosed, true, 'active WebSocket stream must be destroyed when TTL expires');
    assert.strictEqual(mgr.isShared('ws-app'), false);
  } finally {
    await mgr.stopAll();
    if (client && !client.destroyed) client.destroy();
    wsUpstream.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('validateTtlMinutes: validates bounds (0.1 to 1440 min) and rejects malformed values', () => {
  // Valid
  assert.strictEqual(validateTtlMinutes(60).ok, true);
  assert.strictEqual(validateTtlMinutes('60').ok, true);
  assert.strictEqual(validateTtlMinutes(0.1).ok, true);
  assert.strictEqual(validateTtlMinutes(1440).ok, true);

  // Invalid
  assert.strictEqual(validateTtlMinutes(0.09).ok, false);
  assert.strictEqual(validateTtlMinutes(0).ok, false);
  assert.strictEqual(validateTtlMinutes(-1).ok, false);
  assert.strictEqual(validateTtlMinutes(1441).ok, false);
  assert.strictEqual(validateTtlMinutes(NaN).ok, false);
  assert.strictEqual(validateTtlMinutes(Infinity).ok, false);
  assert.strictEqual(validateTtlMinutes('abc').ok, false);
  assert.strictEqual(validateTtlMinutes(undefined).ok, false);
});

test('ShareManager: concurrent start calls coalesce onto same startPromise without double spawn', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-coalesce-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  let spawnCount = 0;
  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\n' +
    'setTimeout(() => console.log("https://coalesce.trycloudflare.com"), 50);\n' +
    'setInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    // Fire two start calls concurrently for the same project
    const p1 = mgr.start({
      name: 'dup-app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });
    const p2 = mgr.start({
      name: 'dup-app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });

    const [url1, url2] = await Promise.all([p1, p2]);
    assert.strictEqual(url1, url2, 'both promises must resolve to the identical URL');
    assert.strictEqual(mgr.childPids().length, 1, 'only one child process must have been spawned');
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareManager: start during STOPPING state waits for teardown before fresh spawn', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-restart-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://restart.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    // 1. Initial start
    await mgr.start({
      name: 'restart-app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });
    assert.strictEqual(mgr.isShared('restart-app'), true);
    const oldPid = mgr.childPids()[0];

    // 2. Trigger stop, and immediately trigger start while state is STOPPING
    const stopPromise = mgr.stop('restart-app');
    const restartPromise = mgr.start({
      name: 'restart-app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });

    await stopPromise;
    const newUrl = await restartPromise;

    assert.ok(newUrl.includes('restart.trycloudflare.com'));
    assert.strictEqual(mgr.isShared('restart-app'), true);
    const newPid = mgr.childPids()[0];
    assert.notStrictEqual(newPid, oldPid, 'new process must be spawned after old process was cleanly stopped');
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareManager: child PID is persisted to shares.state.json immediately upon spawn in STARTING state', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-start-persist-'));
  const stateFile = path.join(dir, 'shares.state.json');
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  // Mock script that delays printing URL so it stays in STARTING state
  const cfScript = path.join(dir, 'fake-slow-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    const startPromise = mgr.start({
      name: 'starting-app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });

    // Wait briefly for spawn
    await new Promise((r) => setTimeout(r, 60));

    // Inspect shares.state.json while state is STARTING
    assert.ok(fs.existsSync(stateFile), 'shares.state.json must exist in STARTING state');
    const content = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    assert.ok(Array.isArray(content.children));
    assert.strictEqual(content.children.length, 1);
    assert.strictEqual(content.children[0].pid, mgr.childPids()[0]);
    assert.ok(content.children[0].startTime, 'startTime must be recorded for crash recovery');

    await mgr.stop('starting-app');
    await startPromise.catch(() => {});
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareGate: session capacity is capped at 200 with LRU and expired eviction', async () => {
  const gate = new ShareGate({ targetPort: 3000, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  try {
    // Fill with 200 active sessions
    for (let i = 0; i < 200; i++) {
      gate.sessions.set(`sess_${i}`, Date.now() + 60000);
    }
    assert.strictEqual(gate.sessions.size, 200);

    // Make 1 session expired
    gate.sessions.set('sess_0', Date.now() - 1000);

    // Redeem new session via HTTP request
    const res = await request(gatePort, `/${gate.token}/`, { headers: NAVIGATE });
    assert.strictEqual(res.status, 302);

    // Expired session must have been evicted, keeping size <= 200
    assert.ok(gate.sessions.size <= 200);
    assert.strictEqual(gate.sessions.has('sess_0'), false, 'expired session must be evicted first');

    // Clear and fill again with 200 fresh non-expired sessions
    gate.sessions.clear();
    for (let i = 0; i < 200; i++) {
      gate.sessions.set(`sess_fresh_${i}`, Date.now() + 60000);
    }
    assert.strictEqual(gate.sessions.size, 200);

    // Redeem another session -> triggers LRU eviction of oldest
    const oldestKey = gate.sessions.keys().next().value;
    const res2 = await request(gatePort, `/${gate.token}/`, { headers: NAVIGATE });
    assert.strictEqual(res2.status, 302);
    assert.strictEqual(gate.sessions.size, 200, 'session capacity must remain capped at 200');
    assert.strictEqual(gate.sessions.has(oldestKey), false, 'oldest LRU session must be evicted when cap is reached');
  } finally {
    await gate.close();
  }
});

test('ShareResult: behaves as string URL while exposing url, expiresAt, and ttlMinutes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-share-res-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://demo-res.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    const res = await mgr.start({
      name: 'app',
      targetPort: port,
      ttlMinutes: 45,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });

    assert.strictEqual(typeof res, 'object');
    assert.ok(String(res).startsWith('https://demo-res.trycloudflare.com/'));
    assert.strictEqual(res.url, String(res));
    assert.strictEqual(res.ttlMinutes, 45);
    assert.ok(res.expiresAt > Date.now());
    assert.ok(res.expiresAt <= Date.now() + 45 * 60 * 1000);
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareGate: rejects requests with invalid or multiple Host headers with HTTP 400', async () => {
  const { server: upstream, port } = await startUpstream();
  const gate = new ShareGate({ targetPort: port, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  try {
    // 1. Multiple Host headers
    const rawMultiple = await new Promise((resolve) => {
      const socket = net.connect(gatePort, '127.0.0.1', () => {
        socket.write(`GET / HTTP/1.1\r\nHost: foo.com\r\nHost: bar.com\r\nConnection: close\r\n\r\n`);
      });
      let data = '';
      socket.on('data', (d) => (data += d));
      socket.on('end', () => resolve(data));
    });
    assert.ok(rawMultiple.startsWith('HTTP/1.1 400 Bad Request'));

    // 2. Malformed Host header (invalid port syntax)
    const rawMalformed = await new Promise((resolve) => {
      const socket = net.connect(gatePort, '127.0.0.1', () => {
        socket.write(`GET / HTTP/1.1\r\nHost: bad[host:99999\r\nConnection: close\r\n\r\n`);
      });
      let data = '';
      socket.on('data', (d) => (data += d));
      socket.on('end', () => resolve(data));
    });
    assert.ok(rawMalformed.startsWith('HTTP/1.1 400 Bad Request'));
  } finally {
    await gate.close();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});

test('ShareManager: re-sharing with changed descriptor (port, ttl) stops existing and restarts', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-share-change-'));
  const mgr = new ShareManager({ dir });
  const u1 = await startUpstream();
  const u2 = await startUpstream();

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://demo-change.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    // 1. Start share on u1.port with 60 min TTL
    await mgr.start({
      name: 'app',
      targetPort: u1.port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });
    const s1 = mgr.status().find((s) => s.name === 'app');
    assert.strictEqual(s1.targetPort, u1.port);
    assert.strictEqual(s1.ttlMinutes, 60);

    // 2. Start share again with different TTL (30 min)
    await mgr.start({
      name: 'app',
      targetPort: u1.port,
      ttlMinutes: 30,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });
    const s2 = mgr.status().find((s) => s.name === 'app');
    assert.strictEqual(s2.targetPort, u1.port);
    assert.strictEqual(s2.ttlMinutes, 30);

    // 3. Start share again with different targetPort (u2.port)
    await mgr.start({
      name: 'app',
      targetPort: u2.port,
      ttlMinutes: 30,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });
    const s3 = mgr.status().find((s) => s.name === 'app');
    assert.strictEqual(s3.targetPort, u2.port);
  } finally {
    await mgr.stopAll();
    u1.server.closeAllConnections();
    u2.server.closeAllConnections();
    await new Promise((r) => u1.server.close(r));
    await new Promise((r) => u2.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareGate: token redemption never redirects cross-origin (protocol-relative Location is collapsed)', async () => {
  const { server: upstream, port } = await startUpstream();
  const gate = new ShareGate({ targetPort: port, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  try {
    // /<token>//evil.example would be a protocol-relative redirect to
    // evil.example if the leading slashes survived — the capability must
    // never be turned into a cross-origin redirect.
    const res = await request(gatePort, `/${gate.token}//evil.example`, { headers: NAVIGATE });
    assert.strictEqual(res.status, 302);
    assert.strictEqual(res.headers['location'], '/evil.example');
    assert.ok(!res.headers['location'].startsWith('//'), 'Location must never be protocol-relative');

    // Non-GET webhook path keeps the same normalization.
    const post = await request(gatePort, `/${gate.token}//evil.example/hook`, { method: 'POST', body: 'x' });
    assert.strictEqual(post.status, 200);
    assert.strictEqual(post.body, 'upstream:/evil.example/hook', 'upstream sees a normalized local path');

    // Backslash variant: the WHATWG URL parser reads /\evil.example as
    // authority, so backslashes must be normalized before the redirect.
    const bs = await request(gatePort, `/${gate.token}/\\evil.example`, { headers: NAVIGATE });
    assert.strictEqual(bs.status, 302);
    assert.strictEqual(bs.headers['location'], '/evil.example');
    assert.strictEqual(
      new URL(bs.headers['location'], 'https://x.trycloudflare.com').host,
      'x.trycloudflare.com',
      'Location must never resolve to a foreign host'
    );

    const bsPost = await request(gatePort, `/${gate.token}/\\evil.example/hook`, { method: 'POST', body: 'x' });
    assert.strictEqual(bsPost.status, 200);
    assert.strictEqual(bsPost.body, 'upstream:/evil.example/hook', 'upstream sees a normalized local path for backslashes too');
  } finally {
    await gate.close();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});

test('ShareGate: WebSocket handshake forwards cookies but never the gate session cookie or token Referer', async () => {
  let upstreamRaw = '';
  const ws = net.createServer((sock) => {
    let handshaken = false;
    sock.on('data', (d) => {
      if (!handshaken) {
        handshaken = true;
        upstreamRaw = d.toString();
        sock.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: fake=\r\n\r\n');
      }
      sock.write(d); // echo everything, like the other raw WS test upstreams
    });
  });
  const wsPort = await new Promise((r) => ws.listen(0, '127.0.0.1', () => r(ws.address().port)));
  const gate = new ShareGate({ targetPort: wsPort, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);

  let clientSock = null;
  try {
    const reply = await new Promise((resolve, reject) => {
      let data = '';
      let timer;
      clientSock = net.connect(gatePort, '127.0.0.1', () => {
        clientSock.write(
          `GET /ws HTTP/1.1\r\nhost: x\r\ncf-connecting-ip: ${VISITOR_IP}\r\nupgrade: websocket\r\nconnection: Upgrade\r\ncookie: pn_share=${sessionId}; app_theme=dark\r\nreferer: https://x.trycloudflare.com/${gate.token}/page\r\nsec-websocket-key: c==\r\nsec-websocket-version: 13\r\n\r\nWS_ECHO_OK`
        );
      });
      clientSock.on('data', (d) => {
        data += d.toString();
        if (data.includes('WS_ECHO_OK')) {
          clearTimeout(timer);
          resolve(data);
        }
      });
      clientSock.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      timer = setTimeout(() => reject(new Error('timeout waiting for WS echo')), 2000);
    });
    assert.ok(reply.includes('101 Switching Protocols'));

    assert.match(upstreamRaw, /cookie:\s*app_theme=dark/i, 'legitimate cookies must reach the upstream handshake');
    assert.ok(!upstreamRaw.toLowerCase().includes('pn_share'), 'the gate session cookie must never reach the upstream handshake');
    assert.ok(!upstreamRaw.includes(gate.token), 'the secret token must never reach the upstream handshake (Referer)');
  } finally {
    if (clientSock && !clientSock.destroyed) clientSock.destroy();
    await gate.close();
    await new Promise((r) => ws.close(r));
  }
});

test('ShareGate: upstream failure answers with no-store 502', async () => {
  // Target port with no listener: connect fails synchronously.
  const gate = new ShareGate({ targetPort: 59999, targetHost: '127.0.0.1', ttlMinutes: 60 });
  const gatePort = await gate.listen();

  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);

  try {
    const res = await request(gatePort, '/whatever', {
      headers: { cookie: `pn_share=${sessionId}` },
    });
    assert.strictEqual(res.status, 502);
    assert.ok((res.headers['cache-control'] || '').includes('no-store'), 'error answers of a public share must be no-store');
  } finally {
    await gate.close();
  }
});

test('ShareGate: downstream abort cancels the upstream request (no orphaned streams)', async () => {
  let upstreamClosed = false;
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
    res.write('data: first\n\n');
    req.on('close', () => { upstreamClosed = true; });
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const uPort = upstream.address().port;

  const gate = new ShareGate({ targetPort: uPort, ttlMinutes: 60 });
  const gatePort = await gate.listen();

  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);

  try {
    await new Promise((resolve) => {
      const req = http.get({
        host: '127.0.0.1',
        port: gatePort,
        path: '/stream',
        headers: { 'cf-connecting-ip': VISITOR_IP, cookie: `pn_share=${sessionId}` },
      }, (res) => {
        res.once('data', () => {
          req.destroy(); // downstream client disappears mid-stream
          setTimeout(resolve, 100);
        });
      });
      req.on('error', () => {});
    });

    assert.strictEqual(upstreamClosed, true, 'the upstream stream must be cancelled when the client aborts');
  } finally {
    await gate.close();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
  }
});



// ---------------------------------------------------------------------------
// Revocation-safe pending starts: a replacement start waiting on the old
// share's teardown must be cancelled by a global revocation (stopAll) instead
// of silently starting its share after the revocation.
// ---------------------------------------------------------------------------

test('ShareManager: a global revocation (stopAll) cancels a pending replacement start', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-revoke-gen-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://revoked-gen.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    await mgr.start({
      name: 'app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });
    const firstPid = mgr.childPids()[0];

    // Seam: hold the old share's teardown so the replacement start waits
    // inside stop().
    const gate = mgr.shares.get('app').gate;
    const origClose = gate.close.bind(gate);
    let releaseClose = null;
    gate.close = () => new Promise((resolve) => {
      releaseClose = () => resolve(origClose());
    });

    const replacement = mgr.start({
      name: 'app',
      targetPort: port,
      ttlMinutes: 30,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    }).then(() => null, (err) => err);
    for (let i = 0; i < 200 && (!mgr.status()[0] || mgr.status()[0].state !== 'STOPPING'); i++) {
      await sleep(10);
    }
    assert.strictEqual(mgr.status()[0].state, 'STOPPING', 'replacement must be waiting inside the teardown');

    // Global revocation while the replacement is still waiting.
    const stopAllPromise = mgr.stopAll();
    await sleep(30); // let stopAll register its revocation generation
    releaseClose();

    const outcome = await replacement;
    assert.ok(outcome instanceof Error, 'the pending replacement must be cancelled by the global revocation');
    assert.match(outcome.message, /revocation/i);
    await stopAllPromise;
    assert.strictEqual(mgr.status().length, 0, 'no share may survive the revocation');
    assert.strictEqual(mgr.childPids().length, 0, 'no tunnel process may survive the revocation');
    let firstAlive = true;
    try { process.kill(firstPid, 0); } catch { firstAlive = false; }
    assert.strictEqual(firstAlive, false, 'the old tunnel child must be gone');
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Honest verification age: a share started with a genuine verification
// timestamp keeps it through activation; a target whose verification went
// stale during a slow tunnel boot is refused, not activated with a fresh
// stamp.
// ---------------------------------------------------------------------------

test('ShareManager: late activation keeps the honest verification age and refuses a stale target', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-stale-activate-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  // Tunnel that only becomes "ready" after 250ms: well past the 80ms grace.
  const cfScript = path.join(dir, 'fake-cf-slow.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nsetTimeout(() => console.log("https://stale-activate.trycloudflare.com"), 250);\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  // The last REAL target verification happened a year ago.
  const verifiedAt = Date.now() - 365 * 24 * 60 * 60 * 1000;

  try {
    const startPromise = mgr.start({
      name: 'app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
      verifiedAt,
      verifyGraceMs: 80,
    }).then(() => null, (err) => err);

    let shareObj = null;
    for (let i = 0; i < 200 && !shareObj; i++) {
      shareObj = mgr.shares.get('app');
      if (!shareObj) await sleep(10);
    }
    assert.ok(shareObj, 'share object must exist while STARTING');
    assert.strictEqual(shareObj.lastVerifiedAt, verifiedAt, 'the share must carry the passed-in verification time');

    const outcome = await startPromise;
    assert.ok(outcome instanceof Error, 'a target with stale verification must not be activated');
    assert.match(outcome.message, /verification expired/i);
    assert.strictEqual(
      shareObj.lastVerifiedAt, verifiedAt,
      'activation must never stamp an artificial fresh verification time'
    );
    assert.strictEqual(shareObj.state, 'STOPPED', 'the refused activation must tear the share down');
    assert.strictEqual(mgr.status().length, 0, 'no share may survive the refusal');
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ShareManager: a fresh verifiedAt survives activation unchanged and activates normally', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-fresh-activate-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://fresh-activate.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  try {
    const before = Date.now() - 5; // verified shortly ago by the daemon scan
    const result = await mgr.start({
      name: 'app',
      targetPort: port,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
      verifiedAt: before,
      verifyGraceMs: 20000,
    });
    assert.ok(String(result).includes('fresh-activate'));
    const shareObj = mgr.shares.get('app');
    assert.strictEqual(shareObj.state, 'ACTIVE');
    assert.strictEqual(shareObj.lastVerifiedAt, before, 'activation must keep the honest verification age');
  } finally {
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Overlapping stopAll sweeps: two concurrent sweeps (e.g. a GUI unshare-all
// racing a CLI one) must keep refusing new starts until the LAST sweep has
// finished — the first sweep's teardown must not re-enable starts that the
// still-running sweep will never stop (its share snapshot predates them).
// ---------------------------------------------------------------------------

test('ShareManager: a start is refused until the LAST of two overlapping stopAll sweeps finishes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-sweep-depth-'));
  const mgr = new ShareManager({ dir });
  const { server: upstream, port } = await startUpstream();

  const cfScript = path.join(dir, 'fake-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nconsole.log("https://sweep-depth.trycloudflare.com");\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);

  // Seam: hold a share's gate teardown until the test releases it.
  const holds = [];
  const holdGateClose = (name) => {
    const state = { release: null };
    const gate = mgr.shares.get(name).gate;
    const origClose = gate.close.bind(gate);
    let fired = false;
    gate.close = () => new Promise((resolve) => {
      state.release = () => { if (!fired) { fired = true; resolve(origClose()); } };
    });
    holds.push(state);
  };

  try {
    await mgr.start({ name: 'a', targetPort: port, ttlMinutes: 60, cloudflaredBin: cfScript, timeoutMs: 5000 });
    await mgr.start({ name: 'b', targetPort: port, ttlMinutes: 60, cloudflaredBin: cfScript, timeoutMs: 5000 });
    holdGateClose('a');
    holdGateClose('b');

    // Delay sweep 2 past sweep 1: sweep 1's stop('b') starts the teardown and
    // returns on time, every later stop('b') (sweep 2's, plus the child-exit
    // monitor's bookkeeping, if any) returns 40ms late — so sweep 1 fully
    // completes (the old bug re-enabled starts here) while sweep 2 is still
    // in flight.
    const origStop = mgr.stop.bind(mgr);
    let bStops = 0;
    mgr.stop = async (name, opts) => {
      const res = await origStop(name, opts);
      if (name === 'b') {
        bStops += 1;
        if (bStops > 1) await sleep(40);
      }
      return res;
    };

    const sweep1 = mgr.stopAll();
    const sweep2 = mgr.stopAll();
    assert.ok(holds[0].release, 'sweep 1 must be held inside the first teardown');

    holds[0].release(); // both sweeps advance past 'a' to 'b'
    for (let i = 0; i < 200 && !holds[1].release; i++) await sleep(5);
    assert.ok(holds[1].release, 'the sweeps must reach the second teardown');
    holds[1].release();

    let sweep2Done = false;
    sweep2.then(() => { sweep2Done = true; });
    await sweep1;
    assert.strictEqual(sweep2Done, false, 'the second sweep must still be running');

    // The window under test: sweep 1 is done, sweep 2 is not — a start here
    // must still be refused (the revocation check precedes argument
    // validation, so an invalid ttl cannot mask the refusal).
    await assert.rejects(
      () => mgr.start({ name: 'c', targetPort: port, ttlMinutes: -1 }),
      /global revocation \(unshare-all or shutdown\) is in progress/
    );

    await sweep2;
    assert.strictEqual(mgr.status().length, 0, 'no share may survive either sweep');
    assert.strictEqual(mgr.childPids().length, 0, 'no tunnel process may survive either sweep');
    // After the LAST sweep the gate is open again: the revocation check
    // passed and the (invalid) ttl arguments surfaced instead.
    await assert.rejects(
      () => mgr.start({ name: 'c', targetPort: port, ttlMinutes: -1 }),
      /invalid ttlMinutes/
    );
  } finally {
    for (const hold of holds) {
      if (hold.release) hold.release();
    }
    await mgr.stopAll();
    upstream.closeAllConnections();
    await new Promise((r) => upstream.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Abort-aware gate boot: a revocation racing a still-pending
// gate.listen() must settle startPromise instead of hanging forever.
// ---------------------------------------------------------------------------

test('ShareGate: close() while listen() is still pending rejects the listen promise', async () => {
  const gate = new ShareGate({ targetPort: 1, ttlMinutes: 60 });
  const listenPromise = gate.listen();
  // Same tick: gate.close() (the stop() path) runs before 'listening' ever
  // fires. Without the abort-aware listener this promise hangs forever.
  const closePromise = gate.close();
  await assert.rejects(listenPromise, /closed before it started listening/);
  await closePromise;
  assert.strictEqual(gate.server.listening, false, 'no listener may survive the close');
});

test('ShareManager: revocation mid-boot (pending gate.listen) settles startPromise, manager stays reusable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-share-bootrace-'));
  const mgr = new ShareManager({ dir });

  // Tunnel binary that would keep the startup phase alive forever — it must
  // never be reached because the boot is revoked before the spawn.
  const cfScript = path.join(dir, 'fake-slow-cf.js');
  fs.writeFileSync(
    cfScript,
    '#!/usr/bin/env node\nsetInterval(() => {}, 1000);\n'
  );
  fs.chmodSync(cfScript, 0o755);
  // Tunnel binary without a URL for the bounded "manager reusable" start.
  const cfNoUrl = path.join(dir, 'fake-nourl-cf.js');
  fs.writeFileSync(cfNoUrl, '#!/usr/bin/env node\nsetInterval(() => {}, 1000);\n');
  fs.chmodSync(cfNoUrl, 0o755);

  try {
    // start() registers the share synchronously; gate.listen() resolves only
    // on a later tick, so calling stop() in the same tick hits exactly the
    // ~2ms window between registration and 'listening'.
    const startPromise = mgr.start({
      name: 'boot-race',
      targetPort: 59999,
      ttlMinutes: 60,
      cloudflaredBin: cfScript,
      timeoutMs: 5000,
    });
    const share = mgr.shares.get('boot-race');
    assert.ok(share, 'the starting share must be registered synchronously');
    assert.strictEqual(share.state, 'STARTING');

    const stopPromise = mgr.stop('boot-race');
    await assert.rejects(startPromise, /closed before it started listening/);
    await stopPromise;

    assert.strictEqual(mgr.isShared('boot-race'), false, 'revoked share must be gone');
    assert.strictEqual(share.gate.server.listening, false, 'no open gate listener may remain');
    assert.strictEqual(mgr.status().length, 0);

    // The manager must be reusable: a fresh start under the same name runs
    // into the (bounded) tunnel boot instead of hanging on stale STARTING
    // state or a wedged startPromise.
    await assert.rejects(
      () => mgr.start({
        name: 'boot-race',
        targetPort: 59999,
        ttlMinutes: 60,
        cloudflaredBin: cfNoUrl,
        timeoutMs: 150,
      }),
      /did not produce a URL within 150ms/
    );
  } finally {
    await mgr.stopAll();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Resolver precedence: an explicit cloudflaredBin override always wins;
// otherwise a payload/bundle operation prefers the bundled binary over the
// absolute Homebrew paths; without a bundled binary Homebrew/PATH still apply.
// ---------------------------------------------------------------------------

test('resolveCloudflaredBin: explicit override wins even with a bundled binary present', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cfbin-home-'));
  try {
    const bundled = path.join(home, 'Library', 'Application Support', 'Portname', 'runtime', 'bin', 'cloudflared');
    fs.mkdirSync(path.dirname(bundled), { recursive: true });
    fs.writeFileSync(bundled, '#!/bin/sh\nexit 0\n');
    fs.chmodSync(bundled, 0o755);
    const homebrewFake = path.join(home, 'brew', 'cloudflared');
    fs.mkdirSync(path.dirname(homebrewFake), { recursive: true });
    fs.writeFileSync(homebrewFake, 'brew');
    assert.strictEqual(
      resolveCloudflaredBin('/explicit/user/cloudflared', {
        isPayloadEntry: true,
        home,
        candidates: [homebrewFake],
      }),
      '/explicit/user/cloudflared'
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('resolveCloudflaredBin: bundled binary beats Homebrew candidates in payload operation', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cfbin-home-'));
  try {
    const payloadRuntime = path.join(home, 'Library', 'Application Support', 'Portname', 'runtime', 'bin');
    const bundled = path.join(payloadRuntime, 'cloudflared');
    fs.mkdirSync(payloadRuntime, { recursive: true });
    fs.writeFileSync(bundled, 'bundled-binary');
    fs.chmodSync(bundled, 0o755);
    // Both "Homebrew" installs (fixtures) exist at the same time.
    const homebrewCandidates = [];
    for (const dir of [path.join(home, 'opt', 'homebrew', 'bin'), path.join(home, 'usr', 'local', 'bin')]) {
      fs.mkdirSync(dir, { recursive: true });
      const c = path.join(dir, 'cloudflared');
      fs.writeFileSync(c, 'homebrew-binary');
      fs.chmodSync(c, 0o755);
      homebrewCandidates.push(c);
    }
    assert.strictEqual(
      resolveCloudflaredBin('cloudflared', { isPayloadEntry: true, home, candidates: homebrewCandidates }),
      bundled,
      'in payload operation the shipped binary is the unambiguous default'
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('resolveCloudflaredBin: without a bundled component the Homebrew/PATH fallback still applies', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cfbin-home-'));
  try {
    // Payload operation, but no bundled cloudflared was shipped.
    fs.mkdirSync(path.join(home, 'Library', 'Application Support', 'Portname', 'runtime', 'bin'), { recursive: true });
    const homebrewFake = path.join(home, 'opt', 'homebrew', 'bin', 'cloudflared');
    fs.mkdirSync(path.dirname(homebrewFake), { recursive: true });
    fs.writeFileSync(homebrewFake, 'homebrew-binary');
    fs.chmodSync(homebrewFake, 0o755);
    assert.strictEqual(
      resolveCloudflaredBin('cloudflared', { isPayloadEntry: true, home, candidates: [homebrewFake] }),
      homebrewFake,
      'first existing Homebrew candidate must win without a bundled binary'
    );

    // Nothing installed at all: fall back to the bare PATH lookup name.
    assert.strictEqual(
      resolveCloudflaredBin('cloudflared', {
        isPayloadEntry: true,
        home,
        candidates: [path.join(home, 'missing', 'cloudflared')],
      }),
      'cloudflared'
    );

    // Not running from the payload: the payload location is never consulted
    // even if a binary happens to exist there.
    const stray = path.join(home, 'Library', 'Application Support', 'Portname', 'runtime', 'bin', 'cloudflared');
    fs.writeFileSync(stray, 'bundled-binary');
    fs.chmodSync(stray, 0o755);
    assert.strictEqual(
      resolveCloudflaredBin('cloudflared', { isPayloadEntry: false, home, candidates: [path.join(home, 'missing', 'cloudflared')] }),
      'cloudflared',
      'outside payload operation the shipped binary must not be picked up silently'
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
