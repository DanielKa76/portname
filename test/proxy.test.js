'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const { createGateway, listenGateway } = require('../lib/proxy');

function startUpstream(bodyFn) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      bodyFn(req, res);
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

const PLAIN = (req, res) => res.end('marker:' + req.url);

// An SSE-style upstream: several events, flushed, before the response ends.
const SSE = (req, res) => {
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  let n = 0;
  const t = setInterval(() => {
    n += 1;
    res.write(`data: event-${n}\n\n`);
    if (n >= 3) {
      clearInterval(t);
      res.end();
    }
  }, 15);
};

function get(port, host, path = '/', extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const req = http
      .get({ host: '127.0.0.1', port, path, headers: { host, ...extraHeaders }, agent: false }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
      })
      .on('error', reject);
  });
}

async function startGateway(routes, opts = {}) {
  const gateway = createGateway({
    getRoute: (name) => routes[name] || null,
    isExposed: opts.isExposed || (() => false),
    log: () => {},
  });
  const bind = await listenGateway(gateway, { mode: opts.mode || 'wildcard', port: 0, fallbackPort: 0, loopbackPort: opts.loopbackPort || 0 });
  return { gateway, port: bind.primary, extra: bind.extra };
}

async function stop(gateway, upstreams = []) {
  await gateway.close();
  for (const u of upstreams) {
    u.closeAllConnections();
    await new Promise((r) => u.close(r));
  }
}

test('gateway routes per request and streams upstream bodies untouched', async () => {
  const a = await startUpstream(PLAIN);
  const b = await startUpstream(SSE);
  const { gateway, port } = await startGateway({ app: { port: a.port }, events: { port: b.port } });
  try {
    const res = await get(port, 'app.localhost', '/deep/path?q=1');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body, 'marker:/deep/path?q=1');

    const events = await get(port, 'events.localhost', '/stream');
    assert.strictEqual(events.status, 200);
    assert.ok(events.body.includes('event-1') && events.body.includes('event-3'), 'SSE events must arrive');
  } finally {
    await stop(gateway, [a.server, b.server]);
  }
});

test('two requests with different hosts ride the same keep-alive connection', async () => {
  const a = await startUpstream((req, res) => res.end('one'));
  const b = await startUpstream((req, res) => res.end('two'));
  const { gateway, port } = await startGateway({ one: { port: a.port }, two: { port: b.port } });
  try {
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    const req = (host) =>
      new Promise((resolve, reject) => {
        http
          .get({ host: '127.0.0.1', port, path: '/', headers: { host }, agent }, (res) => {
            let body = '';
            res.on('data', (d) => (body += d));
            res.on('end', () => resolve(body));
          })
          .on('error', reject);
      });
    assert.strictEqual(await req('one.localhost'), 'one');
    assert.strictEqual(await req('two.localhost'), 'two', 'second request on the same socket must re-route');
    assert.strictEqual(await req('one.localhost'), 'one');
    agent.destroy();
  } finally {
    await stop(gateway, [a.server, b.server]);
  }
});

test('upstream host semantics: host rewritten to localhost:<port>, X-Forwarded-Host set and cannot be spoofed', async () => {
  let capturedHeaders = null;
  const a = await startUpstream((req, res) => {
    capturedHeaders = req.headers;
    res.end('ok');
  });
  const { gateway, port } = await startGateway({ app: { port: a.port } });
  try {
    // 1. Regular request: Host rewritten to localhost:<targetPort>
    await get(port, 'app.localhost', '/test', {
      'x-forwarded-host': 'attacker.example.com',
      'x-custom-hop': 'strip-me',
      connection: 'close, x-custom-hop',
    });
    assert.strictEqual(capturedHeaders['host'], `localhost:${a.port}`);
    assert.strictEqual(capturedHeaders['x-forwarded-host'], 'app.localhost', 'attacker X-Forwarded-Host must be overwritten');
    assert.strictEqual(capturedHeaders['x-forwarded-proto'], 'http');
    assert.strictEqual(capturedHeaders['x-custom-hop'], undefined, 'custom hop-by-hop header must be removed');
  } finally {
    await stop(gateway, [a.server]);
  }
});

test('hop-by-hop response headers are sanitized from upstream', async () => {
  const a = await startUpstream((req, res) => {
    res.writeHead(200, {
      'connection': 'close, x-secret-hop',
      'x-secret-hop': 'secret-value',
      'proxy-authenticate': 'Basic',
      'custom-app-header': 'visible',
    });
    res.end('body');
  });
  const { gateway, port } = await startGateway({ app: { port: a.port } });
  try {
    const res = await get(port, 'app.localhost', '/');
    assert.strictEqual(res.headers['x-secret-hop'], undefined);
    assert.strictEqual(res.headers['proxy-authenticate'], undefined);
    assert.strictEqual(res.headers['custom-app-header'], 'visible');
    assert.strictEqual(res.headers['cache-control'], 'no-store');
  } finally {
    await stop(gateway, [a.server]);
  }
});

test('defined refusals: unknown host 404, missing/duplicate host never reach upstream, CONNECT 405', async () => {
  let upstreamHits = 0;
  const a = await startUpstream((req, res) => {
    upstreamHits += 1;
    res.end('marker');
  });
  const { gateway, port } = await startGateway({ app: { port: a.port } });
  try {
    const unknown = await get(port, 'secret-project.localhost');
    assert.strictEqual(unknown.status, 404);
    assert.strictEqual(unknown.body, '', 'must name nothing');
    assert.strictEqual(unknown.headers['cache-control'], 'no-store');

    const raw = (head) =>
      new Promise((resolve) => {
        let timer;
        const sock = net.connect(port, '127.0.0.1', () => sock.write(head));
        let data = '';
        sock.on('data', (d) => (data += d.toString()));
        sock.on('close', () => {
          clearTimeout(timer);
          resolve(data);
        });
        timer = setTimeout(() => {
          sock.destroy();
          resolve(data);
        }, 500);
      });

    const missing = await raw('GET / HTTP/1.1\r\nconnection: close\r\n\r\n');
    assert.match(missing, /HTTP\/1\.1 400/, 'missing host must be rejected as 400');

    const dup = await raw('GET / HTTP/1.1\r\nhost: app.localhost\r\nhost: other.localhost\r\nconnection: close\r\n\r\n');
    assert.match(dup, /HTTP\/1\.1 4\d\d/, 'duplicate host must be rejected with 4xx');

    const connect = await raw('CONNECT evil.example:443 HTTP/1.1\r\nhost: evil.example:443\r\n\r\n');
    assert.ok(connect.startsWith('HTTP/1.1 405'), 'CONNECT is refused outright');

    assert.strictEqual(upstreamHits, 0, 'refused requests must never touch an upstream');
  } finally {
    await stop(gateway, [a.server]);
  }
});

test('host header split across TCP writes is buffered and routed correctly', async () => {
  const a = await startUpstream(PLAIN);
  const { gateway, port } = await startGateway({ slow: { port: a.port } });
  try {
    const body = await new Promise((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1', () => {
        sock.write('GET /a HTTP/1.1\r\n');
        setTimeout(() => {
          sock.write('host: slow.localhost\r\nconnection: close\r\n\r\n');
        }, 30);
      });
      let data = '';
      sock.on('data', (d) => (data += d.toString()));
      sock.on('close', () => resolve(data));
      sock.on('error', reject);
    });
    assert.ok(body.includes('HTTP/1.1 200'), 'expected upstream 200, got: ' + body.slice(0, 60));
    assert.ok(body.includes('marker:/a'));
  } finally {
    await stop(gateway, [a.server]);
  }
});

test('websocket upgrades splice raw bytes and teardown tracks both ends', async () => {
  let wsUpstreamSocket = null;
  const ws = net.createServer((sock) => {
    wsUpstreamSocket = sock;
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
  const { gateway, port } = await startGateway({ app: { port: wsPort } });
  let clientSock = null;
  try {
    const key = crypto.randomBytes(16).toString('base64');
    const reply = await new Promise((resolve, reject) => {
      let timer;
      clientSock = net.connect(port, '127.0.0.1', () => {
        clientSock.write(
          `GET /ws HTTP/1.1\r\nhost: app.localhost\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: ${key}\r\nsec-websocket-version: 13\r\n\r\nPAYLOAD`
        );
      });
      let data = '';
      clientSock.on('data', (d) => {
        data += d.toString();
        if (data.includes('PAYLOAD')) {
          clearTimeout(timer);
          resolve(data);
        }
      });
      clientSock.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
      timer = setTimeout(() => reject(new Error('no echo: ' + data.slice(0, 80))), 2000);
    });
    assert.ok(reply.includes('101'), 'upgrade handshake should pass through');
    assert.ok(reply.includes('PAYLOAD'), 'bidirectional bytes after upgrade');

    // Both ends tracked
    assert.strictEqual(gateway.activeConnections.size, 1, 'connection pair is tracked');
    const conn = [...gateway.activeConnections][0];
    const clientClosed = new Promise((resolve) => conn.client.on('close', resolve));
    const upstreamClosed = new Promise((resolve) => wsUpstreamSocket.on('close', resolve));

    clientSock.destroy();
    await Promise.all([clientClosed, upstreamClosed]);
    assert.strictEqual(gateway.activeConnections.size, 0, 'tracking set cleaned after close');
    assert.strictEqual(conn.client.destroyed, true, 'client socket destroyed');
    assert.strictEqual(conn.upstream.destroyed, true, 'upstream socket destroyed');
  } finally {
    if (clientSock && !clientSock.destroyed) clientSock.destroy();
    await stop(gateway);
    await new Promise((r) => ws.close(r));
  }
});

test('loopback mode binds IPv4 (127.0.0.1) and IPv6 (::1) atomically', async () => {
  const a = await startUpstream(PLAIN);
  const loopPort = 10000 + Math.floor(Math.random() * 20000);
  const { gateway, port, extra } = await startGateway({ app: { port: a.port } }, {
    mode: 'loopback',
    loopbackPort: loopPort,
  });

  try {
    assert.strictEqual(port, loopPort);
    assert.strictEqual(gateway.servers.length, 2, 'two servers created in loopback mode');

    // Test IPv4 reachability
    const res4 = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path: '/', headers: { host: 'app.localhost' } }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }).on('error', reject);
    });
    assert.strictEqual(res4.status, 200);
    assert.strictEqual(res4.body, 'marker:/');

    // Test IPv6 reachability
    const res6 = await new Promise((resolve, reject) => {
      http.get({ host: '::1', port, path: '/', headers: { host: 'app.localhost' } }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }).on('error', reject);
    });
    assert.strictEqual(res6.status, 200);
    assert.strictEqual(res6.body, 'marker:/');
  } finally {
    await stop(gateway, [a.server]);
  }
});

test('wildcard bind falls back when port 80 is taken', async () => {
  const blocker = net.createServer();
  await new Promise((r) => blocker.listen({ port: 0, host: '::', ipv6Only: false }, r));
  const busy = blocker.address().port;
  const gateway = createGateway({ getRoute: () => null, log: () => {} });
  const bind = await listenGateway(gateway, { mode: 'wildcard', port: busy, fallbackPort: 0 });
  assert.notStrictEqual(bind.primary, busy);
  await gateway.close();
  await new Promise((r) => blocker.close(r));
});

const { rewriteLocationHeader } = require('../lib/headers');

test('rewriteLocationHeader: rewrites internal loopback redirects back to public client host', () => {
  // Absolute redirect to internal port rewritten
  const rewritten1 = rewriteLocationHeader('http://localhost:3000/login?code=123', {
    originalHost: 'shop.localhost',
    targetPort: 3000,
    proto: 'http',
  });
  assert.strictEqual(rewritten1, 'http://shop.localhost/login?code=123');

  // IPv4 loopback redirect rewritten
  const rewritten2 = rewriteLocationHeader('http://127.0.0.1:3000/oauth/callback', {
    originalHost: 'shop.local',
    targetPort: 3000,
    proto: 'http',
  });
  assert.strictEqual(rewritten2, 'http://shop.local/oauth/callback');

  // Public share HTTPS redirect rewritten
  const rewritten3 = rewriteLocationHeader('http://localhost:5173/dashboard', {
    originalHost: 'demo.trycloudflare.com',
    targetPort: 5173,
    proto: 'https',
  });
  assert.strictEqual(rewritten3, 'https://demo.trycloudflare.com/dashboard');

  // External OAuth provider redirect untouched
  const external = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=xyz';
  assert.strictEqual(
    rewriteLocationHeader(external, { originalHost: 'shop.localhost', targetPort: 3000 }),
    external
  );

  // Relative path untouched
  assert.strictEqual(
    rewriteLocationHeader('/login', { originalHost: 'shop.localhost', targetPort: 3000 }),
    '/login'
  );
});

test('Forwarded header: untrusted client Forwarded header is removed and replaced by trusted facts', async () => {
  let receivedHeaders = null;
  const srv = http.createServer((req, res) => {
    receivedHeaders = req.headers;
    res.writeHead(200, { 'content-length': 2 });
    res.end('ok');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;

  const { gateway, port: gwPort } = await startGateway({ app: { port } });
  try {
    const res = await new Promise((resolve, reject) => {
      http.get({
        host: '127.0.0.1',
        port: gwPort,
        path: '/',
        headers: {
          host: 'app.localhost',
          forwarded: 'for=198.51.100.1;host=evil.example;proto=https', // Client spoofing attempt
        },
      }, (r) => {
        r.resume();
        r.on('end', resolve);
      }).on('error', reject);
    });

    assert.ok(receivedHeaders);
    // Spoofed host and IP in Forwarded must not be passed through
    assert.ok(!receivedHeaders['forwarded'].includes('evil.example'));
    assert.ok(!receivedHeaders['forwarded'].includes('198.51.100.1'));
    // Trusted values synthesized
    assert.ok(receivedHeaders['forwarded'].includes('host=app.localhost'));
    assert.ok(receivedHeaders['forwarded'].includes('proto=http'));
  } finally {
    await stop(gateway, [srv]);
  }
});

test('client abort: prematurely disconnecting downstream client aborts upstream HTTP request', async () => {
  let upstreamClosed = false;
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    });
    res.write('event: ping\ndata: 1\n\n');

    req.on('close', () => {
      upstreamClosed = true;
    });
  });

  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const uPort = upstream.address().port;

  const { gateway, port: gwPort } = await startGateway({ sse: { port: uPort } });
  try {
    await new Promise((resolve) => {
      const clientReq = http.get({
        host: '127.0.0.1',
        port: gwPort,
        path: '/',
        headers: { host: 'sse.localhost' },
      }, (res) => {
        res.once('data', () => {
          // Client received first chunk and destroys connection prematurely
          clientReq.destroy();
          setTimeout(resolve, 50);
        });
      });
    });

    assert.strictEqual(upstreamClosed, true, 'upstream request must be destroyed when client disconnects');
  } finally {
    await stop(gateway, [upstream]);
  }
});

test('IPv6 upstream: Gateway routes correctly to an IPv6-only loopback upstream', async () => {
  const srv6 = http.createServer((req, res) => {
    res.writeHead(200);
    res.end('from-ipv6');
  });
  await new Promise((r) => srv6.listen({ host: '::1', port: 0 }, r));
  const port6 = srv6.address().port;

  const { gateway, port: gwPort } = await startGateway({
    ipv6app: { port: port6, upstreamHost: '::1' },
  });

  try {
    const res = await get(gwPort, 'ipv6app.localhost', '/');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body, 'from-ipv6');
  } finally {
    await stop(gateway, [srv6]);
  }
});

test('Host header: malformed host values are strictly rejected with HTTP 400', async () => {
  const { server, port: upstreamPort } = await startUpstream(200, 'upstream-ok');
  const { gateway, port: gwPort } = await startGateway({
    shop: { port: upstreamPort },
  });

  try {
    const malformedHosts = [
      'shop.localhost;evil',
      'shop.localhost:99999',
      'shop.localhost:80:90',
      'shop.localhost:080',
      'shop.localhost:abc',
      'shop.localhost/bad',
      'shop.localhost@evil',
      'shop.localhost:0',
    ];

    for (const badHost of malformedHosts) {
      const res = await get(gwPort, badHost, '/');
      assert.strictEqual(res.status, 400, `Host "${badHost}" must be rejected with HTTP 400`);
    }
  } finally {
    await stop(gateway, [server]);
  }
});

test('Forwarded header: quotes host parameter when port is present per RFC 7239', async () => {
  let receivedHeaders = null;
  const srv = http.createServer((req, res) => {
    receivedHeaders = req.headers;
    res.writeHead(200);
    res.end('ok');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const srvPort = srv.address().port;

  const { gateway, port: gwPort } = await startGateway({
    app: { port: srvPort },
  });

  try {
    // 1. Host with port -> host="app.localhost:8080"
    await get(gwPort, 'app.localhost:8080', '/');
    assert.ok(receivedHeaders['forwarded']);
    assert.ok(
      receivedHeaders['forwarded'].includes('host="app.localhost:8080"'),
      `Forwarded header must quote host when port is present: ${receivedHeaders['forwarded']}`
    );

    // 2. Bare Host without port -> host=app.localhost
    await get(gwPort, 'app.localhost', '/');
    assert.ok(receivedHeaders['forwarded']);
    assert.ok(
      receivedHeaders['forwarded'].includes('host=app.localhost'),
      `Forwarded header must not quote token host: ${receivedHeaders['forwarded']}`
    );
  } finally {
    await stop(gateway, [srv]);
  }
});

