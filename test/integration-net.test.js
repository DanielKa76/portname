'use strict';

// Regression tests for behaviour the gateway (lib/proxy.js) and the share
// gate (lib/share.js) have in common: the client-address metadata an
// upstream may trust, requests whose header list Node may have cut short,
// raw response heads and truncated bodies relayed on the upgrade path,
// unsolicited 101 answers on the pooled path, and token-path access for
// clients without a cookie jar.

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');

const { createGateway, listenGateway } = require('../lib/proxy');
const { ShareGate, randomToken } = require('../lib/share');
const {
  prepareUpstreamRequestHeaders,
  prepareUpgradeRequestHeaders,
  formatWebSocketUpgradeHeaders,
} = require('../lib/headers');

const VISITOR_IP = '203.0.113.21';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function listen(server) {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function closeServer(server) {
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  return new Promise((r) => server.close(() => r()));
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

// A share gate with one live browser session, as after a token redemption.
async function startGate(targetPort, opts = {}) {
  const gate = new ShareGate({ targetPort, ttlMinutes: 60, ...opts });
  const port = await gate.listen();
  const sessionId = randomToken();
  gate.sessions.set(sessionId, gate.expiresAt);
  return { gate, port, cookie: `pn_share=${sessionId}` };
}

function request(port, reqPath, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: reqPath, method, headers, agent: false }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

// Sends raw bytes and reports what came back (latin1, byte for byte) and how
// the connection ended: 'fin' (orderly close), 'reset' (ECONNRESET), 'head'
// (stopped by the caller once a full response head arrived) or 'open' (still
// open at the deadline).
function rawExchange(port, payload, { timeoutMs = 2500, untilHead = false } = {}) {
  return new Promise((resolve) => {
    let data = '';
    let settled = false;
    const sock = net.connect(port, '127.0.0.1', () => sock.write(payload));
    const finish = (ending) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (!sock.destroyed) sock.destroy();
      resolve({ data, ending });
    };
    sock.on('data', (d) => {
      data += d.toString('latin1');
      if (untilHead && data.includes('\r\n\r\n')) finish('head');
    });
    sock.on('end', () => finish('fin'));
    sock.on('error', (err) => finish(err.code === 'ECONNRESET' ? 'reset' : err.code));
    sock.on('close', () => finish('fin'));
    const timer = setTimeout(() => finish('open'), timeoutMs);
  });
}

const WS_HANDSHAKE = (reqPath, extra = '') =>
  `GET ${reqPath} HTTP/1.1\r\n${extra}Connection: Upgrade\r\nUpgrade: websocket\r\n` +
  'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n';

// Test upstreams are plain local listeners; discovery passes of daemon tests
// running in parallel may probe them (GET /json/version), so assertions only
// look at the paths a test sends itself.
const ours = (seen, prefix) => seen.filter((r) => r.url.startsWith(prefix));

// ---------------------------------------------------------------------------
// Client-address metadata: the upstream only ever sees the verified client
// in X-Forwarded-For/Forwarded — never a loopback stand-in, never a
// client-set Client-Ip / X-Real-Ip / True-Client-Ip.
// ---------------------------------------------------------------------------

test('headers: upstream request headers cannot be prepared without a client address', () => {
  const req = { headers: { host: 'app.localhost' }, rawHeaders: ['Host', 'app.localhost'] };
  for (const clientIp of [undefined, null, '']) {
    const opts = { originalHost: 'app.localhost', clientIp, targetPort: 3000 };
    assert.throws(() => prepareUpstreamRequestHeaders(req, opts), /clientIp/, `prepareUpstreamRequestHeaders(${clientIp})`);
    assert.throws(() => prepareUpgradeRequestHeaders(req.rawHeaders, opts), /clientIp/, `prepareUpgradeRequestHeaders(${clientIp})`);
    assert.throws(() => formatWebSocketUpgradeHeaders(req.rawHeaders, opts), /clientIp/, `formatWebSocketUpgradeHeaders(${clientIp})`);
  }
  const ok = prepareUpstreamRequestHeaders(req, { originalHost: 'app.localhost', clientIp: '192.168.1.20', targetPort: 3000 });
  assert.strictEqual(ok['x-forwarded-for'], '192.168.1.20');
  assert.ok(ok.forwarded.startsWith('for=192.168.1.20;'), ok.forwarded);
});

test('gateway: a LAN client cannot pass Client-Ip / X-Real-Ip / True-Client-Ip to the upstream (requests and WebSocket handshakes)', async () => {
  const seen = [];
  const up = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    res.end('ok');
  });
  up.on('upgrade', (req, sock) => {
    seen.push({ url: req.url, headers: req.headers });
    sock.on('error', () => {});
    sock.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
  });
  const upPort = await listen(up);
  // Test seams: every connection is an authorized LAN peer of an exposed route.
  const { gateway, port } = await startGateway({ app: { name: 'app', port: upPort, root: '/r/app' } }, {
    isExposed: () => true,
    getLanInfo: () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' }),
    isLoopbackClient: () => false,
  });
  const spoofed = 'Client-Ip: 127.0.0.1\r\nX-Real-Ip: 127.0.0.1\r\nTrue-Client-Ip: ::1\r\nX-Forwarded-For: 6.6.6.6\r\n'
    + 'X-Client-Ip: 127.0.0.1\r\nX-Cluster-Client-Ip: 127.0.0.1\r\nFastly-Client-Ip: 127.0.0.1\r\nCf-Connecting-Ip: 127.0.0.1\r\n';
  try {
    const plain = await rawExchange(port, `GET /lan-request HTTP/1.1\r\nHost: app.local\r\n${spoofed}Connection: close\r\n\r\n`);
    assert.match(plain.data, /^HTTP\/1\.1 200/, plain.data.split('\r\n')[0]);
    const ws = await rawExchange(port, WS_HANDSHAKE('/lan-ws', `Host: app.local\r\n${spoofed}`), { untilHead: true });
    assert.match(ws.data, /^HTTP\/1\.1 101/, ws.data.split('\r\n')[0]);

    const reached = ours(seen, '/lan-');
    assert.deepStrictEqual(reached.map((r) => r.url), ['/lan-request', '/lan-ws']);
    for (const { url, headers } of reached) {
      assert.strictEqual(headers['client-ip'], undefined, `${url}: Client-Ip`);
      assert.strictEqual(headers['x-real-ip'], undefined, `${url}: X-Real-Ip`);
      assert.strictEqual(headers['true-client-ip'], undefined, `${url}: True-Client-Ip`);
      for (const name of ['x-client-ip', 'x-cluster-client-ip', 'fastly-client-ip', 'cf-connecting-ip']) {
        assert.strictEqual(headers[name], undefined, `${url}: ${name}`);
      }
      assert.match(headers['x-forwarded-for'], /^(::ffff:)?127\.0\.0\.1$/, `${url}: XFF is the socket peer`);
    }
  } finally {
    await gateway.close();
    await closeServer(up);
  }
});

// ---------------------------------------------------------------------------
// Header lists at Node's limit: before the July 2026 security release
// (CVE-2026-58044) Node hid header lines past maxHeadersCount from userland
// but still framed the body by them. A Content-Length hidden that way made
// the relays forward a GET without framing, and the upstream parsed its body
// as a second request on the pooled connection.
// ---------------------------------------------------------------------------

const SMUGGLED = 'GET /cut-SMUGGLED HTTP/1.1\r\nHost: evil.example\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n';
const filler = (count) => 'a: 1\r\n'.repeat(count);

function recordingUpstream() {
  const seen = [];
  const server = http.createServer((req, res) => {
    const entry = { method: req.method, url: req.url, headers: req.headers, body: '' };
    seen.push(entry);
    req.setEncoding('latin1');
    req.on('data', (d) => (entry.body += d));
    req.on('end', () => res.end('ok'));
  });
  return listen(server).then((port) => ({ server, port, seen }));
}

test('gateway and share gate: a request whose header list reached Node\'s limit is refused, never forwarded', async () => {
  const up = await recordingUpstream();
  const { gateway, port } = await startGateway({ app: { port: up.port } });
  const share = await startGate(up.port);
  const body = `Content-Length: ${Buffer.byteLength(SMUGGLED)}\r\nConnection: close\r\n\r\n${SMUGGLED}`;
  const relays = {
    gateway: { port, head: 'Host: app.localhost\r\n' },
    'share gate': { port: share.port, head: `Host: demo.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\nCookie: ${share.cookie}\r\n` },
  };
  try {
    for (const [label, relay] of Object.entries(relays)) {
      up.seen.length = 0;
      // 1000 more lines push Content-Length past the default limit.
      const cut = await rawExchange(relay.port, `GET /cut-request HTTP/1.1\r\n${relay.head}${filler(1000)}${body}`);
      // This relay answers 431; a runtime that refuses such a head itself
      // answers with its own 4xx before the relay sees it.
      assert.match(cut.data, /^HTTP\/1\.1 4(31|00) /, `${label}: ${cut.data.split('\r\n')[0]}`);
      await sleep(150); // a smuggled request would be parsed right behind the first one
      assert.deepStrictEqual(ours(up.seen, '/cut-'), [], `${label}: nothing may reach the upstream`);

      // The same on the upgrade path: the handshake is refused, not relayed.
      const handshake = WS_HANDSHAKE('/cut-ws', relay.head).replace(/\r\n\r\n$/, `\r\n${filler(1000)}\r\n`);
      const ws = await rawExchange(relay.port, handshake);
      assert.match(ws.data, /^HTTP\/1\.1 4(31|00) /, `${label} upgrade: ${ws.data.split('\r\n')[0]}`);
      assert.deepStrictEqual(ours(up.seen, '/cut-'), [], `${label}: no handshake may reach the upstream`);

      // Well below the limit, a header-heavy request is served as usual.
      const many = await rawExchange(relay.port, `GET /cut-many HTTP/1.1\r\n${relay.head}${filler(900)}${body}`);
      assert.match(many.data, /^HTTP\/1\.1 200 /, `${label}: ${many.data.split('\r\n')[0]}`);
      await sleep(150);
      assert.deepStrictEqual(
        ours(up.seen, '/cut-').map((r) => [r.url, r.body]),
        [['/cut-many', SMUGGLED]],
        `${label}: the body arrives as a body`
      );
    }
  } finally {
    await gateway.close();
    await share.gate.close();
    await closeServer(up.server);
  }
});

// ---------------------------------------------------------------------------
// Raw relays on the upgrade path: response heads leave byte for byte (Node
// hands header values over as latin1, one char per byte), and a non-101
// answer, relayed close-delimited, whose upstream body ends early reaches the
// client as an abort — a clean FIN would make the truncated body look whole.
// ---------------------------------------------------------------------------

const truncated = (rest, how) => (sock) => {
  sock.write(`HTTP/1.1 404 Not Found\r\n${rest}`);
  setTimeout(() => (how === 'rst' ? sock.resetAndDestroy() : sock.end()), 50);
};

// Raw upstream for handshakes: the request path picks the answer.
const HANDSHAKE_ANSWERS = {
  '/raw-101': (sock) =>
    sock.write(Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nX-Name: caf\xe9\r\n\r\n', 'latin1')),
  '/raw-403': (sock) => sock.end(Buffer.from('HTTP/1.1 403 Forbidden\r\nX-Name: caf\xe9\r\nContent-Length: 2\r\n\r\nno', 'latin1')),
  '/raw-complete': (sock) => sock.end('HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n'),
  '/raw-chunked-fin': truncated('Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n', 'fin'),
  '/raw-chunked-rst': truncated('Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n', 'rst'),
  '/raw-length-fin': truncated('Content-Length: 100\r\n\r\nhello', 'fin'),
};

async function handshakeUpstream() {
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('error', () => {});
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (!buf.includes('\r\n\r\n')) return;
      const answer = HANDSHAKE_ANSWERS[buf.split(' ')[1]];
      buf = '';
      if (answer) answer(sock);
      else sock.destroy();
    });
  });
  return { server, port: await listen(server) };
}

// Both relays in front of the same upstream, each with what its handshake
// needs to be authorized.
async function upgradeRelays(upPort) {
  const { gateway, port } = await startGateway({ app: { port: upPort } });
  const share = await startGate(upPort);
  return {
    relays: {
      gateway: { port, head: 'Host: app.localhost\r\n' },
      'share gate': { port: share.port, head: `Host: demo.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\nCookie: ${share.cookie}\r\n` },
    },
    close: async () => {
      await gateway.close();
      await share.gate.close();
    },
  };
}

test('upgrade relays: 101 and non-101 response heads are written byte-exact (latin1), never re-encoded as UTF-8', async () => {
  const up = await handshakeUpstream();
  const { relays, close } = await upgradeRelays(up.port);
  try {
    for (const [label, relay] of Object.entries(relays)) {
      const switched = await rawExchange(relay.port, WS_HANDSHAKE('/raw-101', relay.head), { untilHead: true });
      assert.match(switched.data, /^HTTP\/1\.1 101 /, `${label}: ${switched.data.split('\r\n')[0]}`);
      assert.ok(switched.data.includes('X-Name: café\r\n'), `${label} 101: header byte 0xE9 must arrive as is: ${JSON.stringify(switched.data)}`);

      const refused = await rawExchange(relay.port, WS_HANDSHAKE('/raw-403', relay.head));
      assert.match(refused.data, /^HTTP\/1\.1 403 /, `${label}: ${refused.data.split('\r\n')[0]}`);
      assert.match(refused.data, /\r\nx-name: café\r\n/i, `${label} 403: header byte 0xE9 must arrive as is: ${JSON.stringify(refused.data)}`);
    }
  } finally {
    await close();
    await closeServer(up.server);
  }
});

test('upgrade relays: a non-101 answer whose upstream body ends early is aborted (RST), a complete one closes cleanly', async () => {
  const up = await handshakeUpstream();
  const { relays, close } = await upgradeRelays(up.port);
  try {
    for (const [label, relay] of Object.entries(relays)) {
      for (const mode of ['chunked-fin', 'chunked-rst', 'length-fin']) {
        const res = await rawExchange(relay.port, WS_HANDSHAKE(`/raw-${mode}`, relay.head));
        assert.match(res.data, /^(HTTP\/1\.1 404 |$)/, `${label} ${mode}: ${res.data.split('\r\n')[0]}`);
        assert.strictEqual(res.ending, 'reset', `${label} ${mode}: a truncated body must end in a reset, got ${res.ending}`);
      }
      const complete = await rawExchange(relay.port, WS_HANDSHAKE('/raw-complete', relay.head));
      assert.strictEqual(complete.ending, 'fin', `${label}: a complete body ends with an orderly close`);
      assert.match(complete.data, /^HTTP\/1\.1 404 [^]*\r\n\r\nhello$/, `${label}: ${JSON.stringify(complete.data)}`);
    }
  } finally {
    await close();
    await closeServer(up.server);
  }
});

// ---------------------------------------------------------------------------
// Unsolicited 101 on the pooled path: an upstream switching protocols for a
// request that offered no upgrade (the relays strip an h2c offer) is broken.
// With upgrade headers Node used to swallow the answer (no 'response', no
// 'error') and the client hung; without them the 101 was relayed as a switch
// the client never asked for. Both get 502.
// ---------------------------------------------------------------------------

test('pooled path: an unsolicited 101 from the upstream is answered with 502, never a hang or a relayed switch', async () => {
  const upstream = net.createServer((sock) => {
    let buf = '';
    sock.on('error', () => {});
    sock.on('data', (d) => {
      buf += d;
      if (!buf.includes('\r\n\r\n')) return;
      const reqPath = buf.split(' ')[1];
      buf = '';
      if (reqPath === '/u101-headers') sock.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\nRAW-SWITCHED');
      else if (reqPath === '/u101-bare') sock.write('HTTP/1.1 101 Switching Protocols\r\n\r\nRAW-BARE');
      else sock.write('HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok');
    });
  });
  const upPort = await listen(upstream);
  const { gateway, port } = await startGateway({ app: { port: upPort } });
  const share = await startGate(upPort);
  const h2cOffer = 'Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n';
  const cases = [
    ['gateway', port, 'Host: app.localhost\r\n'],
    ['gateway (h2c offer)', port, `Host: app.localhost\r\n${h2cOffer}`],
    ['share gate', share.port, `Host: demo.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\nCookie: ${share.cookie}\r\n`],
  ];
  try {
    for (const [label, relayPort, head] of cases) {
      for (const reqPath of ['/u101-headers', '/u101-bare']) {
        const res = await rawExchange(relayPort, `GET ${reqPath} HTTP/1.1\r\n${head}\r\n`, { untilHead: true });
        assert.match(res.data, /^HTTP\/1\.1 502 /, `${label} ${reqPath}: ${res.ending}, ${JSON.stringify(res.data.split('\r\n')[0])}`);
        assert.ok(!res.data.includes('RAW-'), `${label} ${reqPath}: no upstream bytes past the 101`);
      }
    }
    for (let i = 0; i < 50 && gateway.activeRequests.size > 0; i += 1) await sleep(10);
    assert.strictEqual(gateway.activeRequests.size, 0, 'no request stays tracked');
    const ok = await rawExchange(port, 'GET /fine HTTP/1.1\r\nHost: app.localhost\r\nConnection: close\r\n\r\n');
    assert.match(ok.data, /^HTTP\/1\.1 200 /, 'the gateway keeps serving');
  } finally {
    await gateway.close();
    await share.gate.close();
    await new Promise((r) => upstream.close(r));
  }
});

// ---------------------------------------------------------------------------
// Token path without a cookie jar: webhook providers verify their endpoint
// with a GET (Meta/WhatsApp hub.challenge, X CRC, Strava, Dropbox) and follow
// no redirect with cookies. Only a browser navigation trades the token for a
// session cookie; everything else is served directly on the token path.
// ---------------------------------------------------------------------------

async function challengeUpstream() {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    const challenge = new URL(req.url, 'http://upstream').searchParams.get('hub.challenge');
    res.end(challenge || `page:${req.url}`);
  });
  return { server, seen, port: await listen(server) };
}

test('share gate: a token-path GET from a non-browser client is served directly; the token reaches neither the upstream nor the log', async () => {
  const up = await challengeUpstream();
  const logged = [];
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60, log: (...args) => logged.push(args.map(String).join(' ')) });
  const gatePort = await gate.listen();
  const query = '?hub.mode=subscribe&hub.challenge=4242&hub.verify_token=x';
  const clients = {
    'Accept: */* (curl, requests, undici)': { accept: '*/*' },
    'no Accept (Go net/http, .NET)': {},
    'Accept: application/json': { accept: 'application/json' },
    'Java HttpURLConnection default Accept': { accept: 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2' },
    'fetch() from a page': { 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', accept: 'text/html,application/xhtml+xml' },
    '<img> subresource': { 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'image', accept: 'image/avif,image/webp,*/*' },
  };
  try {
    for (const [label, extra] of Object.entries(clients)) {
      up.seen.length = 0;
      const res = await request(gatePort, `/${gate.token}/webhook${query}`, {
        headers: { 'cf-connecting-ip': VISITOR_IP, referer: `https://demo.trycloudflare.com/${gate.token}/setup`, ...extra },
      });
      assert.strictEqual(res.status, 200, `${label}: served directly, got ${res.status}`);
      assert.strictEqual(res.body, '4242', `${label}: the challenge is answered`);
      assert.strictEqual(res.headers['set-cookie'], undefined, `${label}: no session is minted`);
      assert.strictEqual(res.headers['referrer-policy'], 'no-referrer');
      const reached = ours(up.seen, '/webhook');
      assert.deepStrictEqual(reached.map((r) => r.url), [`/webhook${query}`], `${label}: the upstream sees the clean path`);
      assert.ok(!JSON.stringify(reached[0].headers).includes(gate.token), `${label}: the token never reaches the upstream`);
    }
    assert.strictEqual(gate.sessions.size, 0, 'no session was created');
    assert.ok(!logged.some((line) => line.includes(gate.token)), 'the token is never logged');
  } finally {
    await gate.close();
    await closeServer(up.server);
  }
});

test('share gate: a browser navigation to the token path still trades it for an HttpOnly session cookie and a clean-path redirect', async () => {
  const up = await challengeUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const htmlAccept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
  const navigations = {
    'current browser': { 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document', 'sec-fetch-site': 'none', accept: htmlAccept },
    'navigation without an HTML Accept': { 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document', accept: '*/*' },
    'browser without Sec-Fetch headers': { accept: htmlAccept },
  };
  try {
    for (const [label, extra] of Object.entries(navigations)) {
      up.seen.length = 0;
      const res = await request(gatePort, `/${gate.token}/app?x=1`, { headers: { 'cf-connecting-ip': VISITOR_IP, ...extra } });
      assert.strictEqual(res.status, 302, `${label}: redeemed, got ${res.status}`);
      assert.strictEqual(res.headers.location, '/app?x=1', `${label}: redirect to the clean path`);
      assert.strictEqual(res.headers['referrer-policy'], 'no-referrer');
      const [cookie] = res.headers['set-cookie'] || [];
      assert.match(cookie || '', /^pn_share=[0-9a-f]{64};/, `${label}: ${cookie}`);
      for (const attr of [/HttpOnly/, /Secure/, /SameSite=Lax/]) assert.match(cookie, attr, `${label}: ${cookie}`);
      assert.deepStrictEqual(ours(up.seen, '/app'), [], `${label}: the redemption itself never reaches the upstream`);

      const page = await request(gatePort, '/app?x=1', {
        headers: { 'cf-connecting-ip': VISITOR_IP, cookie: cookie.split(';')[0], ...extra },
      });
      assert.deepStrictEqual([page.status, page.body], [200, 'page:/app?x=1'], `${label}: the session cookie authorizes the clean path`);
    }
  } finally {
    await gate.close();
    await closeServer(up.server);
  }
});
