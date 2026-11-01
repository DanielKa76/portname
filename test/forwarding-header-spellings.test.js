'use strict';

// CGI-style upstreams (PHP's built-in server, Rack, Python's wsgiref) read
// a request header through a variable in which '-' and '_' are the same
// character, and PHP maps '.' to '_' as well: X-Forwarded_For,
// X-Forwarded.For, x_forwarded_for and X-Forwarded-For all become
// HTTP_X_FORWARDED_FOR, the last one usually winning. Client-sent spellings
// of the forwarding and client-address headers must therefore never reach
// the upstream in any of these forms, nor with any other separator, and the
// trusted values must come after every client header. Unrelated headers with
// '_' or '.' stay untouched.

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');

const { prepareUpstreamRequestHeaders, prepareUpgradeRequestHeaders } = require('../lib/headers');
const { createGateway, listenGateway } = require('../lib/proxy');
const { ShareGate } = require('../lib/share');

const TRUSTED = ['x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for', 'forwarded'];
const CLIENT_ADDRESS = [
  'client-ip',
  'true-client-ip',
  'x-real-ip',
  'x-client-ip',
  'x-cluster-client-ip',
  'fastly-client-ip',
  'cf-connecting-ip',
];
const FOLDED = new Set([...TRUSTED, ...CLIENT_ADDRESS]);
const fold = (name) => name.toLowerCase().replace(/[^a-z0-9]/g, '-');

// Title-cased spellings with `sep` for every, the first and the last '-'.
function separatorSpellings(name, sep) {
  if (!name.includes('-')) return [];
  const title = name.replace(/(^|-)([a-z])/g, (m, s, c) => s + c.toUpperCase());
  const first = title.indexOf('-');
  const last = title.lastIndexOf('-');
  return [
    title.split('-').join(sep),
    title.slice(0, first) + sep + title.slice(first + 1),
    title.slice(0, last) + sep + title.slice(last + 1),
  ];
}

// Every punctuation character the HTTP token grammar allows in a header
// name, other than '-'.
const SEPARATORS = "!#$%&'*+.^_`|~";

const SPOOFED = [
  ...new Set([
    ...[...TRUSTED, ...CLIENT_ADDRESS].flatMap((name) => [
      ...separatorSpellings(name, '_'),
      ...separatorSpellings(name, '.'),
    ]),
    'X_Forwarded.For',
    'X.Real_Ip',
    ...[...SEPARATORS].map((sep) => `Client${sep}Ip`),
  ]),
];
const UNRELATED = [['X_Api_Key', 'keep-1'], ['X-Request_Id', 'keep-2'], ['X.Trace.Id', 'keep-3']];

// The attack shape: the dashed spelling first (so a trusted value written in
// its place would sit before the rest), then every '_', '.' and other
// separator spelling, then unrelated '_' and '.' headers, then a marker that
// is the last client header.
function clientHeaderPairs() {
  return [
    ['X-Forwarded-For', '1.1.1.1'],
    ['X-Forwarded-Host', 'dashed.example'],
    ['X-Forwarded-Proto', 'gopher'],
    ...SPOOFED.map((name) => [name, name.toLowerCase().includes('host') ? 'evil.example' : '127.0.0.1']),
    ...UNRELATED,
    ['X-Marker', 'last'],
  ];
}

// Asserts what an upstream sees, given its received names and values in order.
function assertTrustedOnly(pairs, { clientIp, host, proto, label }) {
  const names = pairs.map(([n]) => n.toLowerCase());
  const leaked = pairs.filter(([n]) => FOLDED.has(fold(n)) && !TRUSTED.includes(n.toLowerCase()));
  assert.deepStrictEqual(leaked, [], `${label}: no client spelling of a forwarding or client-address header`);
  for (const name of TRUSTED) {
    assert.strictEqual(names.filter((n) => n === name).length, 1, `${label}: exactly one ${name}`);
  }
  const value = (name) => pairs.find(([n]) => n.toLowerCase() === name)[1];
  assert.strictEqual(value('x-forwarded-for'), clientIp, `${label}: X-Forwarded-For`);
  assert.strictEqual(value('x-forwarded-host'), host, `${label}: X-Forwarded-Host`);
  assert.strictEqual(value('x-forwarded-proto'), proto, `${label}: X-Forwarded-Proto`);
  const marker = names.indexOf('x-marker');
  assert.ok(marker >= 0, `${label}: the client headers arrive`);
  for (const name of TRUSTED) {
    assert.ok(names.indexOf(name) > marker, `${label}: ${name} comes after every client header`);
  }
  for (const [name, val] of UNRELATED) {
    const got = pairs.find(([n]) => n.toLowerCase() === name.toLowerCase());
    assert.ok(got && got[1] === val, `${label}: unrelated header ${name} is kept`);
  }
}

const toPairs = (flat) => {
  const pairs = [];
  for (let i = 0; i < flat.length; i += 2) pairs.push([flat[i], flat[i + 1]]);
  return pairs;
};

test('header spellings: prepareUpstreamRequestHeaders drops every "_", "." and other separator spelling and appends the trusted values', () => {
  const headers = {};
  for (const [name, val] of clientHeaderPairs()) headers[name.toLowerCase()] = val;
  headers.host = 'app.local';
  const out = prepareUpstreamRequestHeaders(
    { headers },
    { originalHost: 'app.local', clientIp: '192.168.1.20', targetPort: 3000, proto: 'http' }
  );
  assertTrustedOnly(Object.entries(out), { clientIp: '192.168.1.20', host: 'app.local', proto: 'http', label: 'http' });
});

test('header spellings: prepareUpgradeRequestHeaders drops every "_", "." and other separator spelling and appends the trusted values', () => {
  const raw = ['Host', 'app.local', 'Upgrade', 'websocket', 'Connection', 'Upgrade'];
  for (const [name, val] of clientHeaderPairs()) raw.push(name, val);
  const out = prepareUpgradeRequestHeaders(raw, {
    originalHost: 'app.local',
    clientIp: '192.168.1.20',
    targetPort: 3000,
    proto: 'http',
  });
  assertTrustedOnly(toPairs(out), { clientIp: '192.168.1.20', host: 'app.local', proto: 'http', label: 'upgrade' });
});

// ---------------------------------------------------------------------------
// End to end: what an upstream behind the gateway and the share gate
// receives, in wire order, on the HTTP and the WebSocket path.
// ---------------------------------------------------------------------------

function recordingUpstream() {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push(toPairs(req.rawHeaders));
    req.resume();
    req.on('end', () => res.end('ok'));
  });
  server.on('upgrade', (req, socket) => {
    seen.push(toPairs(req.rawHeaders));
    socket.on('error', () => {});
    socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen })));
}

function rawRequest(port, head) {
  return new Promise((resolve) => {
    let data = '';
    const sock = net.connect(port, '127.0.0.1', () => sock.write(head));
    sock.on('data', (d) => {
      data += d.toString('latin1');
      if (data.includes('\r\n\r\n')) sock.destroy();
    });
    sock.on('error', () => {});
    sock.on('close', () => resolve(data));
    setTimeout(() => sock.destroy(), 3000).unref();
  });
}

const headerBlock = () => clientHeaderPairs().map(([n, v]) => `${n}: ${v}\r\n`).join('');
const WS = 'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n';

test('header spellings: gateway HTTP and WebSocket requests reach the upstream with trusted forwarding only', async () => {
  const up = await recordingUpstream();
  // A LAN peer on an exposed project (loopback-shaped test sockets).
  const gateway = createGateway({
    getRoute: (name) => (name === 'app' ? { name: 'app', port: up.port, root: '/r/app' } : null),
    isExposed: () => true,
    getLanInfo: () => ({ name: 'en0', address: '127.0.0.1', netmask: '255.255.255.0' }),
    isLoopbackClient: () => false,
    log: () => {},
  });
  const bind = await listenGateway(gateway, { mode: 'wildcard', port: 0, fallbackPort: 0 });
  try {
    const http1 = await rawRequest(bind.primary, `GET /page HTTP/1.1\r\nHost: app.local\r\n${headerBlock()}Connection: close\r\n\r\n`);
    assert.match(http1, /^HTTP\/1\.1 200/);
    const ws = await rawRequest(bind.primary, `GET /ws HTTP/1.1\r\nHost: app.local\r\n${WS}${headerBlock()}\r\n`);
    assert.match(ws, /^HTTP\/1\.1 101/);
    assert.strictEqual(up.seen.length, 2);
    const clientIp = up.seen[0].find(([n]) => n.toLowerCase() === 'x-forwarded-for')[1];
    assert.match(clientIp, /^(::ffff:)?127\.0\.0\.1$/, 'the verified socket address is forwarded');
    assertTrustedOnly(up.seen[0], { clientIp, host: 'app.local', proto: 'http', label: 'gateway http' });
    assertTrustedOnly(up.seen[1], { clientIp, host: 'app.local', proto: 'http', label: 'gateway websocket' });
  } finally {
    await gateway.close();
    up.server.closeAllConnections();
    await new Promise((r) => up.server.close(r));
  }
});

test('header spellings: share gate HTTP and WebSocket requests reach the upstream with trusted forwarding only', async () => {
  const up = await recordingUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  const visitor = 'Host: demo.trycloudflare.com\r\nCf-Connecting-Ip: 203.0.113.7\r\n';
  try {
    const http1 = await rawRequest(gatePort, `POST /${gate.token}/hook HTTP/1.1\r\n${visitor}${headerBlock()}Content-Length: 0\r\nConnection: close\r\n\r\n`);
    assert.match(http1, /^HTTP\/1\.1 200/);
    const ws = await rawRequest(gatePort, `GET /${gate.token}/ws HTTP/1.1\r\n${visitor}${WS}${headerBlock()}\r\n`);
    assert.match(ws, /^HTTP\/1\.1 101/);
    assert.strictEqual(up.seen.length, 2);
    const expected = { clientIp: '203.0.113.7', host: 'demo.trycloudflare.com', proto: 'https' };
    assertTrustedOnly(up.seen[0], { ...expected, label: 'share http' });
    assertTrustedOnly(up.seen[1], { ...expected, label: 'share websocket' });
  } finally {
    await gate.close();
    up.server.closeAllConnections();
    await new Promise((r) => up.server.close(r));
  }
});
