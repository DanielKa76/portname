'use strict';

// Lifecycle of a proxied upstream request on the gateway and the share gate:
// an upstream that answers before the request body is complete must not keep
// its connection once that answer is relayed, and the response-header
// timeout must not count the time a client spends sending its body.

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');

const { createGateway, listenGateway } = require('../lib/proxy');
const { ShareGate } = require('../lib/share');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const VISITOR_IP = '203.0.113.7';

function startUpstream(handler, configure = () => {}) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    configure(server);
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

async function closeUpstream(server) {
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
}

async function startGateway(port, timeouts = {}) {
  const gateway = createGateway({
    getRoute: (name) => (name === 'app' ? { name: 'app', port, root: '/r/app' } : null),
    timeouts,
    log: () => {},
  });
  const bind = await listenGateway(gateway, { mode: 'wildcard', port: 0, fallbackPort: 0 });
  return { gateway, port: bind.primary };
}

function upstreamConnections(server) {
  return new Promise((resolve, reject) => server.getConnections((err, n) => (err ? reject(err) : resolve(n))));
}

async function waitForNoConnections(server, deadlineMs) {
  const until = Date.now() + deadlineMs;
  let open = await upstreamConnections(server);
  while (open > 0 && Date.now() < until) {
    await sleep(25);
    open = await upstreamConnections(server);
  }
  return open;
}

// Sends a request head plus the first bytes of a much larger announced body,
// waits for the response head and then drops the connection mid-upload.
function abortUploadAfterAnswer(port, head) {
  return new Promise((resolve) => {
    let data = '';
    const sock = net.connect(port, '127.0.0.1', () => sock.write(`${head}Content-Length: 1000000\r\n\r\nabc`));
    sock.on('data', (d) => {
      data += d.toString('latin1');
      if (data.includes('\r\n\r\n')) {
        sock.destroy();
        resolve(data);
      }
    });
    sock.on('error', () => resolve(data));
    sock.on('close', () => resolve(data));
  });
}

// Sends `parts` as the body of one POST, `gapMs` apart, and collects the
// complete answer.
function slowUpload(port, head, parts, gapMs) {
  return new Promise((resolve) => {
    let data = '';
    const length = parts.reduce((n, p) => n + Buffer.byteLength(p), 0);
    const sock = net.connect(port, '127.0.0.1', async () => {
      sock.write(`${head}Content-Length: ${length}\r\nConnection: close\r\n\r\n`);
      for (const part of parts) {
        await sleep(gapMs);
        if (sock.destroyed) return;
        sock.write(part);
      }
    });
    sock.on('data', (d) => (data += d.toString('latin1')));
    sock.on('error', () => {});
    sock.on('close', () => resolve(data));
    setTimeout(() => sock.destroy(), 10000).unref();
  });
}

// Upstream that answers an upload only after reading its whole body, echoing
// the byte count; `/silent` reads the whole body and never answers.
async function uploadUpstream() {
  const received = [];
  const up = await startUpstream((req, res) => {
    let bytes = 0;
    req.on('data', (d) => (bytes += d.length));
    req.on('end', () => {
      received.push({ url: req.url, bytes });
      if (req.url.endsWith('/silent')) return;
      res.end(`got ${bytes}`);
    });
  });
  return { ...up, received };
}

// ---------------------------------------------------------------------------
// An upstream answering before the body is complete (an early 401/404/413
// that never reads the upload): once the answer is relayed, the upstream
// request can never finish, so its connection must be closed. keepAliveTimeout
// 0 keeps the upstream from closing idle-looking connections on its own.
// ---------------------------------------------------------------------------

function earlyAnswerUpstream() {
  return startUpstream(
    (req, res) => {
      res.writeHead(404, { 'content-length': 0 });
      res.end();
    },
    (server) => {
      server.keepAliveTimeout = 0;
    }
  );
}

test('gateway: an upload aborted after an early upstream answer leaves no upstream connection open', async () => {
  const up = await earlyAnswerUpstream();
  const { gateway, port } = await startGateway(up.port);
  try {
    for (let i = 0; i < 5; i += 1) {
      const answer = await abortUploadAfterAnswer(port, 'POST /upload HTTP/1.1\r\nHost: app.localhost\r\n');
      assert.match(answer, /^HTTP\/1\.1 404/, 'the early answer reaches the client');
    }
    const open = await waitForNoConnections(up.server, 2000);
    assert.strictEqual(open, 0, `upstream connections still open after aborted uploads: ${open}`);
    assert.strictEqual(gateway.activeRequests.size, 0);
  } finally {
    await gateway.close();
    await closeUpstream(up.server);
  }
});

test('share gate: an upload aborted after an early upstream answer leaves no upstream connection open', async () => {
  const up = await earlyAnswerUpstream();
  const gate = new ShareGate({ targetPort: up.port, ttlMinutes: 60 });
  const gatePort = await gate.listen();
  try {
    for (let i = 0; i < 5; i += 1) {
      const answer = await abortUploadAfterAnswer(
        gatePort,
        `POST /${gate.token}/hook HTTP/1.1\r\nHost: demo.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\n`
      );
      assert.match(answer, /^HTTP\/1\.1 404/, 'the early answer reaches the visitor');
    }
    const open = await waitForNoConnections(up.server, 2000);
    assert.strictEqual(open, 0, `upstream connections still open after aborted uploads: ${open}`);
  } finally {
    await gate.close();
    await closeUpstream(up.server);
  }
});

test('gateway: complete requests with a body keep reusing their pooled upstream connection', async () => {
  const ports = [];
  const up = await startUpstream((req, res) => {
    req.resume();
    req.on('end', () => {
      ports.push(req.socket.remotePort);
      res.end('ok');
    });
  });
  const { gateway, port } = await startGateway(up.port);
  const post = () =>
    new Promise((resolve, reject) => {
      const req = http.request(
        { host: '127.0.0.1', port, path: '/form', method: 'POST', headers: { host: 'app.localhost' }, agent: false },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode));
        }
      );
      req.on('error', reject);
      req.end('field=value');
    });
  try {
    assert.deepStrictEqual([await post(), await post(), await post()], [200, 200, 200]);
    assert.strictEqual(new Set(ports).size, 1, `complete POSTs share one upstream connection: ${ports}`);
  } finally {
    await gateway.close();
    await closeUpstream(up.server);
  }
});

// ---------------------------------------------------------------------------
// The response-header timeout bounds the upstream's answer, not the client's
// upload: it starts once the request body has been completely handed to the
// upstream. Both cases run against the same shortened timeout, so the slow
// upload provably outlasts a timeout that is in effect.
// ---------------------------------------------------------------------------

const HEADER_TIMEOUT_MS = 300;
const PARTS = ['0123456789', '0123456789', '0123456789', '0123456789'];
const GAP_MS = 200; // 4 x 200 ms of body, well past the header timeout

test('gateway: a slow upload outlasting the response-header timeout gets the upstream answer', async () => {
  const up = await uploadUpstream();
  const { gateway, port } = await startGateway(up.port, { upstreamResponseHeaderTimeoutMs: HEADER_TIMEOUT_MS });
  try {
    const started = Date.now();
    const silent = await slowUpload(port, 'POST /silent HTTP/1.1\r\nHost: app.localhost\r\n', ['complete'], 0);
    assert.match(silent, /^HTTP\/1\.1 502/, 'an upstream that never answers a complete body still gets 502');
    assert.ok(Date.now() - started < 3000, 'that wait stays bounded by the response-header timeout');

    const upload = await slowUpload(port, 'POST /upload HTTP/1.1\r\nHost: app.localhost\r\n', PARTS, GAP_MS);
    assert.match(upload, /^HTTP\/1\.1 200/, `a slow upload is answered by the upstream: ${upload.split('\r\n')[0]}`);
    assert.ok(upload.endsWith('got 40'), 'the upstream received the whole body');
  } finally {
    await gateway.close();
    await closeUpstream(up.server);
  }
});

test('share gate: a slow upload outlasting the response-header timeout gets the upstream answer', async () => {
  const up = await uploadUpstream();
  const gate = new ShareGate({
    targetPort: up.port,
    ttlMinutes: 60,
    timeouts: { upstreamResponseHeaderTimeoutMs: HEADER_TIMEOUT_MS },
  });
  const gatePort = await gate.listen();
  const head = (p) =>
    `POST /${gate.token}${p} HTTP/1.1\r\nHost: demo.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\n`;
  try {
    const started = Date.now();
    const silent = await slowUpload(gatePort, head('/silent'), ['complete'], 0);
    assert.match(silent, /^HTTP\/1\.1 502/, 'an upstream that never answers a complete body still gets 502');
    assert.ok(Date.now() - started < 3000, 'that wait stays bounded by the response-header timeout');

    const upload = await slowUpload(gatePort, head('/upload'), PARTS, GAP_MS);
    assert.match(upload, /^HTTP\/1\.1 200/, `a slow upload is answered by the upstream: ${upload.split('\r\n')[0]}`);
    assert.ok(upload.endsWith('got 40'), 'the upstream received the whole body');
  } finally {
    await gate.close();
    await closeUpstream(up.server);
  }
});

// The connect phase stays bounded on its own: with the response-header
// timeout armed only after the body, an upstream connection that never
// completes its TCP handshake must still end in 502 near the connect timeout.
// The pool's sockets are swapped for ones that stay "connecting" forever.
class NeverConnectingAgent extends http.Agent {
  createConnection() {
    const socket = new net.Socket();
    socket.connecting = true;
    return socket;
  }
}

test('gateway and share gate: an upstream connect that never completes is bounded by the connect timeout', async () => {
  const timeouts = { upstreamConnectTimeoutMs: HEADER_TIMEOUT_MS, upstreamResponseHeaderTimeoutMs: 60000 };
  const { gateway, port } = await startGateway(1, timeouts);
  gateway.upstreamAgents.loopback = new NeverConnectingAgent({ keepAlive: true });
  const gate = new ShareGate({ targetPort: 1, ttlMinutes: 60, timeouts });
  gate.upstreamAgent = new NeverConnectingAgent({ keepAlive: true });
  const gatePort = await gate.listen();
  try {
    for (const [label, p, head] of [
      ['gateway', port, 'POST /x HTTP/1.1\r\nHost: app.localhost\r\n'],
      ['share gate', gatePort, `POST /${gate.token}/x HTTP/1.1\r\nHost: demo.trycloudflare.com\r\nCf-Connecting-Ip: ${VISITOR_IP}\r\n`],
    ]) {
      const started = Date.now();
      const answer = await slowUpload(p, head, ['x'], 0);
      assert.match(answer, /^HTTP\/1\.1 502/, `${label}: an upstream that never connects gets 502`);
      assert.ok(Date.now() - started < 3000, `${label}: bounded by the connect timeout`);
    }
  } finally {
    await gateway.close();
    await gate.close();
  }
});
