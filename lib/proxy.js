'use strict';

const http = require('http');
const { pipeline } = require('stream');
const { decide, isLoopbackRemote } = require('./authorize');
const { getLanInterface, isAuthorizedLanClient, cleanIpv4 } = require('./network');
const {
  headerListMayBeTruncated,
  parseHost,
  prepareUpstreamRequestHeaders,
  prepareUpstreamResponseHeaders,
  prepareUpgradeRequestHeaders,
} = require('./headers');

const REASONS = {
  400: 'Bad Request',
  404: 'Not Found',
  405: 'Method Not Allowed',
  431: 'Request Header Fields Too Large',
};

// Bounded waiting where unbounded waiting would leak resources. Deliberately
// NO blanket body/request timeout: SSE, HMR and large uploads are legitimate
// and may stream for hours — only the handshake phases are bounded.
const GATEWAY_TIMEOUTS = {
  // Client -> gateway: how long a client may take to send its request headers.
  headerTimeoutMs: 15000,
  // Gateway -> upstream: how long to wait for the upstream connection.
  upstreamConnectTimeoutMs: 10000,
  // Gateway -> upstream: how long to wait for upstream response headers once
  // the request (body included) has been completely handed to the upstream.
  upstreamResponseHeaderTimeoutMs: 15000,
  // Concurrent loopback connections per listener (browsers use ~6 per origin;
  // 512 is far above every legitimate dev workload).
  maxConnections: 512,
  // Non-loopback (LAN) peers get their own, smaller budget on top, with a
  // per-address cap, so LAN peers can never take the loopback developer's
  // slots. Node enforces a server's maxConnections before it can tell peers
  // apart, so the listener's hard limit is the sum and the LAN share is
  // counted in _handleConnection.
  maxLanConnections: 128,
  maxLanConnectionsPerAddress: 32,
  // How often Node enforces headerTimeoutMs. Its default (30 s) let an idle
  // or dribbling connection hold a slot for up to 45 s.
  connectionsCheckingIntervalMs: 1000,
  // Header lines per request (Node's effective default). A request that
  // reaches it is refused, see headerListMayBeTruncated.
  maxHeadersCount: 1000,
};

// The range ServerResponse.writeHead accepts; anything else is a broken
// upstream and answered with 502.
function isValidStatusCode(status) {
  return Number.isInteger(status) && status >= 100 && status <= 999;
}

// Only a WebSocket handshake may become a raw spliced stream: other upgrade
// protocols (h2c, ...) would give the client a channel to the upstream past
// all request and response sanitization. Their offers are ignored instead
// (RFC 9110 §7.8) and the request is served as plain HTTP/1.1.
function isWebSocketUpgrade(req) {
  return req.method === 'GET' && String(req.headers.upgrade || '').trim().toLowerCase() === 'websocket';
}

function hasRequestBody(req) {
  return req.headers['transfer-encoding'] !== undefined || Number(req.headers['content-length'] || 0) > 0;
}

// A response head for a raw (upgrade-path) socket. `pairs` is a flat
// [name, value, ...] list; a value carrying CR/LF is never emitted.
function formatResponseHead(status, pairs) {
  let head = `HTTP/1.1 ${status} ${http.STATUS_CODES[status] || 'Unknown'}\r\n`;
  for (let i = 0; i < pairs.length; i += 2) {
    const name = String(pairs[i]);
    const value = String(pairs[i + 1]);
    if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) continue;
    head += `${name}: ${value}\r\n`;
  }
  return head + '\r\n';
}

function refuse(res, status) {
  const body = '';
  res.writeHead(status, {
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    connection: 'close',
  });
  res.end(body);
  return status;
}

class Gateway {
  constructor({
    getRoute,
    isExposed = () => false,
    getLanInfo = getLanInterface,
    isLoopbackClient = null, // test seam; defaults to the real socket classification
    timeouts = {},
    log = () => {},
  }) {
    this.getRoute = getRoute;
    this.isExposed = isExposed;
    this.getLanInfo = getLanInfo;
    this.isLoopbackClient = isLoopbackClient;
    this.timeouts = { ...GATEWAY_TIMEOUTS, ...timeouts };
    this.log = log;
    // One keep-alive pool per client trust zone: whatever desynchronizes a
    // pooled upstream connection can never hand a LAN client's response to
    // the loopback developer, or the developer's response to a LAN client.
    this.upstreamAgents = {
      loopback: new http.Agent({ keepAlive: true }),
      lan: new http.Agent({ keepAlive: true }),
    };
    this.activeConnections = new Set(); // upgraded sockets: { client, upstream, name, identity, zone, loopback, port, upstreamHost, processKey }
    this.activeRequests = new Set(); // in-flight requests (SSE, long-poll): { req, res, upstream, name, identity, zone, loopback, port, upstreamHost, processKey }
    this.servers = [];
    this.lanConnections = new Map(); // remote address -> open non-loopback connections
    this.lanConnectionCount = 0;

    this._handleConnection = this._handleConnection.bind(this);
    this._handleRequest = this._handleRequest.bind(this);
    this._handleConnect = this._handleConnect.bind(this);
    this._handleUpgrade = this._handleUpgrade.bind(this);
  }

  _decideRequest(req) {
    if (headerListMayBeTruncated(req, this.timeouts.maxHeadersCount)) return { action: 'reject', status: 431 };
    const hostCount = req.rawHeaders.filter((v, i) => i % 2 === 0 && v.toLowerCase() === 'host').length;
    if (hostCount === 0 || hostCount > 1) return { action: 'reject', status: 400 };
    if (req.method === 'CONNECT') return { action: 'reject', status: 405 };

    const rawHost = req.headers.host;
    const parsedHost = parseHost(rawHost);
    if (!parsedHost) {
      return { action: 'reject', status: 400 };
    }

    const loopback = this.isLoopbackClient
      ? this.isLoopbackClient(req.socket.remoteAddress)
      : isLoopbackRemote(req.socket.remoteAddress);
    const verdict = decide({
      remoteIsLoopback: loopback,
      localAddress: req.socket.localAddress,
      remoteAddress: req.socket.remoteAddress,
      isLanClient: ({ localAddress, remoteAddress }) =>
        isAuthorizedLanClient({ localAddress, remoteAddress, lanInfo: this.getLanInfo() }),
      host: parsedHost.hostname,
      routeExists: this.getRoute,
      isExposed: (routeOrIdentity) => {
        if (typeof routeOrIdentity === 'object' && routeOrIdentity !== null) {
          // Additive: the route rides along as a second argument so the owner
          // of the callback can bind its exposure freshness to the exact
          // endpoint tuple that was verified. Callers that receive only an
          // identity have no tuple to bind to and decide on their own.
          return this.isExposed(routeOrIdentity.root || ('manual:' + routeOrIdentity.name), routeOrIdentity);
        }
        return this.isExposed(routeOrIdentity);
      },
    });
    return {
      ...verdict,
      zone: verdict.zone || null,
      loopback,
      originalHost: parsedHost.canonicalHost,
    };
  }

  // Metadata every long-lived connection records at authorization time, so a
  // later revocation decision can match it against the current policy.
  #connectionMetadata(verdict, upstreamHost) {
    return {
      name: verdict.route.name,
      identity: verdict.route.root || ('manual:' + verdict.route.name),
      zone: verdict.zone,
      loopback: verdict.loopback,
      port: verdict.route.port,
      upstreamHost,
      processKey: verdict.route.processKey || null,
    };
  }

  _handleRequest(req, res) {
    const verdict = this._decideRequest(req);
    if (verdict.action === 'reject') {
      this.log('reject', verdict.status, String(req.headers.host || ''));
      refuse(res, verdict.status);
      return;
    }
    const upstreamHost = verdict.route.upstreamHost || '127.0.0.1';
    let headers;
    try {
      headers = prepareUpstreamRequestHeaders(req, {
        originalHost: verdict.originalHost,
        clientIp: req.socket.remoteAddress,
        targetPort: verdict.route.port,
        proto: 'http',
      });
    } catch {
      // No peer address (the socket is already gone): there is no client to
      // name upstream, and no loopback stand-in is ever forwarded instead.
      refuse(res, 400);
      return;
    }
    const target = {
      host: upstreamHost,
      port: verdict.route.port,
      path: req.url,
      method: req.method,
      headers,
      agent: verdict.loopback ? this.upstreamAgents.loopback : this.upstreamAgents.lan,
    };
    let answered = false;
    const upstream = http.request(target, (ures) => {
      answered = true;
      clearTimeout(handshakeTimer);
      // Node's client parser accepts any three-digit status line ("000",
      // "099") but writeHead throws for those; thrown from this callback it
      // would be uncaught and take the whole daemon down. A 101 without
      // upgrade headers also arrives here; relayed, it would announce a
      // protocol switch to a client that never asked for one.
      if (!isValidStatusCode(ures.statusCode) || ures.statusCode < 200) {
        ures.resume();
        upstream.destroy();
        refuse(res, 502);
        return;
      }
      const respHeaders = prepareUpstreamResponseHeaders(ures.headers, {
        originalHost: verdict.originalHost,
        targetPort: verdict.route.port,
        proto: 'http',
      });
      try {
        res.writeHead(ures.statusCode, respHeaders);
      } catch {
        // Defense in depth: no upstream-supplied value may throw out of here.
        upstream.destroy();
        if (!res.headersSent) refuse(res, 502);
        else res.destroy();
        return;
      }
      // Streamed: SSE and chunked responses flush immediately. pipeline (not
      // pipe) so an upstream that dies mid-body tears the client response
      // down too; pipe() would leave it open forever, since a truncated
      // upstream body never emits 'end' and requestTimeout is deliberately 0.
      pipeline(ures, res, (err) => {
        if (err && !res.destroyed) res.destroy();
      });
    });

    // Bound the handshake phases only: the upstream connect, then the wait
    // for response headers, which starts once the request body has been
    // completely handed to the upstream ('finish'). The body itself streams
    // unbounded (a slow upload is not a silent upstream), and so does the
    // response once its headers arrived (SSE/HMR). A client stalling its
    // body holds just its own connection, inside the connection budgets.
    let handshakeTimer = null;
    const armHandshakeTimer = (ms) => {
      clearTimeout(handshakeTimer);
      handshakeTimer = setTimeout(() => {
        if (!res.headersSent) upstream.destroy();
      }, ms);
      if (handshakeTimer.unref) handshakeTimer.unref();
    };
    armHandshakeTimer(this.timeouts.upstreamConnectTimeoutMs);
    upstream.on('socket', (s) => {
      // A pooled keep-alive socket is already connected.
      if (!s.connecting) clearTimeout(handshakeTimer);
      else s.once('connect', () => clearTimeout(handshakeTimer));
    });
    upstream.on('finish', () => {
      if (!answered) armHandshakeTimer(this.timeouts.upstreamResponseHeaderTimeoutMs);
    });

    // Track the in-flight request for policy-driven teardown (SSE and other
    // long-lived responses never issue a second request to re-decide).
    const entry = { req, res, upstream, ...this.#connectionMetadata(verdict, upstreamHost) };
    this.activeRequests.add(entry);

    // Coupled abort lifecycle: abort upstream request if downstream client
    // aborts. An answer that completed before the request body was completely
    // handed to the upstream (an early 401/404/413 to an upload) ends the
    // upstream request as well: it can never finish or return to the pool,
    // and once the response is done Node emits nothing more on `req`, so a
    // client dropping the rest of its upload would leave the upstream
    // connection open — untracked and outside every connection budget.
    res.on('close', () => {
      clearTimeout(handshakeTimer);
      this.activeRequests.delete(entry);
      if ((!res.writableFinished || !upstream.writableFinished) && !upstream.destroyed) upstream.destroy();
    });

    upstream.on('error', () => {
      if (!res.headersSent) refuse(res, 502);
      else if (!res.writableEnded) res.destroy();
    });
    // A 101 with upgrade headers to a request that offered no upgrade (an
    // h2c offer is stripped above): without this listener Node destroys the
    // socket and emits neither 'response' nor 'error', leaving the client
    // waiting forever. A broken upstream, answered like one.
    upstream.on('upgrade', (ures, upstreamSocket) => {
      answered = true;
      clearTimeout(handshakeTimer);
      upstreamSocket.destroy();
      if (!res.headersSent) refuse(res, 502);
    });
    req.pipe(upstream);
  }

  _handleConnect(req, socket) {
    // Node detaches its own socket error handler before emitting 'connect'.
    // Without this listener a peer reset (RST) surfaces as an uncaught
    // 'error' event and takes the whole daemon down — before any gating.
    socket.on('error', () => socket.destroy());
    socket.end('HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\nconnection: close\r\n\r\n', () => socket.destroy());
  }

  _handleUpgrade(req, socket, head) {
    socket.on('error', () => {}); // same detached-handler hazard as _handleConnect
    let verdict = this._decideRequest(req);
    // Another protocol (h2c, ...) only gets here on runtimes without
    // shouldUpgradeCallback (see _createServer). Its offer is ignored: the
    // request goes upstream as plain HTTP/1.1 without Upgrade, so no 101 and
    // no raw channel can follow. A body would sit unframed in `head`.
    const websocket = isWebSocketUpgrade(req);
    if (verdict.action === 'proxy' && !websocket && hasRequestBody(req)) {
      verdict = { action: 'reject', status: 400 };
    }
    if (verdict.action !== 'proxy') {
      socket.write(`HTTP/1.1 ${verdict.status} ${REASONS[verdict.status] || 'Refused'}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n`);
      socket.destroy();
      return;
    }
    const upstreamHost = verdict.route.upstreamHost || '127.0.0.1';
    const forwarding = {
      originalHost: verdict.originalHost,
      clientIp: socket.remoteAddress,
      targetPort: verdict.route.port,
      proto: 'http',
    };
    // The handshake goes through http.request so the upstream's answer is
    // parsed: the sockets are spliced only after a confirmed 101. Any other
    // answer is relayed as one sanitized response and the connection closed —
    // splicing it would hand the client a raw keep-alive HTTP channel to the
    // upstream, past Host rewriting and the trusted forwarding headers.
    let upstream;
    try {
      upstream = http.request({
        host: upstreamHost,
        port: verdict.route.port,
        method: req.method,
        path: req.url,
        // prepareUpstreamRequestHeaders drops Upgrade, Connection and the
        // headers Connection nominates (HTTP2-Settings).
        headers: websocket
          ? prepareUpgradeRequestHeaders(req.rawHeaders, forwarding)
          : prepareUpstreamRequestHeaders(req, forwarding),
        agent: false, // a dedicated connection: an upgraded socket is never pooled
      });
    } catch {
      socket.write(`HTTP/1.1 400 ${REASONS[400]}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n`);
      socket.destroy();
      return;
    }

    // Bound the handshake (upstream connect, then its answer); after a
    // confirmed 101 the stream is unbounded (WebSockets idle legitimately).
    let handshakeTimer = null;
    const armHandshakeTimer = (ms) => {
      clearTimeout(handshakeTimer);
      handshakeTimer = setTimeout(() => upstream.destroy(), ms);
      if (handshakeTimer.unref) handshakeTimer.unref();
    };
    armHandshakeTimer(this.timeouts.upstreamConnectTimeoutMs);
    upstream.on('socket', (s) => {
      s.once('connect', () => armHandshakeTimer(this.timeouts.upstreamResponseHeaderTimeoutMs));
    });

    // `upstream` is the pending handshake request until the 101 arrives, the
    // spliced upstream socket afterwards; teardown handles both.
    const conn = { client: socket, upstream, ...this.#connectionMetadata(verdict, upstreamHost) };
    this.activeConnections.add(conn);
    let answered = false;
    let relayed = null; // a non-101 answer whose head went out to the client

    const cleanup = () => {
      clearTimeout(handshakeTimer);
      if (!this.activeConnections.has(conn)) return;
      this.activeConnections.delete(conn);
      // A relayed answer is close-delimited: a FIN before its upstream body
      // is complete would present the truncated body as a whole one.
      if (relayed && !relayed.complete && !socket.destroyed) socket.resetAndDestroy();
      if (!socket.destroyed) socket.destroy();
      if (!conn.upstream.destroyed) conn.upstream.destroy();
    };
    const badGateway = () => {
      if (!socket.destroyed) socket.write('HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
      cleanup();
    };

    upstream.on('upgrade', (ures, upstreamSocket, upstreamHead) => {
      clearTimeout(handshakeTimer);
      answered = true;
      conn.upstream = upstreamSocket;
      upstreamSocket.on('error', cleanup);
      upstreamSocket.on('close', cleanup);
      if (!websocket) {
        // A 101 for a request that never offered an upgrade: broken upstream.
        badGateway();
        return;
      }
      if (!this.activeConnections.has(conn) || socket.destroyed) {
        // Torn down mid-handshake (client gone, connection revoked).
        cleanup();
        if (!upstreamSocket.destroyed) upstreamSocket.destroy();
        return;
      }
      // latin1: header values arrive as one char per byte, keep them byte-exact.
      socket.write(formatResponseHead(101, ures.rawHeaders), 'latin1');
      if (upstreamHead && upstreamHead.length) socket.write(upstreamHead);
      if (head && head.length) upstreamSocket.write(head);
      socket.pipe(upstreamSocket);
      upstreamSocket.pipe(socket);
    });

    upstream.on('response', (ures) => {
      clearTimeout(handshakeTimer);
      answered = true;
      // 1xx here means a 101 without the upgrade headers: not a handshake.
      if (!isValidStatusCode(ures.statusCode) || ures.statusCode < 200) {
        ures.resume();
        badGateway();
        return;
      }
      const respHeaders = prepareUpstreamResponseHeaders(ures.headers, {
        originalHost: verdict.originalHost,
        targetPort: verdict.route.port,
        proto: 'http',
      });
      respHeaders.connection = 'close';
      const pairs = [];
      for (const [name, value] of Object.entries(respHeaders)) {
        for (const v of Array.isArray(value) ? value : [value]) pairs.push(name, v);
      }
      socket.write(formatResponseHead(ures.statusCode, pairs), 'latin1');
      relayed = ures;
      // An upstream gone mid-body errors `ures`; abort before pipeline()
      // destroys the client socket with a FIN.
      ures.on('error', cleanup);
      pipeline(ures, socket, cleanup); // body is length- or close-delimited
    });

    upstream.on('error', () => {
      if (!answered) badGateway();
      else cleanup();
    });

    socket.on('error', cleanup);
    socket.on('close', cleanup);
    upstream.end();
  }

  // Tear down tracked long-lived connections (upgraded sockets and in-flight
  // requests) for which `predicate(entry)` returns a truthy value. The daemon
  // drives this with connectionPolicyViolation() so a revocation decision
  // also reaches connections that never issue another request.
  revokeConnections(predicate) {
    for (const conn of [...this.activeConnections]) {
      if (!predicate(conn)) continue;
      if (!conn.client.destroyed) conn.client.destroy();
      if (!conn.upstream.destroyed) conn.upstream.destroy();
    }
    for (const entry of [...this.activeRequests]) {
      if (!predicate(entry)) continue;
      if (!entry.upstream.destroyed) entry.upstream.destroy();
      if (!entry.res.destroyed) entry.res.destroy();
    }
  }

  // Connection-level admission, before a single byte is parsed. Loopback
  // peers are never limited here. A non-loopback peer that is not an
  // authorized LAN client could only ever be refused (decide() answers 404),
  // so it is dropped right away instead of holding a slot until the header
  // timeout. Authorized LAN peers share their own budget, capped per address.
  _handleConnection(socket) {
    const remote = socket.remoteAddress;
    const loopback = this.isLoopbackClient ? this.isLoopbackClient(remote) : isLoopbackRemote(remote);
    if (loopback) return;
    const authorized = isAuthorizedLanClient({
      localAddress: socket.localAddress,
      remoteAddress: remote,
      lanInfo: this.getLanInfo(),
    });
    const key = cleanIpv4(remote) || String(remote);
    const perAddress = this.lanConnections.get(key) || 0;
    if (
      !authorized ||
      this.lanConnectionCount >= this.timeouts.maxLanConnections ||
      perAddress >= this.timeouts.maxLanConnectionsPerAddress
    ) {
      socket.destroy();
      return;
    }
    this.lanConnections.set(key, perAddress + 1);
    this.lanConnectionCount += 1;
    socket.once('close', () => {
      this.lanConnectionCount -= 1;
      const left = (this.lanConnections.get(key) || 1) - 1;
      if (left > 0) this.lanConnections.set(key, left);
      else this.lanConnections.delete(key);
    });
  }

  _createServer() {
    const s = http.createServer({
      connectionsCheckingInterval: this.timeouts.connectionsCheckingIntervalMs,
      // Only a WebSocket handshake becomes an 'upgrade'. Any other offer
      // (h2c from `curl --http2` or the JDK HttpClient on http:// URLs) is an
      // ordinary request, body included, and _handleRequest strips Upgrade
      // as hop-by-hop. Runtimes without this option fall back to the
      // non-WebSocket branch of _handleUpgrade.
      shouldUpgradeCallback: isWebSocketUpgrade,
    }, this._handleRequest);
    s.on('connection', this._handleConnection);
    s.on('connect', this._handleConnect);
    s.on('upgrade', this._handleUpgrade);
    // Bound the client handshake phase. The whole-request timeout is
    // deliberately disabled: legitimate SSE/HMR connections and slow uploads
    // must not be killed by a blanket body timeout.
    s.headersTimeout = this.timeouts.headerTimeoutMs;
    s.requestTimeout = 0;
    s.maxHeadersCount = this.timeouts.maxHeadersCount;
    s.maxConnections = this.timeouts.maxConnections + this.timeouts.maxLanConnections;
    return s;
  }

  destroyUpstreamSockets() {
    for (const conn of this.activeConnections) {
      if (!conn.client.destroyed) conn.client.destroy();
      if (!conn.upstream.destroyed) conn.upstream.destroy();
    }
    this.activeConnections.clear();
    for (const entry of this.activeRequests) {
      if (!entry.upstream.destroyed) entry.upstream.destroy();
      if (!entry.res.destroyed) entry.res.destroy();
    }
    this.activeRequests.clear();
    this.upstreamAgents.loopback.destroy();
    this.upstreamAgents.lan.destroy();
  }

  closeAllConnections() {
    for (const s of this.servers) {
      s.closeAllConnections();
    }
  }

  close(cb) {
    const serversToClose = [...this.servers];
    this.servers = [];

    // Correct shutdown order per Node.js docs:
    // 1. Stop accepting new connections (s.close())
    // 2. Terminate existing connections (s.closeAllConnections())
    // 3. Terminate upgraded/upstream sockets
    const closePromises = serversToClose.map((s) => {
      return new Promise((resolve) => {
        s.close(() => resolve());
        if (typeof s.closeAllConnections === 'function') {
          s.closeAllConnections();
        }
      });
    });

    this.destroyUpstreamSockets();

    return Promise.all(closePromises).then(() => {
      if (cb) cb();
    });
  }
}

function createGateway(opts) {
  return new Gateway(opts);
}

// Bind policy is explicit, never silent:
//   mode 'wildcard' — single dual-stack listener on `port` (80 by default,
//                     the only unprivileged sub-1024 option on macOS 26);
//                     routing is zone-gated per request.
//   mode 'loopback' — maximum isolation: two listeners on 127.0.0.1 and ::1;
//                     requires an explicit port >= 1024 (URLs carry :port).
async function listenGateway(gateway, { mode = 'wildcard', port = 80, loopbackPort = 7777, fallbackPort = 7777 }) {
  const listen = (srv, opts) =>
    new Promise((resolve, reject) => {
      srv.once('error', reject);
      srv.listen(opts, () => {
        srv.removeListener('error', reject);
        resolve(srv.address().port);
      });
    });

  if (mode === 'loopback') {
    const s4 = gateway._createServer();
    const s6 = gateway._createServer();
    try {
      const p4 = await listen(s4, { host: '127.0.0.1', port: loopbackPort });
      try {
        const p6 = await listen(s6, { host: '::1', port: p4 });
        gateway.servers = [s4, s6];
        return { primary: p4, extra: [{ host: '::1', port: p6 }], servers: gateway.servers };
      } catch (err6) {
        s4.close();
        throw err6;
      }
    } catch (err4) {
      s4.close();
      s6.close();
      throw err4;
    }
  }

  const s = gateway._createServer();
  const wildcard = (p) => listen(s, { port: p, host: '::', ipv6Only: false });
  try {
    const actualPort = await wildcard(port);
    gateway.servers = [s];
    return { primary: actualPort, extra: [], servers: gateway.servers };
  } catch (err) {
    if (err.code !== 'EADDRINUSE' && err.code !== 'EACCES') throw err;
    const actualPort = await wildcard(fallbackPort);
    gateway.servers = [s];
    return { primary: actualPort, extra: [], servers: gateway.servers };
  }
}

module.exports = { createGateway, listenGateway, Gateway };
