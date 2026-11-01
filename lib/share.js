'use strict';

const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { pipeline } = require('stream');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { getProcessInfo, getProcessStartTime } = require('./process');
const { atomicWrite } = require('./registry');
const { isStablePayloadEntry, stablePayloadDir } = require('./bundleinstall');
const {
  headerListMayBeTruncated,
  parseHost,
  prepareUpstreamRequestHeaders,
  prepareUpstreamResponseHeaders,
  prepareUpgradeRequestHeaders,
} = require('./headers');

function validateTtlMinutes(val) {
  const num = Number(val);
  if (!Number.isFinite(num) || num < 0.1 || num > 1440) {
    return {
      ok: false,
      reason: 'ttl must be a positive number between 0.1 and 1440 minutes (max 24 hours)',
    };
  }
  return { ok: true, minutes: num };
}

class ShareResult extends String {
  constructor(url, { expiresAt, ttlMinutes, shareId } = {}) {
    super(url);
    this.url = String(url);
    this.expiresAt = expiresAt;
    this.ttlMinutes = ttlMinutes;
    this.shareId = shareId;
  }
}

// Resolve the cloudflared executable. Precedence:
//   1. an explicitly configured `cloudflaredBin` (user override) always wins;
//   2. in bundle/payload operation (this process runs from the stable install
//      payload) the SHIPPED binary is the unambiguous default — the version
//      inventoried in the payload manifest, never a silent Homebrew mismatch;
//   3. Homebrew install locations (absolute candidates);
//   4. bare "cloudflared", i.e. whatever is first on PATH.
// The remaining options are injectable for tests (fixtures, no real
// Homebrew layout required).
function resolveCloudflaredBin(
  override = 'cloudflared',
  {
    isPayloadEntry = isStablePayloadEntry(path.dirname(__dirname)),
    home = os.homedir(),
    candidates = ['/opt/homebrew/bin/cloudflared', '/usr/local/bin/cloudflared'],
  } = {}
) {
  if (override && override !== 'cloudflared') return override;
  if (isPayloadEntry) {
    const bundled = path.join(stablePayloadDir(home), 'runtime', 'bin', 'cloudflared');
    try {
      if (fs.existsSync(bundled)) return bundled;
    } catch {}
  }
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return c;
    } catch {}
  }
  return 'cloudflared';
}

// 32 CSPRNG bytes; the token is a capability that grants access to exactly
// one share.
function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Strip the token prefix off a URL path and normalize the remaining target.
// Leading slashes are collapsed so the redemption redirect can never become a
// protocol-relative URL (e.g. /<token>//evil.example must not 302 to
// //evil.example — that would be a cross-origin redirect of the capability).
// Backslashes are normalized first: the WHATWG URL parser treats them as path
// separators too, so a surviving Location like /\evil.example would resolve
// to host evil.example just the same.
function tokenTargetPath(url, token) {
  let stripped = url.slice(token.length + 1) || '/';
  if (!stripped.startsWith('/')) stripped = '/' + stripped;
  stripped = stripped.replace(/\\/g, '/').replace(/^\/{2,}/, '/');
  return stripped;
}

// Token redemption (session cookie plus a redirect to the clean path) is for
// browser navigations: it takes the capability out of the address bar and
// lets the page's absolute asset URLs authorize by cookie. Any other GET on
// the token path is served directly, like a POST webhook: verification
// handshakes (Meta hub.challenge, X CRC, Strava, Dropbox) and API clients
// have no cookie jar and would end at the 302 or, following it, at a 404.
// Sec-Fetch-Mode decides when present (current browsers send it on every
// HTTPS request); browsers predating it are recognized by their navigation
// Accept, text/html together with application/xhtml+xml. Anything else is
// served directly: when in doubt, a webhook must keep working.
function isBrowserNavigation(req) {
  const mode = req.headers['sec-fetch-mode'];
  if (mode !== undefined) return String(mode).trim().toLowerCase() === 'navigate';
  const types = String(req.headers.accept || '')
    .toLowerCase()
    .split(',')
    .map((type) => type.split(';')[0].trim());
  return types.includes('text/html') && types.includes('application/xhtml+xml');
}

// Bounded handshake phases for the gate. No blanket body timeout: SSE, HMR
// and slow uploads through a share are legitimate and stream unbounded.
const GATE_TIMEOUTS = {
  headerTimeoutMs: 15000, // client -> gate request headers
  upstreamConnectTimeoutMs: 10000, // gate -> upstream connect
  upstreamResponseHeaderTimeoutMs: 15000, // gate -> upstream response headers, after the complete request body
  maxConnections: 512,
  maxHeadersCount: 1000, // a request reaching it is refused (headerListMayBeTruncated)
};

// Tunnel startup output is kept as a bounded tail only: a broken or hostile
// cloudflared printing forever must not grow memory without limit.
const TUNNEL_OUTPUT_TAIL_LIMIT = 16 * 1024;

// The quick-tunnel URL as cloudflared prints it in its startup banner
// ("<ts> INF |  https://brave-quiet-river-lamp.trycloudflare.com   |").
// Matched per complete output line and only as a bare host delimited by
// whitespace, a banner bar or the line end on both sides: an offline error
// like `failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel"`
// must never be taken for the tunnel and reported as a live share. The API
// host is excluded outright as well.
const TUNNEL_URL_RE = /(?:^|[\s|])(https:\/\/(?!api\.)[a-z0-9-]+\.trycloudflare\.com)(?=[\s|]|$)/i;

// cloudflared must only ever serve the gate. Without --config it loads the
// user's ~/.cloudflared/config.yml (or /etc/cloudflared, ...) and that
// file's ingress rules take precedence over --url: the quick tunnel would
// route straight to another origin past the token gate while portname still
// reports the share as ACTIVE. Its flags can also be set through environment
// variables (TUNNEL_*, NO_TLS_VERIFY, ...) — origins, credentials, log files,
// debug log levels that record token paths. So every tunnel runs with a
// portname-owned config file without ingress and an allowlisted environment.
const CLOUDFLARED_CONFIG_FILE = 'cloudflared.yml';
const CLOUDFLARED_CONFIG = '# Written by portname: quick tunnel to the share gate only, no ingress.\nno-autoupdate: true\n';
const CLOUDFLARED_ENV_ALLOWLIST = ['HOME', 'LOGNAME', 'PATH', 'TMPDIR', 'USER'];

function cloudflaredEnv(env = process.env) {
  const clean = {};
  for (const key of CLOUDFLARED_ENV_ALLOWLIST) {
    if (typeof env[key] === 'string') clean[key] = env[key];
  }
  return clean;
}

// Addresses that must never be presented upstream as a public share visitor:
// loopback (incl. IPv4-mapped forms), "this network"/unspecified, and the
// deprecated IPv4-compatible ::/96 block (covers :: and ::1, and ::127.x
// that some stacks fold back to IPv4).
const NON_VISITOR_ADDRESSES = new net.BlockList();
NON_VISITOR_ADDRESSES.addSubnet('127.0.0.0', 8, 'ipv4');
NON_VISITOR_ADDRESSES.addSubnet('0.0.0.0', 8, 'ipv4');
NON_VISITOR_ADDRESSES.addSubnet('::', 96, 'ipv6');

// Public visitor address of a share request. The gate listens on loopback
// and is reached only through cloudflared, so the socket peer is always
// 127.0.0.1 — passing that on would present every link holder to the app as
// a local client (X-Forwarded-For, Forwarded and REMOTE_ADDR all loopback),
// which unlocks loopback-only dev tooling such as Rails web-console. The
// Cloudflare edge sets Cf-Connecting-Ip to the visitor address on every
// proxied HTTP request and cloudflared forwards the edge headers unchanged.
// Exactly one valid, non-loopback, non-unspecified address is accepted
// (duplicates are joined by Node into a list, which is no address); anything
// else yields null and the caller fails closed. There is deliberately no
// fallback — not the socket address, not `for=unknown`, not an omitted
// header: frameworks then fall back to REMOTE_ADDR=127.0.0.1 again.
function shareVisitorAddress(req) {
  const value = req.headers['cf-connecting-ip'];
  if (typeof value !== 'string' || value.includes('%')) return null;
  const family = net.isIP(value);
  if (family === 0) return null;
  if (NON_VISITOR_ADDRESSES.check(value, family === 4 ? 'ipv4' : 'ipv6')) return null;
  return value;
}

// Only a WebSocket handshake may become a spliced stream: another upgrade
// protocol (h2c, ...) answered with 101 would hand the visitor a raw channel
// to the dev server past the gate. Other offers are served as plain HTTP/1.1
// requests instead (RFC 9110 §7.8 lets a server ignore them).
function isWebSocketUpgrade(req) {
  return req.method === 'GET' && String(req.headers.upgrade || '').trim().toLowerCase() === 'websocket';
}

// A response head for the raw upgrade socket. `pairs` is a flat
// [name, value, ...] list; a pair carrying CR/LF is never emitted.
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

// The gate sits between cloudflared and the project server.
// - Browser navigation: GET /<token>/path sets a session cookie (HttpOnly, Secure, SameSite=Lax)
//   and redirects (302) to /path with Referrer-Policy: no-referrer.
// - Subsequent asset requests and WebSockets are authorized by session cookie.
// - Webhooks and other clients: any other request on /<token>/path is served directly, no cookie.
// - Capability isolation: the pn_share session cookie and token-bearing Referers
//   are NEVER forwarded to the upstream dev server. Upstream Set-Cookie cannot collide with pn_share.
// - Visitor address: upstream sees the public visitor (Cf-Connecting-Ip) in X-Forwarded-For and
//   Forwarded, never loopback; a forwarded request without a valid visitor address is refused (400).
// - Cache-Control: no-store is strictly enforced on all public share responses.
// - Coupled abort lifecycle: downstream disconnection cancels upstream requests.
// - WebSockets: the sockets are spliced only after the upstream confirmed 101; any other answer
//   is relayed once with connection: close, so cloudflared never pools a raw channel past the gate.
// - Active connection tracking for WebSockets with symmetric teardown.
class ShareGate {
  constructor({ targetPort, targetHost = '127.0.0.1', ttlMinutes = 60, timeouts = {}, log = () => {} }) {
    this.targetPort = targetPort;
    this.targetHost = targetHost;
    this.timeouts = { ...GATE_TIMEOUTS, ...timeouts };
    this.token = randomToken();
    this.sessions = new Map(); // sessionId -> expiresAt (bounded LRU, max 200)
    this.log = log;
    this.ttlMinutes = ttlMinutes;
    this.expiresAt = Date.now() + ttlMinutes * 60 * 1000;
    this.revoked = false;
    this.activeConnections = new Set(); // set of { client, upstream }
    this.upstreamAgent = new http.Agent({ keepAlive: true });
    // Only a WebSocket handshake becomes an 'upgrade'; any other upgrade
    // offer is an ordinary request (prepareUpstreamRequestHeaders drops
    // Upgrade and Connection). Runtimes without the option fall back to the
    // refusal in #handleUpgrade.
    this.server = http.createServer({ shouldUpgradeCallback: isWebSocketUpgrade }, (req, res) =>
      this.#handle(req, res)
    );
    this.server.on('upgrade', (req, socket, head) => this.#handleUpgrade(req, socket, head));
    // Bound the client handshake phase; no whole-request timeout (see above).
    this.server.headersTimeout = this.timeouts.headerTimeoutMs;
    this.server.requestTimeout = 0;
    this.server.maxConnections = this.timeouts.maxConnections;
    this.server.maxHeadersCount = this.timeouts.maxHeadersCount;
  }

  get expired() {
    return this.revoked || Date.now() >= this.expiresAt;
  }

  activate(expiresAt) {
    this.expiresAt = expiresAt;
  }

  listen() {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      // Abort-aware boot: when the share is revoked while listen() is still
      // pending (stop()/stopAll() racing the first milliseconds of the start),
      // gate.close() closes the server BEFORE 'listening' ever fires. Node
      // then emits 'close' — not 'error' — so without this handler the pending
      // promise (and with it startPromise) would hang forever.
      const onClose = () => {
        reject(new Error('share gate closed before it started listening (share revoked during startup)'));
      };
      this.server.once('close', onClose);
      this.server.listen(0, '127.0.0.1', () => {
        this.server.removeListener('close', onClose);
        resolve(this.server.address().port);
      });
    });
  }

  async close() {
    this.revoked = true;
    this.sessions.clear();

    // Node.js recommended shutdown order: server.close() first, then closeAllConnections()
    const serverClosePromise = new Promise((resolve) => {
      this.server.close(() => resolve());
      if (typeof this.server.closeAllConnections === 'function') {
        this.server.closeAllConnections();
      }
    });

    for (const conn of this.activeConnections) {
      if (!conn.client.destroyed) conn.client.destroy();
      if (!conn.upstream.destroyed) conn.upstream.destroy();
    }
    this.activeConnections.clear();
    this.upstreamAgent.destroy();

    await serverClosePromise;
  }

  #checkAuth(req) {
    if (this.revoked || Date.now() >= this.expiresAt) {
      return { status: 410, action: 'gone' };
    }

    const url = req.url || '/';
    const isTokenPrefix =
      url === '/' + this.token ||
      url.startsWith('/' + this.token + '/') ||
      url.startsWith('/' + this.token + '?');

    if (isTokenPrefix) {
      const stripped = tokenTargetPath(url, this.token);

      if (req.method === 'GET' && isBrowserNavigation(req)) {
        return { status: 302, action: 'redeem_token', targetPath: stripped };
      }
      // Everything else (webhooks, verification GETs, API clients) is
      // authorized directly with the token path
      return { status: 200, action: 'token_direct', targetPath: stripped };
    }

    // Check session cookie
    const cookieHeader = req.headers['cookie'];
    if (cookieHeader) {
      const match = cookieHeader.match(/(?:^|;\s*)pn_share=([0-9a-f]{64})(?:;|$)/i);
      if (match) {
        const sid = match[1];
        if (this.sessions.has(sid)) {
          const exp = this.sessions.get(sid);
          if (Date.now() < exp) {
            // Refresh LRU order
            this.sessions.delete(sid);
            this.sessions.set(sid, exp);
            return { status: 200, action: 'session_cookie', targetPath: url };
          }
          this.sessions.delete(sid);
        }
      }
    }

    return { status: 404, action: 'forbidden' };
  }

  #handle(req, res) {
    if (headerListMayBeTruncated(req, this.timeouts.maxHeadersCount)) {
      res.writeHead(431, {
        'content-length': 0,
        'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
        connection: 'close',
      });
      res.end();
      return;
    }
    const hostCount = (req.rawHeaders || []).filter((v, i) => i % 2 === 0 && v.toLowerCase() === 'host').length;
    if (hostCount !== 1) {
      res.writeHead(400, {
        'content-length': 0,
        'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
      });
      res.end();
      return;
    }
    const parsedHost = parseHost(req.headers.host);
    if (!parsedHost) {
      res.writeHead(400, {
        'content-length': 0,
        'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
      });
      res.end();
      return;
    }

    const auth = this.#checkAuth(req);
    if (auth.action === 'gone') {
      res.writeHead(410, {
        'content-length': 0,
        'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
        'referrer-policy': 'no-referrer',
      });
      res.end();
      return;
    }

    if (auth.action === 'redeem_token') {
      const sessionId = randomToken();
      const sessionExpiry = this.expiresAt;
      // Cap sessions at 200 with LRU eviction and expired cleanup
      if (this.sessions.size >= 200) {
        const now = Date.now();
        for (const [sid, exp] of this.sessions) {
          if (now >= exp) this.sessions.delete(sid);
        }
        while (this.sessions.size >= 200) {
          const oldestKey = this.sessions.keys().next().value;
          this.sessions.delete(oldestKey);
        }
      }
      this.sessions.set(sessionId, sessionExpiry);
      const maxAgeSec = Math.max(0, Math.floor((sessionExpiry - Date.now()) / 1000));
      res.writeHead(302, {
        Location: auth.targetPath,
        'Set-Cookie': `pn_share=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`,
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Referrer-Policy': 'no-referrer',
        'Content-Length': '0',
      });
      res.end();
      return;
    }

    if (auth.action === 'forbidden') {
      res.writeHead(404, {
        'content-length': 0,
        'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
        'referrer-policy': 'no-referrer',
      });
      res.end();
      return;
    }

    // Fail closed without a public visitor address: never fall back to the
    // loopback socket peer (see shareVisitorAddress).
    const visitorIp = shareVisitorAddress(req);
    if (!visitorIp) {
      res.writeHead(400, {
        'content-length': 0,
        'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
        'referrer-policy': 'no-referrer',
      });
      res.end();
      return;
    }

    req.url = auth.targetPath;
    const headers = prepareUpstreamRequestHeaders(req, {
      originalHost: parsedHost.canonicalHost,
      clientIp: visitorIp,
      targetPort: this.targetPort,
      proto: 'https',
      stripShareCookie: true, // Capability isolation
      stripToken: this.token, // Never pass secret token in Referer
    });

    let answered = false;
    const upstream = http.request(
      {
        host: this.targetHost,
        port: this.targetPort,
        path: req.url,
        method: req.method,
        headers,
        agent: this.upstreamAgent,
      },
      (ures) => {
        answered = true;
        clearTimeout(handshakeTimer);
        // Node's parser accepts a three-digit status line below 100 ("050",
        // "000") that writeHead then rejects with a synchronous throw out of
        // this parser callback — uncaught, it would end the whole daemon.
        // A 101 without upgrade headers also arrives here; relayed, it would
        // announce a protocol switch the visitor never asked for. Answer
        // such an upstream like any other broken one: 502, and drop its
        // socket so the keep-alive agent never reuses it.
        const status = ures.statusCode;
        if (!Number.isInteger(status) || status < 200 || status > 999) {
          upstream.destroy();
          if (!res.headersSent) {
            res.writeHead(502, {
              'content-length': 0,
              'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
              'referrer-policy': 'no-referrer',
            });
          }
          res.end();
          return;
        }
        const respHeaders = prepareUpstreamResponseHeaders(ures.headers, {
          originalHost: parsedHost.canonicalHost,
          targetPort: this.targetPort,
          proto: 'https',
          forceNoStore: true, // Strictly enforce no-store for public shares
          isShareGate: true,  // Filter any upstream pn_share Set-Cookie
        });
        respHeaders['referrer-policy'] = 'no-referrer';
        res.writeHead(status, respHeaders);
        // pipeline, not pipe: an upstream that dies mid-body (FIN before the
        // announced length or the final chunk, or RST) must reach the
        // visitor as an aborted response. pipe() never ends the response in
        // that case, leaving the client hanging indefinitely.
        pipeline(ures, res, (err) => {
          if (err && !res.destroyed) res.destroy();
        });
      }
    );

    // Bound the handshake phases only: the upstream connect, then the wait
    // for response headers, which starts once the request body has been
    // completely handed to the upstream ('finish'). A visitor's slow upload
    // and the response stream itself stay unbounded; a stalled body holds
    // one gate connection (maxConnections) until the share ends.
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

    // Coupled abort: cancel upstream request if downstream client aborts.
    // An answer that completed before the request body was completely
    // handed to the upstream (an early 401/404/413 to an upload) ends the
    // upstream request as well: it can never finish or return to the pool,
    // and nothing would end it once the visitor drops the rest of the body.
    res.on('close', () => {
      clearTimeout(handshakeTimer);
      if ((!res.writableFinished || !upstream.writableFinished) && !upstream.destroyed) upstream.destroy();
    });

    upstream.on('error', () => {
      clearTimeout(handshakeTimer);
      if (!res.headersSent) {
        res.writeHead(502, {
          'content-length': 0,
          'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
          'referrer-policy': 'no-referrer',
        });
        res.end();
        return;
      }
      // Headers (and part of the body) are already out: never end cleanly —
      // a terminated chunked body would present the truncated response as
      // complete. Abort the visitor's response instead.
      if (!res.writableEnded) res.destroy();
    });
    // A 101 with upgrade headers to a request that offered no upgrade:
    // without this listener Node destroys the socket and emits neither
    // 'response' nor 'error', leaving the visitor waiting forever.
    upstream.on('upgrade', (ures, upstreamSocket) => {
      answered = true;
      clearTimeout(handshakeTimer);
      upstreamSocket.destroy();
      if (!res.headersSent) {
        res.writeHead(502, {
          'content-length': 0,
          'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
          'referrer-policy': 'no-referrer',
        });
        res.end();
      }
    });
    req.pipe(upstream);
  }

  #handleUpgrade(req, socket, head) {
    // Node detaches its own socket error handler before emitting 'upgrade':
    // a write failing on a connection the peer already reset would surface
    // as an uncaught 'error' during the early refusals below.
    socket.on('error', () => {});
    if (this.revoked || Date.now() >= this.expiresAt) {
      socket.destroy();
      return;
    }

    if (headerListMayBeTruncated(req, this.timeouts.maxHeadersCount)) {
      socket.write('HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    const hostCount = (req.rawHeaders || []).filter((v, i) => i % 2 === 0 && v.toLowerCase() === 'host').length;
    if (hostCount !== 1) {
      socket.write('HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    const parsedHost = parseHost(req.headers.host);
    if (!parsedHost) {
      socket.write('HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    const url = req.url || '/';
    const isTokenPrefix =
      url === '/' + this.token ||
      url.startsWith('/' + this.token + '/') ||
      url.startsWith('/' + this.token + '?');

    let targetPath = url;
    let authorized = false;

    if (isTokenPrefix) {
      targetPath = tokenTargetPath(url, this.token);
      authorized = true;
    } else {
      const cookieHeader = req.headers['cookie'];
      if (cookieHeader) {
        const match = cookieHeader.match(/(?:^|;\s*)pn_share=([0-9a-f]{64})(?:;|$)/i);
        if (match) {
          const sid = match[1];
          if (this.sessions.has(sid)) {
            const exp = this.sessions.get(sid);
            if (Date.now() < exp) {
              authorized = true;
            } else {
              this.sessions.delete(sid);
            }
          }
        }
      }
    }

    if (!authorized) {
      socket.destroy();
      return;
    }

    // Same fail-closed rule as the HTTP path: no loopback stand-in.
    const visitorIp = shareVisitorAddress(req);
    if (!visitorIp) {
      socket.write('HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    // Another protocol (h2c, ...) only gets here on runtimes without
    // shouldUpgradeCallback (see the constructor).
    if (!isWebSocketUpgrade(req)) {
      socket.write('HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
      socket.destroy();
      return;
    }

    // The handshake goes through http.request so the upstream's answer is
    // parsed: the sockets are spliced only after a confirmed 101. A dev server
    // without a WebSocket handler answers like any request (404, keep-alive);
    // splicing that would leave cloudflared a pooled raw HTTP channel to it,
    // and every later WebSocket-marked request from anyone would ride it past
    // the token/cookie check, the visitor-address rule and capability
    // isolation. Such an answer is relayed once and the connection closed.
    let upstream;
    try {
      upstream = http.request({
        host: this.targetHost,
        port: this.targetPort,
        method: req.method,
        path: targetPath,
        headers: prepareUpgradeRequestHeaders(req.rawHeaders, {
          originalHost: parsedHost.canonicalHost,
          clientIp: visitorIp,
          targetPort: this.targetPort,
          proto: 'https',
          stripShareCookie: true, // Capability isolation
          stripToken: this.token,
        }),
        agent: false, // a dedicated connection: an upgraded socket is never pooled
      });
    } catch {
      socket.write('HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
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
    // spliced upstream socket afterwards; cleanup and close() handle both.
    const conn = { client: socket, upstream };
    this.activeConnections.add(conn);
    let answered = false;
    let relayed = null; // a non-101 answer whose head went out to the visitor

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
      if (!socket.destroyed) {
        socket.write(
          'HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n' +
            'cache-control: no-store, no-cache, must-revalidate, max-age=0\r\nconnection: close\r\n\r\n'
        );
      }
      cleanup();
    };

    upstream.on('upgrade', (ures, upstreamSocket, upstreamHead) => {
      clearTimeout(handshakeTimer);
      answered = true;
      conn.upstream = upstreamSocket;
      upstreamSocket.on('error', cleanup);
      upstreamSocket.on('close', cleanup);
      if (!this.activeConnections.has(conn) || socket.destroyed) {
        // Torn down mid-handshake (visitor gone, share revoked).
        cleanup();
        if (!upstreamSocket.destroyed) upstreamSocket.destroy();
        return;
      }
      // The 101 as received, minus any upstream Set-Cookie for pn_share.
      const pairs = [];
      for (let i = 0; i < ures.rawHeaders.length; i += 2) {
        const name = ures.rawHeaders[i];
        const value = ures.rawHeaders[i + 1];
        if (name.toLowerCase() === 'set-cookie' && value.trim().toLowerCase().startsWith('pn_share=')) continue;
        pairs.push(name, value);
      }
      // latin1: header values arrive as one char per byte, keep them byte-exact.
      socket.write(formatResponseHead(101, pairs), 'latin1');
      if (upstreamHead && upstreamHead.length) socket.write(upstreamHead);
      if (head && head.length) upstreamSocket.write(head);
      socket.pipe(upstreamSocket);
      upstreamSocket.pipe(socket);
    });

    upstream.on('response', (ures) => {
      clearTimeout(handshakeTimer);
      answered = true;
      // 1xx here is a 101 without the upgrade headers: not a handshake.
      const status = ures.statusCode;
      if (!Number.isInteger(status) || status < 200 || status > 999) {
        ures.resume();
        badGateway();
        return;
      }
      const respHeaders = prepareUpstreamResponseHeaders(ures.headers, {
        originalHost: parsedHost.canonicalHost,
        targetPort: this.targetPort,
        proto: 'https',
        forceNoStore: true,
        isShareGate: true,
      });
      respHeaders['referrer-policy'] = 'no-referrer';
      respHeaders.connection = 'close';
      const pairs = [];
      for (const [name, value] of Object.entries(respHeaders)) {
        for (const v of Array.isArray(value) ? value : [value]) pairs.push(name, v);
      }
      socket.write(formatResponseHead(status, pairs), 'latin1');
      relayed = ures;
      // An upstream gone mid-body errors `ures`; abort before pipeline()
      // destroys the visitor socket with a FIN.
      ures.on('error', cleanup);
      // The body is length- or close-delimited; the visitor connection then
      // closes and never carries another request.
      pipeline(ures, socket, cleanup);
    });

    upstream.on('error', () => {
      if (!answered) badGateway();
      else cleanup();
    });

    socket.on('error', cleanup);
    socket.on('close', cleanup);
    upstream.end();
  }
}

function sameShareDescriptor(share, { targetPort, targetHost, pinnedPid, pinnedProcessKey, validTtl }) {
  if (share.pinnedPort !== targetPort) return false;
  if ((share.pinnedHost || '127.0.0.1') !== (targetHost || '127.0.0.1')) return false;
  if (share.pinnedPid !== pinnedPid) return false;
  if (share.pinnedProcessKey !== pinnedProcessKey) return false;
  if (share.ttlMinutes !== validTtl) return false;
  return true;
}

class ShareManager {
  constructor({ dir, log = () => {}, getProcessInfo: processInfoFn = getProcessInfo } = {}) {
    this.log = log;
    this.dir = dir;
    this.getProcessInfo = processInfoFn;
    this.shares = new Map(); // name -> share object
    this.stateFile = path.join(dir, 'shares.state.json');
    // Revocation lifecycle for pending starts. A start/replacement job that
    // must wait on an existing share's teardown is bound to the generation
    // it was accepted in: every global revocation (stopAll — unshare-all and
    // daemon shutdown) advances the generation BEFORE stopping anything, so
    // a waiting job resumes into a mismatched generation and aborts instead
    // of silently starting its share after the revocation. While a global
    // revocation sweep is running, new starts are refused outright.
    this.revocationGeneration = 0;
    // Number of stopAll sweeps currently in flight. Sweeps can overlap (a GUI
    // unshare-all racing a CLI one, or a shutdown), and a share snapshot taken
    // by one sweep predates anything started later — so the refusal of new
    // starts may only be lifted by the LAST sweep to finish, never by the
    // first one.
    this.revocationSweepDepth = 0;
    // Name-scoped revocation epochs (monotonic, never truncated on delete):
    // every entry into stop(name) — targeted unshare, TTL expiry, tunnel
    // child exit/error, failure cleanup, scan-driven binding revoke, and the
    // stops inside stopAll/shutdown — advances the name's epoch synchronously
    // BEFORE its first await. The sole exception is a start job's internal
    // replacement stop (_replacementStop): it is part of that job's own
    // contract, not an external invalidation, and must not cancel the job
    // itself. A start job accepted earlier and still waiting on some teardown
    // resumes into a mismatched epoch and aborts instead of silently starting
    // its share after the revocation. A start accepted AFTER the bump
    // snapshots the higher value and runs normally — no start lockout.
    this.nameEpochs = new Map(); // name -> int
  }

  // Throws when the calling start job may no longer start anything. One
  // assert, three additive checks against the job's acceptance snapshot:
  //   1. global: no revocation sweep is running and the global generation is
  //      unchanged (unshare-all / shutdown);
  //   2. the name's revocation epoch is unchanged (every targeted stop of
  //      this name since acceptance — unshare, TTL, child exit, failure
  //      cleanup, scan-driven binding revoke);
  //   3. the name still maps to exactly the snapshotted instance — or, when
  //      this job itself removed that instance (its own replacement stop, or
  //      a stop already tearing it down that the job waited out), to no entry
  //      at all. Any other mapping means someone else revoked or replaced it.
  #assertStartAllowed(name, snap) {
    if (this.revocationSweepDepth > 0 || this.revocationGeneration !== snap.generation) {
      throw new Error(
        `share "${name}" start cancelled: a global revocation (unshare-all or shutdown) began while this start was waiting`
      );
    }
    if ((this.nameEpochs.get(name) || 0) !== snap.nameEpoch) {
      throw new Error(
        `share "${name}" start cancelled: the share was revoked or replaced while this start was waiting`
      );
    }
    const current = this.shares.get(name) || null;
    if (snap.expectedRemoval) {
      if (current) {
        throw new Error(
          `share "${name}" start cancelled: the share was revoked or replaced while this start was waiting`
        );
      }
    } else if ((current && current.shareId) !== snap.instanceId) {
      throw new Error(
        `share "${name}" start cancelled: the share was revoked or replaced while this start was waiting`
      );
    }
  }

  #startCancelled(name) {
    return new Error(
      `share "${name}" start cancelled: the share was revoked or replaced while this start was waiting`
    );
  }

  isShared(name) {
    return this.shares.has(name);
  }

  childPids() {
    return [...this.shares.values()]
      .map((s) => s.cloudflared && s.cloudflared.pid)
      .filter(Boolean);
  }

  status() {
    return [...this.shares.entries()].map(([name, s]) => ({
      name,
      // Random, non-secret identifier of this share instance. Not persisted,
      // renewed for every new share; lets clients address a specific share
      // (share-link / unshare) without ever seeing the token in status.
      shareId: s.shareId,
      url: s.url,
      state: s.state,
      expiresAt: s.gate ? s.gate.expiresAt : null,
      expired: s.gate ? s.gate.expired : false,
      pinnedPid: s.pinnedPid,
      pinnedProcessKey: s.pinnedProcessKey,
      pinnedPort: s.pinnedPort,
      targetPort: s.pinnedPort,
      pinnedHost: s.pinnedHost || '127.0.0.1',
      targetHost: s.pinnedHost || '127.0.0.1',
      ttlMinutes: s.ttlMinutes,
      // When a successful discovery pass last verified this share's binding.
      // Clients may display verification staleness, but the enforcement of
      // the grace window happens daemon-side.
      lastVerifiedAt: s.lastVerifiedAt || null,
    }));
  }

  // Read-only fetch of the full secret link for an exactly matching, still
  // active, not expired share. Never starts a tunnel, never mints a token,
  // never touches a timer. Returns null when there is nothing to hand out.
  link(name) {
    const s = this.shares.get(name);
    if (!s || s.state !== 'ACTIVE' || !s.gate || s.gate.expired || !s.url) return null;
    return {
      url: s.url + '/' + s.gate.token + '/',
      expiresAt: s.gate.expiresAt,
      shareId: s.shareId,
    };
  }

  // At startup, safely clean up orphan tunnel children.
  // Fail-safe contract: requires verifiable process generation (expectedStart).
  // Without expectedStart, we NEVER kill a PID.
  cleanupOrphans() {
    try {
      const recorded = JSON.parse(fs.readFileSync(this.stateFile, 'utf8'));
      const entries = recorded.children || [];
      for (const entry of entries) {
        const pid = typeof entry === 'number' ? entry : entry.pid;
        const expectedStart = typeof entry === 'object' ? entry.startTime : null;
        const expectedCmd = (typeof entry === 'object' && entry.command) || 'cloudflared';
        if (!pid) continue;

        // Fail-safe: refuse to kill if generation cannot be verified
        if (!expectedStart) {
          this.log('share', 'orphan-skipped-unverifiable-generation', { pid });
          continue;
        }

        const currentInfo = this.getProcessInfo(pid);
        if (!currentInfo) {
          // Process already terminated
          continue;
        }

        const startMatches = currentInfo.startTime === expectedStart;
        const cmdMatches = currentInfo.command && currentInfo.command.includes(expectedCmd);
        if (startMatches && cmdMatches) {
          try {
            process.kill(pid, 'SIGTERM');
            this.log('share', 'orphan-killed', pid);
          } catch (err) {}
        } else {
          this.log('share', 'orphan-skipped-pid-reused', {
            pid,
            expectedStart,
            currentStart: currentInfo.startTime,
          });
        }
      }
      fs.unlinkSync(this.stateFile);
    } catch (err) {
      // no previous run or invalid state
    }
  }

  #recordChildren() {
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      const children = [...this.shares.values()]
        .filter((s) => s.cloudflared && s.cloudflared.pid)
        .map((s) => ({
          pid: s.cloudflared.pid,
          startTime: getProcessStartTime(s.cloudflared.pid),
          command: 'cloudflared',
        }));
      if (children.length > 0) {
        atomicWrite(this.stateFile, JSON.stringify({ children }, null, 2) + '\n');
      } else {
        try { fs.unlinkSync(this.stateFile); } catch {}
      }
    } catch (err) {
      // best effort
    }
  }

  async start({
    name,
    targetPort,
    targetHost = '127.0.0.1',
    pinnedPid = null,
    pinnedProcessKey = null,
    ttlMinutes = 60,
    _testTtlMs = null,
    cloudflaredBin = 'cloudflared',
    timeoutMs = 30000,
    // Honest verification age: the epoch (ms) of the last REAL successful
    // target verification (the daemon passes its lastGoodScanAt from the scan
    // that passed the start freshness gate) and the grace window it is bounded
    // by. The share keeps this age through activation — "tunnel ready" is not
    // "target just verified".
    verifiedAt = null,
    verifyGraceMs = null,
  }) {
    if (this.revocationSweepDepth > 0) {
      throw new Error(
        `share "${name}" start refused: a global revocation (unshare-all or shutdown) is in progress`
      );
    }
    // Acceptance snapshot (name-scoped job contract): the global revocation
    // generation, the name's revocation epoch, and the share instance (by
    // shareId) owning the name right now. After EVERY await below — waiting
    // out a foreign startPromise or stopPromise, performing this job's own
    // replacement stop — the job re-checks the snapshot before it may
    // proceed, and again before every recursion (which then snapshots fresh).
    const existingAtAccept = this.shares.get(name) || null;
    const snap = {
      generation: this.revocationGeneration,
      nameEpoch: this.nameEpochs.get(name) || 0,
      instanceId: existingAtAccept ? existingAtAccept.shareId : null,
      expectedRemoval: false,
    };

    let validTtl = 60;
    let ttlMs;
    if (_testTtlMs != null) {
      ttlMs = _testTtlMs;
      validTtl = _testTtlMs / 60000;
    } else {
      const ttlCheck = validateTtlMinutes(ttlMinutes);
      if (!ttlCheck.ok) {
        throw new Error(`invalid ttlMinutes: ${ttlCheck.reason}`);
      }
      validTtl = ttlCheck.minutes;
      ttlMs = validTtl * 60 * 1000;
    }

    if (existingAtAccept) {
      const existing = existingAtAccept;
        if (existing.state === 'STOPPING') {
          if (existing.stopPromise) {
            await existing.stopPromise;
            // This job deliberately waited out the snapshotted instance's
            // teardown: its removal is the expected outcome, not a violation.
            snap.expectedRemoval = true;
          }
          this.#assertStartAllowed(name, snap);
          return this.start({
            name,
            targetPort,
            targetHost,
            pinnedPid,
            pinnedProcessKey,
            ttlMinutes,
            _testTtlMs,
            cloudflaredBin,
            timeoutMs,
            verifiedAt,
            verifyGraceMs,
          });
        } else if (existing.state === 'STARTING') {
          if (sameShareDescriptor(existing, { targetPort, targetHost, pinnedPid, pinnedProcessKey, validTtl })) {
            if (existing.startPromise) return existing.startPromise;
          }
          // Parameters changed while starting: wait for startup to finish, then stop and restart
          await existing.startPromise.catch(() => {});
          this.#assertStartAllowed(name, snap);
          // Internal replacement stop: bound to the snapshotted instance and
          // exempt from the epoch bump. If the instance is already gone or
          // was replaced, abort instead of stopping a newer instance.
          const stopped = await this.stop(name, { expectedShareId: snap.instanceId, _replacementStop: true });
          if (stopped !== true) throw this.#startCancelled(name);
          snap.expectedRemoval = true;
          this.#assertStartAllowed(name, snap);
          return this.start({
            name,
            targetPort,
            targetHost,
            pinnedPid,
            pinnedProcessKey,
            ttlMinutes,
            _testTtlMs,
            cloudflaredBin,
            timeoutMs,
            verifiedAt,
            verifyGraceMs,
          });
        } else if (existing.state === 'ACTIVE') {
          if (!existing.gate.expired && sameShareDescriptor(existing, { targetPort, targetHost, pinnedPid, pinnedProcessKey, validTtl })) {
            return new ShareResult(existing.url + '/' + existing.gate.token + '/', {
              expiresAt: existing.gate.expiresAt,
              ttlMinutes: existing.ttlMinutes,
              shareId: existing.shareId,
            });
          }
          const stopped = await this.stop(name, { expectedShareId: snap.instanceId, _replacementStop: true });
          if (stopped !== true) throw this.#startCancelled(name);
          snap.expectedRemoval = true;
          this.#assertStartAllowed(name, snap);
          return this.start({
            name,
            targetPort,
            targetHost,
            pinnedPid,
            pinnedProcessKey,
            ttlMinutes,
            _testTtlMs,
            cloudflaredBin,
            timeoutMs,
            verifiedAt,
            verifyGraceMs,
          });
        } else if (existing.state === 'STOPPED') {
          const stopped = await this.stop(name, { expectedShareId: snap.instanceId, _replacementStop: true });
          if (stopped !== true) throw this.#startCancelled(name);
          snap.expectedRemoval = true;
          this.#assertStartAllowed(name, snap);
          return this.start({
            name,
            targetPort,
            targetHost,
            pinnedPid,
            pinnedProcessKey,
            ttlMinutes,
            _testTtlMs,
            cloudflaredBin,
            timeoutMs,
            verifiedAt,
            verifyGraceMs,
          });
        }
      }

    const bin = resolveCloudflaredBin(cloudflaredBin);
    const gate = new ShareGate({ targetPort, targetHost, ttlMinutes: validTtl, log: this.log });

    const share = {
      state: 'STARTING',
      name,
      gate,
      cloudflared: null,
      url: null,
      token: gate.token,
      // Random, non-secret, not persisted: identifies this share instance in
      // status so clients can target it without holding the secret token.
      shareId: crypto.randomBytes(8).toString('hex'),
      pinnedPid,
      pinnedProcessKey,
      pinnedPort: targetPort,
      pinnedHost: targetHost || '127.0.0.1',
      ttlMinutes: validTtl,
      ttlTimer: null,
      // Honest age of the last REAL target verification (may be null for
      // callers that do not track one). Refreshed by the daemon on every
      // successful discovery pass; never stamped fresh by activation.
      lastVerifiedAt: Number.isFinite(verifiedAt) ? verifiedAt : null,
      abortController: new AbortController(),
      childExitPromise: null,
      stopPromise: null,
      startPromise: null,
    };
    this.shares.set(name, share);

    share.startPromise = (async () => {
      try {
        const gatePort = await gate.listen();

        if (share.state !== 'STARTING' || share.abortController.signal.aborted) {
          await gate.close();
          throw new Error(`share "${name}" was stopped during startup`);
        }

        const { url, child } = await this.#startTunnel({
          share,
          name,
          gatePort,
          cloudflaredBin: bin,
          timeoutMs,
        });

        if (share.state !== 'STARTING' || share.abortController.signal.aborted) {
          try { child.kill('SIGTERM'); } catch {}
          throw new Error(`share "${name}" was stopped during startup`);
        }

        // Late-activation guard: the tunnel being ready says nothing about
        // the target. If the honest verification age carried from the start
        // went stale while booting (e.g. sustained discovery failure during
        // a slow tunnel start), refuse with a defined error instead of
        // activating with an artificially fresh timestamp.
        if (
          share.lastVerifiedAt !== null &&
          verifyGraceMs !== null &&
          Date.now() - share.lastVerifiedAt > verifyGraceMs
        ) {
          throw new Error(
            `share "${name}" target verification expired during tunnel startup (last verified ${Date.now() - share.lastVerifiedAt}ms ago, grace ${verifyGraceMs}ms); retry once discovery is healthy`
          );
        }

        share.state = 'ACTIVE';
        share.cloudflared = child;
        share.url = url;

        // Lockstep TTL activation: gate and manager share the exact same expiration timestamp
        const expiresAt = Date.now() + ttlMs;
        gate.activate(expiresAt);
        // lastVerifiedAt deliberately keeps the honest age it was started
        // with (and that the daemon refreshes on successful passes):
        // activation completes the tunnel, it does not re-verify the target.

        this.#recordChildren();
        // No token material in logs — not even a prefix.
        // Public origin + shareId identify the share without leaking the secret.
        this.log('share', name, `${url}/ (shareId ${share.shareId})`);

        // Bound the callback to THIS share instance: if the share is replaced
        // by a newer instance under the same name before the timer fires, the
        // stale callback must never stop the newcomer.
        share.ttlTimer = setTimeout(() => {
          share.ttlTimer = null;
          if (this.shares.get(name) !== share) return;
          this.log('share', 'ttl-expired', name);
          this.stop(name).catch(() => {});
        }, ttlMs);
        if (share.ttlTimer.unref) share.ttlTimer.unref();

        return new ShareResult(url + '/' + gate.token + '/', {
          expiresAt,
          ttlMinutes: validTtl,
          shareId: share.shareId,
        });
      } catch (err) {
        // Only clean up when this exact share instance still owns the name:
        // a concurrent stop+start may already have mapped a newer instance,
        // and this failure path must never kill that newcomer.
        if (this.shares.get(name) === share) {
          await this.stop(name).catch(() => {});
        }
        throw err;
      }
    })();

    return share.startPromise;
  }

  #startTunnel({ share, name, gatePort, cloudflaredBin, timeoutMs }) {
    return new Promise((resolve, reject) => {
      if (share.state === 'STOPPING' || share.state === 'STOPPED' || share.abortController.signal.aborted) {
        return reject(new Error(`share "${name}" startup aborted before spawn`));
      }

      // Isolated config (rewritten on every start, 0600, atomic): without it
      // a user cloudflared config could reroute the tunnel past the gate, so
      // failing to write it refuses the start instead of spawning without.
      const configFile = path.join(this.dir, CLOUDFLARED_CONFIG_FILE);
      try {
        fs.mkdirSync(this.dir, { recursive: true });
        atomicWrite(configFile, CLOUDFLARED_CONFIG, { mode: 0o600 });
      } catch (err) {
        return reject(new Error(`share "${name}" could not write the isolated cloudflared config: ${err.message}`));
      }

      const child = spawn(
        cloudflaredBin,
        ['tunnel', '--config', configFile, '--url', `http://127.0.0.1:${gatePort}`, '--no-autoupdate'],
        { stdio: ['ignore', 'pipe', 'pipe'], env: cloudflaredEnv() }
      );

      // Take ownership of the child process handle immediately
      share.cloudflared = child;
      share.childExitPromise = new Promise((res) => {
        child.once('exit', (code, signal) => res({ code, signal }));
        child.once('error', (err) => res({ error: err }));
      });
      // Immediately record child PID in STARTING state
      this.#recordChildren();

      let output = '';
      let urlFound = false;
      // Unterminated last line per stream: the URL is only searched for in
      // complete lines, so a chunk boundary can never cut a host short.
      const pendingLine = { stdout: '', stderr: '' };

      const onAbort = () => {
        cleanup();
        try { child.kill('SIGTERM'); } catch {}
        reject(new Error(`share "${name}" startup aborted`));
      };

      if (share.abortController.signal.aborted) {
        onAbort();
        return;
      }
      share.abortController.signal.addEventListener('abort', onAbort, { once: true });

      const onOutput = (source, d) => {
        const text = d.toString();
        // Bounded tail only: a broken tunnel printing forever must not grow
        // memory without limit. The URL appears early, so tail-keeping never
        // hides the match.
        output = (output + text).slice(-TUNNEL_OUTPUT_TAIL_LIMIT);
        if (urlFound) return;
        const lines = (pendingLine[source] + text).split('\n');
        pendingLine[source] = lines.pop().slice(-TUNNEL_OUTPUT_TAIL_LIMIT);
        for (const line of lines) {
          const match = line.match(TUNNEL_URL_RE);
          if (!match) continue;
          urlFound = true;
          cleanup();
          child.stdout.resume();
          child.stderr.resume();
          resolve({ url: match[1], child });
          return;
        }
      };
      const onStdout = (d) => onOutput('stdout', d);
      const onStderr = (d) => onOutput('stderr', d);

      const timer = setTimeout(() => {
        if (!urlFound) {
          cleanup();
          try { child.kill('SIGTERM'); } catch {}
          reject(new Error(`cloudflared did not produce a URL within ${timeoutMs}ms. Output: ${output.slice(-400)}`));
        }
      }, timeoutMs);

      const onStartupError = (err) => {
        if (!urlFound) {
          cleanup();
          reject(new Error(`cloudflared failed to start: ${err.message}. Install with: brew install cloudflared`));
        }
      };

      const onStartupExit = (code) => {
        if (!urlFound) {
          cleanup();
          reject(new Error(`cloudflared exited early (code ${code}). Output: ${output.slice(-400)}`));
        }
      };

      const cleanup = () => {
        clearTimeout(timer);
        share.abortController.signal.removeEventListener('abort', onAbort);
        child.stdout.removeListener('data', onStdout);
        child.stderr.removeListener('data', onStderr);
        child.removeListener('error', onStartupError);
        child.removeListener('exit', onStartupExit);
      };

      child.stdout.on('data', onStdout);
      child.stderr.on('data', onStderr);
      child.once('error', onStartupError);
      child.once('exit', onStartupExit);

      // Permanent child monitoring — bound to THIS share instance. A late
      // exit/error event from a child of a replaced share must never stop the
      // newer instance that now owns the name. An exit while the share is
      // already STOPPING/STOPPED is the expected consequence of that teardown
      // itself (its stop has already invalidated what it must — a replacement
      // stop deliberately must not), so the monitor's redundant join is
      // skipped: it must never surface as a fresh external revocation.
      child.on('exit', (code, signal) => {
        if (!urlFound) return;
        if (this.shares.get(name) !== share) return;
        if (share.state === 'STOPPING' || share.state === 'STOPPED') return;
        this.log('tunnel', 'child-exited', name, `code ${code}, signal ${signal}`);
        this.stop(name).catch(() => {});
      });
      child.on('error', (err) => {
        if (!urlFound) return;
        if (this.shares.get(name) !== share) return;
        if (share.state === 'STOPPING' || share.state === 'STOPPED') return;
        this.log('tunnel', 'child-error', name, err.message);
        this.stop(name).catch(() => {});
      });

      this.log('tunnel', 'starting', name);
    });
  }

  // Stop the share for `name`. With expectedShareId the stop is bound to that
  // exact share instance: a mismatched or vanished id returns 'stale' and the
  // (possibly newer) share is left untouched. Returns true when a share was
  // (or had already been) stopped, false when none exists.
  //
  // Revocation epoch: every entry bumps the name's epoch synchronously before
  // any await, invalidating pending start jobs for this name — except when
  // _replacementStop marks the internal replacement stop of such a job
  // itself (bound to the instance it replaces via expectedShareId). stopAll
  // stays unmarked: its global generation bump invalidates waiting jobs
  // anyway, so the per-name bumps are redundant but harmless.
  //
  // Order matters: the expectedShareId binding is validated FIRST, before
  // anything is changed. A stale-rejected request (bound to an id that no
  // longer owns the name) must leave the world untouched — in particular it
  // must not advance the epoch, which would improperly cancel the pending
  // replacement jobs of the newer, untouched instance. A request that is not
  // rejected — bound with a matching id, bound onto a vanished share (nothing
  // contradicts the id), or unbound (the invalidation is the point, with or
  // without a visible share) — always bumps.
  async stop(name, { expectedShareId, _replacementStop } = {}) {
    const share = this.shares.get(name);
    if (expectedShareId !== undefined && share && share.shareId !== expectedShareId) {
      return 'stale';
    }
    if (!_replacementStop) {
      this.nameEpochs.set(name, (this.nameEpochs.get(name) || 0) + 1);
    }
    if (!share) return false;
    if (share.state === 'STOPPING') {
      if (share.stopPromise) {
        // Resume via .then instead of a body await: this joiner and the stop's
        // initiator then hang off the teardown promise with the same adoption
        // depth, so the caller that arrived first (the initiator) also resumes
        // first — acceptance order, not promise plumbing, decides which
        // concurrent replacement job wins the restart race.
        return share.stopPromise.then(() => true);
      }
      return true;
    }
    if (share.state === 'STOPPED') return true;

    share.state = 'STOPPING';
    share.stopPromise = (async () => {
      share.abortController.abort();

      if (share.ttlTimer) {
        clearTimeout(share.ttlTimer);
        share.ttlTimer = null;
      }

      // 1. Immediately close the gate and sever all active client connections
      await share.gate.close();

      // 2. Terminate the cloudflared tunnel process
      if (share.cloudflared) {
        try {
          share.cloudflared.kill('SIGTERM');
        } catch (err) {}

        if (share.childExitPromise && share.cloudflared && share.cloudflared.pid) {
          let forceKillTimer = null;
          const killTimeoutPromise = new Promise((res) => {
            forceKillTimer = setTimeout(() => {
              try {
                if (share.cloudflared) share.cloudflared.kill('SIGKILL');
              } catch {}
              res({ timedOut: true });
            }, 1500);
            if (forceKillTimer.unref) forceKillTimer.unref();
          });

          try {
            await Promise.race([share.childExitPromise, killTimeoutPromise]);
          } catch {} finally {
            if (forceKillTimer) clearTimeout(forceKillTimer);
          }
        }
      }

      share.state = 'STOPPED';
      if (this.shares.get(name) === share) {
        this.shares.delete(name);
      }
      this.#recordChildren();
      this.log('share', 'stopped', name);
      return true;
    })();

    return share.stopPromise;
  }

  // Global revocation: stop every live share (ACTIVE, STARTING and already
  // STOPPING ones are awaited; STOPPED ones are skipped — idempotent) and
  // cancel start/replacement jobs still waiting on a teardown. The generation
  // is advanced BEFORE any stop so a pending job resumes into a mismatched
  // generation and aborts instead of starting its share after the revocation;
  // while the sweep runs, new starts are refused outright. Returns the names
  // that were (or had already been) stopped.
  //
  // The shares are torn down in parallel: each stop may wait up to 1.5s for
  // its tunnel child before escalating to SIGKILL, so a sequential sweep of
  // N slow children took N x 1.5s and overran the daemon's 5s shutdown
  // backstop — the later tunnels then never got a signal at all. In
  // parallel the sweep is bounded by the slowest single stop. All stops are
  // entered synchronously (each bumps its name epoch before its first
  // await); a failing stop no longer skips the remaining shares, its error
  // is rethrown once every stop has settled.
  async stopAll() {
    this.revocationSweepDepth += 1;
    this.revocationGeneration += 1;
    const stopped = [];
    try {
      const names = [...this.shares.keys()].filter((name) => {
        const share = this.shares.get(name);
        return share && (share.state === 'ACTIVE' || share.state === 'STARTING' || share.state === 'STOPPING');
      });
      const results = await Promise.allSettled(names.map((name) => this.stop(name)));
      let failure = null;
      results.forEach((result, i) => {
        if (result.status === 'fulfilled') stopped.push(names[i]);
        else if (!failure) failure = result.reason;
      });
      if (failure) throw failure;
    } finally {
      // Only the LAST finishing sweep re-enables starts: with two overlapping
      // sweeps, the first one's teardown must not open the gate for a start
      // the still-running sweep will never stop (its share snapshot predates
      // that start).
      this.revocationSweepDepth -= 1;
    }
    return stopped;
  }
}

module.exports = { ShareGate, ShareManager, ShareResult, randomToken, resolveCloudflaredBin, validateTtlMinutes };
