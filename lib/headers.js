'use strict';

// RFC 7230 §6.1 / RFC 2616 standard hop-by-hop headers
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'forwarded', // RFC 7239: untrusted client-supplied Forwarded must not pass through
]);

function parseConnectionTokens(connectionHeader) {
  if (!connectionHeader) return [];
  return String(connectionHeader)
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

// Message framing is never the sender's to strip by naming it in Connection:
// a request whose Content-Length vanished goes upstream unframed for methods
// Node does not chunk by default (GET/HEAD/DELETE/OPTIONS), and the upstream
// then parses the body as a second, attacker-written request.
const NEVER_CONNECTION_NOMINATED = new Set(['content-length']);

// Client-address headers any client can set and that some stacks trust from
// a loopback proxy (Rack's Client-Ip, chi's RealIP with True-Client-Ip and
// X-Real-Ip, request-ip style libraries with X-Client-Ip, X-Cluster-Client-Ip,
// Fastly-Client-Ip and Cf-Connecting-Ip). A LAN client or share visitor
// sending "X-Real-Ip: 127.0.0.1" would look local to them. X-Forwarded-For
// and Forwarded, written from the verified client address, are the only
// client-address metadata upstream. (The share gate reads the visitor from
// Cf-Connecting-Ip on the incoming request before this strip runs.)
const SPOOFABLE_CLIENT_IP_HEADERS = new Set([
  'client-ip',
  'true-client-ip',
  'x-real-ip',
  'x-client-ip',
  'x-cluster-client-ip',
  'fastly-client-ip',
  'cf-connecting-ip',
]);

// Forwarding metadata only the proxy writes; a client-sent copy is dropped.
const TRUSTED_FORWARDING_HEADERS = new Set(['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto']);

// CGI-style servers (PHP's built-in server, Rack, Python's wsgiref) read a
// header through a variable in which '-' and '_' are the same character, and
// PHP maps '.' to '_' as well: X-Forwarded_For, Client_Ip or Client.Ip
// arrive as HTTP_X_FORWARDED_FOR and HTTP_CLIENT_IP, and may override the
// trusted value. These names are therefore matched with every character
// other than a letter or digit folded to '-', so the match does not depend
// on which separators a particular server maps; other headers carrying '_'
// or '.' are legitimate and pass unchanged.
function isClientAddressHeader(name) {
  const folded = String(name).toLowerCase().replace(/[^a-z0-9]/g, '-');
  return SPOOFABLE_CLIENT_IP_HEADERS.has(folded) || TRUSTED_FORWARDING_HEADERS.has(folded);
}

// Node drops header lines beyond the server's maxHeadersCount from
// req.headers and req.rawHeaders. Runtimes before the July 2026 security
// release (CVE-2026-58044; fixed in 22.23.2, 24.18.1 and 26.5.1) still frame
// the message by the dropped lines: a Content-Length hidden that way leaves
// the body unframed once the request is rebuilt from the visible headers,
// and the upstream parses it as a second request on the pooled connection.
// A header list that reached the limit may have lost lines, so callers
// refuse it (431) instead of forwarding a head they cannot fully see.
function headerListMayBeTruncated(req, maxHeadersCount) {
  return maxHeadersCount > 0 && (req.rawHeaders || []).length >= maxHeadersCount * 2;
}

// The upstream trusts X-Forwarded-For and Forwarded from its loopback peer,
// so every caller must name the real client: there is no loopback stand-in.
function requireClientIp(clientIp) {
  if (typeof clientIp !== 'string' || !clientIp) {
    throw new TypeError('clientIp is required to prepare upstream request headers');
  }
  return clientIp;
}

function forwardedFor(clientIp) {
  return clientIp.includes(':') ? `"[${clientIp}]"` : clientIp;
}

// Strip hop-by-hop headers and any header named in the Connection header
function sanitizeHeaders(headers) {
  const clean = {};
  const customHop = new Set(
    parseConnectionTokens(headers['connection']).filter((t) => !NEVER_CONNECTION_NOMINATED.has(t))
  );

  for (const [key, val] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (HOP_BY_HOP.has(lower) || customHop.has(lower)) {
      continue;
    }
    clean[lower] = val;
  }
  return clean;
}

function stripGateSessionCookie(cookieHeader) {
  if (!cookieHeader) return null;
  const remaining = String(cookieHeader)
    .split(';')
    .map((c) => c.trim())
    .filter((c) => !c.toLowerCase().startsWith('pn_share='))
    .join('; ');
  return remaining || null;
}

function rewriteLocationHeader(location, { originalHost, targetPort, proto = 'http' } = {}) {
  if (!location || !originalHost || !targetPort) return location;
  try {
    const parsed = new URL(location);
    const hostPart = parsed.hostname.toLowerCase();
    const portPart = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);

    const isLoopbackHost = hostPart === 'localhost' || hostPart === '127.0.0.1' || hostPart === '::1';
    if (isLoopbackHost && portPart === Number(targetPort)) {
      const publicBase = new URL(`${proto}://${originalHost}`);
      parsed.protocol = publicBase.protocol;
      parsed.hostname = publicBase.hostname;
      parsed.port = publicBase.port;
      return parsed.toString();
    }
  } catch (err) {
    // Relative URL or invalid - return untouched
  }
  return location;
}

function parseHost(rawHost) {
  if (!rawHost || typeof rawHost !== 'string') return null;
  const trimmed = rawHost.trim().toLowerCase();
  if (!trimmed || trimmed.length > 253) return null;

  // Reject control characters, semicolons, quotes, whitespace, slashes, etc.
  if (/[\s;,"'/\\@?#]/.test(trimmed)) return null;

  let hostname;
  let portStr = null;

  if (trimmed.startsWith('[')) {
    const closeIdx = trimmed.indexOf(']');
    if (closeIdx === -1) return null;
    hostname = trimmed.slice(1, closeIdx);
    const rest = trimmed.slice(closeIdx + 1);
    if (rest) {
      if (!rest.startsWith(':')) return null;
      portStr = rest.slice(1);
    }
  } else {
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx !== -1) {
      hostname = trimmed.slice(0, colonIdx);
      portStr = trimmed.slice(colonIdx + 1);
      if (portStr.includes(':')) return null;
    } else {
      hostname = trimmed;
    }
  }

  let port = null;
  if (portStr !== null) {
    if (!/^\d{1,5}$/.test(portStr)) return null;
    port = Number(portStr);
    if (port < 1 || port > 65535) return null;
    if (String(port) !== portStr) return null; // reject leading zeros
  }

  const canonicalHost = port ? `${hostname}:${port}` : hostname;
  const hostForForwarded = (canonicalHost.includes(':') || canonicalHost.includes('['))
    ? `"${canonicalHost}"`
    : canonicalHost;

  return {
    raw: trimmed,
    hostname,
    port,
    canonicalHost,
    hostForForwarded,
  };
}

function prepareUpstreamRequestHeaders(req, {
  originalHost,
  clientIp,
  targetPort,
  proto = 'http',
  stripShareCookie = false,
  stripToken = null,
} = {}) {
  requireClientIp(clientIp);
  const clean = sanitizeHeaders(req.headers);
  // Every client spelling goes, so the trusted values set below are the only
  // ones and come after all client headers (a value assigned to a key the
  // client sent would keep the client's position, ahead of later spellings).
  for (const name of Object.keys(clean)) {
    if (isClientAddressHeader(name)) delete clean[name];
  }

  // Re-establish request body framing explicitly. Transfer-Encoding is
  // hop-by-hop (the body piped upstream is already de-chunked), and Node only
  // chunks by default for methods that usually carry a body — a chunked GET
  // or DELETE body would otherwise be written raw onto a pooled upstream
  // connection (request smuggling / response-queue poisoning).
  if (req.headers['transfer-encoding']) {
    clean['transfer-encoding'] = 'chunked';
    delete clean['content-length'];
  }

  // Internal hop to upstream dev server sees localhost:<targetPort>
  clean['host'] = `localhost:${targetPort}`;

  // Parse and normalize originalHost to prevent header injection
  const parsedHost = parseHost(originalHost);
  const canonicalHost = parsedHost ? parsedHost.canonicalHost : '127.0.0.1';
  const hostForForwarded = parsedHost ? parsedHost.hostForForwarded : '127.0.0.1';

  // Original client-facing host preserved as trusted forwarding metadata
  clean['x-forwarded-host'] = canonicalHost;
  clean['x-forwarded-proto'] = proto;
  clean['x-forwarded-for'] = clientIp;
  // Synthesize trusted RFC 7239 Forwarded header
  clean['forwarded'] = `for=${forwardedFor(clientIp)};host=${hostForForwarded};proto=${proto}`;

  // Capability isolation: strip gate-internal session cookie
  if (stripShareCookie && clean['cookie']) {
    const stripped = stripGateSessionCookie(clean['cookie']);
    if (stripped) clean['cookie'] = stripped;
    else delete clean['cookie'];
  }

  // Capability isolation: do not forward token-bearing Referer to dev server
  if (stripToken && clean['referer'] && clean['referer'].includes(stripToken)) {
    delete clean['referer'];
  }

  return clean;
}

function prepareUpstreamResponseHeaders(uresHeaders, {
  originalHost,
  targetPort,
  proto = 'http',
  forceNoStore = false,
  isShareGate = false,
} = {}) {
  const clean = sanitizeHeaders(uresHeaders);

  if (clean['location'] && originalHost && targetPort) {
    clean['location'] = rewriteLocationHeader(clean['location'], { originalHost, targetPort, proto });
  }

  if (forceNoStore) {
    clean['cache-control'] = 'no-store, no-cache, must-revalidate, max-age=0';
  } else if (!clean['cache-control']) {
    clean['cache-control'] = 'no-store';
  }

  // Prevent upstream dev server from colliding with gate session cookie
  if (isShareGate && clean['set-cookie']) {
    const cookies = Array.isArray(clean['set-cookie']) ? clean['set-cookie'] : [clean['set-cookie']];
    const filtered = cookies.filter((c) => !c.trim().toLowerCase().startsWith('pn_share='));
    if (filtered.length > 0) {
      clean['set-cookie'] = filtered;
    } else {
      delete clean['set-cookie'];
    }
  }

  return clean;
}

// Upstream headers for a WebSocket upgrade request as a flat raw-header list
// ([name, value, name, value, ...], client order and casing kept) — the form
// http.request accepts verbatim.
function prepareUpgradeRequestHeaders(rawHeaders, {
  originalHost,
  clientIp,
  targetPort,
  proto = 'http',
  stripShareCookie = false,
  stripToken = null,
} = {}) {
  requireClientIp(clientIp);
  const headers = [];

  for (let i = 0; i < rawHeaders.length; i += 2) {
    const key = rawHeaders[i];
    const val = rawHeaders[i + 1];
    const lower = key.toLowerCase();

    if (lower === 'host' || isClientAddressHeader(lower)) {
      continue;
    }

    if (lower === 'cookie' && stripShareCookie) {
      const stripped = stripGateSessionCookie(val);
      if (stripped) headers.push('Cookie', stripped);
      continue;
    }

    if (lower === 'referer' && stripToken && val.includes(stripToken)) {
      continue;
    }

    headers.push(key, val);
  }

  // Parse and normalize originalHost
  const parsedHost = parseHost(originalHost);
  const canonicalHost = parsedHost ? parsedHost.canonicalHost : '127.0.0.1';
  const hostForForwarded = parsedHost ? parsedHost.hostForForwarded : '127.0.0.1';

  // Set internal host and trusted forwarding headers
  headers.unshift('Host', `localhost:${targetPort}`);
  headers.push('X-Forwarded-Host', canonicalHost);
  headers.push('X-Forwarded-Proto', proto);
  headers.push('X-Forwarded-For', clientIp);
  headers.push('Forwarded', `for=${forwardedFor(clientIp)};host=${hostForForwarded};proto=${proto}`);

  return headers;
}

// The same headers serialized as a raw header block (for a hand-written
// request line on a plain socket).
function formatWebSocketUpgradeHeaders(rawHeaders, opts = {}) {
  const pairs = prepareUpgradeRequestHeaders(rawHeaders, opts);
  const lines = [];
  for (let i = 0; i < pairs.length; i += 2) lines.push(`${pairs[i]}: ${pairs[i + 1]}`);
  return lines.join('\r\n') + '\r\n\r\n';
}

module.exports = {
  HOP_BY_HOP,
  headerListMayBeTruncated,
  sanitizeHeaders,
  stripGateSessionCookie,
  rewriteLocationHeader,
  parseHost,
  prepareUpstreamRequestHeaders,
  prepareUpstreamResponseHeaders,
  prepareUpgradeRequestHeaders,
  formatWebSocketUpgradeHeaders,
};
