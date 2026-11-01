'use strict';

// Zone and routing decision, pure so it can be tested without sockets.
//
// The Host header determines routing, never authorization:
//   - loopback connections may reach any known project (*.localhost);
//   - LAN connections may only reach explicitly exposed projects, whatever
//     Host they claim — a faked `private.localhost` from the LAN gets 404;
//   - everything else is refused without revealing that it exists.

const { validateName } = require('./naming');
const { parseHost } = require('./headers');

function isLoopbackRemote(remoteAddress) {
  if (!remoteAddress) return false;
  let addr = remoteAddress;
  if (addr.startsWith('::ffff:')) addr = addr.slice('::ffff:'.length);
  return addr === '127.0.0.1' || addr === '::1';
}

// Splits a bare Host into { name, zone }
// Returns null for anything else (including ports, deep subdomains, or malformed hosts).
function hostRoute(host) {
  if (!host) return null;
  const parsed = parseHost(host);
  if (!parsed || parsed.port !== null) return null;
  const hostname = parsed.hostname;
  let name;
  let zone;
  if (hostname.endsWith('.localhost')) {
    name = hostname.slice(0, -'.localhost'.length);
    zone = 'local';
  } else if (hostname.endsWith('.local')) {
    name = hostname.slice(0, -'.local'.length);
    zone = 'wifi';
  } else {
    return null;
  }
  const check = validateName(name);
  if (!check.ok) return null;
  return { name: check.name, zone };
}

// `ctx`: { remoteIsLoopback, host, routeExists(name) -> route|falsy,
//          isExposed(routeOrIdentity) -> boolean }
function decide(ctx) {
  const parsed = hostRoute(ctx.host);
  if (!parsed) return { action: 'reject', status: 404 };
  if (!ctx.remoteIsLoopback && parsed.zone === 'local') {
    // A LAN client claiming a local name must not learn or reach it.
    return { action: 'reject', status: 404 };
  }
  const route = ctx.routeExists(parsed.name);
  if (!route) return { action: 'reject', status: 404 };
  if (parsed.zone === 'wifi') {
    const isExp = typeof ctx.isExposed === 'function'
      ? (ctx.isExposed(route) || ctx.isExposed(route.root || ('manual:' + route.name)))
      : false;
    if (!isExp) {
      return { action: 'reject', status: 404 };
    }
    if (!ctx.remoteIsLoopback && typeof ctx.isLanClient === 'function') {
      const authorized = ctx.isLanClient({
        localAddress: ctx.localAddress,
        remoteAddress: ctx.remoteAddress,
      });
      if (!authorized) {
        return { action: 'reject', status: 404 };
      }
    }
  }
  // `zone` rides along on the verdict so long-lived connections can record the
  // reachability zone they were authorized in (see connectionPolicyViolation).
  return { action: 'proxy', route, zone: parsed.zone };
}

// Policy check for ALREADY-ESTABLISHED long-lived connections (WebSockets,
// SSE and other streaming responses). Returns a revocation reason string, or
// null when the connection may stay. New requests are re-decided per request;
// this covers the connections that never see a new request again.
//
// conn: the metadata recorded when the connection was authorized:
//   { name, identity, zone, loopback, port, upstreamHost, processKey }
// ctx: { getRoute(name) -> route|null, isExposedIdentity(identity) -> boolean,
//        isLanFresh(identity) -> boolean (optional) }
//
// Order matters: route/target-level inconsistencies apply to every client
// (a loopback browser has no business riding a splice to an unrouted or
// repurposed target either). Only the exposure decision is LAN-scoped —
// revoking LAN exposure must never tear down loopback traffic, and other
// projects are never touched because the check is bound to conn.identity.
// `isLanFresh` extends the LAN-scoped part: WLAN access is bounded by target
// verification freshness, so sustained discovery failure must also reach
// established WLAN streams once the verification deadline has passed.
function connectionPolicyViolation(conn, { getRoute, isExposedIdentity, isLanFresh }) {
  const route = getRoute(conn.name);
  if (!route) return 'route-gone';
  const identity = route.root || ('manual:' + route.name);
  if (identity !== conn.identity) return 'identity-changed';
  if (route.port !== conn.port) return 'target-changed';
  if ((route.upstreamHost || '127.0.0.1') !== (conn.upstreamHost || '127.0.0.1')) return 'target-changed';
  if (route.processKey && conn.processKey && route.processKey !== conn.processKey) return 'target-changed';
  if (conn.loopback) return null;
  if (conn.zone !== 'wifi') return null;
  if (!isExposedIdentity(identity)) return 'exposure-revoked';
  if (typeof isLanFresh === 'function' && !isLanFresh(identity)) {
    return 'target-verification-stale';
  }
  return null;
}

module.exports = { hostRoute, decide, isLoopbackRemote, connectionPolicyViolation };
