'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { hostRoute, decide, isLoopbackRemote } = require('../lib/authorize');
const { validateName, sanitizeName } = require('../lib/naming');

test('validateName enforces DNS label syntax (RFC 1035)', () => {
  assert.deepStrictEqual(validateName('shop'), { ok: true, name: 'shop' });
  assert.deepStrictEqual(validateName('SHOP'), { ok: true, name: 'shop' });
  assert.deepStrictEqual(validateName('my-web-app-1'), { ok: true, name: 'my-web-app-1' });
  assert.strictEqual(validateName('a'.repeat(63)).ok, true);

  // Invalid cases
  assert.strictEqual(validateName('').ok, false);
  assert.strictEqual(validateName('a'.repeat(64)).ok, false);
  assert.strictEqual(validateName('-leading').ok, false);
  assert.strictEqual(validateName('trailing-').ok, false);
  assert.strictEqual(validateName('has.dot').ok, false);
  assert.strictEqual(validateName('has space').ok, false);
  assert.strictEqual(validateName('has_underscore').ok, false);
  assert.strictEqual(validateName(null).ok, false);
});

test('sanitizeName sanitizes input into valid DNS label', () => {
  assert.strictEqual(sanitizeName('My Project!'), 'my-project');
  assert.strictEqual(sanitizeName('---'), 'project');
  assert.strictEqual(sanitizeName('-test-name-'), 'test-name');
  assert.strictEqual(sanitizeName('a'.repeat(80)).length, 63);
});

test('hostRoute recognizes the two route zones and refuses everything else', () => {
  assert.deepStrictEqual(hostRoute('shop.localhost'), { name: 'shop', zone: 'local' });
  assert.deepStrictEqual(hostRoute('SHOP.Local'), { name: 'shop', zone: 'wifi' });
  assert.deepStrictEqual(hostRoute('my-app.localhost'), { name: 'my-app', zone: 'local' });
  assert.deepStrictEqual(hostRoute('shop.localhost:3000'), null, 'bare host expected');
  assert.strictEqual(hostRoute('a.b.localhost'), null, 'deep subdomains are never routes');
  assert.strictEqual(hostRoute('-invalid.localhost'), null, 'leading hyphen not allowed');
  assert.strictEqual(hostRoute('invalid-.localhost'), null, 'trailing hyphen not allowed');
  assert.strictEqual(hostRoute('example.com'), null);
  assert.strictEqual(hostRoute(''), null);
  assert.strictEqual(hostRoute(undefined), null);
  assert.strictEqual(hostRoute('shop.localhost/'), null, 'no path injection in host');
});

test('isLoopbackRemote handles IPv4-mapped addresses', () => {
  assert.strictEqual(isLoopbackRemote('127.0.0.1'), true);
  assert.strictEqual(isLoopbackRemote('::1'), true);
  assert.strictEqual(isLoopbackRemote('::ffff:127.0.0.1'), true);
  assert.strictEqual(isLoopbackRemote('192.168.1.7'), false);
  assert.strictEqual(isLoopbackRemote(undefined), false);
});

const routes = { shop: { port: 3000 }, backend: { port: 8000 } };
const ctx = (over = {}) => ({
  remoteIsLoopback: true,
  host: 'shop.localhost',
  routeExists: (n) => routes[n] || null,
  isExposed: () => false,
  ...over,
});

test('decide: loopback reaches any known *.localhost name', () => {
  assert.deepStrictEqual(decide(ctx()).action, 'proxy');
  assert.strictEqual(decide(ctx()).route.port, 3000);
  assert.deepStrictEqual(decide(ctx({ host: 'backend.localhost' })).route.port, 8000);
});

test('decide: unknown names are refused without revealing existence', () => {
  assert.deepStrictEqual(decide(ctx({ host: 'secret.localhost' })), { action: 'reject', status: 404 });
});

test('decide: a LAN client with a faked local name is refused (host routes, exposure authorizes)', () => {
  const fromLan = ctx({ remoteIsLoopback: false });
  assert.deepStrictEqual(decide(fromLan).action, 'reject', 'faked *.localhost from LAN');
});

test('decide: *.local only routes when exposed, from any zone', () => {
  const exposed = decide(ctx({ host: 'shop.local', isExposed: () => true }));
  assert.deepStrictEqual(exposed.action, 'proxy');
  const unexposed = decide(ctx({ host: 'shop.local', isExposed: () => false }));
  assert.deepStrictEqual(unexposed, { action: 'reject', status: 404 });
  const lanExposed = decide(ctx({ host: 'shop.local', remoteIsLoopback: false, isExposed: () => true }));
  assert.deepStrictEqual(lanExposed.action, 'proxy', 'exposed name answers on the LAN');
});

const { isIpInSubnet, isAuthorizedLanClient, getLanInterface } = require('../lib/network');

test('isIpInSubnet correctly verifies IPv4 subnets', () => {
  assert.strictEqual(isIpInSubnet('192.168.1.50', '192.168.1.10', '255.255.255.0'), true);
  assert.strictEqual(isIpInSubnet('192.168.2.50', '192.168.1.10', '255.255.255.0'), false);
  assert.strictEqual(isIpInSubnet('::ffff:192.168.1.50', '192.168.1.10', '255.255.255.0'), true);
  assert.strictEqual(isIpInSubnet('10.0.0.5', '10.0.0.1', '255.0.0.0'), true);
  assert.strictEqual(isIpInSubnet('10.1.2.3', '10.0.0.1', '255.255.0.0'), false);
});

test('isAuthorizedLanClient enforces interface IP and subnet boundaries', () => {
  const lanInfo = { name: 'en0', address: '192.168.178.29', netmask: '255.255.255.0' };

  // Valid client on same Wi-Fi arriving on Mac's LAN interface
  assert.strictEqual(isAuthorizedLanClient({
    localAddress: '192.168.178.29',
    remoteAddress: '192.168.178.50',
    lanInfo,
  }), true);

  // Client on same subnet but connection arrived on VPN interface address (e.g. 10.8.0.1)
  assert.strictEqual(isAuthorizedLanClient({
    localAddress: '10.8.0.1',
    remoteAddress: '192.168.178.50',
    lanInfo,
  }), false);

  // Connection arrived on LAN interface, but remote IP is outside subnet (e.g. routed from VPN / WAN)
  assert.strictEqual(isAuthorizedLanClient({
    localAddress: '192.168.178.29',
    remoteAddress: '10.8.0.2',
    lanInfo,
  }), false);

  // Tailscale / foreign interface connection
  assert.strictEqual(isAuthorizedLanClient({
    localAddress: '100.64.0.1',
    remoteAddress: '100.64.0.5',
    lanInfo,
  }), false);
});

test('decide: strictly enforces LAN boundary for *.local', () => {
  const lanInfo = { name: 'en0', address: '192.168.1.10', netmask: '255.255.255.0' };
  const isLanClient = ({ localAddress, remoteAddress }) =>
    isAuthorizedLanClient({ localAddress, remoteAddress, lanInfo });

  // 1. Authorized LAN client accessing exposed route -> 200/proxy
  const authorized = decide(ctx({
    host: 'shop.local',
    remoteIsLoopback: false,
    localAddress: '192.168.1.10',
    remoteAddress: '192.168.1.42',
    isLanClient,
    isExposed: () => true,
  }));
  assert.deepStrictEqual(authorized.action, 'proxy');

  // 2. Client connecting over VPN (utun) / Tailscale accessing exposed route -> 404
  const vpnClient = decide(ctx({
    host: 'shop.local',
    remoteIsLoopback: false,
    localAddress: '10.8.0.1',
    remoteAddress: '10.8.0.5',
    isLanClient,
    isExposed: () => true,
  }));
  assert.deepStrictEqual(vpnClient.action, 'reject');
  assert.strictEqual(vpnClient.status, 404);

  // 3. Foreign WAN IP attempting to reach *.local -> 404
  const wanClient = decide(ctx({
    host: 'shop.local',
    remoteIsLoopback: false,
    localAddress: '192.168.1.10',
    remoteAddress: '203.0.113.195',
    isLanClient,
    isExposed: () => true,
  }));
  assert.deepStrictEqual(wanClient.action, 'reject');
  assert.strictEqual(wanClient.status, 404);
});

test('decide: does not accept bare display name for exposure check', () => {
  const lanInfo = { name: 'en0', address: '192.168.1.10', netmask: '255.255.255.0' };
  const isLanClient = ({ localAddress, remoteAddress }) =>
    isAuthorizedLanClient({ localAddress, remoteAddress, lanInfo });

  const route = { name: 'shop', port: 3000, root: '/projects/shop-v2' };
  const exposedCalls = [];
  const res = decide(ctx({
    host: 'shop.local',
    remoteIsLoopback: false,
    localAddress: '192.168.1.10',
    remoteAddress: '192.168.1.42',
    isLanClient,
    route,
    isExposed: (identity) => {
      exposedCalls.push(identity);
      return identity === 'shop'; // Only matches if decide incorrectly falls back to parsed.name
    },
  }));

  assert.deepStrictEqual(res.action, 'reject');
  assert.strictEqual(res.status, 404);
  assert.ok(!exposedCalls.includes('shop'), 'decide() must never pass parsed display name to isExposed');
});

// ---------------------------------------------------------------------------
// connectionPolicyViolation: revocation policy for ALREADY-ESTABLISHED
// long-lived connections (WebSockets, SSE). Pure decision, no sockets.
// ---------------------------------------------------------------------------

const { connectionPolicyViolation } = require('../lib/authorize');

function policyCtx(over = {}) {
  return {
    getRoute: (name) => (name === 'shop'
      ? { name: 'shop', port: 3000, root: '/projects/shop', processKey: '1:a', upstreamHost: '127.0.0.1' }
      : null),
    isExposedIdentity: (identity) => identity === '/projects/shop',
    ...over,
  };
}

const LAN_WS_CONN = {
  name: 'shop',
  identity: '/projects/shop',
  zone: 'wifi',
  loopback: false,
  port: 3000,
  upstreamHost: '127.0.0.1',
  processKey: '1:a',
};

test('connectionPolicyViolation: a matching, exposed LAN connection may stay', () => {
  assert.strictEqual(connectionPolicyViolation(LAN_WS_CONN, policyCtx()), null);
});

test('connectionPolicyViolation: revoked exposure kills only the LAN connection of that project', () => {
  const ctx = policyCtx({ isExposedIdentity: () => false });
  assert.strictEqual(connectionPolicyViolation(LAN_WS_CONN, ctx), 'exposure-revoked');

  // Loopback traffic is never torn down by an exposure change ...
  assert.strictEqual(connectionPolicyViolation({ ...LAN_WS_CONN, loopback: true }, ctx), null);
  // ... and *.localhost connections from loopback neither (different zone).
  assert.strictEqual(connectionPolicyViolation({ ...LAN_WS_CONN, zone: 'local', loopback: true }, policyCtx()), null);
});

test('connectionPolicyViolation: route removal and rename (route-gone) apply to every client', () => {
  const ctx = policyCtx({ getRoute: () => null });
  assert.strictEqual(connectionPolicyViolation(LAN_WS_CONN, ctx), 'route-gone');
  assert.strictEqual(
    connectionPolicyViolation({ ...LAN_WS_CONN, loopback: true }, ctx),
    'route-gone',
    'a loopback browser has no business riding a splice to an unrouted name either'
  );
});

test('connectionPolicyViolation: identity swap behind a name (rename reuse) revokes', () => {
  const ctx = policyCtx({
    getRoute: () => ({ name: 'shop', port: 3000, root: '/projects/other', processKey: '9:z' }),
  });
  assert.strictEqual(connectionPolicyViolation(LAN_WS_CONN, ctx), 'identity-changed');
});

test('connectionPolicyViolation: port, upstream host or process generation change revokes', () => {
  const portChanged = policyCtx({
    getRoute: () => ({ name: 'shop', port: 3001, root: '/projects/shop', processKey: '1:a', upstreamHost: '127.0.0.1' }),
  });
  assert.strictEqual(connectionPolicyViolation(LAN_WS_CONN, portChanged), 'target-changed');

  const hostChanged = policyCtx({
    getRoute: () => ({ name: 'shop', port: 3000, root: '/projects/shop', processKey: '1:a', upstreamHost: '::1' }),
  });
  assert.strictEqual(connectionPolicyViolation(LAN_WS_CONN, hostChanged), 'target-changed');

  const genChanged = policyCtx({
    getRoute: () => ({ name: 'shop', port: 3000, root: '/projects/shop', processKey: '2:b', upstreamHost: '127.0.0.1' }),
  });
  assert.strictEqual(connectionPolicyViolation(LAN_WS_CONN, genChanged), 'target-changed');

  // Manual routes have no processKey — the generation check must not fire.
  const manualRoute = policyCtx({
    getRoute: () => ({ name: 'shop', port: 3000, root: null, processKey: null, upstreamHost: '127.0.0.1' }),
    isExposedIdentity: (identity) => identity === 'manual:shop' || identity === '/projects/shop',
  });
  assert.strictEqual(
    connectionPolicyViolation({ ...LAN_WS_CONN, identity: 'manual:shop', processKey: null }, manualRoute),
    null
  );
});
