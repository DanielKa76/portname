'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  sanitizeName,
  projectRootOf,
  resolveRoutes,
  enrich,
  listenAddressIsExternal,
} = require('../lib/discover');
const { Registry } = require('../lib/registry');

test('sanitizeName keeps only dns-safe characters', () => {
  assert.strictEqual(sanitizeName('Mein Projekt v2!'), 'mein-projekt-v2');
  assert.strictEqual(sanitizeName('---'), 'project');
  assert.strictEqual(sanitizeName('UPPER_case'), 'upper-case');
});

test('projectRootOf walks up to the nearest .git directory', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-root-'));
  fs.mkdirSync(path.join(base, '.git'));
  const deep = path.join(base, 'packages', 'app');
  fs.mkdirSync(deep, { recursive: true });
  assert.strictEqual(projectRootOf(deep, { stopAt: base }), base);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-out-'));
  assert.strictEqual(projectRootOf(outside, { stopAt: base }), outside);
  fs.rmSync(base, { recursive: true, force: true });
  fs.rmSync(outside, { recursive: true, force: true });
});

test('listenAddressIsExternal distinguishes wildcard binds from loopback binds', () => {
  assert.strictEqual(listenAddressIsExternal('*:3000'), true);
  assert.strictEqual(listenAddressIsExternal('192.168.1.7:3000'), true);
  assert.strictEqual(listenAddressIsExternal('127.0.0.1:3000'), false);
  assert.strictEqual(listenAddressIsExternal('[::1]:3000'), false);
});

function listener(pid, port, root, external = false, command = 'node', processKey = null) {
  const pKey = processKey || `${pid}:gen1`;
  return {
    pid,
    port,
    command,
    external,
    cwd: root,
    root,
    processKey: pKey,
    suggestedName: root ? sanitizeName(path.basename(root)) : null,
  };
}

test('resolveRoutes: manual rename beats folder name and cannot be stolen', () => {
  const listeners = [listener(1, 3000, '/p/shop'), listener(2, 8000, '/p/api')];
  const { routes } = resolveRoutes({ listeners, renames: { '/p/api': 'backend' }, names: {} });
  const byName = new Map(routes.map((r) => [r.name, r]));
  assert.strictEqual(byName.get('backend').port, 8000);
  assert.strictEqual(byName.get('shop').port, 3000);
});

test('resolveRoutes: collisions get stable suffixes that persist in the names map', () => {
  const listeners = [listener(1, 3000, '/a/shop'), listener(2, 3001, '/b/shop')];
  const names = {};
  const first = resolveRoutes({ listeners, renames: {}, names });
  assert.deepStrictEqual(first.routes.map((r) => r.name).sort(), ['shop', 'shop-2']);
  assert.ok(names['/a/shop'] && names['/b/shop'], 'assignments persisted');
  assert.strictEqual(first.namesChanged, true);

  // Second scan with reversed listener order must keep the same names.
  const again = resolveRoutes({ listeners: [...listeners].reverse(), renames: {}, names });
  const byRoot = new Map(again.routes.map((r) => [r.root, r.name]));
  assert.strictEqual(byRoot.get('/a/shop'), names['/a/shop']);
  assert.strictEqual(byRoot.get('/b/shop'), names['/b/shop']);
  assert.strictEqual(again.namesChanged, false);
});

test('listener selection: same process auxiliary port does not displace primary port', () => {
  // App starts on 3000 (birth 1000)
  const l1 = listener(10, 3000, '/p/app', false, 'node', '10:T1');
  // Same process opens node inspector on 9229 later (birth 2000)
  const l2 = listener(10, 9229, '/p/app', false, 'node', '10:T1');
  const firstSeen = { '10:T1:3000': 1000, '10:T1:9229': 2000 };

  const { routes, stale } = resolveRoutes({
    listeners: [l1, l2],
    firstSeen,
  });

  assert.strictEqual(routes.length, 1);
  assert.strictEqual(routes[0].port, 3000, 'primary must remain 3000');
  // 9229 here is not detected as an inspector, so it is an additional
  // service of the same generation — never primary, but also not "overhauled".
  const aux = routes[0].services.find((s) => s.port === 9229);
  assert.ok(aux, 'same-generation auxiliary port is listed as an additional service');
  assert.strictEqual(aux.primary, false);
  assert.strictEqual(stale.length, 0, 'same-generation services are not superseded');
});

test('listener selection: new generation takes the name, old distinct-port server stays a service', () => {
  // Old process generation on 3000 (birth 1000)
  const oldProc = listener(10, 3000, '/p/app', false, 'node', '10:T1');
  // New process generation on 3001 (birth 5000)
  const newProc = listener(20, 3001, '/p/app', false, 'node', '20:T2');
  const firstSeen = { '10:T1:3000': 1000, '20:T2:3001': 5000 };

  const { routes, stale } = resolveRoutes({
    listeners: [oldProc, newProc],
    firstSeen,
  });

  assert.strictEqual(routes.length, 1);
  assert.strictEqual(routes[0].port, 3001, 'new process generation on 3001 must win the name');
  assert.strictEqual(stale.length, 0,
    'a different port is a different role: the old server is not "replaced"');
  const old = routes[0].services.find((s) => s.port === 3000);
  assert.ok(old, 'the other generation\'s distinct-port listener stays a visible service');
  assert.strictEqual(old.crossGeneration, true);
  assert.strictEqual(old.primary, false);
  assert.strictEqual(old.serviceId, '/p/app#3000');
  assert.strictEqual(routes[0].services[0].crossGeneration, false, 'primary belongs to the winning generation');
});

test('listener selection: same port in another living generation is genuinely replaced', () => {
  // Cluster-style: two living generations serve the SAME role (port).
  const workerA = listener(10, 3000, '/p/app', false, 'node', '10:T1');
  const workerB = listener(20, 3000, '/p/app', false, 'node', '20:T2');
  const firstSeen = { '10:T1:3000': 1000, '20:T2:3000': 5000 };

  const { routes, stale } = resolveRoutes({ listeners: [workerA, workerB], firstSeen });

  assert.strictEqual(routes.length, 1);
  assert.strictEqual(routes[0].port, 3000);
  assert.strictEqual(routes[0].services.length, 1, 'one role, one service entry');
  assert.strictEqual(routes[0].services[0].pid, 20, 'the newer generation fulfills the role');
  assert.strictEqual(stale.length, 1);
  assert.strictEqual(stale[0].port, 3000, 'the same-port loser of the role is superseded');
  assert.strictEqual(stale[0].serviceId, '/p/app#3000', 'stale carries the same role identity');
});

test('listener selection: inspector-only listener is never auto-promoted to primary', () => {
  const inspectorOnly = listener(10, 9229, '/p/debug', false, 'node', '10:T1');
  inspectorOnly.isInspector = true;
  const { routes, stale } = resolveRoutes({
    listeners: [inspectorOnly],
  });

  assert.strictEqual(routes.length, 0, 'no automatic primary route for inspector-only process');
  assert.strictEqual(stale.length, 1);
  assert.strictEqual(stale[0].port, 9229);
});

test('PID reuse: different process generation bypasses cwdCache', () => {
  const cwdCache = new Map();
  cwdCache.set('999:gen1', '/old/path');

  let cwdLookupCount = 0;
  // Simulated enrich with injected start time getter
  const l = { pid: 999, port: 3000, command: 'node', external: false };
  const enriched = enrich([l], cwdCache, {
    getStartTime: () => 'gen2', // PID reused, new generation!
  });

  // cwdCache should have keyed by '999:gen2', not reusing '/old/path'
  assert.notStrictEqual(enriched[0].processKey, '999:gen1');
  assert.strictEqual(enriched[0].processKey, '999:gen2');
});

test('name ownership: manual registration cannot steal live auto route and vice versa', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-reg-names-'));
  const reg = new Registry(dir);

  // 1. Auto route "shop" is live -> manual add of "shop" must be refused
  const addClash = reg.addManual('shop', 4000, { liveAutoNames: new Set(['shop']) });
  assert.strictEqual(addClash.ok, false);
  assert.match(addClash.reason, /already used by an automatically discovered project/);

  // 2. Manual route "shop" exists -> auto-discovery of a folder named "shop" must get a stable suffixed name (shop-2)
  reg.addManual('shop', 4000);
  const listeners = [listener(1, 3000, '/p/shop')];
  const { routes } = resolveRoutes({
    listeners,
    manualNames: new Set(['shop']),
  });

  assert.strictEqual(routes.length, 1);
  assert.strictEqual(routes[0].name, 'shop-2', 'auto-discovered project must not steal manual shop name');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('Registry: DNS name validation enforces syntax on rename and add', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-reg-val-'));
  const reg = new Registry(dir);

  assert.strictEqual(reg.rename('/p/app', '-invalid').ok, false);
  assert.strictEqual(reg.rename('/p/app', 'invalid-').ok, false);
  assert.strictEqual(reg.rename('/p/app', 'foo.bar').ok, false);
  assert.strictEqual(reg.rename('/p/app', 'valid-name').ok, true);

  assert.strictEqual(reg.addManual('foo.bar', 3000).ok, false);
  assert.strictEqual(reg.addManual('invalid-', 3000).ok, false);
  assert.strictEqual(reg.addManual('good-name', 3000).ok, true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('Registry persists exposed flags and births across instances', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-reg-'));
  const reg = new Registry(dir);
  reg.setExposed('/p/shop', true);
  reg.observe([{ pid: 5, port: 1234, processKey: '5:T1' }], 12345);
  const reg2 = new Registry(dir);
  assert.strictEqual(reg2.isExposed('/p/shop'), true);
  assert.strictEqual(reg2.firstSeen['5:T1:1234'], 12345);
  fs.rmSync(dir, { recursive: true, force: true });
});

const http = require('http');
const { probeIsInspector, probeDebugEndpoint, detectInspectors } = require('../lib/discover');
const { validateName } = require('../lib/naming');

test('dynamic inspector detection: probes /json/version and never selects random inspector port as primary', async () => {
  // 1. Mock inspector server on dynamic port
  const inspServer = http.createServer((req, res) => {
    if (req.url === '/json/version') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ Browser: 'node.js/v26.8.1', 'Protocol-Version': '1.1' }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  // 2. Normal HTTP web server
  const webServer = http.createServer((req, res) => {
    res.writeHead(200);
    res.end('web app');
  });

  await new Promise((r) => inspServer.listen(0, '127.0.0.1', r));
  await new Promise((r) => webServer.listen(0, '127.0.0.1', r));

  const inspPort = inspServer.address().port;
  const webPort = webServer.address().port;

  // The production probe budget is 200ms; under full-suite load a local
  // answer can take longer, so the test grants the probe more time. The
  // verdicts under test are the same.
  const probe = (port, host = '127.0.0.1') => probeDebugEndpoint(port, host, 5000);
  try {
    assert.strictEqual(await probeIsInspector(inspPort, '127.0.0.1', 5000), true);
    assert.strictEqual(await probeIsInspector(webPort, '127.0.0.1', 5000), false);

    const listeners = [
      listener(10, inspPort, '/p/app', false, 'node', '10:T1'),
      listener(10, webPort, '/p/app', false, 'node', '10:T1'),
    ];

    // Detect inspector dynamically
    await detectInspectors(listeners, new Map(), { probe });
    assert.strictEqual(listeners[0].isInspector, true);
    assert.strictEqual(listeners[1].isInspector, undefined);

    // Inspector was observed earlier than webPort (birth 1000 vs 2000)
    const firstSeen = {
      [`10:T1:${inspPort}`]: 1000,
      [`10:T1:${webPort}`]: 2000,
    };

    const { routes, stale } = resolveRoutes({ listeners, firstSeen });
    assert.strictEqual(routes.length, 1);
    assert.strictEqual(routes[0].port, webPort, 'web port must be primary despite inspector port opening first');
    assert.strictEqual(stale.length, 1);
    assert.strictEqual(stale[0].port, inspPort, 'dynamic inspector port must be marked stale');
  } finally {
    inspServer.close();
    webServer.close();
  }
});

test('auto-suffix: bounds base name so that collision suffix never exceeds 63 characters', () => {
  const longName = 'a'.repeat(63);
  const l1 = listener(1, 3000, `/p/${longName}`);
  const l2 = listener(2, 4000, `/other/${longName}`);

  const { routes } = resolveRoutes({
    listeners: [l1, l2],
    renames: {},
    names: {},
  });

  const names = routes.map((r) => r.name);
  assert.strictEqual(names.length, 2);
  assert.ok(names.includes('a'.repeat(63)));
  assert.ok(names.includes('a'.repeat(61) + '-2'));
  for (const name of names) {
    assert.strictEqual(name.length, 63);
    assert.strictEqual(validateName(name).ok, true, 'suffixed name must be valid RFC 1035 DNS label');
  }
});

test('IPv6 upstream: listener with [::1] loopback preserves upstreamHost', () => {
  const l = {
    pid: 1,
    port: 3000,
    command: 'node',
    root: '/p/app',
    suggestedName: 'app',
    processKey: '1:T1',
    external: false,
    upstreamHost: '::1',
  };

  const { routes } = resolveRoutes({ listeners: [l] });
  assert.strictEqual(routes.length, 1);
  assert.strictEqual(routes[0].upstreamHost, '::1');
});

test('resolveRoutes: stopped inactive project reserves name in config.names against newcomer', () => {
  // App1 is stopped and not in listeners, but has persistent name "my-tool" in config.names
  const names = {
    '/p/stopped-app': 'my-tool',
  };
  const renames = {
    '/p/renamed-app': 'custom-name',
  };

  // Newcomer App2 has folder name "my-tool"
  const l2 = listener(2, 4000, '/p/new-app-my-tool', false, 'node', '2:T1');
  l2.suggestedName = 'my-tool';

  // Newcomer App3 has folder name "custom-name"
  const l3 = listener(3, 5000, '/p/new-app-custom', false, 'node', '3:T1');
  l3.suggestedName = 'custom-name';

  const { routes } = resolveRoutes({
    listeners: [l2, l3],
    names,
    renames,
  });

  const route2 = routes.find((r) => r.root === '/p/new-app-my-tool');
  const route3 = routes.find((r) => r.root === '/p/new-app-custom');

  assert.strictEqual(route2.name, 'my-tool-2', 'newcomer must not steal reserved name of stopped project');
  assert.strictEqual(route3.name, 'custom-name-2', 'newcomer must not steal reserved rename of stopped project');
});

test('detectInspectors: inspectorCache avoids redundant probes across discovery passes', async () => {
  let probeCount = 0;
  const inspServer = http.createServer((req, res) => {
    probeCount++;
    if (req.url === '/json/version') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ Browser: 'node.js/v26.8.1', 'Protocol-Version': '1.1' }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  await new Promise((r) => inspServer.listen(0, '127.0.0.1', r));
  const inspPort = inspServer.address().port;

  const inspectorCache = new Map();
  try {
    const listeners1 = [listener(10, inspPort, '/p/app', false, 'node', '10:gen1')];
    await detectInspectors(listeners1, inspectorCache);
    assert.strictEqual(listeners1[0].isInspector, true);
    assert.strictEqual(probeCount, 1);

    // Shut down inspector server: any future HTTP request will fail with ECONNREFUSED
    inspServer.close();

    // Pass 2 with same processKey and port: must hit inspectorCache without making HTTP probe!
    const listeners2 = [listener(10, inspPort, '/p/app', false, 'node', '10:gen1')];
    await detectInspectors(listeners2, inspectorCache);
    assert.strictEqual(listeners2[0].isInspector, true, 'must be served from inspectorCache');
    assert.strictEqual(probeCount, 1, 'HTTP probe count must not increase');
  } finally {
    inspServer.close();
  }
});

test('detectInspectors: non-node service on 9229 or regular service is NOT marked as inspector', async () => {
  const pythonOn9229 = listener(101, 9229, '/p/py', false, 'python3', '101:gen1');
  const goOn9222 = listener(102, 9222, '/p/go', false, 'go', '102:gen1');
  const nodeRegular = listener(103, 9229, '/p/node', false, 'node', '103:gen1');

  await detectInspectors([pythonOn9229, goOn9222, nodeRegular]);

  assert.strictEqual(pythonOn9229.isInspector, undefined, 'Python on 9229 must not be marked as inspector');
  assert.strictEqual(goOn9222.isInspector, undefined, 'Go on 9222 must not be marked as inspector');
  assert.strictEqual(nodeRegular.isInspector, undefined, 'Node on 9229 without flags or probe must not be marked as inspector');
});

test('Registry: sanitizes legacy display name exposures fail-closed or migrates unambiguous matches', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-reg-mig-'));
  const configFile = path.join(dir, 'config.json');

  // Write legacy config with display-name keys
  const legacyConfig = {
    names: { '/projects/shop': 'shop' },
    manual: { db: 5432 },
    renames: {},
    exposed: {
      shop: true,       // unambiguous match in names -> should migrate to /projects/shop
      db: true,         // unambiguous match in manual -> should migrate to manual:db
      unknown: true,    // cannot be matched -> must be discarded fail-closed
      '/good/root': true // already valid project identity -> stays intact
    },
  };
  fs.writeFileSync(configFile, JSON.stringify(legacyConfig, null, 2));

  const reg = new Registry(dir);

  assert.strictEqual(reg.isExposed('/projects/shop'), true, 'unambiguous auto root migrated');
  assert.strictEqual(reg.isExposed('manual:db'), true, 'unambiguous manual entry migrated');
  assert.strictEqual(reg.isExposed('/good/root'), true, 'valid identity preserved');
  assert.strictEqual(reg.isExposed('unknown'), false, 'unknown display name discarded');
  assert.strictEqual(reg.isExposed('shop'), false, 'display name key removed');

  fs.rmSync(dir, { recursive: true, force: true });
});
