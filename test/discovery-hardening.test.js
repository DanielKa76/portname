'use strict';

// Discovery hardening regressions:
//   - subprocesses that ignore SIGTERM or never close their pipes cannot
//     wedge a scan pass (SIGKILL escalation + promise-level settle);
//   - process identity (ps lstart) does not depend on locale or time zone,
//     and a live daemon is never robbed of its lock;
//   - start times are looked up in one batched ps, cached across passes, and
//     a failed lookup never publishes a `<pid>:unknown` generation;
//   - debug endpoints of every runtime are recognised (flags + /json/version)
//     and never win a route — including Firefox's BiDi-only Remote Agent and
//     debugpy's DAP adapter, which only their command lines give away —,
//     WebDriver servers are never auto-discovered, and a stable process is
//     probed once, not every few seconds;
//   - '/' and $HOME are never project identities;
//   - non-ASCII project paths resolve the same under launchd (no LANG) as in
//     a UTF-8 terminal (lsof locale + escape decoding);
//   - a dns-sd child that exits at once (name conflict) is retried with a
//     backoff, and (re-)registering N names costs no synchronous ps;
//   - taking over a stale instance lock is atomic: never two holders, never
//     a half-written claim stolen;
//
// All servers bind port 0, all state lives in temp dirs, and PATH shims are
// restored after every test (tests within one file run sequentially).

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');
const { EventEmitter } = require('events');

const net = require('net');

const http = require('http');

const {
  listListenersAsync,
  enrichAsync,
  detectInspectors,
  debugEndpointsFromArgs,
  probeDebugEndpoint,
  resolveRoutes,
  ignoredCommandsFilter,
  projectRootOf,
  cwdOfAsync,
  decodeLsofName,
} = require('../lib/discover');
const {
  getProcessStartTime,
  getProcessStartTimeAsync,
  getProcessStartTimesAsync,
  getProcessArgsAsync,
  runBounded,
} = require('../lib/process');
const { acquireInstanceLock } = require('../lib/instance-lock');
const { BonjourAnnouncer } = require('../lib/expose');
const { Daemon } = require('../lib/daemon');
const { Registry } = require('../lib/registry');

const PROCESS_JS = path.resolve(__dirname, '../lib/process.js');
const INSTANCE_LOCK_JS = path.resolve(__dirname, '../lib/instance-lock.js');

// Runs a node snippet in a child with extra env vars; resolves to stdout.
function runNode(code, env) {
  return new Promise((resolve, reject) => {
    childProcess.execFile(process.execPath, ['-e', code], {
      env: { ...process.env, ...env },
      timeout: 20000,
    }, (err, stdout, stderr) => {
      if (err) reject(new Error(`${err.message}\n${stderr}`));
      else resolve(stdout.trim());
    });
  });
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Puts an executable `name` with `script` first on PATH; returns a restore fn.
function withShim(name, script) {
  const shimDir = tmpDir(`pn-shim-${name}-`);
  const shim = path.join(shimDir, name);
  fs.writeFileSync(shim, script);
  fs.chmodSync(shim, 0o755);
  const previousPath = process.env.PATH;
  process.env.PATH = `${shimDir}:${previousPath}`;
  return function restore() {
    process.env.PATH = previousPath;
    fs.rmSync(shimDir, { recursive: true, force: true });
  };
}

// Resolves to 'settled' (with the outcome) or 'hung' after `ms`.
async function settlesWithin(promise, ms) {
  let timer;
  const outcome = promise.then((value) => ({ value }), (error) => ({ error }));
  const hung = new Promise((r) => { timer = setTimeout(() => r('hung'), ms); });
  const result = await Promise.race([outcome, hung]);
  clearTimeout(timer);
  return result;
}

// -- wedged subprocesses ------------------------------------------------------

test('listListenersAsync: an lsof that ignores SIGTERM is SIGKILLed and the scan rejects in bounded time', async () => {
  const restore = withShim('lsof', "#!/bin/sh\ntrap '' TERM\nexec sleep 6\n");
  try {
    const started = Date.now();
    // The SIGTERM must arrive after the shim's `trap` ran. With 300ms a
    // shell start under full-suite load on macOS lost that race, and the
    // shim died of the SIGTERM it was meant to ignore. 1000ms leaves the
    // kill at 1500ms and the settle at 2000ms, both well before `sleep 6`.
    const result = await settlesWithin(listListenersAsync({ timeoutMs: 1000 }), 5000);
    assert.notStrictEqual(result, 'hung', 'a SIGTERM-ignoring lsof must not wedge the scan');
    assert.ok(result.error, 'a killed scan is an error, never a snapshot');
    assert.match(result.error.message, /listener scan failed/);
    assert.match(result.error.message, /SIGKILL/);
    assert.ok(Date.now() - started < 4000, `settled after ${Date.now() - started}ms`);
  } finally {
    restore();
  }
});

test('listListenersAsync: a grandchild holding stdout open cannot keep the scan pending', async () => {
  // The shim itself dies on SIGKILL, but a background child keeps the pipe
  // open — execFile alone would wait for that pipe to close.
  const restore = withShim('lsof', "#!/bin/sh\ntrap '' TERM\nsleep 6 &\nexec sleep 6\n");
  try {
    const result = await settlesWithin(listListenersAsync({ timeoutMs: 300 }), 3000);
    assert.notStrictEqual(result, 'hung', 'an inherited pipe must not wedge the scan');
    assert.match(result.error.message, /listener scan failed/);
  } finally {
    restore();
  }
});

test('Daemon: a wedged lsof degrades the pass instead of stalling the refresh chain', async () => {
  const dir = tmpDir('pn-hard-wedge-');
  let restore = null;
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
    refreshMs: 3_600_000, // only explicit refresh() calls
    listListeners: async () => [],
  });
  try {
    await daemon.start();
    restore = withShim('lsof', "#!/bin/sh\ntrap '' TERM\nexec sleep 6\n");
    daemon.listListeners = (opts) => listListenersAsync({ ...opts, timeoutMs: 300 });
    const result = await settlesWithin(daemon.refresh(), 3000);
    assert.notStrictEqual(result, 'hung', 'refresh() must settle while lsof ignores SIGTERM');
    assert.match(String(daemon.lastScanError), /listener scan failed/,
      'the wedged scan must surface as a degraded pass');
  } finally {
    if (restore) restore();
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('getProcessStartTime: a ps that ignores SIGTERM cannot block the caller past its timeout', () => {
  const restore = withShim('ps', "#!/bin/sh\ntrap '' TERM\nexec sleep 7\n");
  try {
    const started = Date.now();
    assert.strictEqual(getProcessStartTime(process.pid), null);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 5000, `sync ps must be SIGKILLed at its timeout (blocked ${elapsed}ms)`);
  } finally {
    restore();
  }
});

test('runBounded: children that survive SIGKILL are abandoned, and further runs fail fast', async () => {
  const realExecFile = childProcess.execFile;
  const fakes = [];
  let spawned = 0;
  childProcess.execFile = () => {
    spawned += 1;
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    child.kill = () => true; // uninterruptible: the signal never takes effect
    child.unref = () => {};
    fakes.push(child);
    return child;
  };
  try {
    for (let i = 0; i < 2; i += 1) {
      await assert.rejects(
        () => runBounded('wedgecmd', [], { timeoutMs: 20, killGraceMs: 20 }),
        (err) => err.killed === true && err.code === 'ETIMEDOUT'
      );
    }
    assert.strictEqual(spawned, 2);
    await assert.rejects(
      () => runBounded('wedgecmd', [], { timeoutMs: 20, killGraceMs: 20 }),
      (err) => err.code === 'ESUBPROCESSWEDGED'
    );
    assert.strictEqual(spawned, 2, 'no further process may be started while two are wedged');

    // Once a wedged child finally exits, the command may run again.
    fakes[0].exitCode = 0;
    fakes[0].emit('exit', 0, null);
    await assert.rejects(
      () => runBounded('wedgecmd', [], { timeoutMs: 20, killGraceMs: 20 }),
      (err) => err.code === 'ETIMEDOUT'
    );
    assert.strictEqual(spawned, 3);
  } finally {
    childProcess.execFile = realExecFile;
    for (const child of fakes) {
      child.exitCode = 0;
      child.emit('exit', 0, null);
    }
  }
});

// -- locale/time-zone independent process identity ----------------------------

test('getProcessStartTime: the identity string is the same in every time zone and locale', async () => {
  const code = `console.log(require(${JSON.stringify(PROCESS_JS)}).getProcessStartTime(${process.pid}))`;
  const tokyo = await runNode(code, { TZ: 'Asia/Tokyo', LANG: 'de_DE.UTF-8', LC_ALL: '' });
  const losAngeles = await runNode(code, { TZ: 'America/Los_Angeles', LC_ALL: 'C.UTF-8' });
  const here = getProcessStartTime(process.pid);
  assert.ok(here, 'own start time must be readable');
  assert.strictEqual(tokyo, here, 'Asia/Tokyo caller must see the same identity');
  assert.strictEqual(losAngeles, here, 'America/Los_Angeles caller must see the same identity');
});

test('instance lock: a contender in another time zone cannot steal the lock of a live owner', async () => {
  const dir = tmpDir('pn-hard-lock-tz-');
  const lock = await acquireInstanceLock({ dir, instanceId: 'owner-utc' });
  try {
    const code = `
      require(${JSON.stringify(INSTANCE_LOCK_JS)})
        .acquireInstanceLock({ dir: ${JSON.stringify(dir)}, instanceId: 'contender-tokyo' })
        .then(() => console.log('ACQUIRED'), (err) => console.log(err.code || err.message));
    `;
    const outcome = await runNode(code, { TZ: 'Asia/Tokyo', LANG: 'de_DE.UTF-8' });
    assert.strictEqual(outcome, 'DAEMON_ALREADY_RUNNING');
    const record = JSON.parse(fs.readFileSync(path.join(dir, 'daemon.lock'), 'utf8'));
    assert.strictEqual(record.instanceId, 'owner-utc', 'the live owner keeps its claim');
  } finally {
    lock.release();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('instance lock: an incomparable record of a daemon that still serves the control socket is not stolen', async () => {
  const dir = tmpDir('pn-hard-lock-sock-');
  const lockFile = path.join(dir, 'daemon.lock');
  // A live owner whose record was written in another locale (older version).
  fs.writeFileSync(lockFile, JSON.stringify({
    pid: process.pid, startTime: 'Sa 31 Okt 07:10:19 2026', instanceId: 'live-old-format',
  }));
  const server = net.createServer((c) => c.destroy());
  try {
    await new Promise((r) => server.listen(path.join(dir, 'daemon.sock'), r));
    try {
      await assert.rejects(
        () => acquireInstanceLock({ dir, instanceId: 'new' }),
        (err) => err.code === 'DAEMON_ALREADY_RUNNING'
      );
      assert.strictEqual(JSON.parse(fs.readFileSync(lockFile, 'utf8')).instanceId, 'live-old-format');
    } finally {
      await new Promise((r) => server.close(r));
    }

    // Without anything serving the socket the mismatch is PID reuse: stolen.
    fs.rmSync(path.join(dir, 'daemon.sock'), { force: true });
    fs.writeFileSync(path.join(dir, 'daemon.sock'), ''); // stale leftover, not a socket
    const lock = await acquireInstanceLock({ dir, instanceId: 'new' });
    assert.strictEqual(lock.instanceId, 'new');
    lock.release();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// -- batched start times, read in every pass ------------------------------------

const REAL_PS = childProcess.execFileSync('sh', ['-c', 'command -v ps'], { encoding: 'utf8' }).trim();

// A `ps` shim that records every invocation and then runs the real ps.
function withCountingPs() {
  const logFile = path.join(tmpDir('pn-ps-log-'), 'calls');
  fs.writeFileSync(logFile, '');
  const restore = withShim('ps', `#!/bin/sh\necho "$*" >> '${logFile}'\nexec '${REAL_PS}' "$@"\n`);
  return {
    calls: () => fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean),
    restore() {
      restore();
      fs.rmSync(path.dirname(logFile), { recursive: true, force: true });
    },
  };
}

function spawnSleepers(n) {
  return Array.from({ length: n }, () => childProcess.spawn('sleep', ['30'], { stdio: 'ignore' }));
}

test('enrichAsync: start times of many pids cost one ps per pass, in every pass', async () => {
  const sleepers = spawnSleepers(5);
  const counting = withCountingPs();
  try {
    const listeners = sleepers.map((c, i) => ({ pid: c.pid, port: 41000 + i, command: 'sleep', cwd: '/tmp' }));
    const cwdCache = new Map();
    const first = await enrichAsync(listeners, cwdCache);
    assert.strictEqual(counting.calls().length, 1, `one batched ps for 5 pids (saw ${counting.calls().length})`);
    for (const l of first) {
      assert.strictEqual(l.processKey, `${l.pid}:${getProcessStartTime(l.pid)}`,
        'batched identities equal the single-pid lookup');
    }
    const before = counting.calls().length;
    const second = await enrichAsync(listeners, cwdCache);
    assert.strictEqual(counting.calls().length, before + 1, 'the next pass re-reads every generation, again in one ps');
    assert.deepStrictEqual(second.map((l) => l.processKey), first.map((l) => l.processKey));
  } finally {
    counting.restore();
    for (const c of sleepers) c.kill('SIGKILL');
  }
});

test('getProcessStartTimeAsync: concurrent single-pid lookups are coalesced into one ps', async () => {
  const sleepers = spawnSleepers(4);
  const counting = withCountingPs();
  try {
    const times = await Promise.all(sleepers.map((c) => getProcessStartTimeAsync(c.pid)));
    assert.strictEqual(counting.calls().length, 1, `one ps for 4 lookups (saw ${counting.calls().length})`);
    sleepers.forEach((c, i) => assert.strictEqual(times[i], getProcessStartTime(c.pid)));
    // A pid in the valid range whose process has already exited: macOS ps
    // refuses pids above PID_MAX (99999) as a usage error, which lsof can
    // never report anyway.
    const gonePid = childProcess.spawnSync(process.execPath, ['-e', '0']).pid;
    const batch = await getProcessStartTimesAsync([...sleepers.map((c) => c.pid), gonePid]);
    assert.strictEqual(batch.size, 4, 'a pid that does not exist is simply missing from the batch');
  } finally {
    counting.restore();
    for (const c of sleepers) c.kill('SIGKILL');
  }
});

// A process that takes over the pid AND the port between two passes is a new
// generation, even right after the previous pass verified the old one: a
// cached identity let it inherit the old cwd, root and share binding.
test('enrichAsync: a new process on the same pid and port is a new generation in the very next pass', async () => {
  const projectA = tmpDir('pn-gen-a-');
  const projectB = tmpDir('pn-gen-b-');
  try {
    let generation = 'T1';
    let lookups = 0;
    const opts = {
      getStartTime: async () => { lookups += 1; return generation; },
      cwdOf: async () => (generation === 'T1' ? projectA : projectB),
    };
    const cwdCache = new Map();
    const listener = () => [{ pid: process.pid, port: 3000, command: 'node' }];
    const first = await enrichAsync(listener(), cwdCache, { ...opts, now: 1_000_000 });
    generation = 'T2';
    const second = await enrichAsync(listener(), cwdCache, { ...opts, now: 1_003_000 });

    assert.strictEqual(lookups, 2, 'both passes read the start time');
    assert.strictEqual(first[0].processKey, `${process.pid}:T1`);
    assert.strictEqual(second[0].processKey, `${process.pid}:T2`);
    assert.strictEqual(second[0].cwd, projectB, 'the new generation gets its own cwd, not the cached one');
  } finally {
    fs.rmSync(projectA, { recursive: true, force: true });
    fs.rmSync(projectB, { recursive: true, force: true });
  }
});

// A start time that cannot be read is never covered by an earlier success:
// the pass fails, so the daemon verifies nothing with it.
test('enrichAsync: a failed lookup of a live pid fails the pass, also right after a successful one', async () => {
  let fail = false;
  const opts = {
    getStartTime: async () => (fail ? null : 'T1'),
    cwdOf: async () => '/tmp',
  };
  const cwdCache = new Map();
  const listener = () => [{ pid: process.pid, port: 3000, command: 'node' }];
  const first = await enrichAsync(listener(), cwdCache, { ...opts, now: 1_000_000 });
  assert.strictEqual(first[0].processKey, `${process.pid}:T1`);
  fail = true;
  await assert.rejects(
    () => enrichAsync(listener(), cwdCache, { ...opts, now: 1_003_000 }),
    (err) => err.code === 'START_TIME_LOOKUP_FAILED' && err.pids.includes(process.pid)
  );
});

test('enrichAsync: a live pid without a known identity fails the enrichment; a gone pid is dropped', async () => {
  await assert.rejects(
    () => enrichAsync([{ pid: process.pid, port: 3000, command: 'node', cwd: '/tmp' }], new Map(), {
      getStartTime: async () => null,
    }),
    (err) => err.code === 'START_TIME_LOOKUP_FAILED' && /start time lookup failed/.test(err.message)
  );

  const dead = childProcess.spawn(process.execPath, ['-e', 'process.exit(0)']);
  await new Promise((r) => dead.once('exit', r));
  const enriched = await enrichAsync([
    { pid: dead.pid, port: 3001, command: 'node', cwd: '/tmp' },
    { pid: process.pid, port: 3002, command: 'node', cwd: '/tmp' },
  ], new Map(), {
    getStartTime: async (pid) => (pid === dead.pid ? null : 'T1'),
  });
  assert.deepStrictEqual(enriched.map((l) => l.processKey), [`${process.pid}:T1`],
    'the exited process vanishes instead of becoming <pid>:unknown');
});

test('Daemon: a failed start-time lookup degrades the pass instead of publishing <pid>:unknown', async () => {
  const dir = tmpDir('pn-hard-starttime-');
  const shopDir = path.join(dir, 'shop');
  const apiDir = path.join(dir, 'api');
  fs.mkdirSync(shopDir);
  fs.mkdirSync(apiDir);
  const sleeper = childProcess.spawn('sleep', ['30'], { stdio: 'ignore' });
  const shop = { pid: process.pid, port: 3000, command: 'node', cwd: shopDir, external: false };
  const api = { pid: sleeper.pid, port: 3001, command: 'node', cwd: apiDir, external: false };
  let listeners = [shop];
  let failApi = true;
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
    refreshMs: 3_600_000,
    listListeners: async () => listeners,
    getStartTime: async (pid) => (pid === sleeper.pid && failApi ? null : `T${pid}`),
  });
  try {
    await daemon.start();
    const shopKey = daemon.routesByName.get('shop').processKey;
    assert.strictEqual(shopKey, `${process.pid}:T${process.pid}`);

    listeners = [shop, api];
    await daemon.refresh();
    assert.match(String(daemon.lastScanError), /start time lookup failed/,
      'an unresolvable live pid degrades the pass');
    assert.strictEqual(daemon.routesByName.has('api'), false, 'nothing is published for it');
    assert.strictEqual(daemon.routesByName.get('shop').processKey, shopKey, 'existing generations are untouched');
    assert.ok(!Object.keys(daemon.registry.firstSeen).some((k) => k.includes(':unknown')),
      'no :unknown generation may reach firstSeen');

    failApi = false;
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, null);
    assert.strictEqual(daemon.routesByName.get('api').processKey, `${sleeper.pid}:T${sleeper.pid}`);
  } finally {
    await daemon.stop();
    sleeper.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// -- debug endpoints: detection and probe frequency ---------------------------

const CHROME_VERSION = {
  Browser: 'Chrome/130.0.6723.58',
  'Protocol-Version': '1.3',
  'User-Agent': 'Mozilla/5.0 HeadlessChrome/130.0.6723.58',
  'V8-Version': '13.0.245.16',
  'WebKit-Version': '537.36',
  webSocketDebuggerUrl: 'ws://localhost:9222/devtools/browser/abc',
};
const DENO_VERSION = { Browser: 'Deno/2.0.0', 'Protocol-Version': '1.3', 'V8-Version': '12.9.202.13' };

// HTTP server on port 0; `handler` defaults to a counted 404. Returns
// { port, requests(), close() }.
async function startServer(handler) {
  let requests = 0;
  const server = http.createServer((req, res) => {
    requests += 1;
    if (handler) return handler(req, res);
    res.writeHead(404);
    res.end('not found');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: server.address().port,
    requests: () => requests,
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
  };
}

function versionServer(doc) {
  return startServer((req, res) => {
    if (req.url === '/json/version') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(doc));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
}

function devServer() {
  return startServer((req, res) => res.end('shop dev server'));
}

function auto(pid, port, root, command, processKey) {
  return {
    pid, port, command, processKey, external: false, cwd: root, root,
    suggestedName: path.basename(root),
  };
}

test('detectInspectors: DevTools endpoints of non-node runtimes are recognised by their /json/version', async () => {
  const chrome = await versionServer(CHROME_VERSION);
  const deno = await versionServer(DENO_VERSION);
  try {
    const listeners = [
      auto(51, chrome.port, '/p/shop', 'Google Chrome fo', '51:A'),
      auto(52, deno.port, '/p/shop', 'deno', '52:A'),
    ];
    await detectInspectors(listeners, new Map(), { getArgs: async () => '' });
    assert.strictEqual(listeners[0].isInspector, true, 'Chrome DevTools endpoint');
    assert.strictEqual(listeners[1].isInspector, true, 'Deno inspector');
  } finally {
    await chrome.close();
    await deno.close();
  }
});

test('detectInspectors: debug flags mark the port for every runtime, without a probe', async () => {
  const args = {
    61: '/opt/chrome/chrome --headless=new --remote-debugging-port=9333 about:blank',
    62: 'deno run --inspect-wait --allow-net main.ts',
    63: 'bun --inspect=127.0.0.1:6499 server.ts',
  };
  let probes = 0;
  const listeners = [
    auto(61, 9333, '/p/e2e', 'chrome', '61:A'),
    auto(62, 9229, '/p/api', 'deno', '62:A'),
    auto(62, 8000, '/p/api', 'deno', '62:A'),
    auto(63, 6499, '/p/web', 'bun', '63:A'),
  ];
  await detectInspectors(listeners, new Map(), {
    getArgs: async (pid) => args[pid],
    probe: async () => { probes += 1; return 'negative'; },
  });
  assert.deepStrictEqual(listeners.map((l) => l.isInspector), [true, true, undefined, true]);
  assert.strictEqual(probes, 1, 'only the unflagged deno port needs a probe');

  // deno --inspect-wait opens the inspector before the server: within that
  // one generation the inspector must still never become primary.
  const firstSeen = { '62:A:9229': 1000, '62:A:8000': 2000 };
  const { routes } = resolveRoutes({ listeners: listeners.filter((l) => l.pid === 62), firstSeen });
  assert.strictEqual(routes.length, 1);
  assert.strictEqual(routes[0].port, 8000);
});

test('resolveRoutes: a newer generation consisting only of a DevTools endpoint never takes the route', async () => {
  const dev = await devServer();
  const chrome = await versionServer(CHROME_VERSION);
  try {
    // Chrome started from the project tree with --remote-debugging-port=0:
    // the port is not in its args, only the probe can tell.
    const listeners = [
      auto(71, dev.port, '/p/shop', 'node', '71:A'),
      auto(72, chrome.port, '/p/shop', 'chrome', '72:B'),
    ];
    await detectInspectors(listeners, new Map(), { getArgs: async () => '' });
    const firstSeen = { [`71:A:${dev.port}`]: 1000, [`72:B:${chrome.port}`]: 5000 };
    const { routes, stale } = resolveRoutes({ listeners, firstSeen });
    assert.strictEqual(routes.length, 1);
    assert.strictEqual(routes[0].port, dev.port, 'the dev server keeps the route');
    assert.ok(!routes[0].services.some((svc) => svc.port === chrome.port), 'the debug endpoint is no service');
    assert.ok(stale.some((l) => l.port === chrome.port), 'it is listed as diagnostic-only');
  } finally {
    await dev.close();
    await chrome.close();
  }
});

test('Daemon: a DevTools endpoint started later in the project tree does not take over the route', async () => {
  const dir = tmpDir('pn-hard-cdp-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const dev = await devServer();
  const chrome = await versionServer(CHROME_VERSION);
  let listeners = [auto(2 ** 22 + 101, dev.port, shopDir, 'node', 'dev:A')];
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
    refreshMs: 3_600_000,
    listListeners: async () => listeners,
  });
  try {
    await daemon.start();
    assert.strictEqual(daemon.routesByName.get('shop').port, dev.port);
    listeners = [...listeners, auto(2 ** 22 + 102, chrome.port, shopDir, 'Google Chrome fo', 'chrome:B')];
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, null);
    const route = daemon.routesByName.get('shop');
    assert.strictEqual(route.port, dev.port, 'the newest listener must not win when it is a debug endpoint');
    assert.strictEqual(route.command, 'node');
  } finally {
    await daemon.stop();
    await dev.close();
    await chrome.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ignoredCommandsFilter: WebDriver servers are never auto-discovered', () => {
  const filter = ignoredCommandsFilter();
  for (const command of ['chromedriver', 'geckodriver', 'msedgedriver', 'safaridriver', 'ChromeDriver']) {
    assert.strictEqual(filter({ command }), false, `${command} must be excluded`);
  }
  assert.strictEqual(filter({ command: 'node' }), true);
  assert.strictEqual(filter({ command: 'ssh' }), true);
});

test('getProcessArgsAsync: long command lines are read in full, not cut at the terminal width', async () => {
  const child = childProcess.spawn(process.execPath,
    ['-e', 'setTimeout(() => {}, 20000)', 'x'.repeat(150), '--remote-debugging-port=9333'],
    { stdio: 'ignore' });
  const previousColumns = process.env.COLUMNS;
  process.env.COLUMNS = '40'; // what ps falls back to without a terminal
  try {
    await delay(200);
    const args = await getProcessArgsAsync(child.pid);
    assert.ok(args.includes('--remote-debugging-port=9333'), `args were cut: ${args.length} chars`);
  } finally {
    if (previousColumns === undefined) delete process.env.COLUMNS;
    else process.env.COLUMNS = previousColumns;
    child.kill('SIGKILL');
  }
});

test('detectInspectors: a dev server answering 404 is probed once per generation, not every few seconds', async () => {
  const server = await startServer(); // counted 404
  try {
    const cache = new Map();
    const t0 = 1_000_000;
    for (let i = 0; i < 20; i += 1) {
      const l = auto(81, server.port, '/p/shop', 'node', '81:A');
      await detectInspectors([l], cache, { getArgs: async () => 'node server.js', now: t0 + i * 3000 });
      assert.strictEqual(l.isInspector, undefined);
    }
    assert.strictEqual(server.requests(), 1, `60 s of 3 s passes sent ${server.requests()} probes`);
  } finally {
    await server.close();
  }
});

test('detectInspectors: unanswered probes back off exponentially up to a cap', async () => {
  const cache = new Map();
  let probes = 0;
  const probe = async () => { probes += 1; return 'transient'; };
  const t0 = 2_000_000;
  for (let i = 0; i < 20; i += 1) {
    await detectInspectors([auto(91, 4000, '/p/x', 'node', '91:A')], cache,
      { getArgs: async () => '', probe, now: t0 + i * 3000 });
  }
  assert.strictEqual(probes, 4, 'probes at 0 s, 6 s, 18 s and 39 s — not every 6 s');
  let now = t0 + 60_000;
  for (let i = 0; i < 12; i += 1) {
    now = cache.get('91:A:4000').retryAt;
    await detectInspectors([auto(91, 4000, '/p/x', 'node', '91:A')], cache, { getArgs: async () => '', probe, now });
  }
  const entry = cache.get('91:A:4000');
  assert.strictEqual(entry.retryAt - entry.at, 5 * 60 * 1000, 'the retry interval is capped');
});

test('probeDebugEndpoint: complete foreign answers are definitive, missing answers transient', async () => {
  const notFound = await startServer();
  const html = await startServer((req, res) => { res.writeHead(200); res.end('<html>app</html>'); });
  const chrome = await versionServer(CHROME_VERSION);
  const rawSockets = new Set();
  const raw = net.createServer((sock) => {
    rawSockets.add(sock);
    sock.on('error', () => {});
    sock.end('SSH-2.0-OpenSSH_9.6\r\n');
  });
  await new Promise((r) => raw.listen(0, '127.0.0.1', r));
  const closed = net.createServer();
  await new Promise((r) => closed.listen(0, '127.0.0.1', r));
  const refusedPort = closed.address().port;
  await new Promise((r) => closed.close(r));
  try {
    assert.strictEqual(await probeDebugEndpoint(notFound.port), 'negative');
    assert.strictEqual(await probeDebugEndpoint(html.port), 'negative');
    assert.strictEqual(await probeDebugEndpoint(chrome.port), 'inspector');
    assert.strictEqual(await probeDebugEndpoint(raw.address().port), 'negative', 'non-HTTP bytes are definitive');
    assert.strictEqual(await probeDebugEndpoint(refusedPort), 'transient');
  } finally {
    await notFound.close();
    await html.close();
    await chrome.close();
    for (const sock of rawSockets) sock.destroy();
    await new Promise((r) => raw.close(r));
  }
});

// A BiDi-only Firefox (>= 129) answers /json/version with 404, so only its
// command line gives it away: the separate-argument form geckodriver uses,
// Marionette (port in prefs) and a random/missing port must all be caught.

test('debugEndpointsFromArgs: separate values, Firefox flags, and fail-closed browser flags', () => {
  const parse = (args) => {
    const { ports, wholeProcess } = debugEndpointsFromArgs(args);
    return { ports: [...ports].sort((a, b) => a - b), wholeProcess };
  };
  assert.deepStrictEqual(parse('firefox --remote-debugging-port 9222'), { ports: [9222], wholeProcess: false });
  assert.deepStrictEqual(parse('firefox -remote-debugging-port 9333 about:blank'), { ports: [9333], wholeProcess: false });
  assert.deepStrictEqual(parse('firefox -start-debugger-server ws:6080'), { ports: [6080], wholeProcess: false });
  // geckodriver's Firefox: Marionette's port is never in the args.
  assert.deepStrictEqual(
    parse('firefox --marionette --remote-debugging-port 9222 --remote-allow-hosts localhost -no-remote -profile /tmp/p'),
    { ports: [9222], wholeProcess: true });
  for (const args of [
    'firefox --remote-debugging-port=0',
    'chrome --headless=new --remote-debugging-port=0 about:blank',
    'firefox --remote-debugging-port',
    'firefox --remote-debugging-port --remote-allow-hosts localhost',
    'chrome --remote-debugging-port=$PORT',
    'firefox -start-debugger-server',
    'firefox --start-debugger-server /tmp/devtools.sock',
  ]) {
    assert.strictEqual(parse(args).wholeProcess, true, `${args}: random, missing or unparsable port`);
  }
  // Inspector flags: a separate --inspect-port value replaces the default;
  // a random inspector port is left to the probe (the process serves the app).
  assert.deepStrictEqual(parse('node --inspect-port 9230 --inspect app.js'), { ports: [9230], wholeProcess: false });
  assert.deepStrictEqual(parse('node --inspect app.js'), { ports: [9229], wholeProcess: false });
  assert.deepStrictEqual(parse('node --inspect=0 server.js'), { ports: [], wholeProcess: false });
  assert.deepStrictEqual(parse('bun --inspect=ws://localhost:6499/x7 server.ts'), { ports: [6499], wholeProcess: false });
  // Look-alikes are no debug flags.
  assert.deepStrictEqual(parse('node server.js --port 9222'), { ports: [], wholeProcess: false });
  assert.deepStrictEqual(parse('node --inspect-portal 3 x.js'), { ports: [], wholeProcess: false });
});

test('debugEndpointsFromArgs: an --inspect without a port names the runtime default (Bun 6499, node and deno 9229)', () => {
  const ports = (args, opts) => [...debugEndpointsFromArgs(args, opts).ports];
  assert.deepStrictEqual(ports('bun --inspect run dev.ts'), [6499]);
  assert.deepStrictEqual(ports('/Users/me/.bun/bin/bun --inspect-brk server.ts'), [6499]);
  assert.deepStrictEqual(ports('bun run --inspect-wait server.ts', { command: 'bun' }), [6499]);
  // A path with spaces hides the executable in the args; the lsof command
  // name still tells the runtime.
  assert.deepStrictEqual(ports('/Users/me/Dev Tools/bun --inspect server.ts', { command: 'bun' }), [6499]);
  assert.deepStrictEqual(ports('node --inspect server.js', { command: 'node' }), [9229]);
  assert.deepStrictEqual(ports('deno run --inspect main.ts', { command: 'deno' }), [9229]);
  // A node script installed below ~/.bun still runs on node.
  assert.deepStrictEqual(ports('node /Users/me/.bun/install/global/node_modules/x/cli.js --inspect', { command: 'node' }), [9229]);
  // A named port wins for every runtime.
  assert.deepStrictEqual(ports('bun --inspect=4000 server.ts', { command: 'bun' }), [4000]);
});

test('detectInspectors: a Bun inspector opened without a port is recognised from the args and never takes the route', async () => {
  let probes = 0;
  const listeners = [
    auto(141, 6499, '/p/web', 'bun', '141:A'),
    auto(141, 8080, '/p/web', 'bun', '141:A'),
  ];
  await detectInspectors(listeners, new Map(), {
    getArgs: async () => 'bun --inspect run server.ts',
    // What Bun answers on /json/version is not relied upon.
    probe: async () => { probes += 1; return 'negative'; },
  });
  assert.deepStrictEqual(listeners.map((l) => l.isInspector), [true, undefined]);
  assert.strictEqual(probes, 1, 'only the app port needs a probe');

  // The inspector opens before the app server, yet the app keeps the route.
  const firstSeen = { '141:A:6499': 1000, '141:A:8080': 2000 };
  const { routes } = resolveRoutes({ listeners, firstSeen });
  assert.strictEqual(routes.length, 1);
  assert.strictEqual(routes[0].port, 8080);
});

test('detectInspectors: listeners without a project root cost no args lookup, no probe and no budget', async () => {
  let argsCalls = 0;
  let probes = 0;
  const getArgs = async () => { argsCalls += 1; return 'node server.js'; };
  const probe = async () => { probes += 1; return 'negative'; };
  // Apps launched by launchd/Finder in '/' (AirPlay receiver, sync clients)
  // and listeners whose cwd could not be read.
  const unrooted = () => [
    { pid: 151, port: 5000, command: 'ControlCenter', processKey: '151:A', external: true, cwd: '/', root: null, suggestedName: null },
    { pid: 152, port: 17500, command: 'Dropbox', processKey: '152:A', external: true, cwd: null, root: null, suggestedName: null },
  ];
  const cache = new Map();
  const listeners = unrooted();
  const pass = await detectInspectors(listeners, cache, { getArgs, probe });
  assert.strictEqual(argsCalls, 0, 'no ps args lookup');
  assert.strictEqual(probes, 0, 'no request to a foreign service');
  assert.deepStrictEqual(listeners.map((l) => l.isInspector), [undefined, undefined]);
  assert.strictEqual(cache.size, 0, 'no verdict is kept, so none is retried either');
  assert.strictEqual(pass.overBudget, false);

  // Past the scan budget they are no skipped work either.
  const late = await detectInspectors(unrooted(), cache, { getArgs, probe, deadline: Date.now() - 1 });
  assert.strictEqual(late.overBudget, false, 'skipping unroutable listeners never degrades a pass');

  // A routable listener in the same pass is still examined.
  const rooted = auto(153, 3000, '/p/shop', 'node', '153:A');
  await detectInspectors([...unrooted(), rooted], cache, { getArgs, probe });
  assert.strictEqual(argsCalls, 1);
  assert.strictEqual(probes, 1);
  assert.deepStrictEqual([...cache.keys()], ['153:A:3000']);
});

test('detectInspectors: a 404-answering listener named by a space-separated --remote-debugging-port is a debug endpoint', async () => {
  const bidi = await startServer(); // counted 404, like a BiDi-only Firefox
  try {
    const l = auto(111, bidi.port, '/p/shop', 'firefox', '111:A');
    await detectInspectors([l], new Map(), {
      getArgs: async () => `firefox --remote-debugging-port ${bidi.port} --remote-allow-hosts localhost`,
    });
    assert.strictEqual(l.isInspector, true);
    assert.strictEqual(bidi.requests(), 0, 'the args decide; no probe needed');
  } finally {
    await bidi.close();
  }
});

test('detectInspectors: a browser debug flag without a usable port marks every listener of the generation, sticky', async () => {
  const bidi = await startServer();
  const other = await startServer((req, res) => res.end('ok'));
  try {
    for (const args of ['firefox --remote-debugging-port=0 -no-remote', 'firefox --marionette -profile /tmp/p']) {
      const cache = new Map();
      const pass = async (getArgs) => {
        const listeners = [
          auto(112, bidi.port, '/p/shop', 'firefox', '112:A'),
          auto(112, other.port, '/p/shop', 'firefox', '112:A'),
        ];
        await detectInspectors(listeners, cache, { getArgs });
        return listeners.map((l) => l.isInspector);
      };
      assert.deepStrictEqual(await pass(async () => args), [true, true], args);
      assert.deepStrictEqual(await pass(async () => ''), [true, true], `${args}: the verdict sticks`);
    }
    assert.strictEqual(bidi.requests() + other.requests(), 0, 'no probe needed');
  } finally {
    await bidi.close();
    await other.close();
  }
});

test('detectInspectors: a probe negative is not pinned while the process args could not be read', async () => {
  const bidi = await startServer();
  try {
    const cache = new Map();
    let args = ''; // ps failed, e.g. failing fast after wedged children
    const pass = async (now) => {
      const l = auto(113, bidi.port, '/p/shop', 'firefox', '113:A');
      await detectInspectors([l], cache, { getArgs: async () => args, now });
      return l.isInspector;
    };
    const t0 = 3_000_000;
    assert.strictEqual(await pass(t0), undefined);
    assert.strictEqual(bidi.requests(), 1);
    args = 'firefox --remote-debugging-port=0';
    assert.strictEqual(await pass(t0 + 60_000), true, 'the generation is re-examined once its args are readable');
  } finally {
    await bidi.close();
  }
});

test('Daemon: a debug browser on a random port, started later in the project tree, does not take over the route', async () => {
  const dir = tmpDir('pn-hard-bidi-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const dev = await devServer();
  // Stand-in for a BiDi-only Firefox: 404 on /json/version, the debug flag
  // (random port) on its real command line, read by the real ps.
  const code = "const s = require('http').createServer((q, r) => { r.writeHead(404); r.end(); });"
    + " s.listen(0, '127.0.0.1', () => console.log(s.address().port));";
  const browser = childProcess.spawn(process.execPath,
    ['-e', code, 'firefox', '--remote-debugging-port=0', '--remote-allow-hosts', 'localhost'],
    { stdio: ['ignore', 'pipe', 'ignore'] });
  let listeners = [auto(2 ** 22 + 111, dev.port, shopDir, 'node', 'dev:A')];
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', loopbackPort: 0, control: false },
    refreshMs: 3_600_000,
    listListeners: async () => listeners,
  });
  try {
    const browserPort = await new Promise((resolve, reject) => {
      browser.stdout.once('data', (d) => resolve(Number(String(d).trim())));
      browser.once('exit', () => reject(new Error('browser stand-in exited')));
    });
    await daemon.start();
    assert.strictEqual(daemon.routesByName.get('shop').port, dev.port);
    listeners = [...listeners, auto(browser.pid, browserPort, shopDir, 'firefox', 'firefox:B')];
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, null);
    const route = daemon.routesByName.get('shop');
    assert.strictEqual(route.port, dev.port, 'the newest generation must not win when it is a debug browser');
    assert.strictEqual(route.command, 'node');
  } finally {
    await daemon.stop();
    await dev.close();
    browser.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// debugpy (VS Code's Python debugger) speaks DAP, which the /json/version
// probe cannot recognise (it reads a 404 or non-HTTP bytes). `python -m
// debugpy --listen ...` / `debugpy.listen()` spawn the adapter as its own
// daemonized process in the project cwd; its command line, as debugpy 1.8
// builds it, is the only tell.
const DEBUGPY_ADAPTER_ARGS = '/usr/bin/python3 /p/shop/.venv/lib/python3.13/site-packages/debugpy/adapter'
  + ' --for-server 37773 --host 127.0.0.1 --port 5678 --server-access-token 3b71005530c7a1f1';

// A DAP-only listener: answers whatever it reads with a DAP frame (no HTTP).
async function dapServer() {
  let connections = 0;
  const sockets = new Set();
  const server = net.createServer((sock) => {
    connections += 1;
    sockets.add(sock);
    sock.on('error', () => {});
    sock.once('data', () => sock.end('Content-Length: 2\r\n\r\n{}'));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: server.address().port,
    connections: () => connections,
    close: () => new Promise((r) => { for (const s of sockets) s.destroy(); server.close(r); }),
  };
}

test('debugEndpointsFromArgs: a debugpy adapter is a whole-process debug endpoint, the debuggee is not', () => {
  const parse = (args) => {
    const { ports, wholeProcess } = debugEndpointsFromArgs(args);
    return { ports: [...ports].sort((a, b) => a - b), wholeProcess };
  };
  for (const args of [
    DEBUGPY_ADAPTER_ARGS,
    // client port 0 (random); a macOS framework Python under a path with spaces
    '/Library/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python'
      + ' /Users/me/Library/Application Support/x/debugpy/adapter --for-server 1 --host 127.0.0.1 --port 0',
    'python3 -m debugpy.adapter --host 127.0.0.1 --port 5678',
    '/p/shop/.venv/bin/python /p/shop/.venv/bin/debugpy-adapter --port 5678',
    // VS Code's own "launch" adapter (stdio client, ephemeral server port)
    '/usr/bin/python3 /Users/me/.vscode/extensions/ms-python.debugpy-2024.0.0/bundled/libs/debugpy/adapter',
  ]) {
    assert.deepStrictEqual(parse(args), { ports: [], wholeProcess: true }, args);
  }
  // VS Code starts launcher and debuggee (the app) through the adapter's
  // directory; neither is the adapter.
  const libs = '/Users/me/.vscode/extensions/ms-python.debugpy-2024.0.0/bundled/libs';
  assert.deepStrictEqual(parse(`python3 ${libs}/debugpy/adapter/../../debugpy/launcher 61232 -- manage.py runserver`),
    { ports: [], wholeProcess: false });
  assert.deepStrictEqual(parse(`python3 -X frozen_modules=off ${libs}/debugpy/adapter/../../debugpy/launcher/../../debugpy`
    + ' --connect 127.0.0.1:61233 --configure-qt none --adapter-access-token ab manage.py runserver --listen 8000'),
  { ports: [], wholeProcess: false });
  // The debugpy CLI's --listen names the DAP port; the program's own does not.
  assert.deepStrictEqual(parse('python -m debugpy --listen 5678 --wait-for-client -m flask run --port 5000'),
    { ports: [5678], wholeProcess: false });
  assert.deepStrictEqual(parse('python3 /p/.venv/bin/debugpy --log-to /tmp/l --listen 0.0.0.0:5679 app.py --listen 9000'),
    { ports: [5679], wholeProcess: false });
  assert.deepStrictEqual(parse('python -m debugpy --connect 5678 app.py --listen 8000'), { ports: [], wholeProcess: false });
  assert.deepStrictEqual(parse('python app.py --listen 8000'), { ports: [], wholeProcess: false });
  assert.deepStrictEqual(parse('python -m my.debugpy.adapter --port 3'), { ports: [], wholeProcess: false });
});

test('detectInspectors: a debugpy adapter answering 404 or DAP bytes is a debug endpoint, sticky', async () => {
  const dap = await dapServer();
  const notFound = await startServer();
  try {
    const cache = new Map();
    const pass = async (getArgs) => {
      const listeners = [
        auto(121, dap.port, '/p/shop', 'python3', '121:A'),
        auto(121, notFound.port, '/p/shop', 'python3', '121:A'),
      ];
      await detectInspectors(listeners, cache, { getArgs });
      return listeners.map((l) => l.isInspector);
    };
    assert.deepStrictEqual(await pass(async () => DEBUGPY_ADAPTER_ARGS), [true, true]);
    assert.deepStrictEqual(await pass(async () => ''), [true, true], 'the verdict sticks for the generation');
    assert.strictEqual(dap.connections() + notFound.requests(), 0, 'the args decide; no probe needed');
  } finally {
    await dap.close();
    await notFound.close();
  }
});

test('resolveRoutes: a debugpy adapter first seen together with the app never takes the route', async () => {
  const dev = await devServer();
  const dap = await dapServer();
  try {
    const args = { 131: 'python3 app.py', 132: DEBUGPY_ADAPTER_ARGS };
    // The adapter has the higher pid: lsof lists it last, so without the
    // detection it would win the tie on firstSeen.
    const listeners = [
      auto(131, dev.port, '/p/shop', 'python3', '131:A'),
      auto(132, dap.port, '/p/shop', 'python3', '132:A'),
    ];
    await detectInspectors(listeners, new Map(), { getArgs: async (pid) => args[pid] });
    const firstSeen = { [`131:A:${dev.port}`]: 1000, [`132:A:${dap.port}`]: 1000 };
    const { routes, stale } = resolveRoutes({ listeners, firstSeen });
    assert.strictEqual(routes.length, 1);
    assert.strictEqual(routes[0].port, dev.port, 'the app keeps the route');
    assert.ok(!routes[0].services.some((svc) => svc.port === dap.port), 'the adapter is no service');
    assert.ok(stale.some((l) => l.port === dap.port), 'it is listed as diagnostic-only');

    // --wait-for-client: the adapter is the project's only listener.
    const alone = resolveRoutes({ listeners: [listeners[1]], firstSeen });
    assert.strictEqual(alone.routes.length, 0, 'a debug adapter alone gets no route');
  } finally {
    await dev.close();
    await dap.close();
  }
});

test('Daemon: a debugpy adapter in the project tree does not take the route (real ps args)', async () => {
  const dir = tmpDir('pn-hard-dap-');
  const shopDir = path.join(dir, 'shop');
  fs.mkdirSync(shopDir);
  const dev = await devServer();
  // Stand-in for the adapter: DAP-only, with debugpy's adapter command line,
  // read by the real ps.
  const code = "const s = require('net').createServer((c) => { c.on('error', () => {});"
    + " c.once('data', () => c.end('Content-Length: 2\\r\\n\\r\\n{}')); });"
    + " s.listen(0, '127.0.0.1', () => console.log(s.address().port));";
  const adapter = childProcess.spawn(process.execPath,
    ['-e', code, path.join(shopDir, '.venv/lib/python3.13/site-packages/debugpy/adapter'),
      '--for-server', '1', '--host', '127.0.0.1', '--port', '0', '--server-access-token', '00'],
    { stdio: ['ignore', 'pipe', 'ignore'] });
  let daemon = null;
  try {
    const adapterPort = await new Promise((resolve, reject) => {
      adapter.stdout.once('data', (d) => resolve(Number(String(d).trim())));
      adapter.once('exit', () => reject(new Error('adapter stand-in exited')));
    });
    // Both first seen in the same scan: a tie on firstSeen.
    const listeners = [
      auto(2 ** 22 + 121, dev.port, shopDir, 'python3', 'app:A'),
      auto(adapter.pid, adapterPort, shopDir, 'python3', 'adapter:B'),
    ];
    daemon = new Daemon({
      dir,
      config: { bind: 'loopback', loopbackPort: 0, control: false },
      refreshMs: 3_600_000,
      listListeners: async () => listeners,
    });
    await daemon.start();
    assert.strictEqual(daemon.lastScanError, null);
    const route = daemon.routesByName.get('shop');
    assert.ok(route, 'the app is routed');
    assert.strictEqual(route.port, dev.port, 'the debug adapter must not win the name');
  } finally {
    if (daemon) await daemon.stop();
    await dev.close();
    adapter.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// -- '/' and $HOME are never project identities -------------------------------

// Runs fn with HOME pointing at a fresh temp dir (os.homedir() reads $HOME).
async function withTempHome(fn) {
  const home = fs.realpathSync(tmpDir('pn-home-'));
  const previous = process.env.HOME;
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previous;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test('projectRootOf: the filesystem root and the home directory are never a project', async () => {
  await withTempHome(async (home) => {
    assert.strictEqual(projectRootOf('/'), null, "launchd/Finder apps run in '/'");
    assert.strictEqual(projectRootOf(home), null);

    // Dotfiles repo in $HOME: non-repo folders must not collapse onto ~.
    fs.mkdirSync(path.join(home, '.git'));
    const demo = path.join(home, 'Downloads', 'random-demo');
    const scratch = path.join(home, 'scratch', 'api-test');
    const repo = path.join(home, 'code', 'shop');
    fs.mkdirSync(demo, { recursive: true });
    fs.mkdirSync(scratch, { recursive: true });
    fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
    fs.mkdirSync(path.join(repo, 'web'));
    assert.strictEqual(projectRootOf(demo), demo);
    assert.strictEqual(projectRootOf(scratch), scratch);
    assert.strictEqual(projectRootOf(path.join(repo, 'web')), repo, 'real repositories still collapse');
    assert.strictEqual(projectRootOf(home), null, 'not even with ~/.git');
  });
});

// $HOME as a symlink (e.g. /Users/me -> /Volumes/Data/me): lsof reports the
// cwd of a process with the symlink resolved.
async function withSymlinkedHome(fn) {
  const base = fs.realpathSync(tmpDir('pn-home-link-'));
  const real = path.join(base, 'real');
  const link = path.join(base, 'link');
  fs.mkdirSync(real);
  fs.symlinkSync(real, link);
  const previous = process.env.HOME;
  process.env.HOME = link;
  try {
    return await fn({ base, real, link });
  } finally {
    process.env.HOME = previous;
    fs.rmSync(base, { recursive: true, force: true });
  }
}

test('projectRootOf: a symlinked $HOME is recognised in the resolved form lsof reports', async () => {
  await withSymlinkedHome(async ({ base, real, link }) => {
    const repo = path.join(real, 'code', 'shop');
    fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
    fs.mkdirSync(path.join(repo, 'apps', 'web'), { recursive: true });

    assert.strictEqual(projectRootOf(real), null, 'the resolved home folder is no project');
    assert.strictEqual(projectRootOf(path.join(repo, 'apps', 'web')), repo,
      'a monorepo subfolder below the resolved home collapses onto its repository');
    // The configured spelling keeps working.
    assert.strictEqual(projectRootOf(link), null);
    assert.strictEqual(projectRootOf(path.join(link, 'code', 'shop', 'apps', 'web')), path.join(link, 'code', 'shop'));

    // The registry judges the resolved home folder alike.
    const reg = new Registry(path.join(base, 'state'));
    assert.strictEqual(reg.rename(real, 'home').code, 'INVALID_REQUEST');
    assert.strictEqual(reg.rename(repo, 'shop').ok, true);
  });
});

test('Daemon: with a symlinked $HOME, a server started in ~ gets no route and a monorepo app keeps its repository', async () => {
  await withSymlinkedHome(async ({ real }) => {
    const dir = tmpDir('pn-hard-home-link-');
    const repo = path.join(real, 'repo');
    fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
    fs.mkdirSync(path.join(repo, 'apps', 'web'), { recursive: true });
    const at = (pid, port, cwd) => ({ pid, port, processKey: `${pid}:s`, command: 'python3', cwd, external: false });
    const daemon = new Daemon({
      dir,
      config: { bind: 'loopback', loopbackPort: 0, control: false },
      refreshMs: 3_600_000,
      listListeners: async () => [
        at(9201, 45101, real), // `python3 -m http.server` started from ~
        at(9202, 45102, path.join(repo, 'apps', 'web')),
      ],
    });
    try {
      await daemon.start();
      assert.deepStrictEqual(daemon.routes.map((r) => [r.name, r.root]), [['repo', repo]]);
      assert.ok(!Object.keys(daemon.registry.config.names).includes(real), 'no name is reserved for ~');
    } finally {
      await daemon.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

test("Daemon: listeners running in '/' or $HOME get no automatic 'project' route", async () => {
  await withTempHome(async (home) => {
    const dir = tmpDir('pn-hard-rootless-');
    const shopDir = path.join(home, 'code', 'shop');
    fs.mkdirSync(path.join(shopDir, '.git'), { recursive: true });
    const unrooted = (pid, port, cwd) => ({ pid, port, processKey: `${pid}:s`, command: 'App', cwd, external: false });
    const daemon = new Daemon({
      dir,
      config: { bind: 'loopback', loopbackPort: 0, control: false },
      refreshMs: 3_600_000,
      listListeners: async () => [
        unrooted(9101, 45001, '/'),
        unrooted(9102, 45002, '/'),
        unrooted(9103, 45003, home),
        unrooted(9104, 45004, shopDir),
      ],
    });
    try {
      await daemon.start();
      assert.deepStrictEqual(daemon.routes.map((r) => r.name), ['shop'],
        "unrelated apps in '/' or ~ must not share one auto-named identity");
      assert.ok(!Object.keys(daemon.registry.config.names).includes('/'));
      assert.deepStrictEqual([...daemon.inspectorCache.keys()], ['9104:s:45004'],
        'only the routable listener is examined for a debug endpoint');
      // The unattributed listeners still verify manual targets.
      await daemon.dispatchControl({ cmd: 'add', name: 'airplay', port: 45001 });
      assert.strictEqual(daemon.routesByName.get('airplay').port, 45001);
    } finally {
      await daemon.stop();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// -- non-ASCII paths through lsof ---------------------------------------------

// Runs fn with a C locale in this process, like a LaunchAgent without LANG.
async function withCLocale(fn) {
  const saved = { LC_ALL: process.env.LC_ALL, LANG: process.env.LANG, LC_CTYPE: process.env.LC_CTYPE };
  process.env.LC_ALL = 'C';
  delete process.env.LANG;
  delete process.env.LC_CTYPE;
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('decodeLsofName: reverses lsof safe-printing', () => {
  assert.strictEqual(decodeLsofName('/p/B\\xc3\\xa4ckerei-shop'), '/p/Bäckerei-shop');
  assert.strictEqual(decodeLsofName('/p/a\\\\b'), '/p/a\\b', 'escaped backslash');
  assert.strictEqual(decodeLsofName('/p/B\\\\xc3\\\\xa4'), '/p/B\\xc3\\xa4', 'a literal "\\x" stays literal');
  assert.strictEqual(decodeLsofName('/p/tab\\there'), '/p/tab\there');
  assert.strictEqual(decodeLsofName('/p/^A'), '/p/\x01');
  assert.strictEqual(decodeLsofName('/p/^A', { carets: false }), '/p/^A');
  assert.strictEqual(decodeLsofName('/p/plain ünïcode 😀'), '/p/plain ünïcode 😀');
});

test('cwdOfAsync: a launchd-style C locale still yields the real UTF-8 path (real lsof)', async () => {
  const base = fs.realpathSync(tmpDir('pn-utf8-'));
  const cwd = path.join(base, 'Bäckerei-shop', 'frontend');
  fs.mkdirSync(cwd, { recursive: true });
  const child = childProcess.spawn('sleep', ['30'], { cwd, stdio: 'ignore' });
  try {
    await delay(100);
    const seen = await withCLocale(() => cwdOfAsync(child.pid));
    assert.strictEqual(seen, cwd);
  } finally {
    child.kill('SIGKILL');
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test('enrichAsync: an escaped cwd still walks up to the repository root', async () => {
  await withTempHome(async (home) => {
    const repo = path.join(home, 'Projekte', 'Bäckerei-shop');
    const frontend = path.join(repo, 'frontend');
    fs.mkdirSync(path.join(repo, '.git'), { recursive: true });
    fs.mkdirSync(frontend);
    // An lsof that escapes like the C-locale safe printer does.
    const escaped = Buffer.from(frontend, 'utf8').toString('latin1')
      .replace(/[\x80-\xff]/g, (c) => `\\x${c.charCodeAt(0).toString(16)}`);
    const restore = withShim('lsof', `#!/bin/sh\nprintf 'p4242\\nfcwd\\nn%s\\n' '${escaped}'\n`);
    try {
      const [l] = await enrichAsync([{ pid: 4242, port: 3000, command: 'node' }], new Map(), {
        getStartTime: async () => 'T1',
      });
      assert.strictEqual(l.cwd, frontend);
      assert.strictEqual(l.root, repo, 'the .git above a non-ASCII path must be found');
      assert.strictEqual(l.suggestedName, 'b-ckerei-shop');
    } finally {
      restore();
    }
  });
});

// -- Bonjour registration children --------------------------------------------

function fakeDnsSd({ exitImmediately = () => false, pidFor = () => 0 } = {}) {
  const spawned = [];
  const spawnFn = (cmd, args) => {
    const child = new EventEmitter();
    child.pid = pidFor(spawned.length) || 70000 + spawned.length;
    child.name = args[1];
    child.kill = () => true;
    spawned.push(child);
    if (exitImmediately(child.name)) process.nextTick(() => child.emit('exit', 255, null));
    return child;
  };
  return { spawnFn, spawned };
}

test('BonjourAnnouncer: a dns-sd child that exits at once is retried with an exponential backoff', async () => {
  let clock = 1_000_000;
  const dns = fakeDnsSd({ exitImmediately: (name) => name === 'shop' });
  const announcer = new BonjourAnnouncer({
    port: 80,
    getLan: () => ({ name: 'en0', address: '192.168.1.5' }),
    spawnFn: dns.spawnFn,
    now: () => clock,
  });
  const spawnsOf = (name) => dns.spawned.filter((c) => c.name === name).length;

  // Ten scan ticks (3 s apart): the conflicting name must not respawn every tick.
  for (let i = 0; i < 10; i += 1) {
    announcer.sync(['shop', 'api']);
    await new Promise((r) => setImmediate(r)); // let the immediate exit surface
    clock += 3000;
  }
  assert.strictEqual(spawnsOf('shop'), 2, 'spawned at 0 s and after the 15 s backoff, not 10 times');
  assert.strictEqual(spawnsOf('api'), 1, 'a healthy registration is untouched');
  assert.strictEqual(announcer.registrationState('shop'), 'conflict');
  assert.strictEqual(announcer.registrationState('api'), 'registered');

  // The backoff doubles…
  clock += 30_000;
  announcer.sync(['shop', 'api']);
  await new Promise((r) => setImmediate(r));
  assert.strictEqual(spawnsOf('shop'), 3);

  // …and a child that ran long enough resets it: the next loss re-registers at once.
  dns.spawned.length = 0;
  const steady = fakeDnsSd();
  announcer.spawnFn = steady.spawnFn;
  clock += 10 * 60_000;
  announcer.sync(['shop', 'api']);
  const shopChild = steady.spawned.find((c) => c.name === 'shop');
  assert.ok(shopChild);
  clock += 60_000;
  shopChild.emit('exit', 0, null); // e.g. mDNSResponder restarted
  announcer.sync(['shop', 'api']);
  assert.strictEqual(steady.spawned.filter((c) => c.name === 'shop').length, 2,
    'a loss after a long run is re-registered immediately');
  announcer.stopAll();
});

test('BonjourAnnouncer: registering N names costs no synchronous ps and one batched start-time lookup', async () => {
  const dir = tmpDir('pn-hard-bonjour-');
  const sleepers = spawnSleepers(10);
  await delay(50);
  const expected = new Map(sleepers.map((c) => [c.pid, getProcessStartTime(c.pid)]));
  const counting = withCountingPs();
  let lan = { name: 'en0', address: '192.168.1.5' };
  const dns = fakeDnsSd({ pidFor: (i) => sleepers[i % sleepers.length].pid });
  const announcer = new BonjourAnnouncer({ port: 80, dir, getLan: () => lan, spawnFn: dns.spawnFn });
  const names = sleepers.map((_, i) => `app${i}`);
  const stateFile = path.join(dir, 'bonjour.state.json');
  const waitForStartTimes = async () => {
    for (let i = 0; i < 100; i += 1) {
      const state = fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, 'utf8')) : null;
      if (state && state.children.length === names.length && state.children.every((c) => c.startTime)) return state;
      await delay(20);
    }
    throw new Error('start times were never persisted');
  };
  try {
    announcer.sync(names);
    assert.strictEqual(counting.calls().length, 0, 'sync() must not run ps on the event loop');
    const state = await waitForStartTimes();
    assert.strictEqual(counting.calls().length, 1, `one batched ps for ${names.length} children`);
    for (const c of state.children) assert.strictEqual(c.startTime, expected.get(c.pid));

    // LAN address change: everything is re-registered — still one lookup.
    dns.spawned.length = 0;
    lan = { name: 'en0', address: '192.168.1.6' };
    announcer.sync(names);
    assert.strictEqual(counting.calls().length, 1);
    await waitForStartTimes();
    assert.strictEqual(counting.calls().length, 2);

    announcer.sync(names); // unchanged: nothing to read or write
    await delay(50);
    assert.strictEqual(counting.calls().length, 2);
  } finally {
    announcer.stopAll();
    counting.restore();
    for (const c of sleepers) c.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// -- atomic lock takeover -----------------------------------------------------

async function deadPid() {
  const dead = childProcess.spawn(process.execPath, ['-e', 'process.exit(0)']);
  await new Promise((r) => dead.once('exit', r));
  return dead.pid;
}

test('instance lock: a fresh unreadable claim is presumed in progress; an old one is stolen', async () => {
  const dir = tmpDir('pn-hard-lock-empty-');
  const lockFile = path.join(dir, 'daemon.lock');
  try {
    fs.writeFileSync(lockFile, ''); // a contender between create and write
    await assert.rejects(
      () => acquireInstanceLock({ dir, instanceId: 'new' }),
      (err) => err.code === 'DAEMON_ALREADY_RUNNING'
    );
    assert.strictEqual(fs.readFileSync(lockFile, 'utf8'), '', 'the fresh claim stays untouched');

    const old = (Date.now() - 60_000) / 1000;
    fs.utimesSync(lockFile, old, old); // left behind by a crash long ago
    const lock = await acquireInstanceLock({ dir, instanceId: 'new' });
    assert.strictEqual(JSON.parse(fs.readFileSync(lockFile, 'utf8')).instanceId, 'new');
    lock.release();
    assert.deepStrictEqual(fs.readdirSync(dir), [], 'no temp or marker files are left behind');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('instance lock: contenders racing for a stale lock never both acquire it', async () => {
  const scriptDir = tmpDir('pn-lock-race-');
  const contender = path.join(scriptDir, 'contender.js');
  // Each contender starts at the same instant; one of them judges the stale
  // owner slowly (a ps call under load), which used to let it delete the
  // fresh claim of the contender that had already taken over.
  fs.writeFileSync(contender, `
    const { acquireInstanceLock } = require(${JSON.stringify(INSTANCE_LOCK_JS)});
    const { getProcessInfo } = require(${JSON.stringify(PROCESS_JS)});
    const [dir, delayMs, startAt] = process.argv.slice(2);
    const busy = (ms) => { const end = Date.now() + ms; while (Date.now() < end) {} };
    busy(Number(startAt) - Date.now());
    acquireInstanceLock({
      dir,
      instanceId: 'c' + process.pid,
      getProcessInfo: (pid) => { busy(Number(delayMs)); return getProcessInfo(pid); },
    }).then(
      (lock) => { console.log('ACQUIRED'); setTimeout(() => lock.release(), 800); },
      (err) => console.log(err.code || err.message)
    );
  `);
  const run = (dir, delayMs, startAt) => new Promise((resolve, reject) => {
    childProcess.execFile(process.execPath, [contender, dir, String(delayMs), String(startAt)],
      { timeout: 20000 }, (err, stdout) => (err ? reject(err) : resolve(stdout.trim())));
  });
  try {
    for (const delays of [[0, 120], [0, 70], [120, 0], [0, 0, 120]]) {
      const dir = tmpDir('pn-lock-race-dir-');
      try {
        fs.writeFileSync(path.join(dir, 'daemon.lock'),
          JSON.stringify({ pid: await deadPid(), startTime: 'Mon Jan  1 00:00:00 2024', instanceId: 'crashed' }));
        const startAt = Date.now() + 400;
        const outcomes = await Promise.all(delays.map((d) => run(dir, d, startAt)));
        const acquired = outcomes.filter((o) => o === 'ACQUIRED').length;
        assert.strictEqual(acquired, 1, `delays ${delays.join('/')}: outcomes ${outcomes.join(', ')}`);
        assert.ok(outcomes.every((o) => o === 'ACQUIRED' || o === 'DAEMON_ALREADY_RUNNING'), outcomes.join(', '));
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }
  } finally {
    fs.rmSync(scriptDir, { recursive: true, force: true });
  }
});
