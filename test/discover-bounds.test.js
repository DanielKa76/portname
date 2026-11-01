'use strict';

// Bounds and failure semantics of discovery:
//   - a failed, truncated or aborted lsof run must never become a "complete"
//     new snapshot (partial stdout is not a scan result);
//   - an empty listener list is only legal for the benign no-match result;
//   - subprocess and inspector-probe fan-out is bounded in parallelism and
//     total duration;
//   - negative cwd/inspector results from transient failures are retried on a
//     bounded interval instead of being pinned for the process lifetime;
//   - firstSeen generations are retained only for a bounded time.
//
// Shimmed-lsof tests are mocks; the single test labeled "(real lsof)" runs the
// real binary and only asserts that a clean scan resolves.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const {
  listListenersAsync,
  enrichAsync,
  probeIsInspector,
  detectInspectors,
  ROOT_CACHE_MAX,
} = require('../lib/discover');
const { Registry } = require('../lib/registry');
const { Daemon } = require('../lib/daemon');

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// -- lsof shims --------------------------------------------------------------

// Creates a directory with an executable named `lsof` on PATH and returns a
// restore function. Tests within one file run sequentially, so swapping PATH
// for the duration of a test is safe.
function withLsofShim(script) {
  const shimDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-lsof-shim-'));
  const shim = path.join(shimDir, 'lsof');
  fs.writeFileSync(shim, script);
  fs.chmodSync(shim, 0o755);
  const previousPath = process.env.PATH;
  process.env.PATH = `${shimDir}:${previousPath}`;
  return function restore() {
    process.env.PATH = previousPath;
    fs.rmSync(shimDir, { recursive: true, force: true });
  };
}

test('listListenersAsync: timeout with well-formed partial output is a diagnosable error, not a snapshot', async () => {
  const restore = withLsofShim(
    '#!/bin/sh\nprintf \'p123\\0cnode\\nn127.0.0.1:3000\\n\'\nexec sleep 30\n'
  );
  try {
    await assert.rejects(
      () => listListenersAsync({ timeoutMs: 300 }),
      (err) => {
        assert.match(err.message, /listener scan failed/);
        assert.match(err.message, /terminated|timeout/);
        return true;
      }
    );
  } finally {
    restore();
  }
});

test('listListenersAsync: output beyond maxBuffer is an error, not a truncated snapshot', async () => {
  const restore = withLsofShim(
    '#!/bin/sh\nnode -e "process.stdout.write(Buffer.alloc(2 * 1024 * 1024, 120))"\n'
  );
  try {
    await assert.rejects(
      () => listListenersAsync({ maxBufferBytes: 64 * 1024 }),
      /listener scan failed.*maxBuffer/
    );
  } finally {
    restore();
  }
});

test('listListenersAsync: exit 1 with no stdout and no stderr is the benign no-match empty list', async () => {
  const restore = withLsofShim('#!/bin/sh\nexit 1\n');
  try {
    const records = await listListenersAsync({});
    assert.deepStrictEqual(records, []);
  } finally {
    restore();
  }
});

test('listListenersAsync: exit 1 with stderr is an error, not an empty list', async () => {
  const restore = withLsofShim(
    '#!/bin/sh\necho "lsof: WARNING: can\'t stat() file system" >&2\nexit 1\n'
  );
  try {
    await assert.rejects(
      () => listListenersAsync({}),
      (err) => {
        assert.match(err.message, /listener scan failed/);
        assert.match(err.message, /WARNING/);
        return true;
      }
    );
  } finally {
    restore();
  }
});

test('listListenersAsync: exit 1 with partial stdout is an error, not a partial snapshot', async () => {
  const restore = withLsofShim(
    '#!/bin/sh\nprintf \'p=123\\0c=node\\nn=127.0.0.1:3000\\n\'\nexit 1\n'
  );
  try {
    await assert.rejects(() => listListenersAsync({}), /listener scan failed/);
  } finally {
    restore();
  }
});

test('listListenersAsync (mock lsof): successful scan parses machine records and honours excludePids', async () => {
  const restore = withLsofShim(
    '#!/bin/sh\n' +
    'printf \'p123\\0cnode\\n\'\n' +
    'printf \'fREG\\0n127.0.0.1:3000\\n\'\n' +
    'printf \'p124\\0cruby\\n\'\n' +
    'printf \'fREG\\0n*:4000\\n\'\n'
  );
  try {
    const records = await listListenersAsync({});
    assert.strictEqual(records.length, 2);
    const byPort = new Map(records.map((r) => [r.port, r]));
    assert.strictEqual(byPort.get(3000).command, 'node');
    assert.strictEqual(byPort.get(4000).external, true);

    const excluded = await listListenersAsync({ excludePids: [123] });
    assert.deepStrictEqual(excluded.map((r) => r.port), [4000]);
  } finally {
    restore();
  }
});

// Real binary: only asserts that a clean scan resolves — the machine may have
// any number of listeners. Not a performance measurement.
test('listListenersAsync (real lsof): a clean scan resolves to an array', async () => {
  const records = await listListenersAsync({});
  assert.ok(Array.isArray(records));
});

// -- enrichAsync: negative cwd backoff, dedup and concurrency bounds ---------

test('enrichAsync: transient cwd failure retries after the bounded interval and recovers', async () => {
  const cwdCache = new Map();
  const cwdRetryAt = new Map();
  let cwdCalls = 0;
  const cwdOf = async () => {
    cwdCalls += 1;
    return cwdCalls < 2 ? null : '/repo/shop';
  };
  const makeListener = () => ({ pid: 4242, port: 3000, command: 'node' });

  const first = await enrichAsync([makeListener()], cwdCache, {
    getStartTime: async () => 'T1',
    cwdOf,
    cwdRetryAt,
    negativeTtlMs: 5000,
    now: 1000,
  });
  assert.strictEqual(first[0].cwd, null);
  assert.strictEqual(first[0].root, null, 'no cwd means no route identity');
  assert.strictEqual(cwdCache.has('4242:T1'), false, 'negative result must not be pinned into the generation cache');
  assert.ok((cwdRetryAt.get('4242:T1') || 0) > 1000, 'negative result sets a bounded retry time');

  // Within the retry interval: no new lookup, still no root.
  const second = await enrichAsync([makeListener()], cwdCache, {
    getStartTime: async () => 'T1',
    cwdOf,
    cwdRetryAt,
    negativeTtlMs: 5000,
    now: 3000,
  });
  assert.strictEqual(cwdCalls, 1, 'within the retry interval the lookup is skipped');
  assert.strictEqual(second[0].root, null);

  // After the interval: the lookup retries and recovers.
  const third = await enrichAsync([makeListener()], cwdCache, {
    getStartTime: async () => 'T1',
    cwdOf,
    cwdRetryAt,
    negativeTtlMs: 5000,
    now: 7000,
  });
  assert.strictEqual(cwdCalls, 2, 'the transient failure is retried after the interval');
  assert.strictEqual(third[0].cwd, '/repo/shop');
  assert.strictEqual(third[0].root, '/repo/shop');
  // Recovered result is pinned for the process generation.
  const fourth = await enrichAsync([makeListener()], cwdCache, {
    getStartTime: async () => 'T1',
    cwdOf,
    cwdRetryAt,
    negativeTtlMs: 5000,
    now: 8000,
  });
  assert.strictEqual(cwdCalls, 2, 'positive cwd stays cached for the process generation');
  assert.strictEqual(fourth[0].root, '/repo/shop');
});

test('enrichAsync: one start-time lookup per distinct pid, bounded in parallelism', async () => {
  const listeners = [];
  for (let i = 1; i <= 40; i += 1) {
    listeners.push({ pid: i, port: 3000 + i, command: 'node' });
  }
  // Same process on a second port: must not cause a second ps call.
  listeners.push({ pid: 7, port: 9999, command: 'node' });

  let calls = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  const getStartTime = async (pid) => {
    calls += 1;
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await delay(15);
    inFlight -= 1;
    return `T${pid}`;
  };

  const enriched = await enrichAsync(listeners, new Map(), { getStartTime });
  assert.strictEqual(calls, 40, 'start times are deduplicated per pid');
  assert.ok(maxInFlight <= 4, `subprocess fan-out must stay bounded (saw ${maxInFlight})`);
  const pid7 = enriched.filter((l) => l.pid === 7);
  assert.strictEqual(pid7.length, 2);
  assert.strictEqual(pid7[0].processKey, '7:T7');
  assert.strictEqual(pid7[1].processKey, '7:T7');
});

test('enrichAsync: cwd lookups start lazily inside the bounded workers', async () => {
  const listeners = [];
  for (let i = 1; i <= 40; i += 1) {
    listeners.push({ pid: 300 + i, port: 5000 + i, command: 'node' });
  }

  let calls = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  const cwdOf = async () => {
    calls += 1;
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await delay(15);
    inFlight -= 1;
    return `/repo/p${calls}`;
  };

  const enriched = await enrichAsync(listeners, new Map(), {
    getStartTime: async (pid) => `T${pid}`,
    cwdOf,
  });
  assert.strictEqual(calls, 40, 'one cwd lookup per distinct process generation');
  assert.ok(maxInFlight <= 4, `cwd fan-out must stay bounded (saw ${maxInFlight})`);
  assert.ok(enriched.every((l) => l.cwd && l.cwd.startsWith('/repo/')));
});

test('enrichAsync: project root canonicalization is cached across scans', async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-rootcache-'));
  try {
    const rootCache = new Map();
    const makeListener = () => ({ pid: 5150, port: 3000, command: 'node', cwd, processKey: '5150:T' });
    // Pre-populate the cache with a value that differs from a fresh walk so we
    // can observe that the cached root is used without re-walking.
    rootCache.set(cwd, { root: '/cached/root', at: 500 });
    const enriched = await enrichAsync([makeListener()], new Map(), {
      getStartTime: async () => 'T',
      rootCache,
      rootTtlMs: 60000,
      now: 1000,
    });
    assert.strictEqual(enriched[0].root, '/cached/root');

    // After the TTL the cache is revalidated (walk returns cwd itself here).
    const refreshed = await enrichAsync([makeListener()], new Map(), {
      getStartTime: async () => 'T',
      rootCache,
      rootTtlMs: 60000,
      now: 99999,
    });
    assert.strictEqual(refreshed[0].root, cwd);
    assert.strictEqual(rootCache.get(cwd).root, cwd);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});

test('enrichAsync: root cache cap evicts the oldest entry instead of flushing the cache', async () => {
  const rootCache = new Map();
  const oldestCwd = '/repo/evict-oldest';
  rootCache.set(oldestCwd, { root: oldestCwd, at: 0 });
  for (let i = 1; rootCache.size < ROOT_CACHE_MAX; i += 1) {
    rootCache.set(`/repo/filler-${i}`, { root: null, at: 0 });
  }
  const makeListener = (cwd) => ({ pid: 4242, port: 3000, command: 'node', cwd, processKey: '4242:T' });

  // One new cwd at the cap: exactly the oldest entry is dropped, the rest of
  // the cache survives (no cold-cache flush).
  const enriched = await enrichAsync([makeListener('/repo/fresh')], new Map(), {
    getStartTime: async () => 'T',
    rootCache,
    now: 1000,
  });
  assert.strictEqual(enriched[0].root, '/repo/fresh');
  assert.strictEqual(rootCache.has(oldestCwd), false, 'the oldest entry is evicted');
  assert.strictEqual(rootCache.size, ROOT_CACHE_MAX, 'the cache stays at its cap');
  assert.strictEqual(rootCache.get('/repo/filler-250').root, null, 'recent entries survive the eviction');
});

// -- inspector probes ---------------------------------------------------------

test('probeIsInspector: a dribbling response is ended by the wall-clock bound, not by socket inactivity', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{ "Browser": "node');
    const drip = setInterval(() => res.write(' '), 30);
    res.on('close', () => clearInterval(drip));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const started = Date.now();
    const result = await probeIsInspector(server.address().port, '127.0.0.1', 200);
    const elapsed = Date.now() - started;
    assert.strictEqual(result, false, 'a partial response is not an inspector');
    assert.ok(elapsed < 2000, `probe must end via the total-duration bound (took ${elapsed}ms)`);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
});

test('detectInspectors: probe negatives are retried after a bounded interval; positives and definitive negatives stick', async () => {
  let probeResult = false;
  let probeCalls = 0;
  const probe = async () => {
    probeCalls += 1;
    return probeResult;
  };
  const inspectorCache = new Map();
  const makeListener = () => listener({ pid: 10, port: 3000, command: 'node', processKey: '10:T1' });

  await detectInspectors([makeListener()], inspectorCache, { probe, negativeTtlMs: 5000, now: 1000 });
  assert.strictEqual(probeCalls, 1);
  assert.strictEqual(makeListener().isInspector, undefined);

  await detectInspectors([makeListener()], inspectorCache, { probe, negativeTtlMs: 5000, now: 3000 });
  assert.strictEqual(probeCalls, 1, 'within the retry interval no new probe is started');

  probeResult = true;
  const recovered = makeListener();
  await detectInspectors([recovered], inspectorCache, { probe, negativeTtlMs: 5000, now: 7000 });
  assert.strictEqual(probeCalls, 2, 'transient negative is retried after the interval');
  assert.strictEqual(recovered.isInspector, true);

  await detectInspectors([makeListener()], inspectorCache, { probe, negativeTtlMs: 5000, now: 99999 });
  assert.strictEqual(probeCalls, 2, 'a positive result sticks for the process generation');

  // Definitive negative: a complete non-debugger answer sticks for the
  // process generation once its args were read. Every command is examined —
  // DevTools endpoints are not node-only — but only once.
  probeResult = 'negative';
  const getArgs = async () => 'python3 -m http.server 3001';
  const python = listener({ pid: 11, port: 3001, command: 'python3', processKey: '11:T1' });
  await detectInspectors([python], inspectorCache, { getArgs, probe, negativeTtlMs: 0, now: 1000 });
  assert.strictEqual(probeCalls, 3, 'non-node commands are examined too');
  assert.strictEqual(python.isInspector, undefined);
  const pythonLater = listener({ pid: 11, port: 3001, command: 'python3', processKey: '11:T1' });
  await detectInspectors([pythonLater], inspectorCache, { getArgs, probe, negativeTtlMs: 0, now: 99999 });
  assert.strictEqual(probeCalls, 3, 'a definitive negative is never re-probed for the generation');
  assert.strictEqual(pythonLater.isInspector, undefined);
});

test('detectInspectors: one args lookup per pid and no probe when the inspect flag matches the port', async () => {
  let argsCalls = 0;
  let probeCalls = 0;
  const getArgs = async () => {
    argsCalls += 1;
    await delay(5);
    return 'node --inspect=9229 server.js';
  };
  const probe = async () => {
    probeCalls += 1;
    return false;
  };
  const listeners = [
    listener({ pid: 21, port: 9229, command: 'node', processKey: '21:T1' }),
    listener({ pid: 21, port: 3000, command: 'node', processKey: '21:T1' }),
  ];
  await detectInspectors(listeners, new Map(), { getArgs, probe });
  assert.strictEqual(argsCalls, 1, 'args lookup is deduplicated per pid');
  assert.strictEqual(listeners[0].isInspector, true, 'explicit inspect flag on the port marks the inspector');
  assert.strictEqual(probeCalls, 1, 'only the non-flag listener needs an HTTP probe');
  assert.strictEqual(listeners[1].isInspector, undefined);
});

test('detectInspectors: overBudget is reported only when work was skipped, not when probes run past the budget', async () => {
  const slowProbe = async () => {
    await delay(50);
    return false;
  };

  // The probe starts before the deadline and ends after it: the pass is
  // complete even though its wall time exceeds the budget.
  const single = [listener({ pid: 31, port: 7000, command: 'node', processKey: '31:T1' })];
  const complete = await detectInspectors(single, new Map(), {
    getArgs: async () => null,
    probe: slowProbe,
    deadline: Date.now() + 10,
  });
  assert.strictEqual(complete.overBudget, false, 'a completed pass is not over budget despite the wall clock');

  // With all lanes busy past the deadline, later listeners are skipped:
  // the pass is incomplete and must be reported.
  const many = [];
  for (let i = 1; i <= 20; i += 1) {
    many.push(listener({ pid: 40 + i, port: 7000 + i, command: 'node', processKey: `${40 + i}:T1` }));
  }
  const truncated = await detectInspectors(many, new Map(), {
    getArgs: async () => null,
    probe: slowProbe,
    deadline: Date.now() + 20,
  });
  assert.strictEqual(truncated.overBudget, true, 'skipped listeners make the pass over budget');
});

test('detectInspectors: probe fan-out stays bounded against a hanging probe server', async () => {
  // The hanging server is the brake: probes run their full wall-clock bound,
  // so real concurrency builds up instead of probes failing fast.
  const server = http.createServer(() => { /* hangs: never responds */ });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  let inFlight = 0;
  let maxInFlight = 0;
  const countedProbe = (p, host) => {
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    return probeIsInspector(p, host).finally(() => { inFlight -= 1; });
  };
  try {
    const listeners = [];
    for (let i = 1; i <= 32; i += 1) {
      listeners.push(listener({ pid: 600 + i, port, command: 'node', processKey: `${600 + i}:T1` }));
    }
    await detectInspectors(listeners, new Map(), { getArgs: async () => null, probe: countedProbe });
    assert.ok(maxInFlight <= 8, `probe fan-out must stay bounded (saw ${maxInFlight})`);
    assert.ok(maxInFlight >= 4, `probes must run concurrently against the hanging server (saw ${maxInFlight})`);
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
});

// A routable listener: only listeners with a project root are examined.
function listener({ pid, port, command, processKey }) {
  return { pid, port, command, processKey, external: false, root: '/p/app' };
}

// -- Registry firstSeen retention ----------------------------------------------

test('Registry.observe: old dead-generation births are pruned; live and recent entries and all name reservations survive', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-firstseen-'));
  const now = 1_800_000_000_000;
  try {
    const reg = new Registry(dir);
    reg.config.names['/p/stopped'] = 'stopped-name';
    reg.config.renames['/p/other'] = 'custom';
    reg.config.primaryPorts['/p/stopped'] = 3000;

    reg.firstSeen['1:T1:3000'] = now - 48 * 60 * 60 * 1000; // old, dead
    reg.firstSeen['2:T2:4000'] = now - 48 * 60 * 60 * 1000; // old, but live below
    reg.firstSeen['3:T3:5000'] = now - 1 * 60 * 60 * 1000; // recent, dead

    reg.observe([{ pid: 2, port: 4000, processKey: '2:T2' }], now);

    assert.strictEqual(reg.firstSeen['1:T1:3000'], undefined, 'old dead generation pruned');
    assert.strictEqual(reg.firstSeen['2:T2:4000'], now - 48 * 60 * 60 * 1000, 'live generation kept');
    assert.strictEqual(reg.firstSeen['3:T3:5000'], now - 1 * 60 * 60 * 1000, 'recent entry kept');
    assert.strictEqual(reg.config.names['/p/stopped'], 'stopped-name', 'name reservations untouched');
    assert.strictEqual(reg.config.renames['/p/other'], 'custom', 'renames untouched');
    assert.strictEqual(reg.config.primaryPorts['/p/stopped'], 3000, 'primary port preferences untouched');

    const reg2 = new Registry(dir);
    assert.strictEqual(reg2.firstSeen['2:T2:4000'], now - 48 * 60 * 60 * 1000, 'pruning persisted');
    assert.strictEqual(reg2.firstSeen['1:T1:3000'], undefined);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// -- daemon scan-cycle bounds --------------------------------------------------

function shopListener(dir) {
  return {
    pid: 3001,
    port: 3000,
    processKey: '3001:start',
    command: 'node',
    cwd: path.join(dir, 'shop'),
    root: path.join(dir, 'shop'),
    suggestedName: 'shop',
    external: false,
  };
}

test('Daemon: a scan over the cycle budget keeps the previous routes and reports the degraded scan', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-budget-'));
  let currentListeners = () => [shopListener(dir)];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    refreshMs: 3_600_000, // only explicit refresh() calls in this test
    listListeners: async () => {
      await delay(80);
      return currentListeners();
    },
  });

  try {
    await daemon.start();
    assert.strictEqual(daemon.routesByName.get('shop').port, 3000);
    assert.strictEqual(daemon.lastScanError, null);

    daemon.scanBudgetMs = 20; // cycle budget far below the 80ms scan
    await daemon.refresh();
    assert.match(daemon.lastScanError, /budget/);
    assert.strictEqual(daemon.routesByName.get('shop').port, 3000, 'previous routes survive a degraded scan');

    daemon.scanBudgetMs = 6000;
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, null, 'a healthy pass clears the degraded flag');
  } finally {
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon: in-flight inspector probes past the budget keep a fully completed pass publishable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-inspector-budget-'));
  // A server that never answers: the inspector probe runs its full 200ms bound.
  const server = http.createServer(() => { /* hangs: never responds */ });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const l = {
    pid: 3002,
    port,
    processKey: '3002:start',
    command: 'node',
    cwd: path.join(dir, 'shop'),
    root: path.join(dir, 'shop'),
    suggestedName: 'shop',
    external: false,
  };
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    refreshMs: 3_600_000, // only explicit refresh() calls in this test
    // Hermetic enrichment: the real start-time lookup spawns a bounded `ps`
    // per distinct pid, which is load-dependent — under parallel test load
    // that single call alone exceeded the tiny 100 ms cycle budget below and
    // degraded the pass during enrichment, before the probe could run. With
    // the stub the only work past the budget is the inspector probe.
    getStartTime: async () => 'fixed-start',
    listListeners: async () => [l],
  });

  try {
    await daemon.start();
    assert.strictEqual(daemon.lastScanError, null);
    // Expired negative inspector entry: the next pass must probe, and the
    // probe's 200ms bound runs the pass past the small cycle budget — yet
    // the pass stays complete and must publish.
    daemon.inspectorCache.set(`3002:start:${port}`, { value: false, at: Date.now() - 60_000, sticky: false });
    daemon.scanBudgetMs = 100;
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, null, 'a complete pass survives in-flight probes past the budget');
    assert.strictEqual(daemon.routesByName.has('shop'), true);
  } finally {
    await daemon.stop();
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon: aborted lsof with partial output never publishes a snapshot; a later benign empty scan does', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-daemon-abort-'));
  let impl = async () => [shopListener(dir)];
  const daemon = new Daemon({
    dir,
    config: { bind: 'wildcard', port: 0, fallbackPort: 0, control: false },
    refreshMs: 3_600_000, // only explicit refresh() calls in this test
    listListeners: (opts) => impl(opts),
  });

  let restore = null;
  try {
    await daemon.start();
    assert.strictEqual(daemon.routesByName.has('shop'), true);

    // Real listListenersAsync against a wedged lsof that emitted well-formed
    // partial output before hanging: the pass must degrade, not republish.
    // (exec sleep so the timeout kill reaches the shim process itself.)
    restore = withLsofShim(
      '#!/bin/sh\nprintf \'p123\\0cnode\\nn127.0.0.1:3000\\n\'\nexec sleep 30\n'
    );
    impl = (opts) => listListenersAsync({ ...opts, timeoutMs: 300 });

    await daemon.refresh();
    assert.match(daemon.lastScanError, /listener scan failed/);
    assert.strictEqual(daemon.routesByName.has('shop'), true, 'aborted scan must not look like "all projects stopped"');

    // Benign no-match (silent exit 1) IS a valid empty scan.
    restore();
    restore = withLsofShim('#!/bin/sh\nexit 1\n');
    impl = (opts) => listListenersAsync(opts);
    await daemon.refresh();
    assert.strictEqual(daemon.lastScanError, null);
    assert.strictEqual(daemon.routesByName.has('shop'), false, 'a genuine empty scan publishes an empty list');
  } finally {
    if (restore) restore();
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
