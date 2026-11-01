#!/usr/bin/env node
'use strict';

// Local discovery benchmark / diagnostic path. No CI, no dependencies.
//
// Measures one discovery pass under synthetic listener loads of 0, 10, 50 and
// 200 listeners:
//
//   pipeline layer  - enrichAsync + detectInspectors + resolveRoutes called
//                     directly with synthetic listeners (mock scan input, real
//                     ps/lsof subprocesses via PATH-counting shims).
//   daemon layer    - a full Daemon with a real loopback gateway + control
//                     socket and synthetic listeners pointed at a real local
//                     upstream. Reports scan duration, event-loop lag and
//                     proxy/control request latency with and without a
//                     concurrent scan.
//
// All numbers are LOCAL SINGLE-SESSION measurements on one development
// machine, not statistical benchmarks. ps/lsof are wrapped by /bin/sh shims
// that count invocations; that adds identical shell-spawn overhead on both
// sides of a before/after comparison.
//
// Usage: node scripts/bench-discovery.js [--sizes 0,10,50,200] [--passes 3] [--json out.json]

const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const http = require('http');
const { monitorEventLoopDelay } = require('perf_hooks');
const { execFile, execFileSync } = require('child_process');

const {
  enrichAsync,
  detectInspectors,
  resolveRoutes,
} = require('../lib/discover');
const { getProcessStartTimeAsync } = require('../lib/process');
const { Daemon } = require('../lib/daemon');

// ---- CLI --------------------------------------------------------------------

const argv = process.argv.slice(2);
function argValue(name, fallback) {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
}
const SIZES = argValue('sizes', '0,10,50,200').split(',').map(Number).filter((n) => Number.isInteger(n) && n >= 0);
const PASSES = Math.max(1, Number(argValue('passes', '3')));

// ---- subprocess counting shims ----------------------------------------------

const benchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-bench-'));
const spawnLog = path.join(benchDir, 'spawns.log');
let restorePath = null;

function installCountingShims() {
  const shimDir = path.join(benchDir, 'shim');
  fs.mkdirSync(shimDir);
  for (const [name, real] of [['ps', '/bin/ps'], ['lsof', '/usr/sbin/lsof']]) {
    if (!fs.existsSync(real)) throw new Error(`expected ${real} to exist`);
    const shim = path.join(shimDir, name);
    fs.writeFileSync(shim, `#!/bin/sh\necho ${name} >> '${spawnLog}'\nexec ${real} "$@"\n`);
    fs.chmodSync(shim, 0o755);
  }
  restorePath = process.env.PATH;
  process.env.PATH = `${shimDir}:${process.env.PATH}`;
}

function uninstallCountingShims() {
  if (restorePath !== null) process.env.PATH = restorePath;
}

function spawnCounts() {
  const lines = fs.existsSync(spawnLog) ? fs.readFileSync(spawnLog, 'utf8').split('\n').filter(Boolean) : [];
  return {
    ps: lines.filter((l) => l === 'ps').length,
    lsof: lines.filter((l) => l === 'lsof').length,
  };
}

// ---- helpers ------------------------------------------------------------------

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function stats(values) {
  if (!values.length) return { n: 0, median: 0, max: 0 };
  return { n: values.length, median: median(values), max: Math.max(...values) };
}

// Samples event-loop delay with perf_hooks.monitorEventLoopDelay (a naive
// setInterval-drift monitor misreports under subprocess load because Node
// coalesces timers). Reports p99 and max in ms.
function startLagMonitor() {
  const histogram = monitorEventLoopDelay({ resolution: 20 });
  histogram.enable();
  return {
    stop() {
      histogram.disable();
      return { p99: histogram.percentile(99) / 1e6, max: histogram.max / 1e6 };
    },
  };
}

// One real HTTP GET through the loopback gateway. The name lookup is pinned
// to 127.0.0.1 so macOS getaddrinfo/threadpool noise does not distort the
// gateway+upstream latency the daemon can actually influence; only 200
// responses count as samples.
function proxyLatencyOnce(port, name) {
  const started = process.hrtime.bigint();
  return new Promise((resolve) => {
    const req = http.get(
      {
        host: '127.0.0.1',
        port,
        path: '/',
        headers: { host: `${name}.localhost` },
        lookup: (h, o, done) => done(null, '127.0.0.1', 4),
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode === 200 ? Number(process.hrtime.bigint() - started) / 1e6 : null));
        res.on('error', () => resolve(null));
      }
    );
    req.on('error', () => resolve(null));
    setTimeout(() => {
      req.destroy();
      resolve(null);
    }, 5000).unref();
  });
}

// One control request over the real unix socket (as the GUI client does).
function controlLatencyOnce(sockFile) {
  const started = process.hrtime.bigint();
  return new Promise((resolve) => {
    const socket = net.connect(sockFile);
    let buf = '';
    const finish = () => {
      socket.destroy();
      resolve(Number(process.hrtime.bigint() - started) / 1e6);
    };
    socket.on('connect', () => socket.write(JSON.stringify({ cmd: 'status' }) + '\n'));
    socket.on('data', (d) => {
      buf += d.toString('utf8');
      if (buf.includes('\n')) finish();
    });
    socket.on('error', () => finish());
    setTimeout(() => finish(), 5000).unref();
  });
}

// ---- synthetic listeners --------------------------------------------------------

// Harvest real pids once per script run (via the absolute ps path, before
// shims are active) so every layer and pass uses the SAME pid set — otherwise
// pid drift between passes would add birth-persistence writes to the
// measurement. Extra synthetic pids are invented beyond the harvested set
// when more listeners are requested.
const harvestedPids = (() => {
  const out = execFileSync('/bin/ps', ['-axo', 'pid='], { encoding: 'utf8' });
  const pids = out.split('\n').map((l) => parseInt(l.trim(), 10)).filter((p) => p > 1);
  return pids;
})();

function harvestPids(count) {
  const harvested = harvestedPids.slice(0, count);
  while (harvested.length < count) {
    harvested.push(900000 + harvested.length); // nonexistent: lookup fails fast
  }
  return harvested;
}

function syntheticListeners(n, { withRoots, upstreamPort }) {
  if (n === 0) return [];
  const pids = harvestPids(n);
  const rootsDir = path.join(benchDir, 'roots');
  fs.mkdirSync(rootsDir, { recursive: true });
  return pids.map((pid, i) => {
    const root = withRoots ? path.join(rootsDir, `proj-${i}`) : undefined;
    if (root && !fs.existsSync(root)) fs.mkdirSync(root, { recursive: true });
    const l = {
      pid,
      port: upstreamPort || 49000 + (i % 900),
      command: i % 2 === 0 ? 'node' : 'vite',
      external: false,
    };
    if (withRoots) {
      l.cwd = root;
      l.root = root;
      l.suggestedName = `proj-${i}`;
    }
    return l;
  });
}

// ---- layer 1: pipeline ----------------------------------------------------------

async function benchPipeline(size, pass) {
  const listeners = syntheticListeners(size, { withRoots: false, upstreamPort: 0 });
  const cwdCache = new Map();
  const inspectorCache = new Map();
  let startInFlight = 0;
  let startMax = 0;
  const getStartTime = async (pid) => {
    startInFlight += 1;
    startMax = Math.max(startMax, startInFlight);
    try {
      return await getProcessStartTimeAsync(pid);
    } finally {
      startInFlight -= 1;
    }
  };

  const before = spawnCounts();
  const lag = startLagMonitor();
  const started = process.hrtime.bigint();
  const enriched = await enrichAsync(listeners, cwdCache, { getStartTime });
  await detectInspectors(enriched, inspectorCache);
  resolveRoutes({ listeners: enriched });
  const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
  const lagStats = lag.stop();
  const after = spawnCounts();

  return {
    layer: 'pipeline',
    size,
    pass,
    durationMs,
    subprocesses: { ps: after.ps - before.ps, lsof: after.lsof - before.lsof },
    maxStartLookupConcurrency: startMax,
    eventLoopLagMs: lagStats,
  };
}

// ---- layer 2: daemon ------------------------------------------------------------

async function benchDaemon(size, pass) {
  const upstream = await new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200);
      res.end('bench');
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-bench-daemon-'));
  // Build the listener pool once (fs work outside the measured window); each
  // scan gets fresh shallow copies, as real lsof output would.
  const pool = syntheticListeners(size, { withRoots: true, upstreamPort: upstream.port });
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', port: 0, fallbackPort: 0, loopbackPort: 0 },
    refreshMs: 3_600_000, // only explicit refresh() calls are measured
    listListeners: async () => pool.map((l) => ({ ...l })),
  });

  const result = { layer: 'daemon', size, pass };
  try {
    await daemon.start(); // warm-up pass (not measured)

    // Idle latency baseline (no scan running).
    const idleProxy = [];
    const idleControl = [];
    for (let i = 0; i < 20; i += 1) idleProxy.push(await proxyLatencyOnce(daemon.activePort, 'proj-0'));
    for (let i = 0; i < 20; i += 1) idleControl.push(await controlLatencyOnce(daemon.sockFile));

    // Concurrent scan: fire proxy/control request bursts WHILE refresh runs.
    const before = spawnCounts();
    const lag = startLagMonitor();
    const started = process.hrtime.bigint();
    const scanPromise = daemon.refresh();
    const underScanProxy = [];
    const underScanControl = [];
    for (let i = 0; i < 20; i += 1) {
      underScanProxy.push(proxyLatencyOnce(daemon.activePort, 'proj-0'));
      underScanControl.push(controlLatencyOnce(daemon.sockFile));
    }
    await scanPromise;
    result.scanDurationMs = Number(process.hrtime.bigint() - started) / 1e6;
    result.eventLoopLagMs = lag.stop();
    const after = spawnCounts();
    result.subprocesses = { ps: after.ps - before.ps, lsof: after.lsof - before.lsof };
    result.proxyIdleMs = stats(idleProxy.filter((v) => v !== null));
    result.proxyUnderScanMs = stats((await Promise.all(underScanProxy)).filter((v) => v !== null));
    result.controlIdleMs = stats(idleControl);
    result.controlUnderScanMs = stats(await Promise.all(underScanControl));
    result.routes = daemon.routes.length;
  } finally {
    await daemon.stop();
    upstream.server.closeAllConnections();
    await new Promise((r) => upstream.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
  return result;
}

// ---- main -----------------------------------------------------------------------

function environment() {
  const cpu = os.cpus()[0] || {};
  return {
    date: new Date().toISOString(),
    platform: `${os.platform()} ${os.release()} (${os.arch()})`,
    cpu: `${cpu.model || 'unknown'} x${os.cpus().length}`,
    node: process.version,
    note: 'ps/lsof run through /bin/sh counting shims (identical overhead on both sides of a comparison)',
  };
}

async function main() {
  installCountingShims();
  const results = { environment: environment(), pipeline: [], daemon: [] };
  try {
    for (const size of SIZES) {
      for (let pass = 1; pass <= PASSES; pass += 1) {
        results.pipeline.push(await benchPipeline(size, pass));
      }
      for (let pass = 1; pass <= PASSES; pass += 1) {
        results.daemon.push(await benchDaemon(size, pass));
      }
    }
  } finally {
    uninstallCountingShims();
  }

  // Console report: median over passes per size.
  console.log(`environment: ${results.environment.platform}, ${results.environment.cpu}, node ${results.environment.node}`);
  console.log(`local single-session measurement, median of ${PASSES} pass(es) per size\n`);
  console.log('pipeline layer (synthetic listeners, real ps/lsof subprocesses):');
  console.log('  size | scan ms | ps spawns | lsof spawns | max start-lookup concurrency | loop lag max ms');
  for (const size of SIZES) {
    const rows = results.pipeline.filter((r) => r.size === size);
    console.log(
      `  ${String(size).padStart(4)} | ${median(rows.map((r) => r.durationMs)).toFixed(1).padStart(7)} | ` +
      `${String(median(rows.map((r) => r.subprocesses.ps))).padStart(9)} | ` +
      `${String(median(rows.map((r) => r.subprocesses.lsof))).padStart(11)} | ` +
      `${String(median(rows.map((r) => r.maxStartLookupConcurrency))).padStart(28)} | ` +
      `${median(rows.map((r) => r.eventLoopLagMs.max)).toFixed(2)}`
    );
  }
  console.log('\ndaemon layer (real gateway + control socket, concurrent scan):');
  console.log('  size | scan ms | ps/lsof | loop lag p99/max ms | proxy idle p50/max ms | proxy during scan p50/max ms | control idle p50/max ms | control during scan p50/max ms');
  for (const size of SIZES) {
    const rows = results.daemon.filter((r) => r.size === size);
    // Aggregate over passes: median of per-pass medians, max of per-pass maxes.
    const agg = (key) => ({
      median: median(rows.map((r) => r[key].median)),
      max: Math.max(...rows.map((r) => r[key].max)),
    });
    const fmt = (a) => `${a.median.toFixed(1)}/${a.max.toFixed(1)}`;
    const lagP99 = median(rows.map((r) => r.eventLoopLagMs.p99));
    const lagMax = Math.max(...rows.map((r) => r.eventLoopLagMs.max));
    console.log(
      `  ${String(size).padStart(4)} | ${median(rows.map((r) => r.scanDurationMs)).toFixed(1).padStart(7)} | ` +
      `${median(rows.map((r) => r.subprocesses.ps))}/${median(rows.map((r) => r.subprocesses.lsof))} | ` +
      `${lagP99.toFixed(1)}/${lagMax.toFixed(1)}`.padEnd(21) + ' | ' +
      `${fmt(agg('proxyIdleMs')).padStart(21)} | ` +
      `${fmt(agg('proxyUnderScanMs')).padStart(28)} | ` +
      `${fmt(agg('controlIdleMs')).padStart(23)} | ` +
      `${fmt(agg('controlUnderScanMs')).padStart(29)}`
    );
  }

  const jsonOut = argValue('json', null);
  if (jsonOut) {
    fs.writeFileSync(jsonOut, JSON.stringify(results, null, 2) + '\n');
    console.log(`\nraw results written to ${jsonOut}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
