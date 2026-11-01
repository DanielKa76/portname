'use strict';

const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { listListenersAsync, enrichAsync, resolveRoutes, detectInspectors, ignoredCommandsFilter } = require('./discover');
const { getProcessStartTimesAsync, runBounded } = require('./process');
const { createGateway, listenGateway } = require('./proxy');
const { connectionPolicyViolation } = require('./authorize');
const { BonjourAnnouncer } = require('./expose');
const { ShareManager, validateTtlMinutes } = require('./share');
const { Registry } = require('./registry');
const { ControlError } = require('./errors');
const { acquireInstanceLock, InstanceLockError } = require('./instance-lock');
const { localBrowserUrl, lanBrowserUrl } = require('./urls');
const { ConfigError, ensurePrivateDir, socketPathProblem } = require('./config');
const { isStablePayloadEntry, readManifest, stablePayloadDir } = require('./bundleinstall');

const REFRESH_MS = 3000;
const PROTOCOL_VERSION = 1;
const MAX_CONTROL_LINE = 64 * 1024;
// Upper bound for waiting on owned resources (share tunnels, gateway) during
// stop(); every participant has its own smaller bound, this is the backstop.
const STOP_TIMEOUT_MS = 5000;
// Upper bound for one whole refresh pass (lsof scan + enrichment + inspector
// detection). Individual subprocess calls are bounded (lsof 5s, ps/cwd 3s,
// inspector probes 200ms wall clock); the budget additionally caps the whole
// cycle. A pass that exceeds it starts no new subprocess work, keeps the
// previous routes and reports the degraded scan.
const SCAN_BUDGET_MS = 6000;

// Discovery freshness policy for public share DECISIONS (deliberately
// separated from the last displayed scan):
// - `routeFreshnessMs`: a new public share — and, symmetrically, a new WLAN
//   exposure — may only start while the route it targets was verified by a
//   SUCCESSFUL discovery scan within this window. The regular scan period is
//   REFRESH_MS, so under healthy conditions the verification is a few seconds
//   old at most.
// - `shareVerifyGraceMs` / `lanVerifyGraceMs`: an ACTIVE share / an exposed
//   WLAN target whose binding was last verified longer ago than this (i.e.
//   discovery kept failing that long) is revoked. A single failed scan
//   defers revocation; sustained failure must not keep a share or a WLAN
//   exposure alive indefinitely. Both bounds are injectable for tests.
//
// Polling honesty: revocation happens on the next refresh pass after the
// deadline (degraded passes run the deadline check; a pass costs at most
// SCAN_BUDGET_MS and passes start every REFRESH_MS), so teardown latency is
// bounded by roughly one scan period past the deadline — never 0 ms.
const ROUTE_FRESHNESS_MS = 10000;
const SHARE_VERIFY_GRACE_MS = 20000;
const LAN_VERIFY_GRACE_MS = 20000;
// Upper bound for one router lookup as a whole (route and arp runs, see
// resolveGatewayMac): every `expose on` and every pass sharing it resumes
// by then, whatever a child process does.
const GATEWAY_LOOKUP_TIMEOUT_MS = 3500;
// How often a successful scan starts pruning stale auto-name reservations
// (Registry.findGoneNameRoots + pruneNames). The first successful scan after
// a start always does. Measured on the monotonic clock.
const NAMES_PRUNE_INTERVAL_MS = 60 * 60 * 1000;

// Daemon lifecycle: STARTING -> RUNNING -> STOPPING -> STOPPED. After
// STOPPING begins, nothing may publish anymore: no routes, no Bonjour
// registrations, no share activations — not even from a scan already in
// flight when stop() was called.
const PUBLISHING_STATES = new Set(['STARTING', 'RUNNING']);

// IPv4 subnet identity "a.b.c.d/prefix" of an interface address, or null.
function networkId(address, netmask) {
  if (!net.isIPv4(String(address || '')) || !net.isIPv4(String(netmask || ''))) return null;
  const toInt = (ip) => ip.split('.').reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
  const mask = toInt(netmask);
  const base = (toInt(address) & mask) >>> 0;
  const prefix = mask.toString(2).split('').filter((bit) => bit === '1').length;
  return `${[24, 16, 8, 0].map((shift) => (base >>> shift) & 255).join('.')}/${prefix}`;
}

// Read-only helper for the router lookup below: stdout, or null on any
// failure (missing tool, no such route, timeout). Bounded like the discovery
// helpers (runBounded: SIGKILL escalation, settles on its own timer), so a
// child that ignores SIGTERM or hangs in the kernel cannot hold the lookup.
function runRouterTool(cmd, args) {
  return runBounded(cmd, args, { timeoutMs: 1000, maxBuffer: 64 * 1024 }).then(({ stdout }) => stdout, () => null);
}

// Whether something accepts connections on a Unix socket path. A stale file
// left by a crashed daemon refuses at once; no answer within the timeout
// counts as alive (refusing to start is the safe side of an unclear verdict,
// as for the instance lock).
function socketAnswers(sockPath, timeoutMs = 500) {
  return new Promise((resolve) => {
    let done = false;
    const sock = net.connect(sockPath);
    const finish = (alive) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(alive);
    };
    const timer = setTimeout(() => finish(true), timeoutMs);
    sock.once('connect', () => finish(true));
    sock.once('error', () => finish(false));
  });
}

// MAC address of the default gateway of the selected LAN interface, or null
// (no router on it, not in the ARP cache yet, not macOS). Unprivileged and
// read-only: the interface-scoped default route (`route -n get -ifscope`,
// with the unscoped one as fallback, so an active VPN does not hide the LAN
// router) and the ARP cache (`arp -n`). The subnet alone cannot tell apart
// networks that share a router default range (192.168.178.0/24 on every
// Fritz!Box, 172.20.10.0/28 on every iPhone hotspot) or a rogue AP that
// hands out the victim's home range. The SSID is not used on purpose:
// reading it requires Location permission on current macOS.
async function resolveGatewayMac(lan, { platform = process.platform, run = runRouterTool } = {}) {
  if (platform !== 'darwin' || !lan || !lan.name) return null;
  const field = (out, name) => {
    const m = new RegExp(`^\\s*${name}:\\s*(\\S+)\\s*$`, 'm').exec(out || '');
    return m ? m[1] : null;
  };
  let gateway = null;
  for (const args of [['-n', 'get', '-ifscope', lan.name, 'default'], ['-n', 'get', 'default']]) {
    const out = await run('/sbin/route', args);
    if (field(out, 'interface') === lan.name && net.isIPv4(field(out, 'gateway') || '')) {
      gateway = field(out, 'gateway');
      break;
    }
  }
  if (!gateway) return null;
  const arp = await run('/usr/sbin/arp', ['-n', gateway]);
  for (const m of String(arp || '').matchAll(/ at ([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5}) on (\S+)/gi)) {
    // macOS prints octets without leading zeros ("0:1e:c2:a:b:c").
    if (m[2] === lan.name) return m[1].toLowerCase().split(':').map((o) => o.padStart(2, '0')).join(':');
  }
  return null;
}

// Stored and compared instead of the MAC itself, which is a location
// identifier (Wi-Fi geolocation databases): config.json keeps only a
// truncated hash, and status never carries either.
function gatewayFingerprint(mac) {
  return crypto.createHash('sha256').update(`portname-lan-gateway:${mac}`).digest('hex').slice(0, 16);
}

const lanKey = (lan) => `${lan.name}|${lan.address}|${lan.netmask}`;

// Whether two network identities ({ network, gateway }, see #networkOf) name
// the same network: the same subnet and, where both routers are identified,
// the same router. The address within the subnet does not count (a DHCP
// renewal, Wi-Fi vs. Ethernet of the same LAN); an unknown subnet never
// matches.
function sameNetwork(a, b) {
  return a.network !== null && a.network === b.network &&
    (a.gateway === null || b.gateway === null || a.gateway === b.gateway);
}

// The confirmed endpoint as clients see it: the router fingerprint stays
// internal (nothing on the client side can act on it). `subnetOnly` tells
// whether the network half is the subnet alone, because no router could be
// identified when it was confirmed: then any network that uses the same
// address range counts as the confirmed one.
function publicExposureTarget(target) {
  if (!target) return null;
  const network = target.network ?? null;
  return { port: target.port, command: target.command ?? null, network, subnetOnly: network !== null && !target.gateway };
}

// Build identity of THIS daemon process, read once: the package version, the
// Node runtime actually serving the gateway, and — when running from the
// installed app payload — the payload manifest id. Replacing the app does
// not update the LaunchAgent's payload, so clients compare these against
// their own build to detect a stale background service.
function readBuildInfo(entryDir = __dirname) {
  let payloadId = null;
  if (isStablePayloadEntry(entryDir)) {
    const manifest = readManifest(stablePayloadDir());
    payloadId = (manifest && typeof manifest.payloadId === 'string' && manifest.payloadId) || null;
  }
  return { daemonVersion: require('../package.json').version, runtimeVersion: process.version, payloadId };
}

// The daemon owns all long-lived state: the host gateway on port 80 (or the
// explicitly configured bind), the Bonjour announcer, the share manager, and
// a control socket for the CLI.
class Daemon {
  #state = 'STOPPED';
  #stopPromise = null;
  constructor({
    dir,
    config = {},
    refreshMs = REFRESH_MS,
    scanBudgetMs = SCAN_BUDGET_MS,
    routeFreshnessMs = ROUTE_FRESHNESS_MS,
    shareVerifyGraceMs = SHARE_VERIFY_GRACE_MS,
    lanVerifyGraceMs = LAN_VERIFY_GRACE_MS,
    gatewayLookupTimeoutMs = GATEWAY_LOOKUP_TIMEOUT_MS,
    stopTimeoutMs = STOP_TIMEOUT_MS,
    namesPruneIntervalMs = NAMES_PRUNE_INTERVAL_MS,
    log = () => {},
    listListeners: listFn = listListenersAsync,
    // Process start-time lookup for enrichment: by default one batched `ps`
    // per pass for every pid (getStartTimes). Tests may inject a per-pid
    // lookup (getStartTime) instead, which then takes precedence.
    getStartTime: getStartTimeFn = null,
    getStartTimes: getStartTimesFn = getProcessStartTimesAsync,
    // Router lookup for the network binding of WLAN exposures (injectable
    // for tests; see resolveGatewayMac).
    resolveGatewayMac: resolveGatewayMacFn = resolveGatewayMac,
    announcer = null,
    buildInfo = readBuildInfo(),
  } = {}) {
    this.dir = dir;
    this.config = { bind: 'wildcard', port: 80, fallbackPort: 7777, loopbackPort: 7777, ...config };
    this.refreshMs = refreshMs;
    this.scanBudgetMs = scanBudgetMs;
    this.routeFreshnessMs = routeFreshnessMs;
    this.shareVerifyGraceMs = shareVerifyGraceMs;
    this.lanVerifyGraceMs = lanVerifyGraceMs;
    this.gatewayLookupTimeoutMs = gatewayLookupTimeoutMs;
    this.stopTimeoutMs = stopTimeoutMs;
    this.namesPruneIntervalMs = namesPruneIntervalMs;
    this.namesPrunedAt = -Infinity;
    this.namesPrune = null; // last background prune (test seam)
    this.namesPruneRunning = false;
    this.liveRoots = new Set();
    this.log = log;
    this.listListeners = listFn;
    this.getStartTime = getStartTimeFn;
    this.getStartTimes = getStartTimesFn;
    this.resolveGatewayMac = resolveGatewayMacFn;
    // Router identity of the current LAN: { key, fingerprint, at } — key is
    // the interface/address/netmask it was looked up for, fingerprint null
    // when no router could be identified. Refreshed per scan pass while an
    // exposure is requested and before every `expose on`.
    this.lanGateway = null;
    // New per daemon run: lets clients detect a daemon restart and discard
    // stale target/share bindings.
    this.daemonInstanceId = crypto.randomUUID();
    this.protocolVersion = PROTOCOL_VERSION;
    this.buildInfo = buildInfo;
    this.routes = [];
    this.stale = [];
    this.routesByName = new Map();
    this.activePort = null;
    this.bindInfo = null;
    this.sockFile = path.join(dir, 'daemon.sock');
    this.registry = null;
    this.gateway = null;
    this.announcer = announcer;
    this.shares = new ShareManager({ dir, log });
    this.cloudflaredBin = this.config.cloudflaredBin || 'cloudflared';
    this.control = null;
    this.refreshTimer = null;
    this.cwdCache = new Map();
    // Bounded-retry state for transient negative lookups (see lib/discover.js
    // enrichAsync): negative cwd results and root canonicalization TTLs.
    this.cwdRetryAt = new Map();
    this.rootCache = new Map();
    this.inspectorCache = new Map();
    this.lastScanError = null;
    // Freshness bookkeeping: timestamp of the last successful discovery pass
    // and the enriched listeners it observed (unfiltered — manual targets are
    // verified against every listener, not only HTTP-suitable ones).
    this.lastGoodScanAt = null;
    this.lastVerifiedListeners = [];
    // LAN freshness bookkeeping: identity -> { host, port, processKey,
    // verifiedAt }. ONE slot per identity: a successful pass re-credits it by
    // overwriting the record with the exact endpoint tuple it observed, and a
    // known target mutation (repoint, remove, primary port change) deletes it
    // before the next pass. The desired WLAN exposure is the persisted
    // registry flag; the CURRENTLY ALLOWED exposure is flag AND a record that
    // matches the route's tuple within lanVerifyGraceMs. Records age out
    // between passes — that is the bounded WLAN verification deadline.
    this.lanVerifiedAt = new Map();
    // Names whose PUBLIC share verification was invalidated by an accepted,
    // security-relevant target mutation (manual entry remove, manual repoint,
    // primary port switch). The stale route snapshot stays DISPLAYED on
    // purpose (failed scans keep it), but it must not stay startable: until
    // the next completed successful pass re-verifies the world, a share
    // start for these names is refused with SHARE_TARGET_UNVERIFIED. Cleared
    // by every completed successful pass — exactly where lastGoodScanAt is
    // stamped, so an in-flight pass can never clear an invalidation made
    // after it (the stamp and the clear are one synchronous block).
    this.publicVerifyInvalid = new Set();
    // Auto-discovery skips known non-HTTP listeners (databases, SSH, …);
    // `ignoreCommands` in config.json extends the built-in set. Manual
    // registrations bypass this deliberately.
    this.listenerFilter = ignoredCommandsFilter(this.config.ignoreCommands);
  }

  get state() {
    return this.#state;
  }

  async start() {
    if (this.#state === 'STARTING' || this.#state === 'RUNNING') {
      throw new Error('daemon is already running');
    }
    if (this.#state === 'STOPPING') {
      throw new Error('daemon is stopping');
    }
    this.#state = 'STARTING';
    try {
      // A control socket path the OS would truncate can never work: refuse
      // before anything is created, locked or bound.
      const sockProblem = this.config.control !== false ? socketPathProblem(this.sockFile) : null;
      if (sockProblem) throw new ConfigError(sockProblem);
      // The parent path must already be private (0700, owned by us, not a
      // symlink) before anything appears in it — this also has to run before
      // acquireInstanceLock(), which creates the state dir itself.
      ensurePrivateDir(this.dir);
      // Exclusive ownership first: no orphan cleanup, no socket unlink, no
      // resource bind before this instance verifiably owns the state dir.
      // A second daemon on the same dir fails here with DAEMON_ALREADY_RUNNING;
      // a lock left by a crashed daemon is stolen only via PID + start time.
      this.instanceLock = await acquireInstanceLock({
        dir: this.dir,
        instanceId: this.daemonInstanceId,
        log: this.log,
      });
    } catch (err) {
      this.#state = 'STOPPED';
      throw err;
    }

    try {
      // A live daemon that holds no instance lock (an older version, or a
      // lock file removed by hand) still answers on the socket: refuse
      // before this start touches anything of it — its registry, its
      // recorded tunnel and Bonjour children, the gateway port.
      if (this.config.control !== false) await this.#refuseLiveSocket();
      this.registry = new Registry(this.dir);
      // A fresh registry reloads config.json: prune it on the first scan.
      this.namesPrunedAt = -Infinity;
      this.namesPruneRunning = false;
      this.shares.cleanupOrphans();

      this.gateway = createGateway({
        getRoute: (name) => this.routesByName.get(name) || null,
        // WLAN exposure is desired (persisted flag) for THIS endpoint (the
        // port + command the user confirmed) AND currently allowed (fresh
        // target verification bound to the route's endpoint tuple). The
        // gateway passes the route additively as a second argument; a call
        // without a route has no endpoint to bind a verification to and
        // fails closed.
        isExposed: (identity, route) => {
          if (!route) return false;
          return this.registry.isExposed(identity) &&
            this.#exposureConfirmed(identity, route) &&
            this.#lanFreshRoute(identity, route);
        },
        log: this.log,
      });
      const bind = await listenGateway(this.gateway, {
        mode: this.config.bind,
        port: this.config.port,
        fallbackPort: this.config.fallbackPort,
        loopbackPort: this.config.loopbackPort,
      });
      this.activePort = bind.primary;
      this.bindInfo = this.config.bind === 'loopback' ? 'loopback' : 'wildcard';

      if (!this.announcer) {
        this.announcer = new BonjourAnnouncer({ port: this.activePort, dir: this.dir, log: this.log });
      }
      this.announcer.cleanupOrphans();

      // Awaited: a listen or chmod failure rejects start() into the teardown
      // below (lock released, gateway closed) instead of surfacing as an
      // uncaught exception after start() already reported success.
      if (this.config.control !== false) await this.#startControl();
      await this.refresh();
      // stop() may have begun while we were starting (e.g. during the first
      // scan): never publish RUNNING after STOPPING/STOPPED was reached.
      if (this.#state === 'STOPPING' || this.#state === 'STOPPED') {
        throw new Error('daemon was stopped during startup');
      }
      this.refreshTimer = setInterval(() => this.refresh().catch((e) => this.log('refresh-error', e.message)), this.refreshMs);
      this.#state = 'RUNNING';
      this.log('daemon', `listening (${this.bindInfo}) on port`, this.activePort);
      return this.activePort;
    } catch (err) {
      // Release whatever was already bound so a failed start leaves no
      // gateway/server/lock behind.
      try {
        await this.#teardown();
      } catch {}
      this.#state = 'STOPPED';
      throw err;
    }
  }

  async stop() {
    if (this.#state === 'STOPPED') return;
    if (this.#state === 'STOPPING') {
      // Idempotent: concurrent stop() calls join the same teardown.
      return this.#stopPromise;
    }
    this.#state = 'STOPPING';
    this.#stopPromise = this.#teardown().finally(() => {
      this.#state = 'STOPPED';
      this.#stopPromise = null;
    });
    return this.#stopPromise;
  }

  // Tear down every owned resource, bounded in time, and release the
  // instance lock last (the lock guards socket unlink and orphan cleanup).
  async #teardown() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    let timeoutHandle = null;
    const resources = (async () => {
      try {
        if (this.announcer) this.announcer.stopAll();
        await this.shares.stopAll();
      } finally {
        // A failing share teardown must not leave the gateway listening.
        if (this.gateway) await this.gateway.close();
      }
    })();
    // A resource failure after the timeout backstop already won must never
    // surface as an unhandled rejection; in-time failures are reported by
    // the race below.
    resources.catch(() => {});
    try {
      const bounded = Promise.race([
        resources,
        new Promise((resolve) => {
          timeoutHandle = setTimeout(resolve, this.stopTimeoutMs);
          if (timeoutHandle.unref) timeoutHandle.unref();
        }),
      ]);
      await bounded.finally(() => {
        if (timeoutHandle) clearTimeout(timeoutHandle);
      });
    } catch (err) {
      // Resource teardown failures must never skip control-socket cleanup
      // and lock release: a leaked lock would make the next start() fail
      // against this instance's own stale claim.
      this.log('daemon', 'teardown-error', (err && err.message) || String(err));
    }
    // Backstop for tunnels: a share teardown that did not finish in time (a
    // tunnel ignoring SIGTERM, many slow sequential stops) must not outlive
    // the daemon — the CLI exits right after stop(), and the per-share
    // SIGKILL timers are unref'd and would never fire.
    this.killChildrenSync();
    if (this.control) {
      // Closing removes only the private name the server was bound under
      // (see #startControl); the published path is removed here, and only
      // while it is still the socket this instance put there. A start that
      // failed before binding, or a socket another daemon placed at the path
      // meanwhile, is never touched.
      this.control.close();
      this.control = null;
      if (this.#ownsControlSocket()) {
        try {
          fs.unlinkSync(this.sockFile);
        } catch (err) {
          // already gone
        }
      }
    }
    this.#sockIdentity = null;
    if (this.instanceLock) {
      this.instanceLock.release();
      this.instanceLock = null;
    }
  }

  // Synchronous last resort for children that must never outlive this
  // process: every tunnel still known to the share manager gets SIGKILL and
  // Bonjour registrations are withdrawn. Used after the stop() backstop and
  // by the CLI's fatal-error path, where no async teardown can run anymore.
  // Children that already exited are untouched (ChildProcess.kill is a
  // no-op then), so a recycled PID is never signalled.
  killChildrenSync() {
    for (const share of this.shares.shares.values()) {
      try {
        if (share.cloudflared) share.cloudflared.kill('SIGKILL');
      } catch {}
    }
    try {
      if (this.announcer) this.announcer.stopAll();
    } catch {}
  }

  // Refresh barrier + coalescing. At most one discovery pass runs at a time;
  // callers arriving while a pass runs share ONE follow-up pass that starts
  // after the running one finishes. Because that follow-up starts only after
  // every currently-waiting caller, awaiting refresh() always guarantees a
  // pass that observed the caller's request — a mutation caller can await its
  // derived changes. Plain status queries never touch this chain. Once stop()
  // has begun, queued passes drain without publishing anything.
  #passRunning = false;
  #passDone = null;
  #followUpDone = null;

  refresh() {
    if (this.#passRunning) {
      if (!this.#followUpDone) {
        // Both handlers drain the follow-up slot: when the tracked pass is
        // rejected, the success handler is skipped and the follow-up must
        // still run — otherwise every later refresh() during the next pass
        // would keep reporting the old failure without any pass ever
        // observing the queued mutation.
        this.#followUpDone = this.#passDone.then(
          () => this.#executePass(true),
          () => this.#executePass(true)
        );
      }
      return this.#followUpDone;
    }
    return this.#executePass(false);
  }

  #executePass(isFollowUp) {
    // The follow-up slot is consumed the moment that pass starts: any caller
    // arriving later must be served by a pass starting after *their* call.
    if (isFollowUp) this.#followUpDone = null;
    this.#passRunning = true;
    const done = Promise.resolve().then(() => {
      if (!PUBLISHING_STATES.has(this.#state)) return undefined;
      return this.#runRefreshPass();
    }).finally(() => {
      if (this.#passDone === done) this.#passDone = null;
      this.#passRunning = false;
    });
    this.#passDone = done;
    return done;
  }

  async #runRefreshPass() {
    // Whole-cycle bound: one pass gets a fixed time budget. Each subprocess
    // call is individually bounded too; past the budget no new work starts.
    const deadline = Date.now() + this.scanBudgetMs;
    // Exclude active child PIDs (tunnels and Bonjour) from listener discovery
    const excludePids = [...this.shares.childPids(), ...(this.announcer ? this.announcer.childPids() : [])];
    // The router lookup for the network binding runs alongside the scan and
    // never rejects (a pass that returns early leaves it unawaited); only
    // needed while some requested exposure is bound to a router.
    const gatewayLookup = this.config.bind !== 'loopback' && this.registry && this.#routerBoundExposure()
      ? this.#refreshLanGateway()
      : null;
    let listeners;
    try {
      listeners = await this.listListeners({ excludePids });
    } catch (err) {
      // A failed scan must never look like "every project was stopped":
      // keep the previous routes and report the degraded scan. Share
      // revocation is deferred — but only up to the verification grace
      // window: sustained scan failure must not keep a public share alive
      // indefinitely.
      this.#noteScanOutcome(String((err && err.message) || err));
      await this.#revokeSharesMissingVerification();
      // Registry-backed decisions must also reach established connections
      // while scans keep failing: after `expose off` a LAN WebSocket/SSE must
      // not outlive the revocation just because discovery never succeeds.
      // Route/target checks stay deliberately scan-bound (a target identity
      // needs a verified scan; the exposure flag does not).
      this.#revokeExposedConnections();
      return;
    }
    // A scan that started before stop() must never publish anything.
    if (!PUBLISHING_STATES.has(this.#state)) return;
    // A timed-out or truncated scan arrives here as a rejection above; an
    // over-budget pass stops before enrichment instead of publishing a stale
    // half-cycle as fresh. A budget abort is a failed scan: degrade exactly
    // like the scan catch above (verification-grace share revoke +
    // exposure-only connection revoke; route/target checks stay scan-bound).
    if (Date.now() >= deadline) {
      this.#noteScanOutcome('scan budget exceeded during listener scan');
      await this.#revokeSharesMissingVerification();
      this.#revokeExposedConnections();
      return;
    }
    let httpListeners = null;
    let inspection = { overBudget: false };
    try {
      // Enrich UNFILTERED: manual targets are verified against every observed
      // listener (the HTTP filter is an auto-discovery filter, not an existence
      // filter — a manually registered postgres port must stay verifiable).
      // The start times of all pids of this pass come from one batched ps
      // (enrichAsync looks each distinct pid up once).
      listeners = await enrichAsync(listeners, this.cwdCache, {
        ...(this.getStartTime ? { getStartTime: this.getStartTime } : { getStartTimes: this.getStartTimes }),
        deadline,
        cwdRetryAt: this.cwdRetryAt,
        rootCache: this.rootCache,
      });
      if (!PUBLISHING_STATES.has(this.#state)) return;
      if (Date.now() >= deadline) {
        // A budget abort is a failed scan: degrade exactly like the scan
        // catch above (verification-grace share revoke + exposure-only
        // connection revoke) instead of publishing a stale half-cycle.
        this.#noteScanOutcome('scan budget exceeded during enrichment');
        await this.#revokeSharesMissingVerification();
        this.#revokeExposedConnections();
        return;
      }
      this.lastVerifiedListeners = listeners;
      httpListeners = listeners.filter(this.listenerFilter);
      // detectInspectors bounds the cache itself (verdicts of listeners that
      // are gone are dropped); flushing it here would discard every sticky
      // verdict and re-probe all live dev servers at once.
      inspection = await detectInspectors(httpListeners, this.inspectorCache, { deadline });
      if (!PUBLISHING_STATES.has(this.#state)) return;
    } catch (err) {
      // Enrichment/inspection failures degrade the pass the same way a failed
      // scan does: keep the previous routes, report the reason, and still run
      // the failure-path revocations (see the scan catch above).
      this.#noteScanOutcome(String((err && err.message) || err));
      await this.#revokeSharesMissingVerification();
      this.#revokeExposedConnections();
      return;
    }
    // Wall time alone would discard fully successful passes whose last
    // in-flight probes (each individually bounded to 200ms) ran a few ms
    // past the budget. Only a real abort — a listener skipped over budget —
    // makes the pass incomplete and degrades it; that abort is a failed scan
    // and degrades exactly like the scan catch above.
    if (inspection.overBudget) {
      this.#noteScanOutcome('scan budget exceeded during inspector detection');
      await this.#revokeSharesMissingVerification();
      this.#revokeExposedConnections();
      return;
    }
    // Exposure decisions below (Bonjour, long-lived connections) use the
    // router identity this pass looked up (individually time-bounded).
    if (gatewayLookup) {
      await gatewayLookup;
      if (!PUBLISHING_STATES.has(this.#state)) return;
    }
    // Listener births are recorded in memory before observe() persists them
    // (state.json); a refused write (full disk, read-only volume) must not
    // abort the pass like the auto-name save below: the routes, the
    // verification stamps and the share/WLAN binding checks of this pass
    // still run. A later successful save persists the births with the rest.
    try {
      this.registry.observe(httpListeners);
    } catch (err) {
      this.log('registry', 'state-save-failed', (err && err.message) || String(err));
    }

    const manualNames = new Set(Object.keys(this.registry.config.manual));
    const { routes, stale, namesChanged } = resolveRoutes({
      listeners: httpListeners,
      renames: this.registry.config.renames,
      names: this.registry.config.names,
      firstSeen: this.registry.firstSeen,
      manualNames,
      preferredPorts: this.registry.config.primaryPorts || {},
    });
    // Only a successful scan knows which projects are live, so the prune
    // starts here and never protects or drops a reservation on a guess.
    this.liveRoots = new Set(httpListeners.map((l) => l.root).filter(Boolean));
    const namesSeenChanged = this.registry.noteNamesSeen(this.liveRoots);
    if (!this.namesPruneRunning && performance.now() - this.namesPrunedAt >= this.namesPruneIntervalMs) {
      this.#startNamesPrune();
    }
    if (namesChanged || namesSeenChanged) {
      // Auto-assigned names stay in effect in memory and are persisted by
      // the next successful save; a refused write (e.g. config.json was
      // damaged by a hand edit) must not abort discovery.
      try {
        this.registry.saveConfig();
      } catch (err) {
        this.log('registry', 'save-failed', (err && err.message) || String(err));
      }
    }

    for (const m of this.registry.manualEntries()) {
      routes.push({
        ...m,
        root: null,
        pid: null,
        processKey: null,
        external: false,
        command: 'manual',
        cwd: null,
        since: 0,
      });
    }

    this.routes = routes;
    this.stale = stale;
    this.routesByName = new Map(routes.map((r) => [r.name, r]));
    // This pass completed successfully: it is now the freshest verified
    // discovery state, and the routes it observed back share verification.
    // Only now is the degraded state over: a pass that fails in a later
    // stage (enrichment, inspection) never reads as healthy in between.
    this.lastGoodScanAt = Date.now();
    this.#noteScanOutcome(null);
    // The world is re-verified: names invalidated by an earlier accepted
    // mutation become startable again (the routes above carry the
    // post-mutation registry). Same synchronous block as the stamp, so a
    // pass that started before a mutation can never clear an invalidation
    // made after it.
    this.publicVerifyInvalid.clear();
    this.lastVerifiedListeners = listeners;
    // Record which identities THIS pass actually verified for LAN exposure
    // purposes, bound to the exact endpoint tuple the pass observed (auto
    // routes are observed by construction; a manual target only when its
    // listener was seen on the pinned port). The one slot per identity is
    // overwritten on re-credit; a successful pass that does NOT observe the
    // tuple leaves the record to age unrefreshed — unless the pinned port is
    // now served by a different upstream host, which invalidates the record
    // outright. Entries not refreshed here hit the LAN verification deadline.
    for (const route of routes) {
      const identity = this.#routeIdentity(route);
      const routeGen = route.processKey || (route.pid != null ? String(route.pid) : null);
      if (route.root !== null) {
        this.lanVerifiedAt.set(identity, {
          host: route.upstreamHost || '127.0.0.1',
          port: route.port,
          processKey: routeGen,
          verifiedAt: this.lastGoodScanAt,
        });
      } else {
        const observed = this.#observedListener(route.port, route.upstreamHost);
        if (observed) {
          // Manual target: the observed listener on the pinned port is its
          // generation — credit exactly what was observed.
          this.lanVerifiedAt.set(identity, {
            host: observed.upstreamHost || '127.0.0.1',
            port: observed.port,
            processKey: observed.processKey || (observed.pid != null ? String(observed.pid) : null),
            verifiedAt: this.lastGoodScanAt,
          });
        } else if (
          this.lastVerifiedListeners.some(
            (l) => l.port === route.port && (l.upstreamHost || '127.0.0.1') !== (route.upstreamHost || '127.0.0.1')
          )
        ) {
          // The pinned port is now served by a different upstream host: the
          // record is not merely stale but wrong — drop it instead of letting
          // it age out within the grace window.
          this.lanVerifiedAt.delete(identity);
        }
        // else: the target was simply not observed — the record ages
        // unrefreshed under the existing grace semantics.
      }
    }

    // A revoked LAN exposure, a removed/renamed route or a moved target must
    // also reach connections that are already established (WebSockets, SSE):
    // they never issue another request, so per-request checks cannot see the
    // revocation.
    if (this.gateway) {
      this.gateway.revokeConnections((conn) => {
        const reason = connectionPolicyViolation(conn, {
          getRoute: (name) => this.routesByName.get(name) || null,
          isExposedIdentity: (identity) => {
            const route = this.routesByName.get(conn.name);
            return this.registry.isExposed(identity) && Boolean(route) && this.#exposureConfirmed(identity, route);
          },
          // Tuple-bound: connectionPolicyViolation has already proven the
          // current route equal to the connection's recorded tuple, so the
          // verification record must match that same route's endpoint.
          isLanFresh: (identity) => {
            const route = this.routesByName.get(conn.name);
            return route ? this.#lanFreshRoute(identity, route) : false;
          },
        });
        if (reason) this.log('gateway', 'revoked long-lived connection', conn.name, reason);
        return Boolean(reason);
      });
    }

    // Bonjour advertises only exposures whose current primary is still the
    // confirmed endpoint on the confirmed network: a project whose name moved
    // to another port or command (a newer listener of the same tree), or a
    // Mac that joined another network, is withdrawn — never announced for a
    // target or to a network nobody confirmed.
    const exposedNames = this.config.bind === 'loopback'
      ? []
      : this.routes
        .filter((r) => {
          const identity = this.#routeIdentity(r);
          return this.registry.isExposed(identity) && this.#exposureConfirmed(identity, r);
        })
        .map((r) => r.name);
    this.announcer.sync(exposedNames);

    // Bind share to route, port, and process generation
    for (const share of this.shares.status()) {
      const route = this.routesByName.get(share.name);
      let revokeReason = null;
      if (!route) {
        revokeReason = 'route no longer exists';
      } else if (route.port !== share.pinnedPort) {
        revokeReason = `port changed (${share.pinnedPort} -> ${route.port})`;
      } else if ((route.upstreamHost || '127.0.0.1') !== (share.pinnedHost || '127.0.0.1')) {
        revokeReason = `upstream host changed (${share.pinnedHost || '127.0.0.1'} -> ${route.upstreamHost || '127.0.0.1'})`;
      } else if (route.root === null) {
        // Manual target: the observed listener on the pinned port is its
        // generation. A port silently reused by a different process must kill
        // the public share even though the manual entry itself is unchanged.
        const observed = this.#observedListener(route.port, route.upstreamHost);
        if (!observed) {
          revokeReason = 'target listener no longer observed';
        } else if (share.pinnedPid !== null && (
          observed.pid !== share.pinnedPid ||
          // PID recycling keeps the pid but is a new process generation.
          (observed.processKey && share.pinnedProcessKey && observed.processKey !== share.pinnedProcessKey)
        )) {
          revokeReason = 'port now served by a different process';
        }
      } else if (share.pinnedProcessKey && route.processKey && route.processKey !== share.pinnedProcessKey) {
        revokeReason = 'process generation changed';
      } else if (route.pid !== null && share.pinnedPid !== null && route.pid !== share.pinnedPid) {
        revokeReason = 'process PID changed';
      }

      if (revokeReason) {
        this.log('share', `revoked (${revokeReason})`, share.name);
        await this.shares.stop(share.name);
      }
    }

    // Every share that survived this pass is verified by it.
    for (const share of this.shares.shares.values()) {
      share.lastVerifiedAt = this.lastGoodScanAt;
    }
  }

  // Records how a pass ended — the degraded reason reported as `scanError`,
  // or null after a successful pass — and writes each CHANGE to the daemon
  // log: the move into the degraded state, a different reason, and the
  // recovery. A failure that persists adds no line per pass (and the
  // logger's rate limit bounds whatever repeats).
  #noteScanOutcome(error) {
    if (error === this.lastScanError) return;
    if (error === null) this.log('discovery', 'recovered', `previous error: ${this.lastScanError}`);
    else this.log('discovery', 'scan-failed', error);
    this.lastScanError = error;
  }

  // The listener observed on port+host by the last successful scan (manual
  // targets have no own process generation; the observation is it).
  #observedListener(port, upstreamHost) {
    const wanted = upstreamHost || '127.0.0.1';
    return this.lastVerifiedListeners.find(
      (l) => l.port === port && (l.upstreamHost || '127.0.0.1') === wanted
    ) || null;
  }

  // Fail-safe for sustained discovery failure: an active share whose binding
  // was last verified longer ago than the grace window is revoked. A single
  // failed scan defers revocation (the previous snapshot must not drive a
  // teardown), but the window is bounded.
  async #revokeSharesMissingVerification() {
    const now = Date.now();
    for (const share of this.shares.status()) {
      // Shares carry the honest time of their last real target verification
      // (passed in at start, refreshed by every successful pass). A STARTING
      // share without one has never been verified and is not
      // staleness-killed mid-boot; with one, tunnel boot is bounded by the
      // same grace as every verified share — "tunnel ready" is not "target
      // just verified".
      if (share.state === 'STARTING' && !share.lastVerifiedAt) continue;
      const verifiedAt = share.lastVerifiedAt || 0;
      if (now - verifiedAt <= this.shareVerifyGraceMs) continue;
      this.log('share', `revoked (target verification stale: no successful discovery scan within ${this.shareVerifyGraceMs}ms)`, share.name);
      await this.shares.stop(share.name);
    }
  }

  // Whether `identity`'s target was verified by a successful discovery scan
  // within `withinMs` (defaults to the WLAN continuation grace). This is the
  // identity-scoped time half of WLAN exposure, used where no verified route
  // exists to compare a tuple against (degraded passes): it reads the last
  // known record without judging its endpoint.
  #lanFresh(identity, withinMs = this.lanVerifyGraceMs) {
    const rec = this.lanVerifiedAt.get(identity);
    return rec != null && Date.now() - rec.verifiedAt <= withinMs;
  }

  // Tuple-bound LAN freshness: the verification record must match the
  // CURRENT route's endpoint tuple — upstream host, port, and (for
  // auto-discovered routes) the process generation — and be younger than the
  // grace window. A record left over from a different port, host or process
  // never vouches for this route; without a record there is no proof at all.
  #lanFreshRoute(identity, route, withinMs = this.lanVerifyGraceMs) {
    const rec = this.lanVerifiedAt.get(identity);
    if (!rec) return false;
    if (Date.now() - rec.verifiedAt > withinMs) return false;
    if ((rec.host || '127.0.0.1') !== (route.upstreamHost || '127.0.0.1')) return false;
    if (rec.port !== route.port) return false;
    if (route.root !== null) {
      const routeGen = route.processKey || (route.pid != null ? String(route.pid) : null);
      if ((rec.processKey || null) !== (routeGen || null)) return false;
    }
    return true;
  }

  // A WLAN exposure is a decision about ONE endpoint (like a public share
  // start): the port and command of the primary the user confirmed with
  // `expose`. The name of a project follows its newest listener — a debug
  // endpoint, a second service or a moved dev server of the same tree can
  // take it over — so the exposure only applies while the current primary
  // is still that endpoint. A restart on the same port with the same command
  // stays exposed; anything else pauses the exposure ("target-changed")
  // until `expose` confirms the new endpoint. An exposure without a recorded
  // endpoint (written by an older daemon) is never confirmed
  // ("target-unconfirmed").
  #exposureTargetConfirmed(identity, route) {
    const target = this.registry.exposedTarget(identity);
    if (!target) return false;
    return target.port === route.port && (target.command ?? null) === (route.command ?? null);
  }

  // The exposure is also a decision about ONE network: the subnet the Mac
  // was on when `expose` confirmed it AND, when it could be identified, that
  // network's router (gateway MAC fingerprint). Another subnet, or the same
  // subnet behind another router (a café or hotel network with the same
  // default range, a rogue AP handing out the home range), pauses it
  // ("changed") until confirmed there. In the confirmed subnet, a router
  // that cannot be identified right now (e.g. just after wake, until the ARP
  // cache knows it again) pauses it too ("unidentified"): that heals with
  // the next successful lookup, or turns into "changed" once another router
  // is identified — it is never a network to confirm. A new DHCP address in
  // the same subnet, or Wi-Fi vs. Ethernet of the same LAN (same router),
  // keeps it. An exposure confirmed without an identified router is bound to
  // the subnet only. Without a recorded or a current subnet there is nothing
  // to compare (no LAN path, or an announcer that cannot report one) and
  // this half does not block ("confirmed").
  #exposureNetworkState(identity) {
    const target = this.registry.exposedTarget(identity);
    if (!target || !target.network) return 'confirmed';
    const current = this.#currentNetwork();
    if (current.network === null) return 'confirmed';
    if (current.network !== target.network) return 'changed';
    if (!target.gateway || current.gateway === target.gateway) return 'confirmed';
    return current.gateway === null ? 'unidentified' : 'changed';
  }

  #exposureNetworkConfirmed(identity) {
    return this.#exposureNetworkState(identity) === 'confirmed';
  }

  #exposureConfirmed(identity, route) {
    return this.#exposureTargetConfirmed(identity, route) && this.#exposureNetworkConfirmed(identity);
  }

  // The announcer's LAN interface selection — the same interface the
  // gateway authorizes LAN clients on — or null.
  #lanSelection() {
    if (!this.announcer || typeof this.announcer.getLan !== 'function') return null;
    return this.announcer.getLan() || null;
  }

  // Network identity of an interface selection: the LAN subnet
  // ("192.168.1.0/24") and the fingerprint of its router. The router
  // identity counts only when it was looked up for this very interface
  // address within lanVerifyGraceMs (wall clock, so a lookup from before a
  // sleep never vouches after wake).
  #networkOf(lan) {
    if (!lan) return { network: null, gateway: null };
    const g = this.lanGateway;
    const fresh = g !== null && g.key === lanKey(lan) && Date.now() - g.at <= this.lanVerifyGraceMs;
    return { network: networkId(lan.address, lan.netmask), gateway: fresh ? g.fingerprint : null };
  }

  #currentNetwork() {
    return this.#networkOf(this.#lanSelection());
  }

  // Whether some requested exposure is bound to a router: only then does a
  // scan pass need the current router identity (`expose on` looks it up
  // itself). Subnet-only bindings never spawn route/arp per pass.
  #routerBoundExposure() {
    return this.registry.exposedIdentities().some((identity) => {
      const target = this.registry.isExposed(identity) ? this.registry.exposedTarget(identity) : null;
      return Boolean(target && target.gateway);
    });
  }

  // The router lookup in flight, if any: { key, promise }.
  #gatewayLookup = null;

  // Looks up the current LAN's router (bounded, never rejects — also when
  // reading the interface selection throws). Callers for the same interface
  // address share the lookup in flight: route/arp run once, and the callers
  // resume in the order they asked, which keeps concurrent `expose on`
  // requests in arrival order. A failed lookup keeps the last identity of the
  // SAME interface address, aging from its own lookup time, so a single miss
  // does not flap the exposure. A lookup whose interface address changed
  // while it ran records nothing: it never vouches for the network the Mac
  // is on now.
  #refreshLanGateway() {
    let lan = null;
    try {
      lan = this.#lanSelection();
    } catch {
      lan = null;
    }
    if (!lan) {
      this.lanGateway = null;
      return Promise.resolve();
    }
    const key = lanKey(lan);
    if (this.#gatewayLookup && this.#gatewayLookup.key === key) return this.#gatewayLookup.promise;
    const lookup = { key, promise: null };
    lookup.promise = (async () => {
      // Bounded as a whole too: a lookup still running after
      // gatewayLookupTimeoutMs counts as failed, and its late answer is
      // dropped.
      let timer = null;
      const mac = await Promise.race([
        (async () => this.resolveGatewayMac(lan))().catch(() => null),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(null), this.gatewayLookupTimeoutMs);
          if (timer.unref) timer.unref();
        }),
      ]);
      clearTimeout(timer);
      let current = null;
      try {
        current = this.#lanSelection();
      } catch {
        current = null;
      }
      if (!current || lanKey(current) !== key) return;
      if (mac) {
        this.lanGateway = { key, fingerprint: gatewayFingerprint(mac), at: Date.now() };
      } else if (!this.lanGateway || this.lanGateway.key !== key) {
        this.lanGateway = { key, fingerprint: null, at: Date.now() };
      }
    })().catch(() => {}).finally(() => {
      if (this.#gatewayLookup === lookup) this.#gatewayLookup = null;
    });
    this.#gatewayLookup = lookup;
    return lookup.promise;
  }

  // Exposure-only teardown for degraded scans. The registry flag is
  // authoritative without any scan, so the LAN-scoped part of
  // connectionPolicyViolation (authorize.js) is enforced here too — including
  // the verification deadline: an exposed identity whose verification aged
  // past lanVerifyGraceMs loses its WLAN streams even while the flag is still
  // set. Route and target checks are intentionally omitted: without a fresh
  // scan there is no verified target identity to compare against.
  #revokeExposedConnections() {
    if (!this.gateway) return;
    this.gateway.revokeConnections((conn) => {
      if (conn.loopback || conn.zone !== 'wifi') return false;
      if (!this.registry.isExposed(conn.identity)) {
        this.log('gateway', 'revoked long-lived connection', conn.name, 'exposure-revoked');
        return true;
      }
      if (!this.#lanFresh(conn.identity)) {
        this.log('gateway', 'revoked long-lived connection', conn.name, 'target-verification-stale');
        return true;
      }
      return false;
    });
  }

  // Scan-independent teardown for an EXPLICIT revocation: close the identity's
  // established WLAN streams (WebSockets, SSE) right here in the control
  // handler instead of waiting for the next scan pass to propagate the flag
  // change. Loopback traffic is never touched.
  #revokeIdentityLanConnections(identity) {
    if (!this.gateway) return;
    this.gateway.revokeConnections((conn) => {
      if (conn.loopback || conn.zone !== 'wifi') return false;
      if (conn.identity !== identity) return false;
      this.log('gateway', 'revoked long-lived connection', conn.name, 'exposure-revoked');
      return true;
    });
  }

  // A known, ACCEPTED target mutation (manual entry remove, manual repoint,
  // primary port switch) must invalidate the PUBLIC side immediately and
  // scan-independently: the scan-driven revocation inside the refresh pass
  // cannot act while discovery keeps failing (the verification grace window
  // deliberately keeps the share alive), and the stale route snapshot stays
  // displayed on purpose. Existing mechanics only — no second state owner:
  //   1. a targeted, name-scoped share stop closes the live gate now and
  //      advances the name's revocation epoch in the ShareManager (bumped
  //      synchronously by every stop of the name), so start jobs accepted
  //      before the mutation and still waiting on a teardown resume into a
  //      changed epoch and abort. Unbound on purpose: every instance
  //      accepted before the mutation carries the same pre-mutation target
  //      intent, so there is no newer instance worth protecting, and the bump
  //      must also fire when no share is currently visible (a waiting job may
  //      still exist);
  //   2. the name enters publicVerifyInvalid, so a NEW share request on the
  //      stale route snapshot is refused until a completed scan re-verifies.
  // Must run BEFORE the handler's refresh() and only after the mutation was
  // accepted by the registry — rejected mutations and genuine no-ops never
  // reach this. The LAN half (endpoint-bound record clear, established WLAN
  // stream teardown) already lives in the handlers themselves
  // (lanVerifiedAt.delete, #revokeIdentityLanConnections) and is not
  // duplicated.
  async #invalidatePublicTarget(name) {
    this.publicVerifyInvalid.add(name);
    await this.shares.stop(name);
  }

  // dev/ino of the control socket file this instance published, or null.
  #sockIdentity = null;

  #ownsControlSocket() {
    if (!this.#sockIdentity) return false;
    try {
      const st = fs.lstatSync(this.sockFile);
      return st.dev === this.#sockIdentity.dev && st.ino === this.#sockIdentity.ino;
    } catch {
      return false;
    }
  }

  // Fails with DAEMON_ALREADY_RUNNING while something serves the socket
  // path: a live daemon that holds no instance lock keeps its socket.
  async #refuseLiveSocket() {
    let st;
    try {
      st = fs.lstatSync(this.sockFile);
    } catch (err) {
      return; // nothing there
    }
    if (st.isSocket() && await socketAnswers(this.sockFile)) {
      throw new InstanceLockError(
        `another portname daemon is already serving ${this.sockFile}; stop it before starting a new one`,
        null
      );
    }
  }

  // A leftover at the socket path is removed only when nobody serves it.
  // Probed again right before the unlink: start() already refused a live
  // socket before its first side effect, but one may have appeared since.
  async #cleanupSocket() {
    await this.#refuseLiveSocket();
    try {
      fs.unlinkSync(this.sockFile);
    } catch (err) {
      // already gone
    }
  }

  async #startControl() {
    await this.#cleanupSocket();
    this.control = net.createServer((socket) => {
      // One request per connection (docs/control-protocol.md): the first
      // complete line is the whole request; anything after it is refused.
      // Bytes are counted on the wire and the line is UTF-8-decoded only
      // once complete, so a multibyte char split across chunks stays intact.
      let buf = Buffer.alloc(0);
      let handled = false;
      const refuse = (out) => {
        handled = true;
        socket.write(JSON.stringify(out) + '\n', () => socket.destroy());
      };
      socket.on('data', (d) => {
        if (handled) {
          socket.destroy();
          return;
        }
        buf = Buffer.concat([buf, d]);
        const nl = buf.indexOf(0x0a);
        if (nl === -1) {
          if (buf.length > MAX_CONTROL_LINE) {
            refuse({ ok: false, error: 'request too large', code: 'REQUEST_TOO_LARGE' });
          }
          return;
        }
        const line = buf.subarray(0, nl);
        if (line.length > MAX_CONTROL_LINE) {
          refuse({ ok: false, error: 'request too large', code: 'REQUEST_TOO_LARGE' });
          return;
        }
        handled = true;
        socket.on('data', () => socket.destroy());
        this.#handleControlMessage(line.toString('utf8'), socket);
      });
      socket.on('error', () => {});
    });
    const server = this.control;
    // Bound under a private name (no longer than the published one, so the
    // path length check in start() covers it), made 0600, then renamed into
    // place: the published path only ever names a finished socket. Node
    // removes the path a Unix socket server was bound to when it closes —
    // that is the private name, never whatever sits at daemon.sock by then.
    const bindPath = path.join(this.dir, `.ctl-${crypto.randomBytes(3).toString('hex')}`);
    return new Promise((resolve, reject) => {
      const onStartError = (err) => reject(err);
      server.once('error', onStartError);
      server.listen(bindPath, () => {
        server.removeListener('error', onStartError);
        // Permanent listener: a later server error is logged, never an
        // uncaught exception that kills the daemon.
        server.on('error', (err) => this.log('control', 'error', err.message));
        try {
          fs.chmodSync(bindPath, 0o600);
          fs.renameSync(bindPath, this.sockFile);
          const st = fs.lstatSync(this.sockFile);
          this.#sockIdentity = { dev: st.dev, ino: st.ino };
        } catch (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  #handleControlMessage(raw, socket) {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch (err) {
      socket.write(JSON.stringify({ ok: false, error: 'invalid json' }) + '\n');
      socket.end();
      return;
    }
    this.#dispatchControl(msg)
      .then((result) => {
        socket.write(JSON.stringify({ ok: true, ...result }) + '\n');
        socket.end();
      })
      .catch((err) => {
        const out = { ok: false, error: err.message };
        if (err.code) out.code = err.code;
        socket.write(JSON.stringify(out) + '\n');
        socket.end();
      });
  }

  dispatchControl(msg) {
    return this.#dispatchControl(msg);
  }

  // Commands allowed once stop() has begun. Everything that publishes or
  // starts resources is refused with a defined error; read-only queries and
  // share revocation (never scan-bound) stay available.
  #controlCommandsDuringStop = new Set(['status', 'share-link', 'unshare', 'unshare-all']);

  // Exposure decisions take effect in arrival order. Every `expose on` draws
  // a ticket when it arrives. While activations of an identity wait for
  // their router lookup, the identity has an entry here: { waiting, revokedAt }
  // — how many are waiting, and the ticket of the last revocation (`expose
  // off`, `remove`) applied meanwhile. An activation older than that
  // revocation never overrides it. Concurrent activations need no entry of
  // their own: they share one router lookup per interface address and
  // resume in arrival order (see #refreshLanGateway). Entries exist only for
  // identities of existing routes with a waiting activation and go with the
  // last of them, so the map stays bounded by the live routes.
  #exposureTicket = 0;
  pendingActivations = new Map();

  // A revocation is applied: every activation of `identity` still waiting
  // for its router lookup is superseded by it.
  #recordRevocation(identity) {
    const pending = this.pendingActivations.get(identity);
    if (pending) pending.revokedAt = ++this.#exposureTicket;
  }

  async #dispatchControl(msg) {
    if (!PUBLISHING_STATES.has(this.#state) && !this.#controlCommandsDuringStop.has(msg.cmd)) {
      throw new ControlError(
        'DAEMON_STOPPING',
        `daemon is ${this.#state}; only read-only commands are accepted`
      );
    }
    switch (msg.cmd) {
      case 'status': {
        const lan = this.#lanInfo();
        const exposedNames = this.config.bind === 'loopback' || !this.announcer.lanAddress()
          ? []
          : this.registry.exposedNames(this.routes);
        const routes = this.routes.map((r) => this.#decorateRoute(r, lan));
        return {
          protocolVersion: this.protocolVersion,
          daemonInstanceId: this.daemonInstanceId,
          // Additive v1 fields: build identity of the running daemon.
          daemonVersion: this.buildInfo.daemonVersion,
          runtimeVersion: this.buildInfo.runtimeVersion,
          payloadId: this.buildInfo.payloadId,
          state: this.#state,
          proxyPort: this.activePort,
          bind: this.bindInfo,
          lan,
          routes,
          stale: this.stale,
          exposed: exposedNames,
          shares: this.shares.status(),
          scanError: this.lastScanError,
          lastGoodScanAt: this.lastGoodScanAt,
          // Additive v1 field: the WLAN continuation grace so clients can
          // display how stale the LAN verification of an exposed target is
          // (it ages out from lastGoodScanAt / per-identity observation).
          lanVerifyGraceMs: this.lanVerifyGraceMs,
        };
      }
      case 'refresh': {
        await this.refresh();
        return { routes: this.routes.length };
      }
      case 'rename': {
        this.#checkRouteRevision(msg);
        const route = this.routesByName.get(msg.name);
        const root = route ? route.root : this.#rootByName(msg.name);
        if (!root) throw new Error(`no project named "${msg.name}" is running`);
        const liveAutoNames = new Set(
          this.routes.filter((r) => !r.manual && r.root !== root).map((r) => r.name)
        );
        const res = this.registry.rename(root, msg.newName, { liveAutoNames });
        if (!res.ok) throw this.#controlFailure(res);
        await this.refresh();
        return { renamed: msg.name, to: res.name };
      }
      case 'add': {
        const name = String(msg.name || '');
        const port = Number(msg.port);
        const liveAutoNames = new Set(this.routes.filter((r) => !r.manual).map((r) => r.name));
        // createOnly turns the historical name upsert into a strict create: the
        // GUI's "add" form must never silently repoint an existing entry.
        const res = this.registry.addManual(name, port, { liveAutoNames, createOnly: Boolean(msg.createOnly) });
        if (!res.ok) throw this.#controlFailure(res);
        // Known target mutation, scan-independent: a repoint to a different
        // port invalidates the endpoint-bound verification record immediately,
        // before the refresh pass — the next credit requires observing the
        // NEW tuple. Same-port upserts (and renames, which keep identity and
        // tuple) leave the record alone. The previous port comes from the
        // registry's canonical entry: "Shop" or " shop " repoint "shop" too.
        const previousPort = res.previousPort;
        if (previousPort !== undefined && Number(previousPort) !== port) {
          this.lanVerifiedAt.delete('manual:' + res.name);
          // Accepted repoint: the public side is invalidated immediately (see
          // #invalidatePublicTarget) — the next share start needs a fresh
          // verified observation of the NEW tuple.
          await this.#invalidatePublicTarget(res.name);
        }
        await this.refresh();
        return { added: res.name, port: res.port };
      }
      case 'remove': {
        this.#checkRouteRevision(msg);
        // Same canonical form addManual stores ("Shop" removes "shop"); own
        // keys only, so "constructor" or "toString" never count as existing.
        const name = this.registry.manualName(msg.name) ?? String(msg.name ?? '');
        const identity = 'manual:' + name;
        const existed = this.registry.hasManual(name);
        // A decision like `expose off`: an activation still waiting for its
        // router lookup never re-exposes the entry (nor a re-add of it).
        this.#recordRevocation(identity);
        // A failed save keeps both revocations in effect in memory (see
        // Registry#commit); every scan-independent teardown below still runs
        // before the error reaches the client — an exposure flag must never
        // outlive its entry and resurface on a later re-add.
        let saveError = null;
        try {
          this.registry.removeManual(name);
        } catch (err) {
          saveError = err;
        }
        try {
          this.registry.setExposed(identity, false);
        } catch (err) {
          saveError = saveError || err;
        }
        // Known target mutation, scan-independent: the endpoint-bound
        // verification record dies with the entry, before the refresh pass.
        this.lanVerifiedAt.delete(identity);
        // Explicit revocation is scan-independent: if the removed manual
        // project was exposed, its established WLAN streams are closed HERE —
        // exactly like the expose-off handler — never held open until the
        // next (possibly blocked or failing) scan pass.
        this.#revokeIdentityLanConnections(identity);
        // Accepted mutation: the public side is invalidated immediately (see
        // #invalidatePublicTarget). A no-op remove (unknown name) destroys
        // nothing.
        if (existed) await this.#invalidatePublicTarget(name);
        if (saveError) throw saveError;
        await this.refresh();
        // `existed` (additive): false when no manual entry had that name —
        // the remove was a no-op, not a success to report.
        return { removed: name, existed };
      }
      case 'expose': {
        // Arrival order (see pendingActivations): the ticket, the target the
        // caller saw and the network the Mac is on (its subnet, and its
        // router as far as identified) are taken now, before the lookup
        // below yields.
        const ticket = ++this.#exposureTicket;
        const arrival = this.routesByName.get(msg.name);
        const arrivalLan = msg.on ? this.#lanSelection() : null;
        const arrivalNetwork = this.#networkOf(arrivalLan);
        let revokedMeanwhile = false;
        // The confirmation also records the current router: look it up now
        // (bounded; a lookup already running for this address is shared),
        // not from a scan that may not have needed it. Before the revision
        // check, so everything below decides on one snapshot.
        if (msg.on && arrival && this.config.bind !== 'loopback') {
          const arrivalIdentity = this.#routeIdentity(arrival);
          const pending = this.pendingActivations.get(arrivalIdentity) || { waiting: 0, revokedAt: 0 };
          pending.waiting += 1;
          this.pendingActivations.set(arrivalIdentity, pending);
          try {
            await this.#refreshLanGateway();
            // A new address in the same subnet meanwhile (a DHCP renewal) is
            // no reason to fail: its router is looked up too, so the check
            // below compares the network, not the address.
            const lan = this.#lanSelection();
            if (arrivalLan && lan && lanKey(lan) !== lanKey(arrivalLan) && arrivalNetwork.network !== null &&
                networkId(lan.address, lan.netmask) === arrivalNetwork.network) {
              await this.#refreshLanGateway();
            }
          } finally {
            // Read and released in the same synchronous block that decides
            // below: no revocation can slip in between.
            revokedMeanwhile = pending.revokedAt > ticket;
            pending.waiting -= 1;
            if (pending.waiting === 0) this.pendingActivations.delete(arrivalIdentity);
          }
          // stop() may have begun during the lookup: publish nothing then.
          if (!PUBLISHING_STATES.has(this.#state)) {
            throw new ControlError('DAEMON_STOPPING', `daemon is ${this.#state}; only read-only commands are accepted`);
          }
        }
        this.#checkRouteRevision(msg);
        const route = this.routesByName.get(msg.name);
        if (!route) throw new ControlError('NO_ROUTE', `no project named "${msg.name}" is running`);
        const identity = route.root || ('manual:' + route.name);
        let networkNow = null;
        if (msg.on) {
          // While the lookup ran, a later `expose off` or `remove` of this
          // project may have been applied, or the name may now denote another
          // target: a stale activation overrides neither.
          if (revokedMeanwhile || !arrival || this.#routeRevision(route) !== this.#routeRevision(arrival)) {
            throw new ControlError('STALE_TARGET', `exposure of "${msg.name}" changed while it was being confirmed; check its state and retry`);
          }
          if (this.config.bind === 'loopback') {
            throw new ControlError('LAN_UNAVAILABLE', 'cannot expose project on LAN while gateway is in loopback-only bind mode');
          }
          if (!this.announcer.lanAddress()) {
            throw new ControlError('LAN_UNAVAILABLE', 'cannot expose project on LAN: no active physical Wi-Fi/LAN interface found');
          }
          // The user confirmed the network the Mac was on when the request
          // arrived; after a switch during the lookup (another subnet, or
          // another identified router) that is not this one.
          const lanNow = this.#lanSelection();
          networkNow = this.#networkOf(lanNow);
          if (arrivalLan && lanNow ? !sameNetwork(arrivalNetwork, networkNow) : arrivalLan !== lanNow) {
            throw new ControlError('STALE_TARGET', `the network changed while the exposure of "${msg.name}" was being confirmed; check its state and retry`);
          }
          // Activation is a decision like a public share start: it requires
          // the target to have been verified by a SUCCESSFUL scan within the
          // freshness window, bound to the exact endpoint tuple of THIS route
          // (a record from a moved, repointed or repurposed target never
          // counts).
          if (!this.#lanFreshRoute(identity, route, this.routeFreshnessMs)) {
            throw new ControlError(
              'LAN_TARGET_UNVERIFIED',
              `cannot expose project "${msg.name}" on LAN: the target was not verified by a recent discovery scan (last successful scan too old or failed); retry once discovery is healthy`
            );
          }
          // A confirmation never weakens a router binding: in the subnet an
          // exposure is bound to a router in, a router that cannot be
          // identified right now (e.g. just after wake) is no reason to bind
          // the subnet alone — that pause ("network-unidentified") heals by
          // itself.
          const bound = this.registry.isExposed(identity) ? this.registry.exposedTarget(identity) : null;
          if (bound && bound.gateway && bound.network === networkNow.network && networkNow.gateway === null) {
            throw new ControlError(
              'NETWORK_UNIDENTIFIED',
              `cannot confirm the exposure of "${msg.name}" yet: the router of ${networkNow.network} is not identified right now (e.g. just after wake), and the exposure stays bound to the router it was confirmed with; retry in a few seconds`
            );
          }
        }
        if (msg.on) {
          // Activation (and re-confirmation after "target-changed") binds
          // the exposure to the endpoint verified above, on the network of
          // its arrival (unchanged, checked above — with the router as
          // identified for the current address). A failed save rolls it back
          // (Registry#commit): the client sees the error and nothing answers
          // on the LAN.
          const { network, gateway } = networkNow;
          this.registry.setExposed(identity, true, {
            port: route.port,
            command: route.command ?? null,
            network,
            gateway,
          });
        } else {
          // Supersedes every activation of this project still waiting for
          // its router lookup (they arrived before this decision).
          this.#recordRevocation(identity);
          try {
            this.registry.setExposed(identity, false);
          } finally {
            // Explicit revocation is scan-independent: this identity's
            // established WLAN streams are closed HERE, never held open until
            // the next (possibly blocked or failing) scan pass — also when
            // persisting the switch-off failed (it stays in effect in memory).
            this.#revokeIdentityLanConnections(identity);
          }
        }
        await this.refresh();
        // Additive: the endpoint the exposure is now bound to (null when off).
        const target = this.registry.isExposed(identity) ? publicExposureTarget(this.registry.exposedTarget(identity)) : null;
        return { name: msg.name, exposed: this.registry.isExposed(identity), target };
      }
      case 'set-primary': {
        // Choose which living service of a project carries the name (e.g.
        // the Vite frontend instead of the API). The preference is stored
        // per project root — never per PID — so it survives restarts.
        this.#checkRouteRevision(msg);
        const route = this.routesByName.get(msg.name);
        if (!route) throw new ControlError('NO_ROUTE', `no project named "${msg.name}" is running`);
        if (!route.root) {
          throw new ControlError('INVALID_REQUEST', 'set-primary applies to discovered projects only');
        }
        const port = Number(msg.port);
        if (!Number.isInteger(port) || port <= 0 || port > 65535) {
          throw new ControlError('INVALID_REQUEST', 'set-primary requires a valid port');
        }
        const services = Array.isArray(route.services) ? route.services : [];
        // The preferred port may also live in a *superseded* generation —
        // that is the whole point: e.g. pointing the name at an older
        // frontend while a newer API holds it. Stale diagnostics carry the
        // route name, so they are unambiguous.
        const inStale = this.stale.some((s) => s.name === msg.name && s.port === port);
        if (!services.some((s) => s.port === port) && route.port !== port && !inStale) {
          throw new ControlError('INVALID_REQUEST', `"${msg.name}" has no running service on port ${port}`);
        }
        const previousPort = route.port;
        this.registry.setPrimaryPort(route.root, port);
        // Known target mutation, scan-independent: a primary switch that
        // moves the endpoint invalidates the verification record before the
        // refresh pass; the next credit requires observing the new tuple.
        if (previousPort !== port) {
          this.lanVerifiedAt.delete(this.#routeIdentity(route));
          // Accepted mutation: the public side is invalidated immediately
          // (see #invalidatePublicTarget) — the name now carries a different
          // target than every share and pending start accepted so far.
          await this.#invalidatePublicTarget(msg.name);
        }
        await this.refresh();
        return { name: msg.name, primaryPort: port };
      }
      case 'share': {
        this.#checkRouteRevision(msg);
        // A recently mutated target (removed / repointed / primary switched)
        // must not be startable off the stale route snapshot: while scans
        // keep failing, the displayed routes are deliberately kept, and the
        // global freshness window may not have expired yet — but the target
        // the snapshot describes is no longer the registry's intent. Refuse
        // until a completed successful scan re-verified the world.
        if (this.publicVerifyInvalid.has(msg.name)) {
          throw new ControlError(
            'SHARE_TARGET_UNVERIFIED',
            `cannot start a public share for "${msg.name}": the target was changed (removed or repointed) and has not been re-verified by a discovery scan yet; retry once discovery is healthy`
          );
        }
        const route = this.routesByName.get(msg.name);
        if (!route) throw new ControlError('NO_ROUTE', `no project named "${msg.name}" is running`);
        const ttlCheck = validateTtlMinutes(msg.ttlMinutes !== undefined ? msg.ttlMinutes : 60);
        if (!ttlCheck.ok) {
          throw new Error(`invalid ttlMinutes: ${ttlCheck.reason}`);
        }
        // Freshness gate: a public share START is a decision, not a display.
        // It requires the target to have been verified by a SUCCESSFUL scan
        // within the freshness window — the last displayed routes may be
        // older (failed scans keep them visible on purpose).
        if (this.lastGoodScanAt === null || Date.now() - this.lastGoodScanAt > this.routeFreshnessMs) {
          throw new ControlError(
            'SHARE_TARGET_UNVERIFIED',
            `cannot start a public share for "${msg.name}": the target was not verified by a recent discovery scan (last successful scan too old or failed); retry once discovery is healthy`
          );
        }
        // A port alone is no identity: manual targets carry no process
        // generation of their own, so the listener observed on the port by
        // the last verified scan is pinned as the generation. Without that
        // observation the start is refused with a plain reason.
        let pinnedPid = route.pid;
        let pinnedProcessKey = route.processKey;
        if (route.root === null) {
          const observed = this.#observedListener(route.port, route.upstreamHost);
          if (!observed) {
            throw new ControlError(
              'SHARE_TARGET_UNVERIFIED',
              `cannot start a public share for "${msg.name}": nothing was observed listening on ${route.upstreamHost || '127.0.0.1'}:${route.port} by the last verified scan`
            );
          }
          pinnedPid = observed.pid;
          pinnedProcessKey = observed.processKey;
        }
        const result = await this.shares.start({
          name: msg.name,
          targetPort: route.port,
          targetHost: route.upstreamHost || '127.0.0.1',
          pinnedPid,
          pinnedProcessKey,
          ttlMinutes: ttlCheck.minutes,
          cloudflaredBin: this.cloudflaredBin,
          // Honest verification age: the freshness gate above passed because
          // of THIS scan, so the share inherits its timestamp instead of
          // stamping a fresh one at the (possibly much later) tunnel
          // activation. verifyGraceMs lets the manager refuse a late
          // activation whose verification went stale during tunnel boot.
          verifiedAt: this.lastGoodScanAt,
          verifyGraceMs: this.shareVerifyGraceMs,
        });
        const url = String(result);
        const expiresAt = (result && result.expiresAt) || (Date.now() + ttlCheck.minutes * 60 * 1000);
        return { url, expiresAt, ttlMinutes: ttlCheck.minutes, shareId: result.shareId };
      }
      case 'share-link': {
        // Read-only: fetch the full secret link for an exactly matching,
        // still-active share. Never starts a tunnel or touches a timer.
        // Fail-closed: the caller must prove it knows the current shareId —
        // a request without that guard never receives the secret token.
        const expected = msg.expectedShareId !== undefined ? String(msg.expectedShareId) : '';
        if (!expected) {
          throw new ControlError('INVALID_REQUEST', 'share-link requires expectedShareId');
        }
        const link = this.shares.link(msg.name);
        if (!link) throw new ControlError('SHARE_NOT_ACTIVE', `no active share for "${msg.name}"`);
        if (expected !== link.shareId) {
          throw new ControlError('STALE_TARGET', `public link for "${msg.name}" changed; reload and retry`);
        }
        return link;
      }
      case 'unshare': {
        this.#checkRouteRevision(msg);
        const expected = msg.expectedShareId !== undefined ? String(msg.expectedShareId) : undefined;
        const res = await this.shares.stop(msg.name, { expectedShareId: expected });
        if (res === 'stale') {
          throw new ControlError('STALE_TARGET', `public link for "${msg.name}" changed; reload and retry`);
        }
        if (!res) throw new Error(`no active share for "${msg.name}"`);
        return { stopped: msg.name };
      }
      case 'unshare-all': {
        // The clearly labeled, deliberately blunt revocation of every live
        // public link (GUI footer / `portname unshare-all`). Routed through
        // the manager's stopAll, which advances the revocation generation
        // BEFORE stopping anything: start/replacement jobs already accepted
        // and waiting on a teardown are cancelled instead of silently
        // starting their share after the revocation, and new starts are
        // refused while the sweep runs. Every share goes through the normal
        // bounded per-share stop path — no shortcut. Idempotent.
        const stopped = await this.shares.stopAll();
        return { stopped };
      }
      default:
        throw new Error(`unknown command: ${msg.cmd}`);
    }
  }

  // Route identity mirrors the exposure identity model: canonical project root
  // for auto-discovered projects, `manual:<name>` for manual registrations.
  #routeIdentity(route) {
    return route.root || ('manual:' + route.name);
  }

  // The revision pins the concrete target (daemon instance, identity, name,
  // upstream host, port, known process generation). Stable across identical
  // polls; changes whenever the target changes. Manual entries have no
  // process generation, so none is invented.
  #routeRevision(route) {
    const parts = [
      this.daemonInstanceId,
      this.#routeIdentity(route),
      route.name,
      route.upstreamHost || '127.0.0.1',
      route.port,
      route.processKey || (route.pid != null ? String(route.pid) : ''),
    ];
    return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 16);
  }

  #decorateRoute(route, lan) {
    const identity = this.#routeIdentity(route);
    const exposureRequested = this.registry.isExposed(identity);
    // The EFFECTIVE WLAN exposure is the same decision the gateway applies
    // per request: the desired flag AND the confirmed endpoint AND a
    // tuple-bound fresh verification of the CURRENT route (the shared
    // helpers, never a recomputed lookalike). A wish without that
    // verification is "paused": the advertised address (lanUrl, Bonjour)
    // stays up, but the gateway refuses access until a fresh scan
    // re-verifies the target. A moved endpoint ("target-changed") keeps
    // lanUrl as the desired address but is withdrawn from Bonjour.
    let exposureEffective = 'off';
    let exposurePauseReason = null;
    let exposureVerifiedAt = null;
    if (exposureRequested) {
      const rec = this.lanVerifiedAt.get(identity);
      exposureVerifiedAt = rec ? rec.verifiedAt : null;
      if (!lan.available) {
        // No WLAN path at all — the reason vocabulary mirrors lan.reason
        // ("loopback-bind" / "no-lan-interface").
        exposureEffective = 'paused';
        exposurePauseReason = lan.reason || 'no-lan-interface';
      } else if (!this.#lanFreshRoute(identity, route)) {
        exposureEffective = 'paused';
        exposurePauseReason = 'target-not-verified';
      } else if (this.registry.exposedTarget(identity) === null) {
        // A wish stored by an older daemon that recorded no endpoint: nothing
        // moved, but no endpoint was ever confirmed for the Wi-Fi. Refused
        // and withdrawn like "target-changed" until `expose` confirms the
        // current one once.
        exposureEffective = 'paused';
        exposurePauseReason = 'target-unconfirmed';
      } else if (!this.#exposureTargetConfirmed(identity, route)) {
        // The verified current endpoint (port or command) is not the one
        // confirmed by `expose`: refused and not advertised until the user
        // confirms again — never healed by a scan. Reported only once the
        // target is verified, i.e. exactly when `expose` can succeed.
        exposureEffective = 'paused';
        exposurePauseReason = 'target-changed';
      } else if (this.#exposureNetworkState(identity) === 'unidentified') {
        // The confirmed subnet, but its router is not identified right now
        // (just after wake): refused and not advertised like
        // "network-changed", but heals by itself — nothing to confirm
        // (`expose` refuses to drop the router binding meanwhile).
        exposureEffective = 'paused';
        exposurePauseReason = 'network-unidentified';
      } else if (!this.#exposureNetworkConfirmed(identity)) {
        // Confirmed on another network: not advertised and refused here
        // until `expose` confirms it for the current network.
        exposureEffective = 'paused';
        exposurePauseReason = 'network-changed';
      } else {
        exposureEffective = 'active';
      }
    }
    return {
      ...route,
      id: identity,
      revision: this.#routeRevision(route),
      localUrl: localBrowserUrl(route.name, this.activePort),
      lanUrl: exposureRequested && lan.available ? lanBrowserUrl(route.name, this.activePort) : null,
      exposureRequested,
      exposureEffective,
      exposurePauseReason,
      exposureVerifiedAt,
      // The endpoint the exposure is bound to ({ port, command, network }),
      // null when no exposure is requested or none was ever confirmed.
      exposureTarget: exposureRequested ? publicExposureTarget(this.registry.exposedTarget(identity)) : null,
      // Whether lanUrl's name is actually ours on the network (see
      // #lanRegistration); null while it is not advertised.
      lanRegistration: exposureRequested && lan.available ? this.#lanRegistration(route.name) : null,
    };
  }

  // The Bonjour registration of `<name>.local` as far as the announcer knows
  // it — dns-sd reports no success back: "registering" / "registered" while
  // its registration child runs, "conflict" while the name is backed off
  // after dns-sd ended with "name in use" (another device on the network
  // answers for it, so lanUrl leads there), "retrying" after any other quick
  // exit; null otherwise, and for announcers that cannot tell.
  #lanRegistration(name) {
    if (!this.announcer || typeof this.announcer.registrationState !== 'function') return null;
    return this.announcer.registrationState(name) ?? null;
  }

  #lanInfo() {
    if (this.config.bind === 'loopback') {
      return { available: false, reason: 'loopback-bind', interfaceName: null, address: null, network: null };
    }
    const address = this.announcer.lanAddress();
    // Optional so older announcer doubles in tests (and future announcers)
    // keep working: the interface name is display metadata.
    const interfaceName = typeof this.announcer.lanInterfaceName === 'function'
      ? this.announcer.lanInterfaceName()
      : null;
    // The current subnet, comparable with exposureTarget.network (a client
    // can name the network a "network-changed" confirmation would expose to).
    const { network } = this.#currentNetwork();
    return address
      ? { available: true, reason: null, interfaceName, address, network }
      : { available: false, reason: 'no-lan-interface', interfaceName, address: null, network: null };
  }

  // GUI mutations carry the revision they acted on. When the expectation is
  // present it is validated strictly before any effect; absence (old CLI)
  // keeps the unguarded behavior.
  #checkRouteRevision(msg) {
    if (msg.expectedRouteRevision === undefined || msg.expectedRouteRevision === null) return;
    const route = this.routesByName.get(msg.name);
    const current = route ? this.#routeRevision(route) : null;
    if (!current || current !== String(msg.expectedRouteRevision)) {
      throw new ControlError('STALE_TARGET', `route "${msg.name}" changed; reload the project list and retry`);
    }
  }

  #controlFailure(res) {
    return res.code ? new ControlError(res.code, res.reason) : new Error(res.reason);
  }

  // Runs in the background: the directory checks may take a while, or hang
  // on a dead network mount, and must never delay a scan or the gateway. The
  // result is applied with the live roots of the latest scan, and only while
  // the same registry is in use.
  #startNamesPrune() {
    this.namesPrunedAt = performance.now();
    this.namesPruneRunning = true;
    const registry = this.registry;
    const run = registry
      .findGoneNameRoots({ liveRoots: this.liveRoots })
      .then((gone) => {
        if (this.registry !== registry || !PUBLISHING_STATES.has(this.#state)) return;
        const { dropped, changed } = registry.pruneNames({ gone, liveRoots: this.liveRoots });
        if (dropped > 0) this.log('registry', 'names-pruned', dropped);
        if (changed) registry.saveConfig();
      })
      .catch((err) => this.log('registry', 'names-prune-failed', (err && err.message) || String(err)))
      .finally(() => {
        if (this.namesPrune === run) this.namesPruneRunning = false;
      });
    this.namesPrune = run;
  }

  #rootByName(name) {
    for (const [root, n] of Object.entries(this.registry.config.names)) {
      if (n === name) return root;
    }
    for (const [root, n] of Object.entries(this.registry.config.renames)) {
      if (n === name) return root;
    }
    return null;
  }
}

module.exports = { Daemon, REFRESH_MS, readBuildInfo, resolveGatewayMac, runRouterTool };
