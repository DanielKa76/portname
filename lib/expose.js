'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { getLanInterface } = require('./network');
const { getProcessInfo, getProcessStartTimesAsync } = require('./process');
const { atomicWrite } = require('./registry');

// After a spawn failure (e.g. dns-sd not installed) registration attempts
// back off for this long instead of failing — and logging — every scan tick.
const SPAWN_ERROR_BACKOFF_MS = 30000;
// A registration child that exits this soon after its spawn failed — dns-sd
// exits at once on a name conflict ("Name in use", exit code 255). Its name is
// then retried with an exponential backoff instead of on every scan tick; a
// child that ran longer resets the backoff, so e.g. a mDNSResponder restart
// re-registers immediately.
const FAST_EXIT_MS = 10000;
const RESPAWN_BACKOFF_BASE_MS = 15000;
const RESPAWN_BACKOFF_MAX_MS = 5 * 60 * 1000;
const NAME_CONFLICT_EXIT_CODE = 255;

// dns-sd is a diagnostic tool; its docs warn about automating it. This class
// is the small, exchangeable adapter around that: given a name, port and LAN
// address it keeps one registration child alive and reports loss.
//
// We use proxy-style registration (`dns-sd -P`) with an explicit hostname and
// address — that publishes an A/AAAA record for `<name>.local`. The plain
// service registration (`-R`) would only create an SRV record pointing at the
// Mac's own hostname, so `name.local` would never resolve.
class BonjourAnnouncer {
  #lastChildrenSig = null;
  // Start time per registration child, read once in a batched async lookup
  // (orphan cleanup needs it) instead of re-reading every child
  // synchronously, on the gateway's event loop, whenever the set changes.
  #startTimes = new WeakMap();
  #startTimeLookup = null;
  #spawnedAt = new WeakMap();
  #retry = new Map(); // name -> { failures, retryAt, lastExitCode }

  constructor({
    port,
    dir = null,
    log = () => {},
    getLan = getLanInterface,
    getProcessInfo: processInfoFn = getProcessInfo,
    getStartTimes = getProcessStartTimesAsync,
    spawnFn = spawn,
    now = Date.now,
  } = {}) {
    this.port = port;
    this.dir = dir;
    this.stateFile = dir ? path.join(dir, 'bonjour.state.json') : null;
    this.log = log;
    this.getLan = getLan;
    this.getProcessInfo = processInfoFn;
    this.getStartTimes = getStartTimes;
    this.spawnFn = spawnFn;
    this.now = now;
    this.children = new Map(); // name -> child
    this.registeredIp = null;
    // Timestamp until which new dns-sd spawns are suppressed after a spawn
    // failure; sync() keeps withdrawing stale names meanwhile.
    this.spawnBlockedUntil = 0;
    // Signature of the child set already persisted: sync() runs every few
    // seconds, so identical registrations must not re-read start times or
    // rewrite the state file.
    this.#lastChildrenSig = null;
  }

  // Active physical LAN/Wi-Fi IPv4 address of this Mac.
  lanAddress() {
    const lan = this.getLan();
    return lan ? lan.address : null;
  }

  // BSD interface name of the selected LAN/Wi-Fi interface (e.g. "en0").
  // Display metadata for clients: a change of interface/address means the
  // machine roamed to a different network — the UI must never keep saying
  // "same trusted Wi-Fi" across such a change.
  lanInterfaceName() {
    const lan = this.getLan();
    return lan ? lan.name : null;
  }

  childPids() {
    return [...this.children.values()].map((c) => c.pid).filter(Boolean);
  }

  #recordChildren() {
    if (!this.stateFile) return;
    // Only persist when the set of live children (or what is known about
    // them) actually changed: rewriting the file every sync pass is pure
    // waste.
    const live = [...this.children.entries()].filter(([, child]) => child && child.pid);
    const sig = live
      .map(([name, child]) => `${name}:${child.pid}:${this.#startTimes.has(child) ? 1 : 0}`)
      .sort()
      .join('|');
    if (sig === this.#lastChildrenSig) return;
    this.#lastChildrenSig = sig;
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      const children = live.map(([name, child]) => ({
        name,
        pid: child.pid,
        // null until the lookup resolved: cleanupOrphans never kills an
        // entry without a verified start time.
        startTime: this.#startTimes.get(child) || null,
        command: 'dns-sd',
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

  // Reads the start times of children that have none yet — one batched,
  // asynchronous ps for all of them — and persists them once known. A failed
  // lookup is retried on the next sync().
  #resolveStartTimes() {
    if (!this.stateFile || this.#startTimeLookup) return;
    const pending = [...this.children.values()].filter((c) => c && c.pid && !this.#startTimes.has(c));
    if (pending.length === 0) return;
    const lookup = Promise.resolve()
      .then(() => this.getStartTimes(pending.map((c) => c.pid)))
      .then((times) => {
        const current = new Set(this.children.values());
        let changed = false;
        for (const child of pending) {
          const startTime = times.get(child.pid);
          if (startTime && current.has(child)) {
            this.#startTimes.set(child, startTime);
            changed = true;
          }
        }
        if (changed) this.#recordChildren();
      }, () => {})
      .finally(() => {
        if (this.#startTimeLookup === lookup) this.#startTimeLookup = null;
      });
    this.#startTimeLookup = lookup;
  }

  // Per-name registration state for status output. dns-sd reports nothing
  // back to us, so a living child is 'registering' until it outlived the
  // fast-exit window ('registered'); during a backoff the name is
  // 'conflict' (dns-sd's name-in-use exit) or 'retrying'; otherwise null.
  registrationState(name) {
    const child = this.children.get(name);
    if (child) {
      const spawnedAt = this.#spawnedAt.get(child);
      return spawnedAt !== undefined && this.now() - spawnedAt < FAST_EXIT_MS ? 'registering' : 'registered';
    }
    const retry = this.#retry.get(name);
    if (retry && this.now() < retry.retryAt) {
      return retry.lastExitCode === NAME_CONFLICT_EXIT_CODE ? 'conflict' : 'retrying';
    }
    return null;
  }

  // Fail-safe cleanup of orphan dns-sd processes from crashed previous daemon runs
  cleanupOrphans() {
    if (!this.stateFile) return;
    try {
      if (!fs.existsSync(this.stateFile)) return;
      const data = JSON.parse(fs.readFileSync(this.stateFile, 'utf8'));
      const children = Array.isArray(data.children) ? data.children : [];
      for (const entry of children) {
        if (!entry || typeof entry !== 'object') continue;
        const pid = Number(entry.pid);
        const expectedStart = entry.startTime;
        if (!pid || !expectedStart) continue;

        const currentInfo = this.getProcessInfo(pid);
        if (
          currentInfo &&
          currentInfo.startTime === expectedStart &&
          currentInfo.command &&
          currentInfo.command.includes('dns-sd')
        ) {
          try {
            process.kill(pid, 'SIGTERM');
            this.log('bonjour', 'orphan-killed', pid);
          } catch (err) {}
        }
      }
      try { fs.unlinkSync(this.stateFile); } catch {}
    } catch (err) {
      // invalid state or already cleaned
    }
  }

  #startOne(name, ip) {
    const args = ['-P', name, '_http._tcp', 'local.', String(this.port), `${name}.local.`, ip];
    let child;
    try {
      child = this.spawnFn('dns-sd', args, { stdio: 'ignore' });
    } catch (err) {
      this.#onSpawnError(name, err);
      return;
    }
    // A missing/unspawnable dns-sd binary only reports asynchronously
    // (ENOENT). Without this handler the daemon would die with an
    // uncaught exception; instead the failure is logged and backed off.
    child.on('error', (err) => {
      if (this.children.get(name) === child) {
        this.children.delete(name);
        this.#recordChildren();
      }
      this.#onSpawnError(name, err);
    });
    child.on('exit', (code) => {
      if (this.children.get(name) === child) {
        this.children.delete(name);
        this.#recordChildren();
        this.log('bonjour', 'lost', name, `exit ${code}`);
        this.#noteExit(name, child, code);
      }
    });
    this.children.set(name, child);
    this.#spawnedAt.set(child, this.now());
    // Persisted once at the end of sync(), not per registration.
    this.log('bonjour', 'register', `${name}.local -> ${ip}:${this.port}`);
  }

  // A child that exits right after its spawn is a failed registration:
  // back off exponentially for this name. A long-lived child resets it.
  #noteExit(name, child, code) {
    const spawnedAt = this.#spawnedAt.get(child);
    if (spawnedAt === undefined || this.now() - spawnedAt >= FAST_EXIT_MS) {
      this.#retry.delete(name);
      return;
    }
    const failures = ((this.#retry.get(name) || {}).failures || 0) + 1;
    const backoff = Math.min(RESPAWN_BACKOFF_MAX_MS, RESPAWN_BACKOFF_BASE_MS * 2 ** (failures - 1));
    this.#retry.set(name, { failures, retryAt: this.now() + backoff, lastExitCode: code });
    this.log('bonjour', 'backoff', name, `exit ${code}`, `retry in ${Math.round(backoff / 1000)}s`);
  }

  #onSpawnError(name, err) {
    this.spawnBlockedUntil = this.now() + SPAWN_ERROR_BACKOFF_MS;
    this.log('bonjour', 'spawn-error', name, err.message);
  }

  // Sync registrations to the wanted names. Re-registers everything when the
  // LAN address changed (DHCP renew) or a child died.
  sync(wantedNames) {
    const ip = this.lanAddress();
    if (!ip) {
      this.stopAll();
      return { ok: false, reason: 'no non-internal IPv4 address; not on a LAN?' };
    }
    const want = new Set(wantedNames);
    const ipChanged = this.registeredIp !== null && this.registeredIp !== ip;
    if (ipChanged) {
      this.stopAll();
    }
    this.registeredIp = ip;
    for (const [name, child] of this.children) {
      if (!want.has(name)) {
        child.kill('SIGTERM');
        this.children.delete(name);
        this.log('bonjour', 'withdraw', name);
      }
    }
    // Re-exposing a withdrawn name is a fresh decision: no inherited backoff.
    for (const name of [...this.#retry.keys()]) {
      if (!want.has(name)) this.#retry.delete(name);
    }
    for (const name of want) {
      if (this.children.has(name)) continue;
      if (this.now() < this.spawnBlockedUntil) continue; // backing off after spawn failure
      const retry = this.#retry.get(name);
      if (retry && this.now() < retry.retryAt) continue; // backing off after fast exits
      this.#startOne(name, ip);
    }
    this.#recordChildren();
    this.#resolveStartTimes();
    return { ok: true };
  }

  stopAll() {
    for (const child of this.children.values()) {
      try { child.kill('SIGTERM'); } catch {}
    }
    this.children.clear();
    this.#recordChildren();
    this.registeredIp = null;
  }
}

module.exports = { BonjourAnnouncer };
