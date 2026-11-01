'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { validateName } = require('./naming');
const { isUnattributableDir } = require('./discover');
const { ConfigError, readJsonObject, validateConfig, validateStateMap, ensurePrivateDir } = require('./config');

// Fresh nested objects per instance — a shared constant would leak mutations
// of one Registry's maps into every later instance (regressions like a rename
// "already used by" a foreign project root depend on this isolation).
const freshConfig = () => ({
  renames: {},
  exposed: {},
  // identity -> { port, command, network, gateway }: the endpoint the user
  // confirmed with `expose`, and the LAN subnet plus router fingerprint it
  // was confirmed on (lib/daemon.js). The exposure applies to that endpoint
  // on that network only; a primary that moves to another port or command,
  // or another network, pauses it until confirmed again.
  exposedTargets: {},
  manual: {},
  names: {},
  // root -> day (days since 1970-01-01, UTC) the project was last live; only
  // for roots with a names entry. Drives the expiry in pruneNames.
  namesSeen: {},
  primaryPorts: {},
});

// The config.json keys this registry owns and rewrites. Everything else in
// the file (bind, ports, ignoreCommands, cloudflaredBin, unknown additive
// fields) belongs to the user, who may edit it while the daemon runs; a save
// re-reads those from disk instead of writing back the startup snapshot.
const REGISTRY_KEYS = Object.keys(freshConfig());

// Config maps keyed by project root (exposed/exposedTargets: by identity,
// i.e. a root or `manual:<name>`).
const ROOT_KEYED = ['renames', 'names', 'namesSeen', 'primaryPorts', 'exposed', 'exposedTargets'];

// The filesystem root and the home directory are never project identities
// (lib/discover.js projectRootOf): no discovered route carries them, so a key
// naming one can only be a leftover of an older version. Such a key is never
// accepted — it would hand a name, a primary port or a WLAN exposure to
// whichever unrelated process runs there. Discovery and the registry share
// one check, so both judge a symlinked $HOME alike.
function isUnattributableRoot(key) {
  if (typeof key !== 'string' || !key.startsWith('/')) return false;
  return isUnattributableDir(key);
}

// Auto-assigned names (config.names) keep a stopped project's name reserved,
// so a newcomer with the same folder name gets "-2" instead of taking it.
// Without cleanup every directory that ever ran a server kept its reservation
// forever: test suites and coding agents start servers in throwaway temp
// dirs, and one Mac collected 7,790 entries, 98.5% of them for deleted
// directories, with suffixes up to "tree-4140". The daemon therefore drops
// the reservations of deleted directories, of projects not live for
// NAME_RESERVATION_TTL_DAYS, and the least recently live ones beyond
// MAX_NAME_ENTRIES (findGoneNameRoots + pruneNames).
const MAX_NAME_ENTRIES = 500;
const NAME_RESERVATION_TTL_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1000;
// Paths on external or network volumes may be missing only because the volume
// is unmounted: never judged deleted.
const UNPROBED_ROOT_PREFIXES = ['/Volumes/', '/net/', '/Network/'];

function dayNumber(ms = Date.now()) {
  return Math.floor(ms / DAY_MS);
}

// Resolves true only when the directory definitely does not exist; any other
// error (permissions, I/O) keeps the reservation. Asynchronous on purpose: a
// stat that hangs on a dead network mount ties up one libuv worker, never the
// event loop that serves the gateway.
async function directoryGone(dir) {
  try {
    await fs.promises.stat(dir);
    return false;
  } catch (err) {
    return err.code === 'ENOENT' || err.code === 'ENOTDIR';
  }
}

let tempSequence = 0;

// How long births of process generations that are no longer live are kept.
// Generations of running processes are always kept, however old.
const FIRST_SEEN_MAX_AGE_MS = 24 * 60 * 60 * 1000;

// Atomic replace via a uniquely named temp file:
//   - created with 'wx' (exclusive) and mode 0600, so a temp-file collision or
//     a pre-planted symlink at the temp path can never be written through;
//   - rename() replaces the target atomically and does not follow a symlink
//     sitting at the target path;
//   - on any failure the target stays untouched, and the temp path is unlinked
//     only if this call actually created it: a failed open (e.g. EEXIST) means
//     a foreign file sits there, which must never be modified or deleted.
function atomicWrite(file, data, { mode = 0o600 } = {}) {
  const tmp = `${file}.${process.pid}.${++tempSequence}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  let fd = null;
  let created = false;
  try {
    fd = fs.openSync(tmp, 'wx', mode);
    created = true;
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = null;
    fs.renameSync(tmp, file);
  } catch (err) {
    try {
      if (fd !== null) fs.closeSync(fd);
    } catch {} // already closed
    if (created) {
      try {
        fs.unlinkSync(tmp);
      } catch {} // best effort
    }
    throw err;
  }
}

class Registry {
  constructor(dir) {
    this.dir = dir;
    this.configFile = path.join(dir, 'config.json');
    this.stateFile = path.join(dir, 'state.json');
    // Fail-closed loading: a file that exists but cannot be read, parsed or
    // validated throws ConfigError here — it must never silently degrade to
    // defaults, because defaults include the wildcard bind. Missing files are
    // the one safe case (fresh first start). Unknown additive fields are
    // preserved through the shallow merge.
    const loadedConfig = readJsonObject(this.configFile, validateConfig);
    this.config = { ...freshConfig(), ...(loadedConfig || {}) };
    const rootsDropped = this.#dropUnattributableRoots();
    if (this.#sanitizeExposed() || rootsDropped) this.saveConfig();
    const loadedState = readJsonObject(this.stateFile, validateStateMap);
    this.firstSeen = loadedState || {};
    this.changed = false;
  }

  // Fail-closed on load: root-keyed entries for '/' or the home directory are
  // dropped (and the file rewritten without them). Returns whether any was.
  #dropUnattributableRoots() {
    let dirty = false;
    for (const map of ROOT_KEYED) {
      const entries = this.config[map];
      if (!entries || typeof entries !== 'object') continue;
      for (const key of Object.keys(entries)) {
        if (isUnattributableRoot(key)) {
          delete entries[key];
          dirty = true;
        }
      }
    }
    return dirty;
  }

  // Returns whether legacy keys were rewritten (the caller saves).
  #sanitizeExposed() {
    if (!this.config.exposed || typeof this.config.exposed !== 'object') {
      this.config.exposed = {};
      return false;
    }
    let dirty = false;
    for (const key of Object.keys(this.config.exposed)) {
      if (key.startsWith('/') || key.startsWith('manual:')) {
        continue;
      }
      // Legacy display name key (e.g. "shop")
      dirty = true;
      delete this.config.exposed[key];

      // Attempt unambiguous migration:
      const matchingRoots = Object.entries({ ...(this.config.names || {}), ...(this.config.renames || {}) })
        .filter(([, name]) => name === key)
        .map(([root]) => root);
      // Own keys only: a name like "constructor" must never match the
      // object prototype.
      const isManual = Boolean(this.config.manual && Object.hasOwn(this.config.manual, key));

      if (matchingRoots.length === 1 && !isManual) {
        this.config.exposed[matchingRoots[0]] = true;
      } else if (matchingRoots.length === 0 && isManual) {
        this.config.exposed['manual:' + key] = true;
      }
      // Otherwise ambiguous or unknown project: safely discarded (fail-closed)
    }
    return dirty;
  }

  // Lost-update guard: only the registry-owned keys come from memory; every
  // other key is taken from config.json as it is on disk NOW, so a hand edit
  // made while the daemon runs (e.g. "bind": "loopback") survives the next
  // save. A file that became damaged meanwhile is never overwritten
  // (readJsonObject throws ConfigError). Something other than a regular file
  // at the path (symlink, directory) is never read through; the startup
  // snapshot is the base then, and atomicWrite replaces the entry.
  saveConfig() {
    ensurePrivateDir(this.dir);
    let base = this.config;
    let st = null;
    try {
      st = fs.lstatSync(this.configFile);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      base = {};
    }
    if (st && st.isFile()) base = readJsonObject(this.configFile, validateConfig) || {};
    const out = { ...base };
    for (const key of REGISTRY_KEYS) out[key] = this.config[key];
    atomicWrite(this.configFile, JSON.stringify(out, null, 2) + '\n');
  }

  // Applies a registry mutation in memory, persists it, and rolls the
  // in-memory state back when the save fails: the client receives the error,
  // so the change must not stay in effect (an `expose on` that failed to
  // persist would otherwise answer on the LAN right away). Revocations pass
  // keepOnFailure — a failed save must never re-enable what the user just
  // switched off; the error still reaches the caller (fail-closed).
  #commit(mutate, { keepOnFailure = false } = {}) {
    const snapshot = structuredClone(Object.fromEntries(REGISTRY_KEYS.map((k) => [k, this.config[k]])));
    const result = mutate();
    try {
      this.saveConfig();
    } catch (err) {
      if (!keepOnFailure) Object.assign(this.config, snapshot);
      throw err;
    }
    return result;
  }

  // A root whose auto-name must survive pruning: the user decided something
  // about it (rename, primary port, Wi-Fi exposure) or it is live right now.
  #namePinned(root, liveRoots) {
    if (liveRoots.has(root)) return true;
    return ['renames', 'primaryPorts', 'exposed', 'exposedTargets'].some(
      (map) => Boolean(this.config[map]) && Object.hasOwn(this.config[map], root)
    );
  }

  // Records today as the last live day of every live project that holds a
  // reservation. Returns whether anything changed (at most once a day per
  // project), so the caller saves only then.
  noteNamesSeen(liveRoots, today = dayNumber()) {
    const { names, namesSeen } = this.config;
    let changed = false;
    for (const root of liveRoots) {
      if (!Object.hasOwn(names, root) || namesSeen[root] === today) continue;
      namesSeen[root] = today;
      changed = true;
    }
    return changed;
  }

  // The roots pruneNames may drop as deleted: unpinned, not on an unprobed
  // volume, and gone on disk. One directory at a time, so a hanging mount
  // holds at most one libuv worker.
  async findGoneNameRoots({ liveRoots = new Set(), isGone = directoryGone } = {}) {
    const gone = new Set();
    for (const root of Object.keys(this.config.names)) {
      if (this.#namePinned(root, liveRoots)) continue;
      if (UNPROBED_ROOT_PREFIXES.some((prefix) => root.startsWith(prefix))) continue;
      if (await isGone(root)) gone.add(root);
    }
    return gone;
  }

  // Drops the reservations of the given deleted roots, of projects not live
  // for more than ttlDays, and the least recently live ones beyond
  // maxEntries. Pinned roots (#namePinned) neither count nor go. A
  // reservation without a recorded day (written before namesSeen existed)
  // gets today, so its expiry starts now. Changes memory only and returns
  // { dropped, changed }; the caller saves when changed.
  pruneNames({
    gone = new Set(),
    liveRoots = new Set(),
    today = dayNumber(),
    ttlDays = NAME_RESERVATION_TTL_DAYS,
    maxEntries = MAX_NAME_ENTRIES,
  } = {}) {
    const { names, namesSeen } = this.config;
    let dropped = 0;
    let changed = false;
    const drop = (root) => {
      delete names[root];
      delete namesSeen[root];
      dropped += 1;
      changed = true;
    };
    const unpinned = [];
    for (const root of Object.keys(names)) {
      if (this.#namePinned(root, liveRoots)) continue;
      if (gone.has(root)) {
        drop(root);
        continue;
      }
      if (!Number.isInteger(namesSeen[root])) {
        namesSeen[root] = today;
        changed = true;
      }
      if (today - namesSeen[root] > ttlDays) {
        drop(root);
        continue;
      }
      unpinned.push(root);
    }
    if (unpinned.length > maxEntries) {
      // Oldest last-live day first; the map's own order breaks ties.
      const position = new Map(unpinned.map((root, i) => [root, i]));
      unpinned.sort((a, b) => namesSeen[a] - namesSeen[b] || position.get(a) - position.get(b));
      for (const root of unpinned.slice(0, unpinned.length - maxEntries)) drop(root);
    }
    for (const root of Object.keys(namesSeen)) {
      if (!Object.hasOwn(names, root)) {
        delete namesSeen[root];
        changed = true;
      }
    }
    return { dropped, changed };
  }

  saveState() {
    ensurePrivateDir(this.dir);
    atomicWrite(this.stateFile, JSON.stringify(this.firstSeen, null, 2) + '\n');
  }

  // Renaming validates DNS name constraints and refuses collisions with other
  // roots (explicit renames or auto-names) or manual registrations.
  rename(root, rawName, { liveAutoNames = new Set() } = {}) {
    if (isUnattributableRoot(root)) {
      return { ok: false, code: 'INVALID_REQUEST', reason: 'the filesystem root and the home folder are never a project' };
    }
    const check = validateName(rawName);
    if (!check.ok) {
      return { ok: false, code: 'INVALID_NAME', reason: check.reason };
    }
    const name = check.name;

    for (const [otherRoot, otherName] of Object.entries(this.config.renames)) {
      if (otherName === name && otherRoot !== root) {
        return { ok: false, code: 'NAME_CONFLICT', reason: `name "${name}" is already used by ${otherRoot}` };
      }
    }
    for (const [otherRoot, otherName] of Object.entries(this.config.names || {})) {
      if (otherName === name && otherRoot !== root) {
        return { ok: false, code: 'NAME_CONFLICT', reason: `name "${name}" is already used by ${otherRoot}` };
      }
    }
    if (liveAutoNames.has(name)) {
      return { ok: false, code: 'NAME_CONFLICT', reason: `name "${name}" is already used by an automatically discovered project` };
    }
    if (Object.hasOwn(this.config.manual, name)) {
      return { ok: false, code: 'NAME_CONFLICT', reason: `name "${name}" is already manually registered` };
    }

    this.#commit(() => {
      this.config.renames[root] = name;
      this.config.names[root] = name;
    });
    return { ok: true, name };
  }

  clearRename(root) {
    this.#commit(() => {
      delete this.config.renames[root];
    });
  }

  // Manual registrations (`portname add <name> <port>`) are the escape hatch
  // for Docker containers and anything lsof cannot attribute.
  // Fails closed if the name is already taken by live auto-routes, renames, or another port.
  // With createOnly, an existing manual name is rejected instead of updated —
  // the GUI's add form uses this so it can never silently repoint an entry.
  addManual(rawName, port, { liveAutoNames = new Set(), createOnly = false } = {}) {
    const check = validateName(rawName);
    if (!check.ok) {
      return { ok: false, code: 'INVALID_NAME', reason: check.reason };
    }
    const name = check.name;

    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      return { ok: false, code: 'INVALID_PORT', reason: 'invalid port' };
    }

    if (liveAutoNames.has(name)) {
      return { ok: false, code: 'NAME_CONFLICT', reason: `name "${name}" is already used by an automatically discovered project` };
    }

    if (createOnly && Object.hasOwn(this.config.manual, name)) {
      return { ok: false, code: 'NAME_CONFLICT', reason: `name "${name}" is already manually registered` };
    }

    for (const [otherRoot, otherName] of Object.entries(this.config.renames)) {
      if (otherName === name) {
        return { ok: false, code: 'NAME_CONFLICT', reason: `name "${name}" is already used by ${otherRoot}` };
      }
    }

    for (const [otherRoot, otherName] of Object.entries(this.config.names || {})) {
      if (otherName === name) {
        return { ok: false, code: 'NAME_CONFLICT', reason: `name "${name}" is already reserved by ${otherRoot}` };
      }
    }

    for (const [other, otherPort] of Object.entries(this.config.manual)) {
      if (otherPort === port && other !== name) {
        return { ok: false, code: 'NAME_CONFLICT', reason: `port ${port} is already registered as "${other}"` };
      }
      if (other === name) {
        this.#commit(() => {
          this.config.manual[name] = port;
        });
        // The previous port of the canonical entry: the daemon decides on
        // the scan-independent invalidation from this, never from its own
        // lookup of the raw (uncanonicalized) request name.
        return { ok: true, updated: true, name, port, previousPort: otherPort };
      }
    }

    this.#commit(() => {
      this.config.manual[name] = port;
    });
    return { ok: true, name, port };
  }

  // Canonical manual-entry name for a raw request name ("Shop", " shop "
  // -> "shop"), or null when the name can never be a manual entry.
  manualName(rawName) {
    const check = validateName(String(rawName ?? ''));
    return check.ok ? check.name : null;
  }

  hasManual(name) {
    return name !== null && name !== undefined && Object.hasOwn(this.config.manual, name);
  }

  // A revocation: a failed save keeps the removal in effect in memory.
  removeManual(name) {
    this.#commit(() => {
      delete this.config.manual[name];
    }, { keepOnFailure: true });
  }

  // The user's choice of which service (listener port) of a project carries
  // the project name. Keyed by root — never by PID — so the choice survives
  // restarts and process generations. Discovery honours it across
  // generations; if no living listener has the port, it falls back and the
  // route reports `preferredMissing` instead of silently picking.
  setPrimaryPort(root, port) {
    if (!root || isUnattributableRoot(root)) return;
    this.#commit(() => {
      this.config.primaryPorts = this.config.primaryPorts || {};
      this.config.primaryPorts[root] = port;
    });
  }

  primaryPort(root) {
    const ports = this.config.primaryPorts;
    return (ports && Object.hasOwn(ports, root) && ports[root]) || null;
  }

  manualEntries() {
    return Object.entries(this.config.manual).map(([name, port]) => ({ name, port, manual: true }));
  }

  isExposed(identity) {
    if (!identity) return false;
    return Object.hasOwn(this.config.exposed, identity) && this.config.exposed[identity] === true;
  }

  // Activation records the confirmed endpoint ({ port, command }) and is
  // rolled back when it cannot be persisted (fail-closed); deactivation
  // drops both and stays in effect in memory even then.
  setExposed(identity, on, target = null) {
    if (!identity || (on && isUnattributableRoot(identity))) return;
    this.#commit(() => {
      this.config.exposedTargets = this.config.exposedTargets || {};
      if (on) {
        this.config.exposed[identity] = true;
        if (target) {
          this.config.exposedTargets[identity] = {
            port: target.port,
            command: target.command ?? null,
            network: target.network ?? null,
            gateway: target.gateway ?? null,
          };
        }
      } else {
        delete this.config.exposed[identity];
        delete this.config.exposedTargets[identity];
      }
    }, { keepOnFailure: !on });
  }

  // The endpoint confirmed by the last `expose` of this identity, or null
  // (never confirmed, or confirmed by an older daemon that did not record
  // it — such an exposure stays paused until confirmed again).
  exposedTarget(identity) {
    const targets = this.config.exposedTargets;
    if (!identity || !targets || !Object.hasOwn(targets, identity)) return null;
    return targets[identity];
  }

  exposedIdentities() {
    return Object.keys(this.config.exposed);
  }

  exposedNames(routes = []) {
    return routes
      .filter((r) => this.isExposed(r.root || ('manual:' + r.name)))
      .map((r) => r.name);
  }

  // Persist listener births so "newest listener of a project wins the name".
  //
  // Retention bound: births of superseded process generations are only needed
  // while their listeners are alive. Dead generations older than
  // FIRST_SEEN_MAX_AGE_MS are dropped so the map cannot grow without bound.
  // Name reservations are NOT stored here (names/renames/primaryPorts are
  // config state), so pruning never touches named projects or reservations —
  // a stopped project keeps its name purely via config.json.
  observe(listeners, now = Date.now()) {
    let dirty = false;
    for (const l of listeners) {
      const key = l.processKey ? `${l.processKey}:${l.port}` : `${l.pid}:${l.port}`;
      if (!this.firstSeen[key]) {
        this.firstSeen[key] = now;
        dirty = true;
      }
    }
    const liveKeys = new Set(
      listeners.map((l) => (l.processKey ? `${l.processKey}:${l.port}` : `${l.pid}:${l.port}`))
    );
    for (const [key, ts] of Object.entries(this.firstSeen)) {
      if (now - ts > FIRST_SEEN_MAX_AGE_MS && !liveKeys.has(key)) {
        delete this.firstSeen[key];
        dirty = true;
      }
    }
    if (dirty) this.saveState();
  }
}

module.exports = { Registry, atomicWrite, dayNumber, MAX_NAME_ENTRIES, NAME_RESERVATION_TTL_DAYS };
