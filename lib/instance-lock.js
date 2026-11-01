'use strict';

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { getProcessInfo, getProcessStartTime } = require('./process');

// Exclusive ownership of a daemon state directory.
//
// Before a daemon may clean up "orphan" children, unlink the control socket
// or bind resources, it must hold this lock. The lock records robust process
// identity (PID *and* kernel process start time) plus a random instance id,
// so a bare stale PID file can never grant ownership: a PID that was reused
// by another process has a different start time and is treated as stale.
//
// Two live contenders can never both hold the lock: a complete claim is
// hard-linked into place, which fails atomically when a claim exists, so no
// reader ever sees an empty or half-written one. A lock whose owner is
// verifiably dead (process gone, or PID reused with a different start time
// and no daemon serving the control socket) may be stolen by a new daemon —
// that is the crash-recovery path. Takeovers are serialized by an O_EXCL
// marker and bound to the exact claim that was judged (same inode, same
// content): a contender whose judgment is late can never remove the fresh
// claim of the contender that already took over. A marker left behind by a
// contender that died is removed the same way — only the entry judged
// stale, never the fresh marker of a contender that is taking over.
class InstanceLockError extends Error {
  constructor(message, owner) {
    super(message);
    this.code = 'DAEMON_ALREADY_RUNNING';
    this.owner = owner;
  }
}

const LOCK_FILE = 'daemon.lock';
// The control socket the owning daemon serves in the same state dir.
const CONTROL_SOCKET = 'daemon.sock';
const ACQUIRE_ATTEMPTS = 10;
const ACQUIRE_RETRY_MS = 50;
const SOCKET_PROBE_TIMEOUT_MS = 500;
// An unparsable claim younger than this may still be in the middle of being
// written (older versions created the file empty first): it is no evidence
// of a crash and is not stolen.
const UNREADABLE_CLAIM_GRACE_MS = 2000;
// A takeover marker older than this was left by a contender that died while
// taking over.
const TAKEOVER_STALE_MS = 10000;
// Filesystems without hard links fall back to an O_EXCL create.
const LINK_UNSUPPORTED = new Set(['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS']);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// Jittered, so contenders that collided do not retry in lockstep.
const retryDelay = () => ACQUIRE_RETRY_MS / 2 + Math.random() * ACQUIRE_RETRY_MS;

function parseOwner(text) {
  try {
    const raw = JSON.parse(text);
    // A null start time is a degraded but valid claim: the owner could not
    // read its own start time while acquiring (transient ps failure). It is
    // verified via the signal-0 probe instead of a start-time comparison.
    if (raw && Number.isInteger(raw.pid) && raw.pid > 0 &&
        (raw.startTime === null || typeof raw.startTime === 'string')) {
      return raw;
    }
  } catch {
    // unreadable / partially written — treated as unverified below
  }
  return null;
}

function readOwner(lockFile) {
  try {
    return parseOwner(fs.readFileSync(lockFile, 'utf8'));
  } catch {
    return null;
  }
}

// The claim as judged: its owner plus the identity of the file it was read
// from (dev/ino and raw content), so a takeover can never remove a different
// — newer — claim. Null when no claim exists.
function readClaim(lockFile) {
  let fd;
  try {
    fd = fs.openSync(lockFile, 'r');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  try {
    const st = fs.fstatSync(fd);
    const text = fs.readFileSync(fd, 'utf8');
    return { owner: parseOwner(text), text, dev: st.dev, ino: st.ino, mtimeMs: st.mtimeMs };
  } finally {
    fs.closeSync(fd);
  }
}

function sameClaim(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.text === b.text;
}

// Moves a fully written claim into place. link() fails with EEXIST when a
// claim exists, so publishing is atomic and never exposes partial content.
// Returns false when another claim is in place.
function linkClaim(tmpFile, lockFile) {
  try {
    fs.linkSync(tmpFile, lockFile);
    return true;
  } catch (err) {
    if (err.code === 'EEXIST') return false;
    if (!LINK_UNSUPPORTED.has(err.code)) throw err;
  }
  const content = fs.readFileSync(tmpFile);
  let fd;
  try {
    fd = fs.openSync(lockFile, 'wx', 0o600);
  } catch (err) {
    if (err.code === 'EEXIST') return false;
    throw err;
  }
  try {
    fs.writeFileSync(fd, content);
  } finally {
    fs.closeSync(fd);
  }
  return true;
}

function sameEntry(st, expected) {
  return st.dev === expected.dev && st.ino === expected.ino && st.mtimeMs === expected.mtimeMs;
}

// Removes `file` only while it is the exact entry `expected` (an fs.Stats)
// describes; the mtime guards against an inode number reused by a newer
// file. There is no unlink-if-same: the entry is renamed aside under a
// unique name first, which captures whatever sits there atomically, and only
// the captured entry is checked. An entry that replaced the expected one
// after it was judged is therefore never deleted but put back — unless a
// newer one took the name meanwhile. Returns whether the entry was removed.
function removeIfSame(file, expected) {
  try {
    if (!sameEntry(fs.lstatSync(file), expected)) return false;
  } catch {
    return false;
  }
  const aside = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.aside`;
  try {
    fs.renameSync(file, aside);
  } catch {
    return false; // removed by someone else meanwhile
  }
  let same = false;
  try {
    same = sameEntry(fs.lstatSync(aside), expected);
  } catch {}
  if (!same) {
    try {
      fs.linkSync(aside, file);
    } catch (err) {
      // Without hard links it goes back by name, unless the name is taken.
      if (LINK_UNSUPPORTED.has(err.code) && !fs.existsSync(file)) {
        try { fs.renameSync(aside, file); } catch {}
      }
    }
  }
  try { fs.unlinkSync(aside); } catch {}
  return same;
}

// Replaces the judged stale claim with ours in one critical section,
// serialized by an O_EXCL marker. Inside it the claim on disk must still be
// exactly the judged one; otherwise someone already took over and nothing is
// removed. Returns true when our claim is in place.
function takeOverStaleClaim(lockFile, judged, tmpFile, log) {
  const marker = `${lockFile}.takeover`;
  let markerStat;
  try {
    const fd = fs.openSync(marker, 'wx', 0o600);
    markerStat = fs.fstatSync(fd);
    fs.closeSync(fd);
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
    // Another contender is taking over right now — or died doing so. Only
    // the marker judged stale is removed, never a fresh one that replaced it
    // in the meantime; the marker is then claimed through O_EXCL on a later
    // attempt, never taken over in this one.
    try {
      const st = fs.lstatSync(marker);
      if (Date.now() - st.mtimeMs > TAKEOVER_STALE_MS && removeIfSame(marker, st)) {
        log('daemon', 'lock-takeover-marker-stale', marker);
      }
    } catch {}
    return false;
  }
  try {
    const current = readClaim(lockFile);
    if (current && !sameClaim(current, judged)) return false;
    if (current) fs.unlinkSync(lockFile);
    return linkClaim(tmpFile, lockFile);
  } finally {
    removeIfSame(marker, markerStat);
  }
}

// Conservative signal-0 probe: success and EPERM mean the process exists
// (EPERM: it is alive, just not signalable by us); only ESRCH is positive
// evidence that it is gone. Anything else is treated as alive.
function pidExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code !== 'ESRCH';
  }
}

// Whether something accepts connections on the state dir's control socket.
// A stale socket file (crashed owner) refuses; a missing one does not exist.
// No answer within the timeout counts as alive: refusing to start is the
// safe side of an unclear verdict.
function controlSocketAnswers(sockPath, timeoutMs = SOCKET_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    let done = false;
    let sock = null;
    let timer = null;
    const finish = (value) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (sock) sock.destroy();
      resolve(value);
    };
    timer = setTimeout(() => finish(true), timeoutMs);
    try {
      sock = net.connect(sockPath);
    } catch {
      finish(false);
      return;
    }
    sock.once('connect', () => finish(true));
    sock.once('error', () => finish(false));
  });
}

async function ownerIsAlive(owner, getProcessInfoFn, isOwnerServing) {
  const info = getProcessInfoFn(owner.pid);
  if (!info) {
    // `ps` found nothing: that is either a dead process or a transient ps
    // failure. Steal only on positive evidence that the PID is gone — a
    // wrongful "dead" verdict would let the stealer's cleanupOrphans kill
    // the live owner's children.
    return pidExists(owner.pid);
  }
  if (typeof owner.startTime !== 'string') {
    // Degraded claim: the start time cannot be compared, so fall back to
    // the probe only.
    return pidExists(owner.pid);
  }
  // Alive when the kernel start time still matches what the owner recorded:
  // protects against PID reuse by an unrelated process.
  if (info.startTime === owner.startTime) return true;
  // A mismatch on a live PID is PID reuse — or a live owner whose record is
  // not comparable (written by an older version in another locale or time
  // zone). A daemon still serving this state dir's control socket is alive
  // whatever its record says; only without one is the claim stale.
  return isOwnerServing();
}

async function acquireInstanceLock({
  dir,
  instanceId,
  getProcessInfo: processInfoFn = getProcessInfo,
  isOwnerServing = null,
  log = () => {},
} = {}) {
  if (!dir) throw new Error('acquireInstanceLock requires a state dir');
  fs.mkdirSync(dir, { recursive: true });
  const lockFile = path.join(dir, LOCK_FILE);
  const ownerServing = isOwnerServing || (() => controlSocketAnswers(path.join(dir, CONTROL_SOCKET)));
  const myIdentity = {
    pid: process.pid,
    // May be null when ps fails transiently; the lock then carries a
    // degraded claim that contenders verify via the signal-0 probe.
    startTime: getProcessStartTime(process.pid),
    instanceId,
    acquiredAt: new Date().toISOString(),
  };

  const handle = {
    file: lockFile,
    instanceId,
    // Release only when the file still names *this* instance: a successor
    // that stole our (somehow stale-looking) claim must keep its own.
    release() {
      const owner = readOwner(lockFile);
      if (!owner || owner.instanceId !== instanceId) return;
      try { fs.unlinkSync(lockFile); } catch {}
    },
  };

  // The complete claim is written once, up front, to a private file; every
  // attempt only links it into place. Created while any judged claim still
  // exists, its inode can never be mistaken for one.
  const tmpFile = `${lockFile}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(myIdentity, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  try {
    for (let attempt = 0; attempt < ACQUIRE_ATTEMPTS; attempt++) {
      if (linkClaim(tmpFile, lockFile)) return handle;

      // Someone else holds the claim. Fail defined only when that owner is
      // verifiably alive; anything else is a stale claim after a crash.
      const claim = readClaim(lockFile);
      if (!claim) continue; // released meanwhile: link again right away
      if (claim.owner) {
        const owner = claim.owner;
        if (await ownerIsAlive(owner, processInfoFn, ownerServing)) {
          throw new InstanceLockError(
            `another portname daemon (pid ${owner.pid}, started ${owner.startTime}) is already managing ${dir}`,
            { pid: owner.pid, startTime: owner.startTime, instanceId: owner.instanceId }
          );
        }
      } else if (Date.now() - claim.mtimeMs < UNREADABLE_CLAIM_GRACE_MS) {
        await sleep(retryDelay());
        continue;
      }
      log('daemon', claim.owner ? 'lock-stolen-from-dead-owner' : 'lock-stolen-unreadable',
        claim.owner ? claim.owner.pid : lockFile);
      if (takeOverStaleClaim(lockFile, claim, tmpFile, log)) return handle;
      await sleep(retryDelay());
    }
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }

  throw new InstanceLockError(
    `could not acquire daemon lock for ${dir} after ${ACQUIRE_ATTEMPTS} attempts (concurrent start?)`,
    null
  );
}

module.exports = { acquireInstanceLock, InstanceLockError, LOCK_FILE };
