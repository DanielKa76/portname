'use strict';

const childProcess = require('child_process');

// Bounded subprocess runs. Node's execFile timeout sends ONE SIGTERM and only
// calls back once the child has exited and its pipes have closed — a child
// that ignores SIGTERM, hands its stdout to a grandchild, or hangs in an
// uninterruptible kernel wait would leave the promise (and with it a whole
// discovery pass) pending forever. runBounded therefore escalates to SIGKILL
// after a grace period and settles on its own timer after another one,
// whatever the child does.
const SUBPROCESS_TIMEOUT_MS = 3000;
const SUBPROCESS_MAX_BUFFER_BYTES = 1024 * 1024;
const KILL_GRACE_MS = 500;
// A child still alive after the promise gave up on it (not even SIGKILL got
// through) is tracked per command. While that many are stuck, new runs of the
// command fail fast instead of piling up one more wedged process per scan.
const MAX_ABANDONED_PER_COMMAND = 2;
const abandonedChildren = new Map(); // cmd -> Set<ChildProcess>

function runBounded(cmd, args, {
  timeoutMs = SUBPROCESS_TIMEOUT_MS,
  maxBuffer = SUBPROCESS_MAX_BUFFER_BYTES,
  env = undefined,
  killGraceMs = KILL_GRACE_MS,
} = {}) {
  return new Promise((resolve, reject) => {
    const stuck = abandonedChildren.get(cmd);
    if (stuck && stuck.size >= MAX_ABANDONED_PER_COMMAND) {
      const err = new Error(`${cmd} not started: ${stuck.size} earlier ${cmd} process(es) did not exit after SIGKILL`);
      err.code = 'ESUBPROCESSWEDGED';
      reject(err);
      return;
    }
    let settled = false;
    let escalateTimer = null;
    let settleTimer = null;
    const child = childProcess.execFile(cmd, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer, env }, (err, stdout, stderr) => {
      clearTimeout(escalateTimer);
      clearTimeout(settleTimer);
      if (settled) return;
      settled = true;
      if (err) {
        err.stdout = stdout;
        err.stderr = stderr;
        reject(err);
      } else {
        resolve({ stdout, stderr });
      }
    });
    const exited = () => child.exitCode !== null || child.signalCode !== null;
    escalateTimer = setTimeout(() => {
      if (!exited()) {
        try { child.kill('SIGKILL'); } catch {}
      }
    }, timeoutMs + killGraceMs);
    settleTimer = setTimeout(() => {
      if (settled) return;
      settled = true;
      // Detach: the pipes may be held open by a grandchild, and the child
      // itself may never exit — neither may keep the promise or the daemon's
      // event loop alive.
      try { child.stdout && child.stdout.destroy(); } catch {}
      try { child.stderr && child.stderr.destroy(); } catch {}
      child.unref();
      if (!exited()) {
        if (!abandonedChildren.has(cmd)) abandonedChildren.set(cmd, new Set());
        const set = abandonedChildren.get(cmd);
        set.add(child);
        child.once('exit', () => {
          set.delete(child);
          if (set.size === 0 && abandonedChildren.get(cmd) === set) abandonedChildren.delete(cmd);
        });
      }
      const err = new Error(`${cmd} did not finish within ${timeoutMs}ms (killed)`);
      err.killed = true;
      err.signal = 'SIGKILL';
      err.code = 'ETIMEDOUT';
      err.stdout = '';
      err.stderr = '';
      reject(err);
    }, timeoutMs + 2 * killGraceMs);
  });
}

// Process identity is the text of `ps -o lstart`. ps formats it with
// strftime("%c", localtime(...)), so the string depends on the caller's
// locale and time zone: a LaunchAgent without LANG and a Terminal with
// de_DE.UTF-8 — or one daemon before and after a time-zone change — would
// disagree about the identity of the same live process (and steal its lock or
// revoke its shares). Every ps call therefore runs in the C locale and UTC.
const PS_ENV = Object.freeze({ LC_ALL: 'C', LANG: 'C', TZ: 'UTC0' });

function psEnv() {
  return { ...process.env, ...PS_ENV };
}

// Synchronous lookups (lock acquisition, orphan cleanup) are bounded too:
// without killSignal SIGKILL, execFileSync would wait out a child that
// ignores the timeout's SIGTERM.
function psSync(args) {
  return childProcess.execFileSync('ps', args, {
    encoding: 'utf8',
    env: psEnv(),
    timeout: SUBPROCESS_TIMEOUT_MS,
    killSignal: 'SIGKILL',
    stdio: ['ignore', 'pipe', 'ignore'],
  });
}

function getProcessStartTime(pid) {
  try {
    return psSync(['-p', String(pid), '-o', 'lstart=']).trim() || null;
  } catch (err) {
    return null;
  }
}

function getProcessCommand(pid) {
  try {
    return psSync(['-p', String(pid), '-o', 'comm=']).trim() || null;
  } catch (err) {
    return null;
  }
}

// Async variants for the regular discovery loop: they keep the Node event
// loop — and with it the HTTP gateway — free while child processes run, and
// are bounded (see runBounded) so a wedged ps cannot stall a scan.
async function execFileAsync(cmd, args) {
  return (await runBounded(cmd, args, { env: psEnv() })).stdout;
}

// One `ps` for many pids. Resolves to a Map pid -> start time for every pid
// ps reported; a pid missing from the map is not running. Rejects when ps
// itself failed (timeout, spawn error, unexpected exit) so callers can tell
// "process gone" from "lookup failed". The start time string is identical to
// getProcessStartTime's for the same pid (same environment, same column).
async function getProcessStartTimesAsync(pids) {
  const wanted = [...new Set(pids.map(Number).filter((p) => Number.isInteger(p) && p > 0))];
  const times = new Map();
  if (wanted.length === 0) return times;
  // Separate -o/-p flags: BSD ps lets a `keyword=` header swallow the rest of
  // its argument, so `-o pid=,lstart=` would not print the start time there.
  const args = ['-o', 'pid=', '-o', 'lstart='];
  for (const pid of wanted) args.push('-p', String(pid));
  let stdout;
  try {
    ({ stdout } = await runBounded('ps', args, { env: psEnv() }));
  } catch (err) {
    // ps exits 1 when (some of) the selected pids do not exist; the pids it
    // did find are still listed. Anything else is a failed lookup.
    if (err.killed || err.signal || err.code !== 1 || String(err.stderr || '').trim()) throw err;
    stdout = err.stdout || '';
  }
  const wantedSet = new Set(wanted);
  for (const line of String(stdout).split('\n')) {
    const m = /^\s*(\d+)\s+(\S.*?)\s*$/.exec(line);
    if (m && wantedSet.has(Number(m[1]))) times.set(Number(m[1]), m[2]);
  }
  return times;
}

// Single-pid lookup with the historical contract (null on any failure).
// Calls made in the same event-loop turn — e.g. the bounded fan-out of one
// discovery pass — are coalesced into one batched ps.
let pendingStartTimeBatch = null;

function getProcessStartTimeAsync(pid) {
  return new Promise((resolve) => {
    if (!pendingStartTimeBatch) {
      const batch = new Map(); // pid -> [resolve]
      pendingStartTimeBatch = batch;
      setImmediate(() => {
        if (pendingStartTimeBatch === batch) pendingStartTimeBatch = null;
        getProcessStartTimesAsync([...batch.keys()]).then(
          (times) => {
            for (const [p, waiters] of batch) for (const w of waiters) w(times.get(p) || null);
          },
          () => {
            for (const waiters of batch.values()) for (const w of waiters) w(null);
          }
        );
      });
    }
    const key = Number(pid);
    if (!pendingStartTimeBatch.has(key)) pendingStartTimeBatch.set(key, []);
    pendingStartTimeBatch.get(key).push(resolve);
  });
}

async function getProcessArgsAsync(pid) {
  try {
    // -ww: BSD ps truncates the last column to the terminal width (79
    // columns when there is no terminal, e.g. under launchd) — debug flags
    // late in a long command line would otherwise be cut off.
    return (await execFileAsync('ps', ['-ww', '-p', String(pid), '-o', 'args='])).trim();
  } catch (err) {
    return '';
  }
}

function getProcessKey(pid, startTime) {
  return `${pid}:${startTime || 'unknown'}`;
}

function getProcessInfo(pid) {
  const startTime = getProcessStartTime(pid);
  if (!startTime) return null;
  const command = getProcessCommand(pid);
  return { pid, startTime, command, processKey: getProcessKey(pid, startTime) };
}

module.exports = {
  getProcessStartTime,
  getProcessStartTimeAsync,
  getProcessStartTimesAsync,
  getProcessCommand,
  getProcessArgsAsync,
  getProcessKey,
  getProcessInfo,
  runBounded,
  PS_ENV,
};
