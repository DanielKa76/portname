'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');
const { validateName, sanitizeName } = require('./naming');
const {
  getProcessStartTime,
  getProcessStartTimesAsync,
  getProcessArgsAsync,
  getProcessKey,
  runBounded,
} = require('./process');

// Machine-readable lsof: -F0 field separator (NUL), fields p<pid> c<command>
// n<address>. lsof selection flags OR-combine; we rely on the kernel instead
// of -a: a non-root lsof only ever sees the current user's descriptors.
// lsof address forms: *:8080, 127.0.0.1:8080, [::1]:8080, 192.168.0.5:8080.
function listenAddressIsExternal(address) {
  let host;
  if (address.startsWith('[')) {
    const close = address.indexOf(']');
    host = close !== -1 ? address.slice(1, close) : address;
  } else {
    const lastColon = address.lastIndexOf(':');
    host = lastColon !== -1 ? address.slice(0, lastColon) : address;
  }
  return host !== '127.0.0.1' && host !== '::1' && host !== 'localhost';
}

const LSOF_ARGS = ['-nP', '-iTCP', '-sTCP:LISTEN', '-F0pcnt'];

// The async listener scan is bounded in time and output size: a wedged lsof
// must delay a scan pass, not stall it (runBounded escalates to SIGKILL and
// settles even when the child never exits), and a huge listener table must
// not exhaust memory via stdout buffering.
const LSOF_TIMEOUT_MS = 5000;
const LSOF_CWD_TIMEOUT_MS = 3000;

// lsof prints names through its "safe" printer: in a non-UTF-8 locale — a
// LaunchAgent has no LANG — every non-ASCII byte of a path becomes `\xNN`.
// The root walk then never found the .git above `~/Projekte/Bäckerei-shop/…`,
// and a launchd daemon named projects differently than a Terminal one. lsof
// therefore runs in a UTF-8 locale, and escapes that still appear (invalid
// UTF-8, control characters, older lsof builds) are decoded below.
const LSOF_UTF8_LOCALE = process.platform === 'darwin' ? 'en_US.UTF-8' : 'C.UTF-8';

function lsofEnv() {
  return { ...process.env, LC_ALL: LSOF_UTF8_LOCALE };
}

const LSOF_CONTROL_ESCAPES = { b: 0x08, f: 0x0c, n: 0x0a, r: 0x0d, t: 0x09 };

// Reverses lsof's safe printing: `\\` (backslash), `\xNN` (raw byte),
// `\b \f \n \r \t`, and — unless `carets` is false — `^@`..`^_` (control
// characters). Literal `^` is not escaped by lsof, so caret decoding is
// ambiguous; callers try both readings (see resolveLsofPath).
function decodeLsofName(raw, { carets = true } = {}) {
  if (!/[\\^]/.test(raw)) return raw;
  const bytes = [];
  let i = 0;
  while (i < raw.length) {
    const ch = raw[i];
    const next = raw[i + 1];
    if (ch === '\\' && next === '\\') {
      bytes.push(0x5c);
      i += 2;
    } else if (ch === '\\' && next === 'x' && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 2, i + 4))) {
      bytes.push(parseInt(raw.slice(i + 2, i + 4), 16));
      i += 4;
    } else if (ch === '\\' && next !== undefined && LSOF_CONTROL_ESCAPES[next] !== undefined) {
      bytes.push(LSOF_CONTROL_ESCAPES[next]);
      i += 2;
    } else if (carets && ch === '^' && next !== undefined && next.charCodeAt(0) >= 0x40 && next.charCodeAt(0) <= 0x5f) {
      bytes.push(next.charCodeAt(0) - 0x40);
      i += 2;
    } else {
      const literal = String.fromCodePoint(raw.codePointAt(i));
      for (const b of Buffer.from(literal, 'utf8')) bytes.push(b);
      i += literal.length;
    }
  }
  return Buffer.from(bytes).toString('utf8');
}

// A cwd reported by lsof, as a usable path: the decoded reading that exists
// on disk wins; otherwise the name as printed is kept (stable identity, no
// worse than before).
function resolveLsofPath(raw) {
  const candidates = [decodeLsofName(raw), decodeLsofName(raw, { carets: false })];
  if (candidates[0] === raw) return raw;
  try {
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) return candidate;
    }
  } catch {
    // fall through to the raw name
  }
  return raw;
}
const LSOF_MAX_BUFFER_BYTES = 16 * 1024 * 1024;

// Failure semantics: lsof exits 1 with NO stdout and NO stderr when the
// selection matches nothing — that is the one benign result allowed to become
// an empty scan. Everything else (killed by timeout, forced termination,
// maxBuffer truncation, missing binary, exit 1 with warnings, exit 1 with
// partial output) throws with the exit reason, so the daemon keeps its
// previous routes and reports a degraded scan instead of publishing a
// "complete" snapshot built from partial output.
function parseListenerRecords(out, excludePids = []) {
  const selfPid = process.pid;
  const byKey = new Map();
  // -F0 layout: fields are NUL-terminated, lines are newline-terminated, and
  // a listener's p/c/t fields and its f/n fields land on DIFFERENT lines — so
  // the current process context is carried across lines until an n-field.
  let curPid = null;
  let curCommand = null;
  let curType = null;
  for (const record of out.split('\n')) {
    if (!record) continue;
    for (const field of record.split('\0')) {
      if (!field) continue;
      const c = field[0];
      const v = field.slice(1);
      if (c === 'p') {
        curPid = Number(v);
        curCommand = null;
        curType = null;
      } else if (c === 'c') {
        curCommand = v;
      } else if (c === 't') {
        curType = v;
      } else if (c === 'n' && curPid != null) {
        const lastColon = v.lastIndexOf(':');
        if (lastColon === -1) continue;
        const hostPart = v.slice(0, lastColon);
        const portPart = v.slice(lastColon + 1);
        const port = Number(portPart);
        if (!port || Number.isNaN(port)) continue;
        if (curPid === selfPid || excludePids.includes(curPid)) continue;

        const key = `${curPid}:${port}`;
        const external = listenAddressIsExternal(v);

        let upstreamHost = '127.0.0.1';
        const cleanHost = hostPart.replace(/^\[|\]$/g, '');
        if (cleanHost === '::1') {
          upstreamHost = '::1';
        } else if (cleanHost === '::' || (cleanHost === '*' && curType === 'IPv6')) {
          upstreamHost = '::1';
        } else if (cleanHost === '*' || cleanHost === '0.0.0.0' || cleanHost === '127.0.0.1' || cleanHost === 'localhost') {
          upstreamHost = '127.0.0.1';
        } else if (cleanHost) {
          upstreamHost = cleanHost;
        }

        const existing = byKey.get(key);
        if (existing) {
          existing.external = existing.external || external;
          if (upstreamHost === '::1') {
            existing.upstreamHost = '::1';
          }
        } else {
          byKey.set(key, { pid: curPid, port, command: curCommand || 'proc', external, upstreamHost });
        }
      }
    }
  }
  return [...byKey.values()];
}

// Classifies a failed lsof run. Returns null for the one benign no-match
// shape (exit 1, no stdout, no stderr, not killed); otherwise a diagnostic
// reason string.
function lsofFailureReason(err, stdout, stderr) {
  if (!err.killed && !err.signal && err.code === 1 && !stdout && !stderr) {
    return null;
  }
  let reason;
  if (err.killed || err.signal) {
    reason = `terminated by ${err.signal || 'signal'} (timeout)`;
  } else if (err.code === 'ESUBPROCESSWEDGED') {
    reason = err.message;
  } else if (err.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') {
    reason = 'output exceeded maxBuffer (truncated)';
  } else if (err.code === 'ENOENT') {
    reason = 'lsof not found';
  } else {
    reason = `exit code ${err.code ?? err.status ?? 'unknown'}`;
  }
  const stderrLine = String(stderr || '').split('\n').find((l) => l.trim());
  if (stderrLine) reason += `: ${stderrLine.slice(0, 200)}`;
  return reason;
}

// Async scanner: keeps the event loop (and the HTTP gateway riding on it)
// responsive while lsof runs. This is the variant the daemon uses. On failure
// it rejects — a timeout or forced kill with partial stdout is never resolved
// as a (partial) snapshot.
async function listListenersAsync({ excludePids = [], timeoutMs = LSOF_TIMEOUT_MS, maxBufferBytes = LSOF_MAX_BUFFER_BYTES } = {}) {
  let stdout;
  try {
    ({ stdout } = await runBounded('lsof', LSOF_ARGS, { timeoutMs, maxBuffer: maxBufferBytes, env: lsofEnv() }));
  } catch (err) {
    const reason = lsofFailureReason(err, err.stdout, err.stderr);
    if (reason === null) return [];
    throw new Error(`listener scan failed (${reason})`);
  }
  return parseListenerRecords(stdout, excludePids);
}

// Known non-HTTP listeners. The gateway proxies HTTP only, so services like
// databases can never work as <name>.localhost routes — they would only ever
// answer with 502 — and are excluded from auto-discovery. The set is extended
// by `ignoreCommands` from ~/.portname/config.json; manual registrations are
// unaffected (those are explicit human decisions).
//
// Deliberately NOT listed: `ssh`/`sshd`. An ssh -L port-forward is
// indistinguishable by command name from a working HTTP route (its far end is
// often a web server) — live evidence: a routed ssh listener answering 200.
// The same caution applies to lima/virtualization port-forwards.
const NON_HTTP_COMMANDS = new Set([
  'postgres', 'postmaster', 'mysqld', 'mariadbd', 'mongod', 'redis-server',
  'memcached', 'limactl',
]);

// WebDriver servers speak HTTP, but an automatically routed — let alone
// WLAN-exposed — chromedriver hands out browser control and process launch
// to whoever reaches it. They are never auto-discovered; `portname add`
// stays possible as an explicit decision.
const AUTOMATION_DRIVER_COMMANDS = new Set([
  'chromedriver', 'geckodriver', 'msedgedriver', 'safaridriver',
]);

function ignoredCommandsFilter(extraCommands = []) {
  const ignored = new Set([...NON_HTTP_COMMANDS, ...AUTOMATION_DRIVER_COMMANDS]);
  for (const c of extraCommands) {
    const lower = String(c || '').trim().toLowerCase();
    if (lower) ignored.add(lower);
  }
  return (listener) => !ignored.has(String(listener.command || '').toLowerCase());
}

function cwdOf(pid) {
  try {
    const out = execFileSync('lsof', ['-a', '-p', String(pid), '-d', 'cwd', '-Fn'], {
      encoding: 'utf8',
      env: lsofEnv(),
      timeout: LSOF_CWD_TIMEOUT_MS,
      killSignal: 'SIGKILL',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    for (const line of out.split('\n')) {
      if (line.startsWith('n')) return resolveLsofPath(line.slice(1));
    }
  } catch (err) {
    // Process may have exited between listing and cwd lookup.
  }
  return null;
}

async function cwdOfAsync(pid) {
  try {
    const { stdout: out } = await runBounded('lsof', ['-a', '-p', String(pid), '-d', 'cwd', '-Fn'], {
      timeoutMs: LSOF_CWD_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
      env: lsofEnv(),
    });
    for (const line of out.split('\n')) {
      if (line.startsWith('n')) return resolveLsofPath(line.slice(1));
    }
  } catch (err) {
    // Process may have exited between listing and cwd lookup.
  }
  return null;
}

// Walk up from cwd to the nearest directory containing .git; fall back to cwd
// itself so worktree subdirectories still collapse onto their repository name.
//
// The filesystem root and the home directory are never a project identity:
// every app launched by launchd/Finder runs in '/', and a dotfiles repo
// (~/.git) would merge every non-repo folder under ~ into one project. An
// identity shared by unrelated processes would hand its name — and a WLAN
// exposure — from one app to whichever starts next. Such listeners stay
// unattributed (null): no automatic route, `portname add` still works.
//
// lsof reports a cwd with symlinks resolved, so $HOME and the walk's upper
// bound are compared in both forms (see dirForms): a symlinked $HOME must
// neither become a project itself nor turn every repository below it into
// "outside $HOME", where monorepo subfolders would become separate projects.
function projectRootOf(cwd, { stopAt = os.homedir() } = {}) {
  if (!cwd) return null;
  const start = path.resolve(cwd);
  const stops = stopAt ? dirForms(stopAt) : [];
  const homeForms = dirForms(os.homedir());
  const unattributable = (dir) => isUnattributableDir(dir, homeForms);
  const within = (dir) => stops.some((stop) => dir.startsWith(stop + path.sep));
  const fallback = unattributable(start) ? null : start;
  let dir = start;
  for (;;) {
    if (!unattributable(dir)) {
      try {
        if (fs.existsSync(path.join(dir, '.git'))) return dir;
      } catch (err) {
        return fallback;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) return fallback;
    if (stops.length > 0 && (stops.includes(dir) || !within(dir))) return fallback;
    dir = parent;
  }
}

// A directory as given and with symlinks resolved — the two spellings a
// path can arrive in (configuration vs. lsof).
function dirForms(dir) {
  const resolved = path.resolve(dir);
  try {
    const real = fs.realpathSync.native(resolved);
    if (real !== resolved) return [resolved, real];
  } catch {
    // missing or unreadable: the given spelling is all there is
  }
  return [resolved];
}

// The filesystem root and the home directory (in either form) are never a
// project identity: projectRootOf attributes nothing to them, and the
// registry refuses them as keys.
function isUnattributableDir(dir, homeForms = dirForms(os.homedir())) {
  const resolved = path.resolve(dir);
  return resolved === path.parse(resolved).root || homeForms.includes(resolved);
}

function isInspectorListener(l) {
  return Boolean(l.isInspector);
}

// Runs `worker` over `items` with at most `limit` workers in flight. A small
// local helper instead of a dependency: the only fan-out that needs bounding
// here is discovery subprocess/probe scheduling.
async function mapWithLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  const lanes = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: lanes }, async () => {
    for (;;) {
      const i = next;
      next += 1;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  }));
  return results;
}

// Debug endpoints (Node/Deno/Bun inspectors, Chromium/Electron DevTools,
// Firefox Remote Agent/Marionette, debugpy) must never become a route's
// primary: proxied through the gateway with `Host: localhost`, they would
// hand code execution and file access to every client of the route.
// Detection runs for every command, not only node, and for every listener
// with a project root — the only ones that can become routes.
//
// Verdicts are cached per process generation + port (`<processKey>:<port>`),
// so a stable process is examined once instead of on every scan:
//   - a debug flag naming the port (or args that make every listener of the
//     process a debug endpoint, see debugEndpointsFromArgs), or a
//     /json/version answer shaped like a DevTools/inspector endpoint:
//     positive, sticky;
//   - any other complete answer (404, HTML, foreign JSON, oversized body,
//     non-HTTP bytes) once the process args were read: definitive negative,
//     sticky;
//   - no answer (timeout, refused, reset): transient, retried with an
//     exponential backoff from negativeTtlMs up to INSPECTOR_RETRY_MAX_MS.
// A new process generation (or a recycled pid) has a new key.
const INSPECTOR_PROBE_CONCURRENCY = 8;
const INSPECTOR_NEGATIVE_TTL_MS = 5000;
const INSPECTOR_RETRY_MAX_MS = 5 * 60 * 1000;
const INSPECTOR_CACHE_PRUNE_AT = 100;

const PROBE_INSPECTOR = 'inspector';
const PROBE_NEGATIVE = 'negative';
const PROBE_TRANSIENT = 'transient';

// Debug endpoints announced on the command line, for every runtime:
//   - `--inspect[-brk|-wait][=[host:]port]` and `--inspect-port[=| ]port`
//     (node, deno, bun; without any port: the runtime's default, 6499 for
//     Bun and 9229 for node and deno);
//   - `--remote-debugging-port[=| ]N` (Chromium, Electron, Chrome for
//     Testing, Firefox's Remote Agent / WebDriver BiDi);
//   - `-start-debugger-server [ws:]N` (Firefox DevTools server) and
//     `--marionette` (Firefox; its port lives in prefs, never in args).
// Browsers accept one or two leading dashes and the value after `=` or as
// the next argument (geckodriver passes `--remote-debugging-port 9222`).
//
// Browser/automation flags fail closed: with a port of 0 (random), missing or
// unparsable, the args cannot say which listener is the debug endpoint, and
// the probe cannot either (a BiDi-only Firefox answers /json/version with
// 404). Every listener of such a process then counts as a debug endpoint —
// browsers serve no project content, so nothing is lost.
const DEBUG_FLAG_RE = /(?:^|\s)--?(inspect(?:-brk|-wait|-port)?|remote-debugging-port|start-debugger-server|marionette)(?:=(\S*)|\s+(?!-)(\S+))?(?=\s|$)/g;
const SEPARATE_VALUE_FLAGS = new Set(['inspect-port', 'remote-debugging-port', 'start-debugger-server']);
const BROWSER_DEBUG_FLAGS = new Set(['remote-debugging-port', 'start-debugger-server', 'marionette']);
const DEFAULT_INSPECTOR_PORT = 9229;
const BUN_DEFAULT_INSPECTOR_PORT = 6499;
// Bun's executable as the first word of the command line (`bun`,
// `~/.bun/bin/bun`); a path with spaces is caught by the lsof command name.
const BUN_EXECUTABLE_RE = /^(?:\S*\/)?bun(?=\s|$)/;

function defaultInspectorPort(args, command) {
  const bun = BUN_EXECUTABLE_RE.test(args) || String(command || '').toLowerCase() === 'bun';
  return bun ? BUN_DEFAULT_INSPECTOR_PORT : DEFAULT_INSPECTOR_PORT;
}

// debugpy (VS Code's Python debugger) speaks DAP, not HTTP, so the probe
// cannot recognise it; only command lines give it away:
//   - its debug adapter (`<python> <dir>/debugpy/adapter --for-server N
//     --host H --port P ...`, `-m debugpy.adapter`, `debugpy-adapter`) is a
//     separate, daemonized process that keeps the project cwd and serves
//     nothing but DAP — on the client port and on an ephemeral one for the
//     debuggee —, so every listener of it is a debug endpoint. The script
//     must be the adapter itself: VS Code starts the debuggee (the app) as
//     `<python> .../debugpy/adapter/../../debugpy/launcher/../../debugpy
//     --connect ...`, which passes through that directory;
//   - the debugpy CLI's `--listen [host:]port` names the DAP port of an
//     in-process listener. Only debugpy's own switches, which precede its
//     target (<file> | -m <module> | -c <code> | --pid <pid>), are read, so a
//     `--listen` of the program itself is not taken for the debugger's.
const DEBUGPY_ADAPTER_RE = /(?:^|[\s/\\])(?:debugpy[/\\]adapter(?:[/\\](?:__main__\.py)?)?|debugpy-adapter)(?=\s|$)|(?:^|\s)-m\s*debugpy\.adapter(?=\s|$)/;
const DEBUGPY_CLI_RE = /(?:^|\s)(?:-m\s*debugpy|(?:\S*[/\\])?debugpy(?:[/\\]__main__\.py)?)(?=\s|$)/;
const DEBUGPY_VALUE_SWITCH_RE = /^--(?:listen|connect|log-to|configure-.+|parent-session-pid|adapter-access-token)$/;

function debugpyListenPort(args) {
  const cli = DEBUGPY_CLI_RE.exec(args);
  if (!cli) return null;
  const tokens = args.slice(cli.index + cli[0].length).split(/\s+/).filter(Boolean);
  for (let i = 0; i < tokens.length; i += 1) {
    const eq = tokens[i].indexOf('=');
    const flag = eq > 0 ? tokens[i].slice(0, eq) : tokens[i];
    if (!flag.startsWith('--') || flag === '--pid') return null; // the target
    if (!DEBUGPY_VALUE_SWITCH_RE.test(flag)) continue; // a switch without value
    const value = eq > 0 ? tokens[i].slice(eq + 1) : tokens[(i += 1)];
    if (flag === '--listen') return value === undefined ? null : portOfFlagValue(value);
  }
  return null;
}

// `[scheme://][host:]port[/path]` -> port, or null when there is none.
function portOfFlagValue(value) {
  const hostPort = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/.*$/, '');
  const text = hostPort.slice(hostPort.lastIndexOf(':') + 1);
  return /^\d{1,5}$/.test(text) && Number(text) <= 65535 ? Number(text) : null;
}

// -> { ports: debug ports named in the args, wholeProcess: every listener of
// the process is a debug endpoint (fail-closed browser flag, debugpy adapter) }
// `command` is the listener's lsof command name; it only picks the runtime's
// default inspector port.
function debugEndpointsFromArgs(args, { command = null } = {}) {
  const ports = new Set();
  let wholeProcess = false;
  let inspectorDefault = false;
  let inspectorPortGiven = false;
  for (const m of String(args || '').matchAll(DEBUG_FLAG_RE)) {
    const flag = m[1];
    const value = m[2] !== undefined ? m[2] : (SEPARATE_VALUE_FLAGS.has(flag) ? m[3] : undefined);
    const port = value === undefined ? null : portOfFlagValue(value);
    if (BROWSER_DEBUG_FLAGS.has(flag)) {
      if (port) ports.add(port);
      else wholeProcess = true;
    } else if (port !== null) {
      // `--inspect-port 9230 --inspect` listens on 9230 only; port 0 is a
      // random one the probe has to find.
      inspectorPortGiven = true;
      if (port) ports.add(port);
    } else {
      inspectorDefault = true;
    }
  }
  const text = String(args || '');
  if (inspectorDefault && !inspectorPortGiven) ports.add(defaultInspectorPort(text, command));
  if (DEBUGPY_ADAPTER_RE.test(text)) wholeProcess = true;
  const dapPort = debugpyListenPort(text);
  if (dapPort) ports.add(dapPort);
  return { ports, wholeProcess };
}

// Injected probes may still answer with a boolean: true is an inspector;
// false cannot tell a definitive answer from a failure and stays transient.
function probeVerdict(result) {
  if (result === true) return PROBE_INSPECTOR;
  if (result === PROBE_INSPECTOR || result === PROBE_NEGATIVE) return result;
  return PROBE_TRANSIENT;
}

async function detectInspectors(listeners, inspectorCache = new Map(), {
  concurrency = INSPECTOR_PROBE_CONCURRENCY,
  getArgs = getProcessArgsAsync,
  probe = probeDebugEndpoint,
  negativeTtlMs = INSPECTOR_NEGATIVE_TTL_MS,
  now = Date.now(),
  deadline = Infinity,
} = {}) {
  // One ps args lookup per distinct pid per pass, shared by all its listeners.
  const argsMemo = new Map();
  const argsFor = (pid) => {
    if (!argsMemo.has(pid)) argsMemo.set(pid, Promise.resolve(getArgs(pid)));
    return argsMemo.get(pid);
  };
  const isUsable = (entry) => entry && (
    entry.value || entry.sticky || now < (entry.retryAt !== undefined ? entry.retryAt : entry.at + negativeTtlMs)
  );

  // Reported to the caller: true only when a listener was skipped because the
  // pass was over its budget (incomplete work). Probes that merely run past
  // the budget do not set this — such a pass is complete and publishable.
  let overBudget = false;

  await mapWithLimit(listeners, concurrency, async (l) => {
    // A listener without a project root never becomes a route (resolveRoutes
    // skips it), so its verdict is never read: apps launched from '/' or ~
    // (AirPlay receiver, sync and chat clients) cost no args lookup, no
    // request to a foreign service and no scan budget.
    if (!l.root) return;
    if (l.isInspector !== undefined) return;
    const cacheKey = `${l.processKey || l.pid}:${l.port}`;
    const cached = inspectorCache.get(cacheKey);
    if (isUsable(cached)) {
      if (cached.value) {
        l.isInspector = true;
      }
      return;
    }
    // A scan over its time budget starts no new work; in-flight probes stay
    // individually bounded.
    if (Date.now() >= deadline) {
      overBudget = true;
      return;
    }

    const args = await argsFor(l.pid);
    const announced = debugEndpointsFromArgs(args, { command: l.command });
    if (announced.wholeProcess || announced.ports.has(l.port)) {
      l.isInspector = true;
      inspectorCache.set(cacheKey, { value: true, at: now, sticky: true });
      return;
    }

    const host = l.upstreamHost === '::1' ? '::1' : (l.upstreamHost || '127.0.0.1');
    const verdict = probeVerdict(await probe(l.port, host));
    // A negative is pinned only to an identified generation whose args were
    // read: an unidentified key may name a different process on the next
    // pass, and a failed args lookup may have hidden a debug flag that the
    // probe cannot see (WebDriver BiDi answers /json/version with 404).
    const identified = Boolean(l.processKey) && !String(l.processKey).endsWith(':unknown');
    if (verdict === PROBE_INSPECTOR) {
      l.isInspector = true;
      inspectorCache.set(cacheKey, { value: true, at: now, sticky: true });
    } else if (verdict === PROBE_NEGATIVE && identified && args) {
      inspectorCache.set(cacheKey, { value: false, at: now, sticky: true });
    } else {
      const failures = cached && !cached.value && !cached.sticky ? (cached.failures || 1) + 1 : 1;
      const retryIn = Math.min(INSPECTOR_RETRY_MAX_MS, negativeTtlMs * 2 ** (failures - 1));
      inspectorCache.set(cacheKey, { value: false, at: now, sticky: false, failures, retryAt: now + retryIn });
    }
  });

  // Verdicts of listeners that are gone are dead weight: drop them instead of
  // letting the cache grow until a caller flushes it (a flush would re-probe
  // every live listener at once).
  if (inspectorCache.size > INSPECTOR_CACHE_PRUNE_AT) {
    const live = new Set(listeners.map((l) => `${l.processKey || l.pid}:${l.port}`));
    for (const key of [...inspectorCache.keys()]) {
      if (!live.has(key)) inspectorCache.delete(key);
    }
  }

  return { overBudget };
}

// Probe bounds: the socket-inactivity timeout alone does not end a probe —
// a server that keeps the connection trickling would hold it open forever.
// A wall-clock timer therefore ends every probe and the body is byte-capped.
const INSPECTOR_PROBE_TIMEOUT_MS = 200;
const INSPECTOR_PROBE_MAX_BYTES = 4096;

// A /json/version document of a debug endpoint: Chromium/Electron/Chrome for
// Testing carry webSocketDebuggerUrl, every CDP/V8-inspector implementation
// (node, deno, Chromium) carries Protocol-Version.
function isDebuggerVersionInfo(info) {
  if (!info || typeof info !== 'object' || Array.isArray(info)) return false;
  if (typeof info.webSocketDebuggerUrl === 'string') return true;
  if (info['Protocol-Version'] !== undefined) return true;
  return typeof info.Browser === 'string' && info.Browser.toLowerCase().includes('node.js');
}

// Tri-state probe: PROBE_INSPECTOR, PROBE_NEGATIVE (a complete answer that is
// not a debugger's) or PROBE_TRANSIENT (no usable answer — retry later).
function probeDebugEndpoint(port, host = '127.0.0.1', timeoutMs = INSPECTOR_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    let settled = false;
    const req = http.get(
      {
        host,
        port,
        path: '/json/version',
        timeout: timeoutMs,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          finish(PROBE_NEGATIVE);
          return;
        }
        let data = '';
        let bytes = 0;
        res.on('data', (chunk) => {
          bytes += chunk.length;
          // No version document is that large.
          if (bytes > INSPECTOR_PROBE_MAX_BYTES) finish(PROBE_NEGATIVE);
          else data += chunk;
        });
        res.on('end', () => {
          if (settled) return;
          let parsed = null;
          try {
            parsed = JSON.parse(data);
          } catch {
            // complete, but not JSON: not a debugger
          }
          finish(isDebuggerVersionInfo(parsed) ? PROBE_INSPECTOR : PROBE_NEGATIVE);
        });
        res.on('error', () => finish(PROBE_TRANSIENT));
      }
    );
    // Wall-clock total duration: socket inactivity alone is no total bound.
    const totalTimer = setTimeout(() => finish(PROBE_TRANSIENT), timeoutMs);
    function finish(value) {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      req.destroy();
      resolve(value);
    }
    // An answer that is not HTTP at all is definitive; connection-level
    // failures (refused, reset) are not.
    req.on('error', (err) => {
      finish(String((err && err.code) || '').startsWith('HPE_') ? PROBE_NEGATIVE : PROBE_TRANSIENT);
    });
    req.on('timeout', () => finish(PROBE_TRANSIENT));
  });
}

function probeIsInspector(port, host = '127.0.0.1', timeoutMs = INSPECTOR_PROBE_TIMEOUT_MS) {
  return probeDebugEndpoint(port, host, timeoutMs).then((verdict) => verdict === PROBE_INSPECTOR);
}

// Resolve live listeners into named routes.
//
// Separates three identities that must never be conflated:
//   1. Project / worktree identity (canonical root directory — two worktrees
//      of one repository are two different projects)
//   2. Service identity (role): the port inside a project, surfaced as
//      `serviceId` = `<root>#<port>`
//   3. Process generation (processKey: pid + start time)
//
// Rules:
// - Debug endpoints (inspector/DevTools, identified via command-line flags or
//   the /json/version probe, for every runtime) never become automatic
//   primary; a generation consisting only of debug endpoints never wins.
// - Within the same living process generation: existing primary listener is retained
//   and not displaced by later auxiliary/debug ports.
// - Across process generations the newest living one wins the NAME (framework
//   auto-port increment). But a listener of ANOTHER living generation counts
//   as replaced only when the winning generation serves the SAME port (same
//   service role — cluster workers, dual-stack). A different port is a
//   different role: a frontend (PID A, :5173) and a backend (PID B, :3333) of
//   one project are simultaneously valid services and are all reported in
//   `route.services` (cross-generation ones with `crossGeneration: true`),
//   never as stale.
// - The user's stored preference (`preferredPorts[root]`) overrides both
//   rules: the newest living generation carrying that port wins, and its
//   preferred-port listener becomes primary. A project with a frontend AND a
//   backend is the normal case here — the non-preferred listener is a real
//   service (reported in `route.services`), not an "overwritten" one.
// - Manual names are strictly reserved so auto-discovery never steals them.
function resolveRoutes({
  listeners,
  renames = {},
  names = {},
  firstSeen = {},
  now = Date.now(),
  manualNames = new Set(),
  preferredPorts = {},
}) {
  const byRoot = new Map();
  for (const l of listeners) {
    if (!l.root) continue;
    if (!byRoot.has(l.root)) byRoot.set(l.root, []);
    byRoot.get(l.root).push(l);
  }

  const routes = [];
  const stale = [];
  const birth = (l) => {
    const key = l.processKey ? `${l.processKey}:${l.port}` : `${l.pid}:${l.port}`;
    return firstSeen[key] || firstSeen[`${l.pid}:${l.port}`] || 0;
  };
  let namesChanged = false;

  const owner = new Map(); // name -> root
  // Manual registrations reserve their names first
  for (const m of manualNames) {
    owner.set(m, '__manual__');
  }
  // All persisted renames reserve their names (active or inactive)
  for (const [r, name] of Object.entries(renames || {})) {
    owner.set(name, r);
  }
  // All persisted auto-names reserve their names (active or inactive)
  for (const [r, name] of Object.entries(names || {})) {
    if (!owner.has(name)) {
      owner.set(name, r);
    }
  }

  const roots = [...byRoot.keys()].sort((a, b) => {
    const am = renames[a] ? 0 : 1;
    const bm = renames[b] ? 0 : 1;
    return am !== bm ? am - bm : a < b ? -1 : 1;
  });

  for (const root of roots) {
    const allListeners = byRoot.get(root);
    const preferred = Number(preferredPorts[root]) || null;

    // Group listeners by process generation
    const byGen = new Map();
    for (const l of allListeners) {
      const genKey = l.processKey || String(l.pid);
      if (!byGen.has(genKey)) byGen.set(genKey, []);
      byGen.get(genKey).push(l);
    }

    // For each generation, select its primary listener
    const generations = [];
    for (const [genKey, genListeners] of byGen) {
      const genBirth = Math.min(...genListeners.map((l) => birth(l) || now));
      // Exclude inspector listeners from being primary candidates
      const candidates = genListeners.filter((l) => !isInspectorListener(l));
      if (candidates.length > 0) {
        // Earliest observed listener in this generation stays primary
        candidates.sort((a, b) => {
          const ba = birth(a);
          const bb = birth(b);
          if (ba !== bb) return ba - bb;
          return a.port - b.port;
        });
        generations.push({
          genKey,
          genBirth,
          primary: candidates[0],
          listeners: genListeners,
        });
      } else {
        // Generation has only inspector/auxiliary listeners; no primary
        generations.push({
          genKey,
          genBirth,
          primary: null,
          listeners: genListeners,
        });
      }
    }

    // Winning generation: the user's preferred port wins across generations —
    // the newest living generation carrying it (frontend/backend choice beats
    // the auto-port-increment recency rule). Otherwise: newest living
    // generation with a valid primary candidate.
    const eligibleGens = generations
      .filter((g) => g.primary !== null)
      .sort((a, b) => a.genBirth - b.genBirth);
    let winningGen = null;
    let preferredMissing = false;
    if (preferred !== null) {
      winningGen = eligibleGens
        .filter((g) => g.listeners.some((l) => !isInspectorListener(l) && l.port === preferred))
        .pop() || null;
      if (!winningGen) {
        // The preference points at nothing alive; fall back to the default
        // rule and report the mismatch instead of silently picking.
        preferredMissing = true;
      }
    }
    if (!winningGen) {
      winningGen = eligibleGens[eligibleGens.length - 1] || null;
    }
    if (!winningGen) {
      // No non-inspector listeners found; mark all as stale without creating an auto route
      for (const l of allListeners) {
        stale.push({
          serviceId: `${root}#${l.port}`,
          name: renames[root] || sanitizeName(path.basename(root)),
          port: l.port,
          upstreamHost: l.upstreamHost || '127.0.0.1',
          pid: l.pid,
          processKey: l.processKey,
          command: l.command,
          since: birth(l) || now,
        });
      }
      continue;
    }

    let primary = winningGen.primary;
    if (preferred !== null) {
      const byPreference = winningGen.listeners.find((l) => !isInspectorListener(l) && l.port === preferred);
      if (byPreference) primary = byPreference;
    }

    let name = names[root];
    if (name && owner.get(name) === root) {
      // keep persisted assignment
    } else {
      const base = sanitizeName(renames[root] || primary.suggestedName);
      name = base;
      let n = 2;
      while (owner.has(name) && owner.get(name) !== root) {
        const suffix = `-${n}`;
        const allowedBaseLen = 63 - suffix.length;
        const safeBase = base.slice(0, allowedBaseLen).replace(/-+$/, '');
        name = `${safeBase}${suffix}`;
        n += 1;
      }
      names[root] = name;
      namesChanged = true;
    }
    owner.set(name, root);

    // Service role mapping across generations. The port is the role inside
    // the project: listeners of other living generations whose port the
    // winning generation does not serve are additional valid services;
    // only same-port listeners (and inspector/debug ports) are superseded.
    const winningPorts = new Set(winningGen.listeners.map((l) => l.port));
    const serviceEntries = [];
    const superseded = [];
    for (const l of allListeners) {
      if (isInspectorListener(l)) {
        superseded.push(l); // diagnostic-only, in every generation
      } else if (winningGen.listeners.includes(l)) {
        serviceEntries.push({ l, crossGeneration: false });
      } else if (winningPorts.has(l.port)) {
        superseded.push(l); // same role (port), replaced generation
      } else {
        serviceEntries.push({ l, crossGeneration: true });
      }
    }

    const serviceOf = (l, crossGeneration) => ({
      serviceId: `${root}#${l.port}`,
      port: l.port,
      upstreamHost: l.upstreamHost || '127.0.0.1',
      command: l.command,
      pid: l.pid,
      processKey: l.processKey || `${l.pid}:${l.since || now}`,
      since: birth(l) || now,
      primary: l === primary,
      crossGeneration,
    });
    // Primary first, then the winning generation's other services by port,
    // then cross-generation services by port — a stable, readable order.
    serviceEntries.sort((a, b) => {
      const ra = a.l === primary ? 0 : a.crossGeneration ? 2 : 1;
      const rb = b.l === primary ? 0 : b.crossGeneration ? 2 : 1;
      if (ra !== rb) return ra - rb;
      return a.l.port - b.l.port;
    });

    routes.push({
      name,
      root,
      port: primary.port,
      upstreamHost: primary.upstreamHost || '127.0.0.1',
      pid: primary.pid,
      processKey: primary.processKey || `${primary.pid}:${primary.since || now}`,
      external: primary.external,
      command: primary.command,
      cwd: primary.cwd,
      since: birth(primary) || now,
      services: serviceEntries.map(({ l, crossGeneration }) => serviceOf(l, crossGeneration)),
      preferredPort: preferred,
      preferredMissing,
    });

    // Superseded / diagnostic-only listeners: inspector and debug ports (in
    // every generation) and listeners whose port (role) the winning
    // generation also serves — the one case where another generation is
    // genuinely replaced. Everything else stays a living service above.
    for (const l of superseded) {
      stale.push({
        serviceId: `${root}#${l.port}`,
        name,
        port: l.port,
        upstreamHost: l.upstreamHost || '127.0.0.1',
        pid: l.pid,
        processKey: l.processKey || `${l.pid}:${l.since || now}`,
        command: l.command,
        since: birth(l) || now,
      });
    }
  }

  routes.sort((a, b) => (a.name < b.name ? -1 : 1));
  return { routes, stale, namesChanged };
}

// Enrich raw listeners with cwd/root/suggestedName/processKey.
// Cwd cache is keyed by processKey (not raw PID) to remain safe across PID reuse.
function enrich(listeners, cwdCache = new Map(), { getStartTime = getProcessStartTime } = {}) {
  // Prune stale process keys from cwdCache opportunistically
  const liveProcessKeys = new Set();

  const enriched = listeners.map((l) => {
    const processKey = l.processKey || getProcessKey(l.pid, getStartTime(l.pid));
    liveProcessKeys.add(processKey);

    let cwd = l.cwd;
    if (cwd === undefined) {
      if (!cwdCache.has(processKey)) {
        cwdCache.set(processKey, cwdOf(l.pid));
      }
      cwd = cwdCache.get(processKey);
    }
    const root = l.root !== undefined ? l.root : projectRootOf(cwd);
    const suggestedName = l.suggestedName !== undefined
      ? l.suggestedName
      : (root ? sanitizeName(path.basename(root)) : null);

    return {
      ...l,
      processKey,
      cwd,
      root,
      suggestedName,
    };
  });

  // Cleanup keys that no longer correspond to any live listener
  if (cwdCache.size > 200) {
    for (const k of cwdCache.keys()) {
      if (!liveProcessKeys.has(k)) cwdCache.delete(k);
    }
  }

  return enriched;
}

// Async enrich for the daemon's regular scan loop: start times resolve in one
// batched ps (or, with an injected per-pid lookup, at bounded concurrency)
// and cwd lookups use async lsof, so the gateway's event loop never blocks on
// child processes. The sync `enrich` above stays for callers with
// pre-resolved listener fixtures.
//
// Cache semantics:
//   - start times: NOT cached. Every pass reads the start time of every pid
//     it saw (one batched ps). The process generation is what shares and
//     Wi-Fi exposures are bound to, and a pass that verifies them must have
//     checked it: a cached identity let a process that took over the same
//     pid and port between two passes inherit the old generation (and its
//     cwd, root and share). A live pid whose lookup fails fails the
//     enrichment, so the daemon degrades the pass like a failed scan and
//     verifies nothing; a verifiably gone pid's listeners are dropped.
//   - cwdCache: positive cwd, keyed by processKey — pinned for the process
//     generation, pruned once the generation is no longer live.
//   - cwdRetryAt: negative cwd results (transient lookup failures) are NOT
//     pinned; they carry a bounded retry time so a failed lookup is retried
//     after the interval instead of keeping the process routeless for life.
//   - rootCache: cwd -> project root canonicalization, TTL-bounded so the
//     sync .git walk does not run per listener on every scan.
//   - `deadline`: a scan past its budget schedules no new subprocess work;
//     each in-flight lookup remains individually bounded.
const SUBPROCESS_CONCURRENCY = 4;
const CWD_NEGATIVE_TTL_MS = 5000;
const CWD_RETRY_MAP_MAX = 400;
const ROOT_CACHE_TTL_MS = 30000;
const ROOT_CACHE_MAX = 500;

// Signal-0 probe: only ESRCH is evidence that the process is gone.
function pidIsAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code !== 'ESRCH';
  }
}

async function enrichAsync(listeners, cwdCache = new Map(), {
  getStartTime = null,
  getStartTimes = null,
  isPidAlive = pidIsAlive,
  cwdOf = cwdOfAsync,
  concurrency = SUBPROCESS_CONCURRENCY,
  negativeTtlMs = CWD_NEGATIVE_TTL_MS,
  now = Date.now(),
  deadline = Infinity,
  cwdRetryAt = new Map(),
  rootCache = new Map(),
  rootTtlMs = ROOT_CACHE_TTL_MS,
} = {}) {
  // Pass 1: resolve process generations — one start time per distinct PID,
  // shared by all of its listeners, read in every pass (see above).
  const distinctPids = [...new Set(listeners.filter((l) => !l.processKey).map((l) => l.pid))];
  const looked = new Map(); // pid -> start time | null; absent: skipped over budget
  if (distinctPids.length > 0) {
    if (getStartTime) {
      // Injected per-pid lookup: bounded fan-out.
      const SKIPPED = Symbol('start time lookup skipped over budget');
      const results = await mapWithLimit(distinctPids, concurrency, async (pid) => {
        if (Date.now() >= deadline) return SKIPPED; // over budget: no new subprocess
        return getStartTime(pid);
      });
      distinctPids.forEach((pid, i) => {
        if (results[i] !== SKIPPED) looked.set(pid, results[i] || null);
      });
    } else if (Date.now() < deadline) {
      let times = null;
      try {
        times = await (getStartTimes || getProcessStartTimesAsync)(distinctPids);
      } catch {
        times = null; // a failed batch is a failed lookup for every pid
      }
      for (const pid of distinctPids) looked.set(pid, (times && times.get(pid)) || null);
    }
  }

  const startTimeByPid = new Map();
  const gonePids = new Set();
  const unresolved = [];
  for (const pid of distinctPids) {
    const startTime = looked.get(pid);
    if (startTime) {
      startTimeByPid.set(pid, startTime);
    } else if (looked.has(pid) && !isPidAlive(pid)) {
      // Exited between the listener scan and the lookup: drop its listeners.
      gonePids.add(pid);
    } else if (looked.has(pid)) {
      // A live pid whose generation could not be read: never publish a
      // guessed identity, neither `<pid>:unknown` nor the last known one.
      unresolved.push(pid);
    }
    // else: skipped over budget. The caller sees the expired deadline and
    // degrades the pass, so no identity of this pass is published.
  }
  if (unresolved.length > 0) {
    const err = new Error(`process start time lookup failed for live pid(s) ${unresolved.join(', ')}`);
    err.code = 'START_TIME_LOOKUP_FAILED';
    err.pids = unresolved;
    throw err;
  }

  const liveProcessKeys = new Set();
  const withKey = [];
  for (const l of listeners) {
    if (!l.processKey && gonePids.has(l.pid)) continue;
    const processKey = l.processKey || getProcessKey(l.pid, startTimeByPid.get(l.pid));
    liveProcessKeys.add(processKey);
    withKey.push({ ...l, processKey });
  }

  // Pass 2: fetch missing cwds at bounded concurrency; the generation cache
  // answers repeats, the retry map suppresses recent transient failures.
  // Tasks are collected as {key, pid} descriptors and started lazily inside
  // the workers below — creating the lookups in this loop would fan out
  // unbounded and only bound the awaiting, not the subprocess starts.
  const cwdTasks = [];
  const queuedCwdKeys = new Set();
  for (const l of withKey) {
    if (l.cwd !== undefined) continue;
    if (cwdCache.has(l.processKey)) continue;
    if (queuedCwdKeys.has(l.processKey)) continue;
    if (now < (cwdRetryAt.get(l.processKey) || 0)) continue;
    queuedCwdKeys.add(l.processKey);
    cwdTasks.push({ key: l.processKey, pid: l.pid });
  }
  // Marker for tasks the workers refuse past the budget: a budget skip is
  // not a lookup failure and must not schedule a negative retry either.
  const CWD_OVER_BUDGET = Symbol('cwd lookup skipped over budget');
  const cwdResults = await mapWithLimit(cwdTasks, concurrency, (t) => {
    // A scan over its time budget starts no new subprocess work.
    if (Date.now() >= deadline) return CWD_OVER_BUDGET;
    return cwdOf(t.pid);
  });
  for (let i = 0; i < cwdTasks.length; i += 1) {
    const key = cwdTasks[i].key;
    const cwd = cwdResults[i];
    if (cwd === CWD_OVER_BUDGET) continue;
    if (cwd) {
      cwdCache.set(key, cwd);
      cwdRetryAt.delete(key);
    } else {
      // Transient failure: bound the retry interval instead of caching the
      // negative result for the whole process lifetime.
      cwdRetryAt.set(key, now + negativeTtlMs);
    }
  }
  // Opportunistically drop expired negative entries; the map stays small.
  if (cwdRetryAt.size > CWD_RETRY_MAP_MAX) {
    for (const [key, retryAt] of cwdRetryAt) {
      if (retryAt <= now) cwdRetryAt.delete(key);
    }
  }

  const rootFor = (cwd) => {
    if (!cwd) return null;
    const hit = rootCache.get(cwd);
    if (hit && now - hit.at < rootTtlMs) return hit.root;
    const root = projectRootOf(cwd);
    if (rootCache.size >= ROOT_CACHE_MAX) {
      // Evict the oldest entry (Map insertion order): a size cap must not
      // turn into a cold-cache flush.
      rootCache.delete(rootCache.keys().next().value);
    }
    rootCache.set(cwd, { root, at: now });
    return root;
  };

  const enriched = withKey.map((l) => {
    let cwd = l.cwd;
    if (cwd === undefined) {
      cwd = cwdCache.get(l.processKey) ?? null;
    }
    const root = l.root !== undefined ? l.root : rootFor(cwd);
    const suggestedName = l.suggestedName !== undefined
      ? l.suggestedName
      : (root ? sanitizeName(path.basename(root)) : null);
    return { ...l, cwd, root, suggestedName };
  });

  // Cleanup keys that no longer correspond to any live listener
  if (cwdCache.size > 200) {
    for (const k of cwdCache.keys()) {
      if (!liveProcessKeys.has(k)) cwdCache.delete(k);
    }
  }

  return enriched;
}

module.exports = {
  listListenersAsync,
  cwdOf,
  cwdOfAsync,
  decodeLsofName,
  projectRootOf,
  isUnattributableDir,
  sanitizeName,
  resolveRoutes,
  enrich,
  enrichAsync,
  listenAddressIsExternal,
  isInspectorListener,
  probeIsInspector,
  probeDebugEndpoint,
  debugEndpointsFromArgs,
  detectInspectors,
  mapWithLimit,
  NON_HTTP_COMMANDS,
  AUTOMATION_DRIVER_COMMANDS,
  ROOT_CACHE_MAX,
  ignoredCommandsFilter,
};
