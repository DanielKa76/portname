'use strict';

// Static contract checks for the macOS app (macos/), which cannot be
// compiled or run in the Linux CI: the GUI must follow the daemon's WLAN
// exposure contract (docs/control-protocol.md, `exposurePauseReason` and
// `expose`), and the mechanical parts Swift review misses (texts claiming
// the opposite of what the daemon does) are pinned here.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SOURCES_DIR = path.join(ROOT, 'macos/Sources');
const APP_DIR = path.join(SOURCES_DIR, 'PortnameApp');
const CORE_DIR = path.join(SOURCES_DIR, 'PortnameCore');
const TABLES = ['de', 'en'].map((lang) =>
  path.join(CORE_DIR, `Resources/${lang}.lproj/Localizable.strings`));

function read(file) {
  return fs.readFileSync(file, 'utf8');
}

// Swift sources without `//` line comments: comments may name the old
// behavior, only code and literals count.
function code(file) {
  return read(file).split('\n').filter((line) => !line.trim().startsWith('//')).join('\n');
}

function swiftFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) swiftFiles(p, out);
    else if (p.endsWith('.swift')) out.push(p);
  }
  return out;
}

const unescapeXml = (s) => s.replace(/&quot;/g, '"').replace(/&apos;/g, "'")
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

// key -> value pairs of one Localizable.strings plist.
function tablePairs(file) {
  const pairs = new Map();
  const re = /<key>([\s\S]*?)<\/key>\s*<string>([\s\S]*?)<\/string>/g;
  let match;
  while ((match = re.exec(read(file)))) pairs.set(unescapeXml(match[1]), unescapeXml(match[2]));
  return pairs;
}

// printf conversions as String(format:) reads them; `%%` is a literal.
const SPECIFIER = /%(?:\d+\$)?[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|q|z|t|j)?[@dDiuUxXoOfFeEgGcCsSpaA%]/g;
const specifiers = (s) => (s.match(SPECIFIER) || []).filter((spec) => spec !== '%%');

// Index of the closing quote of the string literal opening at src[i].
function skipString(src, i) {
  for (i += 1; i < src.length; i += 1) {
    if (src[i] === '\\') {
      if (src[i + 1] === '(') i = skipBalanced(src, i + 1);
      else i += 1;
    } else if (src[i] === '"') {
      return i;
    }
  }
  throw new Error('unterminated string literal');
}

// Index of the parenthesis closing the one at src[i].
function skipBalanced(src, i) {
  let depth = 0;
  for (; i < src.length; i += 1) {
    if (src[i] === '"') i = skipString(src, i);
    else if (src[i] === '(') depth += 1;
    else if (src[i] === ')' && --depth === 0) return i;
  }
  throw new Error('unbalanced parentheses');
}

// Number of arguments after the pattern literal of an L10n.format call:
// top-level commas up to the call's closing parenthesis.
function trailingArgumentCount(src, i) {
  let depth = 0;
  let count = 0;
  for (; i < src.length; i += 1) {
    const c = src[i];
    if (c === '"') i = skipString(src, i);
    else if ('([{'.includes(c)) depth += 1;
    else if (')]}'.includes(c)) {
      if (depth === 0) return count;
      depth -= 1;
    } else if (c === ',' && depth === 0) count += 1;
  }
  throw new Error('unterminated call');
}

test('network-change note: exposures are paused on another network, never carried over', () => {
  const menuBar = code(path.join(APP_DIR, 'MenuBarView.swift'));
  assert.ok(!menuBar.includes('gelten jetzt für das aktuelle Netz'),
    'the daemon pauses exposures confirmed on another network ("network-changed"); ' +
    'the note must not claim they now apply to the current network');
  assert.match(menuBar, /L10n\.text\("Netzwerkwechsel — [^"]*bleiben pausiert, bis du sie hier bestätigst\."\)/);
});

// A translation that drops, adds or reorders a conversion makes
// String(format:) read the wrong argument type — a crash, not a typo.
test('every table entry keeps the format conversions of its key', () => {
  const mismatches = [];
  for (const file of TABLES) {
    for (const [key, value] of tablePairs(file)) {
      if (specifiers(key).join(' ') !== specifiers(value).join(' ')) {
        mismatches.push(`${path.basename(path.dirname(file))}: ${JSON.stringify(key)} -> ${JSON.stringify(value)}`);
      }
    }
  }
  assert.deepStrictEqual(mismatches, []);
});

test('L10n.format passes one argument per conversion; L10n.text literals carry none', () => {
  const callSite = /L10n\.(text|format)\(\s*"/g;
  const problems = [];
  let calls = 0;
  for (const file of swiftFiles(SOURCES_DIR)) {
    const src = read(file);
    let match;
    while ((match = callSite.exec(src))) {
      const open = match.index + match[0].length - 1;
      const close = skipString(src, open);
      const literal = src.slice(open + 1, close);
      if (literal.includes('\\(')) continue; // interpolated: not a table key (parity harness)
      const wanted = specifiers(literal).length;
      const given = match[1] === 'format' ? trailingArgumentCount(src, close + 1) : 0;
      calls += 1;
      if (wanted !== given) {
        problems.push(`${path.basename(file)}: L10n.${match[1]}(${JSON.stringify(literal)}) has ${wanted} conversion(s), ${given} argument(s)`);
      }
    }
  }
  assert.ok(calls >= 160, `harness must see the call sites (found ${calls})`);
  assert.deepStrictEqual(problems, []);
});

// docs/control-protocol.md: clients must offer `expose { on: true }` for an
// exposure paused with target-unconfirmed, target-changed or
// network-changed — and only for those (target-not-verified and
// network-unidentified heal by themselves and an activation is refused
// meanwhile; no-lan-interface/loopback-bind have no WLAN path at all).
test('every pause reason the daemon emits is mapped; only binding reasons await confirmation', () => {
  const daemon = read(path.join(ROOT, 'lib/daemon.js'));
  const emitted = new Set([...daemon.matchAll(/exposurePauseReason = '([a-z-]+)'/g)].map((m) => m[1]));
  // `lan.reason || 'no-lan-interface'`: the LAN reasons are passed through.
  for (const m of daemon.matchAll(/reason: '([a-z-]+)'/g)) emitted.add(m[1]);
  for (const reason of ['target-not-verified', 'target-unconfirmed', 'target-changed', 'network-changed',
    'network-unidentified', 'no-lan-interface', 'loopback-bind']) {
    assert.ok(emitted.has(reason), `expected the daemon to emit ${reason}`);
  }

  const pause = code(path.join(CORE_DIR, 'ExposurePause.swift'));
  const mapped = new Map([...pause.matchAll(/case "([a-z-]+)": self = \.(\w+)/g)].map((m) => [m[1], m[2]]));
  const unmapped = [...emitted].filter((reason) => !mapped.has(reason));
  assert.deepStrictEqual(unmapped, [], 'daemon pause reasons without a GUI mapping');

  const awaits = pause.match(/var awaitsConfirmation: Bool \{[\s\S]*?case ([^:]+):\s*return true/);
  assert.ok(awaits, 'awaitsConfirmation must list the confirmable reasons in one `return true` case');
  const confirmable = awaits[1].split(',').map((s) => s.trim().replace(/^\./, '')).sort();
  assert.deepStrictEqual(confirmable,
    [mapped.get('network-changed'), mapped.get('target-changed'), mapped.get('target-unconfirmed')].sort());
  // Self-healing reasons are listed as such, not left to a catch-all.
  const notAwaiting = pause.match(/var awaitsConfirmation: Bool \{[\s\S]*?return true\s*case ([^:]+):\s*return false/);
  assert.ok(notAwaiting, 'awaitsConfirmation must list the other reasons in one `return false` case');
  const selfHealing = notAwaiting[1].split(',').map((s) => s.trim().replace(/^\./, ''));
  for (const reason of ['target-not-verified', 'network-unidentified']) {
    assert.ok(selfHealing.includes(mapped.get(reason)), `${reason} must not await a confirmation`);
  }
});

// docs/control-protocol.md: a router that cannot be identified right now is
// `network-unidentified`; `network-changed` in the confirmed subnet means
// the daemon identified ANOTHER router. Its badge and row texts must neither
// offer the harmless "not identified yet" reading nor promise that the pause
// heals by itself — in either table.
test('network-changed texts name another network or router and never promise self-healing', () => {
  const pause = code(path.join(CORE_DIR, 'ExposurePause.swift'));
  const blocks = [...pause.matchAll(/case \.networkChanged:([\s\S]*?)case \.networkUnidentified:/g)].map((m) => m[1]);
  assert.strictEqual(blocks.length, 2, 'badge help and row note both word network-changed');
  const literals = blocks.flatMap((block) => [...block.matchAll(/L10n\.(?:text|format)\(\s*"((?:\\.|[^"\\])*)"/g)]
    .map((m) => m[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\')));
  assert.ok(literals.length >= 3, `expected the network-changed texts (found ${literals.length})`);
  const [de, en] = TABLES.map(tablePairs);
  const misleading = /noch nicht erkannt|von selbst|not (?:yet )?identified|by itself/i;
  const stale = [];
  for (const literal of literals) {
    for (const [lang, text] of [['de', de.get(literal)], ['en', en.get(literal)]]) {
      assert.ok(text, `${lang} table lacks ${JSON.stringify(literal)}`);
      if (misleading.test(text)) stale.push(`${lang}: ${text}`);
    }
  }
  assert.deepStrictEqual(stale, []);
});

test('paused WLAN rows explain the reason and offer the confirmation next to switching off', () => {
  const row = code(path.join(APP_DIR, 'ProjectRow.swift'));
  assert.ok(!row.includes('(Ziel nicht frisch verifiziert)'),
    'the paused badge must not claim "not verified" for every reason');
  assert.match(row, /\.help\(ExposurePauseText\.badgeHelp\(for: pauseReason\)\)/);
  assert.match(row, /ExposurePauseText\.note\(for: route, currentNetwork: model\.status\?\.lan\?\.network\)/);

  const actions = code(path.join(APP_DIR, 'ProjectActionsView.swift'));
  const confirm = actions.match(/if route\.awaitsExposureConfirmation \{([\s\S]*?)L10n\.text\("WLAN-Freigabe bestätigen"\)/);
  assert.ok(confirm, 'the actions menu must offer "WLAN-Freigabe bestätigen" while a confirmation is awaited');
  assert.match(confirm[1], /_ = await model\.confirmExposure\(route\)/,
    'the confirmation goes through the model, which decides on a fresh status read');
  assert.ok(!/setExposed\(\w+, on: true\)/.test(confirm[1]),
    'a confirmation is not a plain switch-on: the wish is already set, only the binding proves it');
  assert.match(actions, /model\.setExposed\(current, on: !\(current\.exposureRequested == true\)\)/,
    'the off toggle stays');
});

// A confirmation is `expose on` while the wish is already set. The cached
// snapshot may be a poll interval old, so the model re-reads the status
// before deciding whether a confirmation is still awaited; and since the
// wish proves nothing, a lost answer may only be reconciled from the binding
// the confirmation writes (`exposureTarget` equal to the endpoint and network
// captured when it was issued), never from another pause reason or a return
// to the previously confirmed state.
test('a WLAN confirmation decides on a fresh read and reconciles only from its own binding', () => {
  const model = code(path.join(CORE_DIR, 'AppModel.swift'));
  const fn = model.match(/func confirmExposure\(_ route: Route\) async -> MutationOutcome \{([\s\S]*?)\n {4}\}\n/);
  assert.ok(fn, 'AppModel.confirmExposure must exist');
  const body = fn[1];
  const read = body.indexOf('fresh = try await api.status()');
  const check = body.indexOf('current.awaitsExposureConfirmation');
  assert.ok(read >= 0 && check > read, 'fresh status read, then the awaits-confirmation check on it');
  assert.match(body, /expectation: \.exposureConfirmed\(target: target, preBound: current\.exposureTarget == target\)/);

  const met = model.match(/case \.exposureConfirmed\(let target, let preBound\):([\s\S]*?)\n {8}case \./);
  assert.ok(met, 'isExpectationMet must handle .exposureConfirmed');
  assert.match(met[1], /if preBound \{ return false \}/, 'an indistinguishable binding stays unclear');
  assert.match(met[1], /!route\.awaitsExposureConfirmation/);
  assert.match(met[1], /route\.exposureTarget == target/, 'only the confirmed binding proves the confirmation');
});

// The fresh read only decides WHETHER a confirmation is still awaited; WHAT
// is confirmed is what the panel showed. The daemon's route revision pins
// port and process, so sending the revision of the fresh read would let a
// listener that took over the name after the panel was drawn (e.g. a debug
// port of the same project, still waiting for a confirmation) be exposed
// although the user confirmed another endpoint.
test('a WLAN confirmation binds the endpoint, revision and network the user saw', () => {
  const model = code(path.join(CORE_DIR, 'AppModel.swift'));
  const fn = model.match(/func confirmExposure\(_ route: Route\) async -> MutationOutcome \{([\s\S]*?)\n {4}\}\n/);
  assert.ok(fn, 'AppModel.confirmExposure must exist');
  const body = fn[1];
  const seen = body.indexOf('let seenNetwork = status?.lan?.network');
  const read = body.indexOf('fresh = try await api.status()');
  assert.ok(seen >= 0 && seen < read, 'the network the panel showed is taken before the fresh read');
  assert.match(body, /let target = ExposureTarget\(port: route\.port, command: route\.command, network: seenNetwork\)/,
    'the binding is the endpoint and network the user saw');
  const guard = body.match(/guard current\.revision == route\.revision,\s*ExposureTarget\(port: current\.port, command: current\.command, network: fresh\.lan\?\.network\) == target else \{([\s\S]*?)\n {8}\}/);
  assert.ok(guard, 'a fresh read with another revision, endpoint or network sends nothing');
  assert.match(guard[1], /return \.staleTarget/);
  assert.ok(!guard[1].includes('api.expose'), 'the refusal sends nothing');
  const send = body.indexOf('api.expose(name: route.name, on: true, expectedRouteRevision: route.revision)');
  assert.ok(send > body.indexOf(guard[0]), 'expose on carries the revision the user saw, after the check');
  assert.ok(!/expectedRouteRevision: current\.revision/.test(body),
    'the revision of the fresh read is never sent: the user did not see it');
});
