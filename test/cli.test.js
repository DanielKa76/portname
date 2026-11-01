'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const { formatRemainingTtl, browserHost, cmdStatus, exposeMessage, stableNodePath, plist } = require('../bin/portname');

const BIN_PATH = path.resolve(__dirname, '../bin/portname.js');

test('CLI: bin/portname.js has node shebang and executable permissions', () => {
  const content = fs.readFileSync(BIN_PATH, 'utf8');
  const firstLine = content.split('\n')[0];
  assert.strictEqual(firstLine, '#!/usr/bin/env node', 'first line must be node shebang');

  const stat = fs.statSync(BIN_PATH);
  // User executable bit
  assert.ok((stat.mode & 0o100) !== 0, 'bin/portname.js must have user executable permission');
});

test('CLI: executes directly via shebang to display help', async () => {
  const proc = spawn(BIN_PATH, ['help'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  proc.stdout.on('data', (d) => (stdout += d));
  proc.stderr.on('data', (d) => (stderr += d));

  const exitCode = await new Promise((resolve) => proc.on('close', resolve));
  assert.strictEqual(exitCode, 0);
  assert.ok(stdout.includes('portname — every local project gets a real address'));
  assert.strictEqual(stderr, '');
});

test('CLI: LaunchAgent plist pins a node path that survives brew upgrades', () => {
  // Regression: the plist used process.execPath, which resolves to the
  // versioned Homebrew Cellar binary. After `brew upgrade node` the pinned
  // path disappears and the daemon dies with EX_CONFIG at every boot.
  const fakeExists = (p) => p === '/opt/homebrew/bin/node';
  assert.strictEqual(
    stableNodePath('/opt/homebrew/Cellar/node/26.8.1/bin/node', fakeExists),
    '/opt/homebrew/bin/node',
    'a Cellar path with a stable sibling symlink must resolve to it'
  );
  assert.strictEqual(
    stableNodePath('/opt/homebrew/Cellar/node/26.8.1/bin/node', () => false),
    '/opt/homebrew/Cellar/node/26.8.1/bin/node',
    'without a stable sibling the concrete path is kept'
  );
  assert.strictEqual(
    stableNodePath('/Users/me/.nvm/versions/node/v22/bin/node', fakeExists),
    '/Users/me/.nvm/versions/node/v22/bin/node',
    'non-Cellar installations are never rewritten'
  );

  // The generated plist references an existing binary and the launchd musts.
  const generated = plist();
  const nodeMatch = generated.match(/<array>\s*<string>([^<]+)<\/string>/);
  assert.ok(nodeMatch, 'plist carries ProgramArguments');
  assert.ok(require('fs').existsSync(nodeMatch[1]), `plist node path must exist: ${nodeMatch[1]}`);
  assert.ok(!nodeMatch[1].includes('/Cellar/') || stableNodePath(nodeMatch[1]) === nodeMatch[1],
    'no bare Cellar pin unless no stable alternative exists');
  assert.ok(generated.includes('RunAtLoad') && generated.includes('KeepAlive'));
  assert.ok(generated.includes('daemon.log'));
});

test('CLI: daemon stays alive until SIGTERM and shuts down cleanly (exit 0)', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-cli-daemon-'));
  const configFile = path.join(tmpDir, 'config.json');
  // loopbackPort 0: a fixed 7777 here collided with other test files that
  // bind the same default under parallel suite runs (EADDRINUSE killed the
  // daemon ~100 ms in).
  fs.writeFileSync(
    configFile,
    JSON.stringify({ bind: 'loopback', port: 0, fallbackPort: 0, loopbackPort: 0, control: true }, null, 2)
  );

  const proc = spawn(process.execPath, [BIN_PATH, 'daemon'], {
    env: { ...process.env, PORTNAME_DIR: tmpDir },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';
  proc.stdout.on('data', (d) => (stdout += d));
  proc.stderr.on('data', (d) => (stderr += d));

  try {
    const sockFile = path.join(tmpDir, 'daemon.sock');
    const startWait = Date.now();
    while (!fs.existsSync(sockFile) && Date.now() - startWait < 8000) {
      if (proc.exitCode !== null) break;
      await new Promise((r) => setTimeout(r, 100));
    }

    // Socket file must have been created and process must stay alive
    assert.ok(fs.existsSync(sockFile), 'daemon.sock must be created');
    assert.strictEqual(proc.exitCode, null, 'daemon process must remain alive after start()');
    assert.strictEqual(proc.killed, false);

    // Send SIGTERM to initiate clean shutdown
    proc.kill('SIGTERM');

    const exitCode = await new Promise((resolve) => proc.on('close', resolve));
    assert.strictEqual(exitCode, 0, 'daemon must exit cleanly with code 0 on SIGTERM');
  } finally {
    if (proc.exitCode === null) {
      proc.kill('SIGKILL');
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('CLI: formatRemainingTtl correctly handles fractional minutes and seconds', () => {
  const now = Date.now();

  // 6 seconds left (0.1 min)
  assert.strictEqual(formatRemainingTtl(now + 6000), '6 sec');

  // 30 seconds left (0.5 min)
  assert.strictEqual(formatRemainingTtl(now + 30000), '30 sec');

  // 1.0 minute left
  assert.strictEqual(formatRemainingTtl(now + 60000), '1 min');

  // 1.6 minutes left
  assert.strictEqual(formatRemainingTtl(now + 96000), '1.6 min');

  // 15 minutes left
  assert.strictEqual(formatRemainingTtl(now + 15 * 60 * 1000), '15 min');

  // 60 minutes left
  assert.strictEqual(formatRemainingTtl(now + 60 * 60 * 1000), '60 min');

  // Fallback minutes when expiresAt is absent
  assert.strictEqual(formatRemainingTtl(null, 0.1), '6 sec');
  assert.strictEqual(formatRemainingTtl(null, 15), '15 min');
});

test('CLI: cmdStatus displays (public link starting…) during STARTING state without null URL', () => {
  const logged = [];
  const origLog = console.log;
  console.log = (...args) => logged.push(args.join(' '));

  try {
    const data = {
      proxyPort: 80,
      bind: 'wildcard on port 80',
      routes: [
        { name: 'shop', port: 3000, command: 'node', external: false },
      ],
      stale: [],
      exposed: [],
      shares: [
        { name: 'shop', state: 'STARTING', url: null, expired: false },
      ],
    };

    cmdStatus(data);

    const output = logged.join('\n');
    assert.ok(output.includes('(public link starting…)'), 'must display starting indicator');
    assert.ok(!output.includes('null/…/'), 'must never display null/…/');
    assert.ok(!output.includes('Internet'), 'starting share must not be marked as Internet');
  } finally {
    console.log = origLog;
  }
});

function runCmdStatus(routes, exposed, lan = undefined) {
  const logged = [];
  const origLog = console.log;
  console.log = (...args) => logged.push(args.join(' '));
  try {
    cmdStatus({
      proxyPort: 80,
      bind: 'wildcard on port 80',
      routes,
      stale: [],
      exposed,
      shares: [],
      lan,
    });
  } finally {
    console.log = origLog;
  }
  return logged.join('\n');
}

test('CLI: cmdStatus marks an effectively paused WLAN exposure instead of plain Wi-Fi', () => {
  const output = runCmdStatus(
    [
      {
        name: 'shop', port: 3000, command: 'node', external: false,
        exposureRequested: true, lanUrl: 'http://shop.local:80/',
        exposureEffective: 'paused', exposurePauseReason: 'target-not-verified',
      },
    ],
    ['shop']
  );
  assert.ok(output.includes('Wi-Fi'), 'the wish still shows in the reachability column');
  assert.ok(/paused/i.test(output), 'the pause must be visible, not a plain "(on your Wi-Fi)"');
  assert.ok(output.includes('target not verified'), 'the machine-readable reason is spelled out');
});

// The reach column of the route's first line ("Mac", "Mac+Wi-Fi", …).
function reachColumn(output, name = 'shop') {
  const line = output.split('\n').find((l) => l.startsWith(`${name}.localhost`));
  return line.trim().split(/\s{2,}/).pop();
}

test('CLI: cmdStatus lists Wi-Fi as reachable only while the exposure is effective', () => {
  const route = (exposureEffective, exposurePauseReason) => ({
    name: 'shop', port: 3000, command: 'node', external: false,
    exposureRequested: true, lanUrl: 'http://shop.local:80/',
    exposureEffective, exposurePauseReason,
    exposureTarget: { port: 3000, command: 'node', network: '192.168.178.0/24', subnetOnly: false },
  });
  const lan = { available: true, network: '192.168.178.0/24' };
  assert.strictEqual(reachColumn(runCmdStatus([route('active', null)], ['shop'], lan)), 'Mac+Wi-Fi');
  for (const reason of ['target-not-verified', 'target-unconfirmed', 'target-changed', 'network-changed', 'network-unidentified']) {
    const output = runCmdStatus([route('paused', reason)], ['shop'], lan);
    assert.strictEqual(reachColumn(output), 'Mac+Wi-Fi (paused)', `${reason}: the overview must not claim Wi-Fi reach`);
  }
  // An older daemon reports only the wish; no wish, no Wi-Fi.
  assert.strictEqual(reachColumn(runCmdStatus([{ name: 'shop', port: 3000, command: 'node', external: false }], ['shop'])), 'Mac+Wi-Fi');
  assert.strictEqual(reachColumn(runCmdStatus([{ ...route('off', null), exposureRequested: false }], [])), 'Mac');
});

test('CLI: cmdStatus marks a Wi-Fi name another device already answers for as not reachable', () => {
  const route = (lanRegistration, extra = {}) => ({
    name: 'shop', port: 3000, command: 'node', external: false,
    exposureRequested: true, lanUrl: 'http://shop.local:80/',
    exposureEffective: 'active', exposurePauseReason: null, lanRegistration,
    ...extra,
  });
  const conflict = runCmdStatus([route('conflict')], ['shop']);
  assert.strictEqual(reachColumn(conflict), 'Mac+Wi-Fi (name in use)', conflict);
  const lanLine = conflict.split('\n').find((l) => l.startsWith('shop.local '));
  assert.ok(lanLine.includes('name in use: another device on this network answers for shop.local'), lanLine);
  assert.ok(lanLine.includes('portname rename shop <new-name>'), lanLine);
  assert.ok(!lanLine.includes('(on your Wi-Fi)'), 'never the plain reachable wording');

  // A manual entry is renamed by registering it again.
  const manual = runCmdStatus([route('conflict', { name: 'db', port: 5432, command: 'manual', manual: true, root: null })], ['db']);
  assert.ok(manual.includes('portname remove db, then portname add <new-name> 5432 and portname expose <new-name>'), manual);

  for (const state of ['registering', 'registered', 'retrying', null, undefined]) {
    const output = runCmdStatus([route(state)], ['shop']);
    assert.strictEqual(reachColumn(output), 'Mac+Wi-Fi', String(state));
    assert.ok(output.includes('(on your Wi-Fi)'), String(state));
  }
});

test('CLI: cmdStatus keeps the legacy wording for an active exposure', () => {
  const output = runCmdStatus(
    [
      {
        name: 'shop', port: 3000, command: 'node', external: false,
        exposureRequested: true, lanUrl: 'http://shop.local:80/',
        exposureEffective: 'active', exposurePauseReason: null,
      },
    ],
    ['shop']
  );
  assert.ok(output.includes('(on your Wi-Fi)'), 'active exposure keeps the established wording');
  assert.ok(!/paused/i.test(output));
});

test('CLI: cmdStatus old-daemon regression — routes without effective fields print as before', () => {
  const output = runCmdStatus(
    [{ name: 'shop', port: 3000, command: 'node', external: false }],
    ['shop']
  );
  assert.ok(output.includes('(on your Wi-Fi)'), 'an older daemon (no effective fields) keeps the legacy display');
  assert.ok(!/paused/i.test(output));
});

test('CLI: cmdStatus tells how to resume an exposure paused by a target change', () => {
  const output = runCmdStatus(
    [
      {
        name: 'shop', port: 9222, command: 'chrome', external: false,
        exposureRequested: true, lanUrl: 'http://shop.local:80/',
        exposureEffective: 'paused', exposurePauseReason: 'target-changed',
        exposureTarget: { port: 5173, command: 'node' },
      },
    ],
    ['shop']
  );
  assert.ok(output.includes('target changed'), 'the reason is spelled out');
  assert.ok(output.includes('confirmed :5173 node'), 'the confirmed endpoint is named');
  assert.ok(output.includes('now :9222 chrome'), 'the endpoint a confirmation would expose is named');
  assert.ok(output.includes('portname expose shop'), 'the way to confirm the new target is named');
});

test('CLI: cmdStatus does not call a wish from before the update a target change', () => {
  const output = runCmdStatus(
    [
      {
        name: 'shop', port: 5173, command: 'node', external: false,
        exposureRequested: true, lanUrl: 'http://shop.local:80/',
        exposureEffective: 'paused', exposurePauseReason: 'target-unconfirmed',
        exposureTarget: null,
      },
    ],
    ['shop']
  );
  assert.ok(!output.includes('target changed'), 'nothing changed — only a confirmation is missing');
  assert.ok(output.includes('not confirmed since the update'));
  assert.ok(output.includes('now :5173 node'), 'the endpoint a confirmation would expose is named');
  assert.ok(output.includes('portname expose shop'));
});

test('CLI: cmdStatus explains an exposure paused by a network change', () => {
  const output = runCmdStatus(
    [
      {
        name: 'shop', port: 3000, command: 'node', external: false,
        exposureRequested: true, lanUrl: 'http://shop.local:80/',
        exposureEffective: 'paused', exposurePauseReason: 'network-changed',
      },
    ],
    ['shop']
  );
  assert.ok(output.includes('another network'));
  assert.ok(output.includes('portname expose shop'));
});

test('CLI: cmdStatus names the confirmed and the current network of a network-changed pause', () => {
  const route = (network) => ({
    name: 'shop', port: 3000, command: 'node', external: false,
    exposureRequested: true, lanUrl: 'http://shop.local:80/',
    exposureEffective: 'paused', exposurePauseReason: 'network-changed',
    exposureTarget: { port: 3000, command: 'node', network },
  });
  const moved = runCmdStatus([route('192.168.1.0/24')], ['shop'], { available: true, network: '10.42.0.0/21' });
  assert.ok(moved.includes('192.168.1.0/24, now 10.42.0.0/21'));
  // Same default range (every Fritz!Box): only the router tells them apart.
  // The daemon reports this reason only once ANOTHER router is identified;
  // a router not identified yet is "network-unidentified" (nothing to confirm).
  const sameRange = runCmdStatus([route('192.168.178.0/24')], ['shop'], { available: true, network: '192.168.178.0/24' });
  assert.ok(sameRange.includes('(same range 192.168.178.0/24, another router);'), sameRange);
  assert.ok(!sameRange.includes('not identified'), 'no hint that invites confirming an unidentified router');
  assert.ok(sameRange.includes('portname expose shop'));
});

test('CLI: cmdStatus offers no confirmation while the confirmed router is not identified yet', () => {
  const output = runCmdStatus(
    [
      {
        name: 'shop', port: 3000, command: 'node', external: false,
        exposureRequested: true, lanUrl: 'http://shop.local:80/',
        exposureEffective: 'paused', exposurePauseReason: 'network-unidentified',
        exposureTarget: { port: 3000, command: 'node', network: '192.168.178.0/24', subnetOnly: false },
      },
    ],
    ['shop'],
    { available: true, network: '192.168.178.0/24' }
  );
  assert.ok(output.includes('router of this network is not identified yet'), output);
  assert.ok(output.includes('resumes by itself'), output);
  assert.ok(!output.includes('portname expose shop'), 'nothing to confirm: `expose` refuses meanwhile');
});

test('CLI: expose says when the binding is the address range alone (router not identified)', () => {
  const answer = (target) => exposeMessage('shop', { ok: true, name: 'shop', exposed: true, target });
  const bound = answer({ port: 3000, command: 'node', network: '192.168.1.0/24', subnetOnly: false });
  assert.strictEqual(bound, 'shop.local now answers on your Wi-Fi (-> :3000 node; this network only: 192.168.1.0/24).');
  const rangeOnly = answer({ port: 3000, command: 'node', network: '192.168.1.0/24', subnetOnly: true });
  assert.ok(rangeOnly.includes('this address range only: 192.168.1.0/24'), rangeOnly);
  assert.ok(rangeOnly.includes('router could not be identified'), rangeOnly);
  assert.ok(!answer({ port: 3000, command: 'node', network: null, subnetOnly: false }).includes('network'));
  assert.strictEqual(exposeMessage('shop', { ok: true, exposed: false, target: null }), 'shop.local is no longer reachable.');
});
