'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const bundleinstall = require('../lib/bundleinstall');
const {
  generateManifest,
  verifyManifest,
  MANIFEST_SCHEMA,
} = require('../scripts/lib/payload-manifest');
const { plist } = require('../bin/portname');
const { makeLaunchctlStub } = require('./helpers/launchctl-stub');

const BUNDLE_ID = 'dev.portname.app';
const BIN_PATH = path.resolve(__dirname, '../bin/portname.js');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}.`));
}

// Builds a fake bundle payload root (Resources layout) with a valid manifest.
function fakePayload(root, { nodeBody = '#!/bin/node\nstub\n' } = {}) {
  const files = {
    'daemon/bin/portname.js': 'console.log("cli")\n',
    'daemon/lib/urls.js': 'module.exports = {};\n',
    'daemon/package.json': '{"name":"portname","version":"0.0.0-test"}\n',
    'runtime/bin/node': nodeBody,
    'bin/portname': '#!/bin/sh\nexec stub "$@"\n',
  };
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), body);
  }
  fs.chmodSync(path.join(root, 'runtime/bin/node'), 0o755);
  fs.chmodSync(path.join(root, 'bin/portname'), 0o755);
  const manifest = generateManifest({
    root,
    bundleId: BUNDLE_ID,
    components: { app: { version: '0.0.0-test' } },
  });
  assert.strictEqual(manifest.schema, MANIFEST_SCHEMA);
  fs.writeFileSync(path.join(root, 'MANIFEST.json'), JSON.stringify(manifest));
  return manifest;
}

test('bundleinstall: app bundle layout detection is pure path logic', () => {
  const layout = bundleinstall.appBundleLayout(
    '/Users/u/Applications/Portname.app/Contents/Resources/daemon/bin'
  );
  assert.strictEqual(layout.isBundle, true);
  assert.strictEqual(layout.appPath, '/Users/u/Applications/Portname.app');
  assert.strictEqual(layout.resourcesDir, '/Users/u/Applications/Portname.app/Contents/Resources');

  assert.strictEqual(bundleinstall.appBundleLayout('/Users/u/Code/portname/bin').isBundle, false);
  // A path containing Contents/Resources without an .app root is not a bundle.
  assert.strictEqual(
    bundleinstall.appBundleLayout('/Users/u/Code/Contents/Resources/x').isBundle,
    false
  );
});

test('bundleinstall: stable payload entry detection', () => {
  const home = tmpDir('bi-home');
  try {
    const payload = bundleinstall.stablePayloadDir(home);
    assert.strictEqual(
      payload,
      path.join(home, 'Library', 'Application Support', 'Portname')
    );
    assert.strictEqual(
      bundleinstall.isStablePayloadEntry(path.join(payload, 'daemon', 'bin'), home),
      true
    );
    assert.strictEqual(bundleinstall.isStablePayloadEntry('/usr/local/bin', home), false);
    // Sibling directories with a shared prefix are not inside the payload.
    assert.strictEqual(
      bundleinstall.isStablePayloadEntry(`${payload}-evil/daemon/bin`, home),
      false
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('bundleinstall: manifest generate/verify roundtrip and tamper detection', () => {
  const root = tmpDir('bi-src');
  try {
    fakePayload(root);
    assert.strictEqual(verifyManifest(root).ok, true);

    // A mode change (e.g. `chmod -x` on the bundled runtime) must be
    // detected: mode is recorded in the manifest and checked on verify —
    // both verifier implementations agree. (Mode is the only violation
    // here: content is still pristine.)
    fs.chmodSync(path.join(root, 'runtime/bin/node'), 0o644);
    for (const verify of [verifyManifest, bundleinstall.verifyManifest]) {
      const demoted = verify(root);
      assert.strictEqual(demoted.ok, false, `${verify.name || 'verifier'} must detect mode changes`);
      assert.ok(demoted.errors.some((e) => e.includes('mode mismatch')));
    }
    fs.chmodSync(path.join(root, 'runtime/bin/node'), 0o755);

    // Tampering with a shipped file must be detected via SHA-256 (same-size
    // rewrite isolates the hash check from the size check).
    fs.writeFileSync(path.join(root, 'daemon/lib/urls.js'), 'module.exports = XX;\n');
    const tampered = verifyManifest(root);
    assert.strictEqual(tampered.ok, false);
    assert.ok(tampered.errors.some((e) => e.includes('sha256 mismatch')));

    // A size change is reported as a size mismatch.
    fs.appendFileSync(path.join(root, 'daemon/lib/urls.js'), '// longer\n');
    const resized = verifyManifest(root);
    assert.strictEqual(resized.ok, false);
    assert.ok(resized.errors.some((e) => e.includes('size mismatch')));

    // A missing file must be reported.
    fs.rmSync(path.join(root, 'runtime/bin/node'));
    const missing = verifyManifest(root);
    assert.strictEqual(missing.ok, false);
    assert.ok(missing.errors.some((e) => e.includes('missing')));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('bundleinstall: sync installs idempotently, repairs damage, replaces outdated payloads', () => {
  const src = tmpDir('bi-src');
  const home = tmpDir('bi-home');
  try {
    fakePayload(src);
    const dest = bundleinstall.stablePayloadDir(home);

    // 1. fresh install
    const first = bundleinstall.syncPayload({ sourceRoot: src, home });
    assert.strictEqual(first.changed, true);
    assert.strictEqual(
      fs.readFileSync(path.join(dest, 'daemon/lib/urls.js'), 'utf8'),
      'module.exports = {};\n'
    );
    // Executable modes survive the copy.
    const nodeMode = fs.statSync(path.join(dest, 'runtime/bin/node')).mode & 0o777;
    assert.strictEqual(nodeMode, 0o755, 'bundled runtime must stay executable');

    // 2. identical payload → no-op (intact + same payloadId)
    const second = bundleinstall.syncPayload({ sourceRoot: src, home });
    assert.strictEqual(second.changed, false);

    // 2b. demoted executable bit → detected as damage via the mode check
    // and repaired (the manifest's recorded mode is restored).
    fs.chmodSync(path.join(dest, 'runtime/bin/node'), 0o644);
    assert.strictEqual(bundleinstall.verifyManifest(dest).ok, false);
    const modeRepair = bundleinstall.syncPayload({ sourceRoot: src, home });
    assert.strictEqual(modeRepair.changed, true, 'mode violation must trigger repair');
    assert.strictEqual(fs.statSync(path.join(dest, 'runtime/bin/node')).mode & 0o777, 0o755);
    assert.strictEqual(bundleinstall.verifyManifest(dest).ok, true);

    // 3. damaged payload → repaired
    fs.writeFileSync(path.join(dest, 'daemon/lib/urls.js'), 'damaged');
    const repair = bundleinstall.syncPayload({ sourceRoot: src, home });
    assert.strictEqual(repair.changed, true);
    assert.strictEqual(verifyManifest(dest).ok, true);

    // 4. different payload (runtime update) → replaced atomically
    fs.appendFileSync(path.join(src, 'runtime/bin/node'), 'v2\n');
    const manifest2 = generateManifest({ root: src, bundleId: BUNDLE_ID, components: {} });
    fs.writeFileSync(path.join(src, 'MANIFEST.json'), JSON.stringify(manifest2));
    const upgrade = bundleinstall.syncPayload({ sourceRoot: src, home });
    assert.strictEqual(upgrade.changed, true);
    assert.strictEqual(
      fs.readFileSync(path.join(dest, 'runtime/bin/node'), 'utf8').endsWith('v2\n'),
      true
    );
    // No sync leftovers next to the payload.
    const leftovers = fs.readdirSync(path.dirname(dest)).filter((n) => n.startsWith('.Portname.'));
    assert.deepStrictEqual(leftovers, []);
  } finally {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('bundleinstall: sync refuses payloads with a foreign bundle id', () => {
  const src = tmpDir('bi-src');
  const home = tmpDir('bi-home');
  try {
    fakePayload(src);
    const manifest = JSON.parse(fs.readFileSync(path.join(src, 'MANIFEST.json'), 'utf8'));
    manifest.bundleId = 'com.evil.other';
    fs.writeFileSync(path.join(src, 'MANIFEST.json'), JSON.stringify(manifest));
    assert.throws(() => bundleinstall.syncPayload({ sourceRoot: src, home }), /refusing to install/);
  } finally {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('bundleinstall: payload removal only touches verifiably own payloads', () => {
  const src = tmpDir('bi-src');
  const home = tmpDir('bi-home');
  try {
    fakePayload(src);
    const dest = bundleinstall.stablePayloadDir(home);
    bundleinstall.syncPayload({ sourceRoot: src, home });
    assert.strictEqual(bundleinstall.removePayloadIfOurs(dest), true);
    assert.strictEqual(fs.existsSync(dest), false);

    // A foreign directory (no manifest / foreign bundle id) must survive.
    fs.mkdirSync(dest, { recursive: true });
    fs.writeFileSync(path.join(dest, 'important.txt'), 'keep');
    assert.strictEqual(bundleinstall.removePayloadIfOurs(dest), false);
    assert.strictEqual(fs.existsSync(path.join(dest, 'important.txt')), true);

    const foreign = tmpDir('bi-foreign');
    try {
      fakePayload(foreign);
      const manifest = JSON.parse(fs.readFileSync(path.join(foreign, 'MANIFEST.json'), 'utf8'));
      manifest.bundleId = 'com.other.vendor';
      fs.writeFileSync(path.join(dest, 'MANIFEST.json'), JSON.stringify(manifest));
      assert.strictEqual(bundleinstall.removePayloadIfOurs(dest), false);
      assert.strictEqual(fs.existsSync(dest), true);
    } finally {
      fs.rmSync(foreign, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('bundleinstall: payload install args stay inside the payload dir', () => {
  const dest = bundleinstall.stablePayloadDir('/mockhome');
  const args = bundleinstall.payloadInstallArgs(dest);
  assert.strictEqual(args.nodePath, path.join(dest, 'runtime', 'bin', 'node'));
  assert.strictEqual(args.entryPath, path.join(dest, 'daemon', 'bin', 'portname.js'));
  assert.strictEqual(args.extraPath, path.join(dest, 'runtime', 'bin'));
  for (const p of [args.nodePath, args.entryPath, args.extraPath]) {
    assert.ok(p.startsWith(dest), `path must stay inside the payload: ${p}`);
  }
});

test('CLI: plist prepends the payload runtime bin dir to the agent PATH', () => {
  const withPayload = plist({ extraPath: '/Users/u/Library/Application Support/Portname/runtime/bin' });
  assert.ok(
    withPayload.includes(
      '<string>/Users/u/Library/Application Support/Portname/runtime/bin:/opt/homebrew/bin:'
    ),
    'payload runtime bin must be prepended to the agent PATH'
  );
  // Without a payload the PATH is unchanged (existing behavior).
  assert.ok(plist().includes('<string>/opt/homebrew/bin:/usr/local/bin:'));
});

test('CLI: install/uninstall --dry-run validate but never write anything (isolated HOME, launchctl stubbed)', async () => {
  const home = tmpDir('bi-dryrun');
  const launchctlStub = makeLaunchctlStub();
  try {
    const env = launchctlStub.env({ ...process.env, HOME: home, PORTNAME_DIR: path.join(home, '.portname') });
    const proc = spawn(process.execPath, [BIN_PATH, 'install', '--dry-run'], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    proc.stdout.on('data', (d) => (stdout += d));
    const code = await new Promise((resolve) => proc.on('close', resolve));
    assert.strictEqual(code, 0, `dry-run install failed: ${stdout}`);
    assert.ok(stdout.includes('dry-run'), 'must state dry-run');
    assert.ok(stdout.includes('launchctl not invoked'), 'must state launchctl was not invoked');

    // A dry-run must leave NO traces in the isolated HOME:
    // no LaunchAgent plist, no state dir, no synced payload (~130 MB).
    const plistPath = path.join(home, 'Library', 'LaunchAgents', 'dev.portname.daemon.plist');
    assert.strictEqual(fs.existsSync(plistPath), false, 'dry-run must not write the agent plist');
    assert.strictEqual(fs.existsSync(path.join(home, 'Library', 'Application Support', 'Portname')), false, 'dry-run must not sync the payload');
    assert.strictEqual(fs.existsSync(path.join(home, '.portname')), false, 'dry-run must not create the state dir');
    assert.deepStrictEqual(fs.readdirSync(home), [], 'dry-run must leave the HOME untouched');

    const uninstall = spawn(process.execPath, [BIN_PATH, 'uninstall', '--dry-run'], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let uout = '';
    uninstall.stdout.on('data', (d) => (uout += d));
    const ucode = await new Promise((resolve) => uninstall.on('close', resolve));
    assert.strictEqual(ucode, 0);
    assert.ok(uout.includes('dry-run'));

    // Defense in depth: the children ran with a launchctl
    // stub first on PATH, so even a bug in the dry-run logic could never
    // reach the real launchctl — and an EMPTY stub log proves launchctl was
    // in fact never invoked.
    assert.deepStrictEqual(launchctlStub.calls(), [], 'dry-run must never invoke launchctl (not even the stub)');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    launchctlStub.dispose();
  }
});

test('CLI: developer install writes the plist and invokes launchctl only through the stub (isolated HOME)', async () => {
  const home = tmpDir('bi-devinstall');
  const launchctlStub = makeLaunchctlStub();
  try {
    const env = launchctlStub.env({ ...process.env, HOME: home, PORTNAME_DIR: path.join(home, '.portname') });
    const proc = spawn(process.execPath, [BIN_PATH, 'install'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    proc.stdout.on('data', (d) => (stdout += d));
    const code = await new Promise((resolve) => proc.on('close', resolve));
    assert.strictEqual(code, 0, `developer install failed: ${stdout}`);

    const plistPath = path.join(home, 'Library', 'LaunchAgents', 'dev.portname.daemon.plist');
    const generated = fs.readFileSync(plistPath, 'utf8');
    assert.ok(generated.includes('<string>daemon</string>'), 'plist carries the daemon argument');
    assert.ok(
      generated.includes(BIN_PATH.replace(/&/g, '&amp;')),
      'developer install pins the checkout entry path'
    );
    assert.ok(
      !generated.includes('Application Support/Portname'),
      'developer install must not reference the payload location'
    );

    // The stub (not the real launchctl) handled the bootstrap/bootout.
    const uid = process.getuid();
    const calls = launchctlStub.calls();
    assert.ok(
      calls.includes(`bootout gui/${uid} ${plistPath}`) && calls.includes(`bootstrap gui/${uid} ${plistPath}`),
      `launchctl stub must record bootout+bootstrap for the agent: ${JSON.stringify(calls)}`
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    launchctlStub.dispose();
  }
});

test('CLI: bundle install syncs payload and pins the agent to the stable location (isolated HOME, launchctl stubbed)', async () => {
  const home = tmpDir('bi-bundle-e2e');
  const appRoot = tmpDir('bi-fake-app');
  const launchctlStub = makeLaunchctlStub();
  try {
    // Assemble a minimal fake .app: Contents/Resources with a real manifest and
    // the real CLI entry (shipped daemon payload).
    const res = path.join(appRoot, 'Fake.app/Contents/Resources');
    fs.mkdirSync(path.join(res, 'daemon/bin'), { recursive: true });
    fs.mkdirSync(path.join(res, 'daemon/lib'), { recursive: true });
    fs.mkdirSync(path.join(res, 'runtime/bin'), { recursive: true });
    fs.mkdirSync(path.join(res, 'bin'), { recursive: true });
    fs.copyFileSync(BIN_PATH, path.join(res, 'daemon/bin/portname.js'));
    // bundleinstall is required by the shipped CLI — ship the real lib files.
    for (const f of fs.readdirSync(path.resolve(BIN_PATH, '../../lib'))) {
      fs.copyFileSync(path.resolve(BIN_PATH, '../../lib', f), path.join(res, 'daemon/lib', f));
    }
    fs.writeFileSync(path.join(res, 'daemon/package.json'), '{"name":"portname","version":"0.0.0-test"}\n');
    // The bundled runtime in this test is the test runner's own node binary.
    fs.copyFileSync(process.execPath, path.join(res, 'runtime/bin/node'));
    fs.chmodSync(path.join(res, 'runtime/bin/node'), 0o755);
    fs.writeFileSync(path.join(res, 'bin/portname'), '#!/bin/sh\nexec stub\n');
    fs.chmodSync(path.join(res, 'bin/portname'), 0o755);
    const manifest = generateManifest({
      root: res,
      bundleId: BUNDLE_ID,
      components: { app: { version: '0.0.0-test' } },
    });
    fs.writeFileSync(path.join(res, 'MANIFEST.json'), JSON.stringify(manifest));

    // Full install path (not dry-run): the payload sync runs for real, and
    // launchctl can only be reached through the stub (`bootout` resolves
    // the service by label even for a foreign plist path, so the real
    // launchctl would unload the machine's production Portname agent under
    // the real UID).
    const env = launchctlStub.env({ ...process.env, HOME: home, PORTNAME_DIR: path.join(home, '.portname') });
    const proc = spawn(process.execPath, [path.join(res, 'daemon/bin/portname.js'), 'install'], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    proc.stdout.on('data', (d) => (stdout += d));
    const code = await new Promise((r) => proc.on('close', r));
    assert.strictEqual(code, 0, `bundle install failed: ${stdout}`);
    assert.ok(stdout.includes('Installed background service payload'), stdout);

    const payload = bundleinstall.stablePayloadDir(home);
    const plistPath = path.join(home, 'Library', 'LaunchAgents', 'dev.portname.daemon.plist');
    const generated = fs.readFileSync(plistPath, 'utf8');
    assert.ok(
      generated.includes(`${payload}/runtime/bin/node`),
      'agent must pin the payload node runtime'
    );
    assert.ok(
      generated.includes(`${payload}/daemon/bin/portname.js`),
      'agent must pin the payload entry script'
    );
    // Scope the .app check to the program arguments: the plist boilerplate
    // (DTD URL "…www.apple.com…") legitimately contains the substring ".app".
    const argsBlock = generated.match(/<array>[\s\S]*?<\/array>/)[0];
    assert.ok(
      !argsBlock.includes('.app'),
      'agent must not reference the app bundle'
    );
    assert.ok(
      generated.includes(`${payload}/runtime/bin:/opt/homebrew/bin`),
      'agent PATH must start with the payload runtime bin (bundled cloudflared)'
    );
    assert.strictEqual(bundleinstall.verifyManifest(payload).ok, true, 'payload must verify');

    // The install ran with the stub first on PATH — the stub log proves the
    // child used it (an empty log would mean it reached the REAL launchctl).
    const uid = process.getuid();
    const installCalls = launchctlStub.calls();
    assert.ok(
      installCalls.includes(`bootout gui/${uid} ${plistPath}`) && installCalls.includes(`bootstrap gui/${uid} ${plistPath}`),
      `launchctl stub must record bootout+bootstrap for the agent: ${JSON.stringify(installCalls)}`
    );

    // Uninstall from the payload removes the agent plist and the payload itself.
    const un = spawn(process.execPath, [path.join(payload, 'daemon/bin/portname.js'), 'uninstall'], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let unErr = '';
    un.stderr.on('data', (d) => (unErr += d));
    const unCode = await new Promise((r) => un.on('close', r));
    assert.strictEqual(unCode, 0, `payload uninstall failed: ${unErr}`);
    assert.strictEqual(fs.existsSync(plistPath), false, 'agent plist removed');
    assert.strictEqual(fs.existsSync(payload), false, 'own payload removed');
    const uninstallCalls = launchctlStub.calls();
    assert.ok(
      uninstallCalls.filter((c) => c === `bootout gui/${uid} ${plistPath}`).length >= 2,
      `uninstall must bootout via the stub as well: ${JSON.stringify(uninstallCalls)}`
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(appRoot, { recursive: true, force: true });
    launchctlStub.dispose();
  }
});

// ---------------------------------------------------------------------------
// An existing install target is only ever touched when it is verifiably
// a portname payload. Foreign content, foreign bundle ids, unreadable
// manifests and symlinks are left untouched and the install is refused.
// ---------------------------------------------------------------------------

test('bundleinstall: sync refuses to replace a foreign target directory (byte-exact preservation)', () => {
  const src = tmpDir('bi-src');
  const home = tmpDir('bi-home');
  try {
    fakePayload(src);
    const dest = bundleinstall.stablePayloadDir(home);
    fs.mkdirSync(dest, { recursive: true });
    fs.writeFileSync(path.join(dest, 'important.txt'), 'user data 12345\n');
    fs.mkdirSync(path.join(dest, 'nested'));
    fs.writeFileSync(path.join(dest, 'nested', 'more.bin'), Buffer.from([0x00, 0x01, 0x02, 0xff]));

    assert.throws(
      () => bundleinstall.syncPayload({ sourceRoot: src, home }),
      /refusing to install.*no valid MANIFEST\.json|refusing to install.*not a recognizable portname payload/
    );

    // Byte-exact preservation: nothing was renamed away, replaced or deleted.
    assert.strictEqual(fs.readFileSync(path.join(dest, 'important.txt'), 'utf8'), 'user data 12345\n');
    assert.deepStrictEqual(
      fs.readFileSync(path.join(dest, 'nested', 'more.bin')),
      Buffer.from([0x00, 0x01, 0x02, 0xff])
    );
    assert.deepStrictEqual(fs.readdirSync(dest).sort(), ['important.txt', 'nested']);
    // No sync leftovers (the old target must never sit in a hidden backup).
    const leftovers = fs.readdirSync(path.dirname(dest)).filter((n) => n.startsWith('.Portname.'));
    assert.deepStrictEqual(leftovers, []);
  } finally {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('bundleinstall: sync refuses a target holding a foreign bundle id', () => {
  const src = tmpDir('bi-src');
  const home = tmpDir('bi-home');
  const foreign = tmpDir('bi-foreign');
  try {
    fakePayload(src);
    const dest = bundleinstall.stablePayloadDir(home);
    fs.mkdirSync(dest, { recursive: true });
    fs.writeFileSync(path.join(dest, 'vendor.txt'), 'other vendor data\n');
    const manifest = JSON.parse(fs.readFileSync(path.join(src, 'MANIFEST.json'), 'utf8'));
    // Valid manifest schema, but a different bundle id.
    fs.writeFileSync(
      path.join(dest, 'MANIFEST.json'),
      JSON.stringify({ ...manifest, bundleId: 'com.other.vendor' })
    );

    assert.throws(
      () => bundleinstall.syncPayload({ sourceRoot: src, home }),
      /refusing to install: .*bundle id 'com\.other\.vendor'/
    );
    assert.strictEqual(fs.readFileSync(path.join(dest, 'vendor.txt'), 'utf8'), 'other vendor data\n');
    assert.strictEqual(fs.existsSync(dest), true);
  } finally {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(foreign, { recursive: true, force: true });
  }
});

test('bundleinstall: unreadable own manifest is refused, damaged files in a verifiable own payload stay repairable', () => {
  const src = tmpDir('bi-src');
  const home = tmpDir('bi-home');
  try {
    fakePayload(src);
    const dest = bundleinstall.stablePayloadDir(home);

    // Variant A: corrupt MANIFEST.json (no longer readable) — the directory
    // can no longer be identified as ours, so the install is REFUSED.
    fs.mkdirSync(dest, { recursive: true });
    fs.writeFileSync(path.join(dest, 'MANIFEST.json'), '{ this is not json');
    assert.throws(
      () => bundleinstall.syncPayload({ sourceRoot: src, home }),
      /refusing to install/
    );
    assert.strictEqual(fs.readFileSync(path.join(dest, 'MANIFEST.json'), 'utf8'), '{ this is not json');

    // Variant B (defined behavior, documented): a verifiably OWN installation
    // (valid manifest with our bundle id) whose payload files are damaged
    // remains replaceable via the existing repair path.
    fs.rmSync(dest, { recursive: true, force: true });
    const first = bundleinstall.syncPayload({ sourceRoot: src, home });
    assert.strictEqual(first.changed, true);
    fs.writeFileSync(path.join(dest, 'runtime/bin/node'), 'corrupted-bytes');
    const repair = bundleinstall.syncPayload({ sourceRoot: src, home });
    assert.strictEqual(repair.changed, true, 'own damaged payload must stay repairable');
    assert.strictEqual(bundleinstall.verifyManifest(dest).ok, true);
  } finally {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('bundleinstall: sync refuses a symlinked target and leaves it untouched', () => {
  const src = tmpDir('bi-src');
  const home = tmpDir('bi-home');
  const behind = tmpDir('bi-behind');
  try {
    fakePayload(src);
    const dest = bundleinstall.stablePayloadDir(home);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.symlinkSync(behind, dest, 'dir');

    assert.throws(
      () => bundleinstall.syncPayload({ sourceRoot: src, home }),
      /refusing to install: .*symlink/
    );
    // The symlink itself and everything behind it must survive untouched.
    fs.statSync(dest); // throws if the symlink is gone
    assert.strictEqual(fs.readlinkSync(dest), behind);
    assert.strictEqual(fs.existsSync(path.join(behind, 'anything')), false);
    assert.deepStrictEqual(fs.readdirSync(behind), []);
  } finally {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(behind, { recursive: true, force: true });
  }
});

test('bundleinstall: sync refuses a plain file at the target path', () => {
  const src = tmpDir('bi-src');
  const home = tmpDir('bi-home');
  try {
    fakePayload(src);
    const dest = bundleinstall.stablePayloadDir(home);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, 'not a directory\n');

    assert.throws(
      () => bundleinstall.syncPayload({ sourceRoot: src, home }),
      /refusing to install: .*not a directory/
    );
    assert.strictEqual(fs.readFileSync(dest, 'utf8'), 'not a directory\n');
  } finally {
    fs.rmSync(src, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});
