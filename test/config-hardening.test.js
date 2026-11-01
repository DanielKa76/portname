'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { spawn } = require('child_process');

const { Registry, atomicWrite } = require('../lib/registry');
const { Daemon } = require('../lib/daemon');
const { ConfigError, validateConfig, ensurePrivateDir } = require('../lib/config');
const { send, MAX_RESPONSE_BYTES, xmlEscape, plist, assertPlistSafePath } = require('../bin/portname');

const BIN_PATH = path.resolve(__dirname, '../bin/portname.js');

function tmpDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `pn-hard-${label}-`));
}

function writeJson(file, value) {
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2));
}

function fileMode(p) {
  return fs.statSync(p).mode & 0o777;
}

test('config validation: known bind modes, ports and booleans are enforced, additive fields ignored', () => {
  // Valid full schema passes
  validateConfig({
    bind: 'loopback', port: 0, fallbackPort: 0, loopbackPort: 7777, control: true,
    cloudflaredBin: '/opt/homebrew/bin/cloudflared',
    ignoreCommands: ['postgres'],
    renames: { '/p/a': 'a' }, names: { '/p/a': 'a' }, manual: { db: 5432 },
    exposed: { '/p/a': true }, primaryPorts: { '/p/a': 3000 },
    exposedTargets: {
      '/p/a': { port: 3000, command: 'node' },
      'manual:db': { port: 5432, command: null },
      '/p/b': { port: 5173, command: 'node', network: '192.168.1.0/24', gateway: '0123456789abcdef' },
    },
    // unknown additive field: must be tolerated, never a validation error
    futureFeature: { nested: [1, 2, 3] },
  }, 'config.json');

  const cases = [
    [{ bind: 'ftp' }, /bind must be "wildcard" or "loopback"/],
    [{ bind: 123 }, /bind must be "wildcard" or "loopback"/],
    [{ port: '80' }, /port must be an integer/],
    [{ fallbackPort: 70000 }, /fallbackPort must be an integer/],
    [{ loopbackPort: -1 }, /loopbackPort must be an integer/],
    [{ control: 'yes' }, /control must be a boolean/],
    [{ cloudflaredBin: '' }, /cloudflaredBin must be a non-empty string/],
    [{ ignoreCommands: 'postgres' }, /ignoreCommands must be an array of strings/],
    [{ ignoreCommands: [42] }, /ignoreCommands must be an array of strings/],
    [{ renames: { a: 5 } }, /renames must map names to non-empty strings/],
    [{ names: [] }, /names must map names to names/],
    [{ manual: { app: '3000' } }, /manual must map names to ports/],
    [{ manual: { app: 0 } }, /manual must map names to ports/],
    [{ exposed: { x: 'yes' } }, /exposed must map identities to booleans/],
    [{ primaryPorts: { '/p/a': '80' } }, /primaryPorts must map roots to ports/],
    [{ exposedTargets: [] }, /exposedTargets must map identities/],
    [{ exposedTargets: { '/p/a': { port: '3000', command: 'node' } } }, /exposedTargets must map identities/],
    [{ exposedTargets: { '/p/a': { port: 3000 } } }, /exposedTargets must map identities/],
    [{ exposedTargets: { '/p/a': { port: 3000, command: 'node', gateway: 42 } } }, /exposedTargets must map identities/],
  ];
  for (const [bad, pattern] of cases) {
    assert.throws(() => validateConfig(bad, 'config.json'), ConfigError, `expected ConfigError for ${JSON.stringify(bad)}`);
    assert.throws(() => validateConfig(bad, 'config.json'), pattern, `message must name the problem for ${JSON.stringify(bad)}`);
  }
});

test('Registry first start: missing files are a safe fresh start, no fail-closed', () => {
  const dir = tmpDir('fresh');
  try {
    const reg = new Registry(dir);
    assert.strictEqual(reg.isExposed('/p/x'), false, 'missing config must start from safe defaults');
    assert.deepStrictEqual(reg.manualEntries(), []);
    reg.setExposed('/p/x', true);
    assert.strictEqual(reg.isExposed('/p/x'), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Registry: corrupt JSON config fails closed with a repair hint and is never overwritten', () => {
  const dir = tmpDir('corrupt');
  const configFile = path.join(dir, 'config.json');
  const damaged = '{"bind": "loopback", "port": 7777,tru';
  writeJson(configFile, damaged);
  const before = fs.readFileSync(configFile, 'utf8');
  try {
    assert.throws(() => new Registry(dir), ConfigError);
    assert.throws(() => new Registry(dir), /config\.json.*not valid JSON/);
    assert.strictEqual(fs.readFileSync(configFile, 'utf8'), before, 'damaged config must not be modified or replaced');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Registry: unreadable config file fails closed instead of silently applying defaults', function () {
  if (process.getuid() === 0) this.skip('permission checks are meaningless as root');
  const dir = tmpDir('unreadable');
  const configFile = path.join(dir, 'config.json');
  writeJson(configFile, { bind: 'loopback', loopbackPort: 7777 });
  fs.chmodSync(configFile, 0o000);
  try {
    assert.throws(() => new Registry(dir), ConfigError);
    assert.throws(() => new Registry(dir), /cannot be read/);
    assert.strictEqual(fileMode(configFile), 0o000, 'unreadable file must be left untouched');
  } finally {
    fs.chmodSync(configFile, 0o600);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Registry: mistyped persisted values fail closed; file stays byte-identical', () => {
  const dir = tmpDir('mistyped');
  const configFile = path.join(dir, 'config.json');
  const before = JSON.stringify({ bind: 'wildcard', manual: { app: '3000' }, extra: { kept: true } });
  writeJson(configFile, before);
  try {
    assert.throws(() => new Registry(dir), ConfigError);
    assert.throws(() => new Registry(dir), /manual must map names to ports/);
    assert.strictEqual(fs.readFileSync(configFile, 'utf8'), before, 'mistyped config must not be "repaired" in place');

    const stateFile = path.join(dir, 'state.json');
    writeJson(stateFile, { '5:T1:3000': 'yesterday' });
    // The Registry must get past the (now repaired) config before the state
    // file check can fire.
    writeJson(configFile, { bind: 'wildcard', manual: { app: 3000 } });
    assert.throws(() => new Registry(dir), ConfigError);
    assert.throws(() => new Registry(dir), /state\.json.*timestamp/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Registry: unknown additive fields survive a load/save round-trip', () => {
  const dir = tmpDir('additive');
  try {
    writeJson(path.join(dir, 'config.json'), {
      manual: { db: 5432 },
      futurePlugin: { enabled: true, opts: ['a'] },
    });
    const reg = new Registry(dir);
    reg.setExposed('/p/app', true); // triggers saveConfig()
    const onDisk = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
    assert.deepStrictEqual(onDisk.futurePlugin, { enabled: true, opts: ['a'] }, 'additive fields must not be destroyed');
    assert.strictEqual(onDisk.manual.db, 5432);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('file modes under umask 022: state dir 0700, config/state files 0600; too-open existing dir is tightened', () => {
  const dir = tmpDir('modes');
  const oldUmask = process.umask(0o022);
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    fs.chmodSync(dir, 0o755); // simulate a too-open pre-existing state dir
    const reg = new Registry(dir);
    reg.setExposed('/p/app', true);
    reg.observe([{ pid: 7, port: 3100, processKey: '7:T1' }], 999);

    assert.strictEqual(fileMode(dir), 0o700, 'state dir must be private (0700)');
    assert.strictEqual(fileMode(path.join(dir, 'config.json')), 0o600, 'config.json must be 0600');
    assert.strictEqual(fileMode(path.join(dir, 'state.json')), 0o600, 'state.json must be 0600');
  } finally {
    process.umask(oldUmask);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ensurePrivateDir: refuses symlinks and foreign-owned directories', function () {
  if (process.getuid() === 0) this.skip('ownership checks are meaningless as root');
  const outer = tmpDir('private');
  try {
    const real = path.join(outer, 'real');
    fs.mkdirSync(real, { mode: 0o700 });
    const link = path.join(outer, 'link');
    fs.symlinkSync(real, link);
    assert.throws(() => ensurePrivateDir(link), /symlink/, 'symlinked state dir must be refused');

    const foreign = path.join(outer, 'foreign');
    fs.mkdirSync(foreign, { mode: 0o700 });
    // Simulate foreign ownership without needing a second user (same DI seam
    // as stableNodePath(execPath, existsSync)):
    const fakeStat = { isSymbolicLink: () => false, isDirectory: () => true, uid: process.getuid() + 137, mode: 0o700 };
    assert.throws(
      () => ensurePrivateDir(foreign, { lstat: () => fakeStat }),
      /owned by/,
      'foreign-owned state dir must be refused'
    );
  } finally {
    fs.rmSync(outer, { recursive: true, force: true });
  }
});

test('failed atomic write: throws, leaves target untouched, and cleans up temp files', () => {
  const dir = tmpDir('atomic-fail');
  try {
    const reg = new Registry(dir);
    reg.setExposed('/p/app', true); // config.json now exists on disk

    // Make the final rename step fail: the target path is occupied by a
    // non-empty directory, so renameSync cannot replace it.
    const configFile = path.join(dir, 'config.json');
    fs.unlinkSync(configFile);
    fs.mkdirSync(configFile);
    fs.mkdirSync(path.join(configFile, 'occupied'));

    assert.throws(() => reg.setExposed('/p/other', true), /rename|ENOTEMPTY|EISDIR|EPERM/);

    const leftovers = fs.readdirSync(dir).filter((f) => f.endsWith('.tmp'));
    assert.deepStrictEqual(leftovers, [], 'a failed atomic write must not leave temp files behind');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('atomic write: stale temp files from earlier crashes do not collide; symlinked target is replaced, not followed', () => {
  const outer = tmpDir('atomic-sym');
  const dir = path.join(outer, 'state');
  fs.mkdirSync(dir);
  try {
    const configFile = path.join(dir, 'config.json');
    // 1. leftover temp files under both old and new naming schemes
    writeJson(`${configFile}.4242.tmp`, 'junk from a crashed run');
    const reg = new Registry(dir);
    reg.setExposed('/p/app', true);
    assert.strictEqual(reg.isExposed('/p/app'), true, 'save must succeed despite stale temp files');

    // 2. config.json as a symlink to a decoy outside the state dir
    const decoy = path.join(outer, 'decoy.json');
    writeJson(decoy, 'DECOY-UNTOUCHED');
    fs.unlinkSync(configFile);
    fs.symlinkSync(decoy, configFile);

    reg.setExposed('/p/other', true);
    assert.strictEqual(fs.readFileSync(decoy, 'utf8'), 'DECOY-UNTOUCHED', 'atomic write must never follow a foreign symlink');
    const after = fs.lstatSync(configFile);
    assert.strictEqual(after.isSymbolicLink(), false, 'symlink must be replaced, not written through');
    assert.strictEqual(JSON.parse(fs.readFileSync(configFile, 'utf8')).exposed['/p/other'], true);
  } finally {
    fs.rmSync(outer, { recursive: true, force: true });
  }
});

test('atomicWrite: temp-path collision (EEXIST) is rejected without touching the foreign file', () => {
  const dir = tmpDir('atomic-eexist');
  const target = path.join(dir, 'out.json');
  try {
    const realOpenSync = fs.openSync;
    let collided = null;
    // Faithful collision: the moment atomicWrite opens its *.tmp path, a
    // foreign file already sits there and the exclusive open fails with
    // EEXIST — exactly what a pre-planted file at the temp path produces.
    fs.openSync = function forcedEEXIST(p, flags, ...rest) {
      if (typeof p === 'string' && p.endsWith('.tmp') && collided === null) {
        collided = p;
        const fd = realOpenSync.call(fs, p, 'wx', 0o600);
        fs.writeSync(fd, Buffer.from('FOREIGN-FILE-UNTOUCHED'));
        fs.closeSync(fd);
        const err = new Error(`EEXIST: file already exists, open '${p}'`);
        err.code = 'EEXIST';
        err.errno = -17;
        err.syscall = 'open';
        err.path = p;
        throw err;
      }
      return realOpenSync.call(fs, p, flags, ...rest);
    };
    try {
      assert.throws(() => atomicWrite(target, '{"x":1}\n'), /EEXIST/, 'the collision must fail the write definedly');
    } finally {
      fs.openSync = realOpenSync;
    }

    assert.ok(collided, 'the exclusive temp open must have been reached');
    assert.strictEqual(
      fs.readFileSync(collided, 'utf8'),
      'FOREIGN-FILE-UNTOUCHED',
      'a foreign file occupying the temp path must never be removed or modified'
    );
    assert.strictEqual(fs.existsSync(target), false, 'the target must stay untouched');
    assert.deepStrictEqual(
      fs.readdirSync(dir).filter((f) => f !== path.basename(collided)),
      [],
      'nothing besides the pre-existing foreign file may remain in the directory'
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('Daemon.start(): corrupt config refuses the network start; no socket is created', async () => {
  const dir = tmpDir('daemon-corrupt');
  try {
    writeJson(path.join(dir, 'config.json'), '{"bind": "loopback", tru');
    const daemon = new Daemon({ dir, config: {} });
    await assert.rejects(() => daemon.start(), ConfigError);
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.sock')), false, 'no control socket may exist after a failed start');
  } finally {
    await daemonStopQuiet(dir);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

async function daemonStopQuiet(dir) {
  // Nothing was started on the failure path; nothing to stop.
  void dir;
}

test('Daemon.start(): parent path is private before bind and control socket is 0600', async () => {
  const dir = tmpDir('daemon-sock');
  const u1 = await startUpstream();
  let daemon = null;
  try {
    daemon = new Daemon({
      dir,
      config: { bind: 'loopback', port: 0, fallbackPort: 0, loopbackPort: 0 },
    });
    await daemon.start();
    const sockFile = path.join(dir, 'daemon.sock');
    assert.ok(fs.existsSync(sockFile), 'control socket must exist');
    assert.strictEqual(fileMode(sockFile), 0o600, 'control socket must be 0600');
    assert.strictEqual(fileMode(dir), 0o700, 'state dir must be 0700 while daemon runs');
  } finally {
    if (daemon) await daemon.stop();
    u1.server.closeAllConnections();
    await new Promise((r) => u1.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function startUpstream() {
  const http = require('http');
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => res.end('upstream'));
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

test('CLI daemon command: corrupt config exits non-zero with a concrete repair message and never binds', async () => {
  const dir = tmpDir('cli-corrupt');
  try {
    writeJson(path.join(dir, 'config.json'), '{"bind":');
    const proc = spawn(process.execPath, [BIN_PATH, 'daemon'], {
      env: { ...process.env, PORTNAME_DIR: dir },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    proc.stderr.on('data', (d) => (stderr += d));
    const exitCode = await new Promise((resolve) => proc.on('close', resolve));
    assert.strictEqual(exitCode, 1, 'daemon must refuse to start on a damaged config');
    assert.match(stderr, /config\.json/);
    assert.match(stderr, /not valid JSON/);
    assert.strictEqual(fs.existsSync(path.join(dir, 'daemon.sock')), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---- CLI transport framing invariants (same contract as the Swift client) ----

function startFakeDaemon(handler) {
  return new Promise((resolve) => {
    const sockPath = path.join(tmpDir('sock'), 'fake.sock');
    const server = net.createServer(handler);
    server.listen(sockPath, () => resolve({ server, sockPath }));
  });
}

test('CLI send: resolves the first complete newline-framed JSON response', async () => {
  const { server, sockPath } = await startFakeDaemon((s) => {
    s.on('data', () => {
      s.end(JSON.stringify({ ok: true, answer: 42 }) + '\n');
    });
  });
  try {
    const res = await send({ cmd: 'status' }, { sockPath, timeoutMs: 2000 });
    assert.deepStrictEqual(res, { ok: true, answer: 42 });
  } finally {
    server.close();
  }
});

test('CLI send: multibyte UTF-8 split across TCP chunks decodes intact after the complete frame', async () => {
  const payload = Buffer.from(JSON.stringify({ ok: true, name: 'kaffee–øjle–日本語' }) + '\n', 'utf8');
  // Split inside the last multibyte character so a naive per-chunk decode
  // would produce replacement characters.
  const splitAt = payload.length - 6;
  const { server, sockPath } = await startFakeDaemon((s) => {
    s.on('data', () => {
      s.write(payload.subarray(0, splitAt));
      setTimeout(() => {
        s.write(payload.subarray(splitAt));
        s.end();
      }, 30);
    });
  });
  try {
    const res = await send({ cmd: 'status' }, { sockPath, timeoutMs: 3000 });
    assert.strictEqual(res.name, 'kaffee–øjle–日本語', 'UTF-8 must be decoded only after the frame is complete');
  } finally {
    server.close();
  }
});

test('CLI send: EOF/close before a complete frame rejects immediately (no timeout hang)', async () => {
  const { server, sockPath } = await startFakeDaemon((s) => {
    s.on('data', () => {
      s.write('{"ok": tr'); // partial frame
      setTimeout(() => s.destroy(), 20);
    });
  });
  try {
    const t0 = Date.now();
    await assert.rejects(
      () => send({ cmd: 'status' }, { sockPath, timeoutMs: 10000 }),
      /closed the connection/
    );
    assert.ok(Date.now() - t0 < 5000, 'EOF must be reported at once, not after the deadline');
  } finally {
    server.close();
  }
});

test('CLI send: oversized response without a frame end is rejected at a bounded size', async () => {
  const { server, sockPath } = await startFakeDaemon((s) => {
    s.on('error', () => {}); // client hangs up once the bound is hit — that is the point
    s.on('data', () => {
      const chunk = Buffer.alloc(64 * 1024, 0x61); // 'a', never a newline
      const iv = setInterval(() => {
        if (s.destroyed) {
          clearInterval(iv);
          return;
        }
        s.write(chunk);
      }, 5);
      s.on('close', () => clearInterval(iv));
    });
  });
  try {
    await assert.rejects(
      () => send({ cmd: 'status' }, { sockPath, timeoutMs: 10000 }),
      (err) => /response exceeds/.test(err.message) || /too large/.test(err.message)
    );
    assert.ok(MAX_RESPONSE_BYTES >= 64 * 1024 && MAX_RESPONSE_BYTES <= 8 * 1024 * 1024, 'response bound must be finite and sane');
  } finally {
    server.close();
  }
});

test('CLI send: defined deadline fires even when the daemon never answers', async () => {
  const { server, sockPath } = await startFakeDaemon(() => {});
  try {
    const t0 = Date.now();
    await assert.rejects(
      () => send({ cmd: 'status' }, { sockPath, timeoutMs: 150 }),
      /timeout waiting for daemon/
    );
    const elapsed = Date.now() - t0;
    assert.ok(elapsed >= 100 && elapsed < 5000, `deadline must be honored, took ${elapsed}ms`);
  } finally {
    server.close();
  }
});

test('CLI send: late bytes/close after the frame never cause a second settlement or crash', async () => {
  const { server, sockPath } = await startFakeDaemon((s) => {
    s.on('data', () => {
      s.write(JSON.stringify({ ok: true }) + '\n');
      s.write('GARBAGE-AFTER-FRAME');
      setTimeout(() => s.destroy(), 20);
    });
  });
  const unhandled = [];
  const onUnhandled = (err) => unhandled.push(err);
  process.on('unhandledRejection', onUnhandled);
  try {
    const res = await send({ cmd: 'status' }, { sockPath, timeoutMs: 3000 });
    assert.deepStrictEqual(res, { ok: true }, 'exactly the first frame must be the resolution');
    await new Promise((r) => setTimeout(r, 100));
    assert.strictEqual(unhandled.length, 0, 'no late rejection may surface');
  } finally {
    process.off('unhandledRejection', onUnhandled);
    server.close();
  }
});

test('CLI send: does not retry a mutation after an unclear outcome (single write, single attempt)', async () => {
  let connections = 0;
  let writes = 0;
  const { server, sockPath } = await startFakeDaemon((s) => {
    connections += 1;
    s.on('data', () => {
      writes += 1;
      s.destroy(); // unclear outcome: connection killed mid-request
    });
  });
  try {
    await assert.rejects(() => send({ cmd: 'add', name: 'x', port: 1 }, { sockPath, timeoutMs: 2000 }));
    await new Promise((r) => setTimeout(r, 50));
    assert.strictEqual(connections, 1, 'exactly one connection attempt');
    assert.strictEqual(writes, 1, 'the request must be written exactly once');
  } finally {
    server.close();
  }
});

// ---- LaunchAgent plist: XML escaping, custom state path, fixed executables ----

test('plist: XML-escapes paths with special characters and stays valid XML', () => {
  const weirdDir = '/Users/some one/My & <Tools> "quoted" \'path\' $HOME `x`';
  const generated = plist({ dir: weirdDir, nodePath: '/opt/homebrew/bin/node', entryPath: '/a b/portname.js' });

  assert.ok(generated.includes('&amp;'), '& must be escaped');
  assert.ok(generated.includes('&lt;Tools&gt;'), '< must be escaped');
  assert.ok(generated.includes('&quot;quoted&quot;'), 'double quotes must be escaped');
  assert.strictEqual(xmlEscape('a&<>"\''), 'a&amp;&lt;&gt;&quot;&apos;');

  // The ProgramArguments strings must be intact after escaping
  assert.ok(generated.includes('<string>/opt/homebrew/bin/node</string>'));
  assert.ok(generated.includes('<string>/a b/portname.js</string>'));
  assert.ok(generated.includes('<string>daemon</string>'));

  // If plutil is available, the plist must actually parse
  const { execFileSync } = require('child_process');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-plist-'));
  try {
    const file = path.join(tmp, 'dev.portname.daemon.plist');
    fs.writeFileSync(file, generated);
    try {
      execFileSync('plutil', ['-lint', file], { stdio: 'pipe' });
    } catch (err) {
      if (err.code === 'ENOENT') {
        // plutil not available on this machine; XML shape checks above stand.
      } else {
        throw new Error(`generated plist is not valid: ${err.message}`);
      }
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('plist: custom PORTNAME_DIR is passed consistently to the LaunchAgent', () => {
  const custom = '/Users/me/custom portname state';
  const generated = plist({ dir: custom, nodePath: '/usr/local/bin/node', entryPath: '/x/portname.js' });
  assert.ok(generated.includes('<key>PORTNAME_DIR</key>'), 'LaunchAgent must carry PORTNAME_DIR');
  const envBlock = generated.split('<key>PORTNAME_DIR</key>')[1];
  assert.ok(envBlock.includes(`<string>${xmlEscape(custom)}</string>`), 'PORTNAME_DIR value must match the install dir');

  // Default plist (no overrides) still references the live install
  const def = plist();
  assert.ok(def.includes('dev.portname.daemon'));
  assert.ok(def.includes('<string>daemon</string>'));
});

test('install/uninstall: launchctl is invoked as a fixed executable with argument arrays (no shellstrings)', () => {
  const source = fs.readFileSync(BIN_PATH, 'utf8');
  assert.ok(source.includes("execFileSync('launchctl'"), 'launchctl must run via execFileSync with an argv array');
  assert.ok(!/execSync\(\s*['"`]launchctl/.test(source), 'shellstring launchctl calls are forbidden');
  assert.ok(!/exec\(\s*['"`]launchctl/.test(source), 'shell exec() launchctl calls are forbidden');
  // The plist file path reaches launchctl as one argv element (spaces survive)
  assert.match(source, /runLaunchctl\(\['bootout', `gui\/\$\{uid\}`, file\]/);
  assert.match(source, /runLaunchctl\(\['bootstrap', `gui\/\$\{uid\}`, file\]/);
});

test('install: XML-illegal control characters and lone surrogates in paths are rejected with a defined error', () => {
  // XML 1.0 cannot represent these (below 0x20 only tab/LF/CR are legal) and
  // escaping does not help, so the install must refuse up front — visibly and
  // with the offending code point plus a remedy.
  assert.throws(
    () => assertPlistSafePath(
      '/Users/me/.port\x07name',
      'the state directory "/Users/me/.port\u0007name"',
      'set PORTNAME_DIR to a path without control characters'
    ),
    (err) => {
      assert.match(err.message, /refusing to install/);
      assert.match(err.message, /state directory/);
      assert.match(err.message, /U\+0007/);
      assert.match(err.message, /set PORTNAME_DIR/);
      return true;
    },
    'the message must name the code point and the remedy'
  );

  // The only control characters XML 1.0 allows stay acceptable.
  assert.doesNotThrow(() => assertPlistSafePath('/Users/me/.port\tname', 'x', 'y'));

  // Lone surrogates are not representable in well-formed XML either.
  assert.throws(
    () => assertPlistSafePath('/Users/me/.port\uD800name', 'the node binary path', 'keep node on a clean path'),
    /U\+d800/
  );

  // Ordinary paths — including non-ASCII — remain allowed.
  assert.doesNotThrow(() => assertPlistSafePath('/Users/mé/ßtraße/日本語', 'x', 'y'));
});

test('install: the XML-safety check runs before the state dir is created or written', () => {
  const source = fs.readFileSync(BIN_PATH, 'utf8');
  const validateMatch = source.match(/assertPlistSafePath\(\s*\n\s*DIR,/);
  const ensurePos = source.indexOf('ensurePrivateDir(DIR)');
  assert.ok(validateMatch, 'cmdInstall must validate the state dir path');
  assert.ok(ensurePos !== -1, 'cmdInstall must still ensure the private state dir');
  assert.ok(validateMatch.index < ensurePos, 'validation must happen before anything is created in the state dir');
});

test('registry: the filesystem root and the home folder are never accepted as project keys', () => {
  const dir = tmpDir('registry-roots');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-hard-home-'));
  const savedHome = process.env.HOME;
  process.env.HOME = home;
  try {
    const project = path.join(home, 'shop');
    const target = { port: 3000, command: 'node', network: null, gateway: null };
    writeJson(path.join(dir, 'config.json'), {
      bind: 'wildcard',
      renames: { '/': 'everything', [home + '/']: 'me', [project]: 'shop' },
      names: { '/': 'project', [home]: 'me', [project]: 'shop' },
      primaryPorts: { '/': 3000, [home]: 4000, [project]: 5173 },
      exposed: { '/': true, [home]: true, [project]: true, 'manual:db': true },
      exposedTargets: { '/': target, [home]: target, [project]: target },
      manual: { db: 5432 },
    });
    const reg = new Registry(dir);
    const onDisk = JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'));
    for (const cfg of [reg.config, onDisk]) {
      assert.deepStrictEqual(cfg.renames, { [project]: 'shop' });
      assert.deepStrictEqual(cfg.names, { [project]: 'shop' });
      assert.deepStrictEqual(cfg.primaryPorts, { [project]: 5173 });
      assert.deepStrictEqual(cfg.exposed, { [project]: true, 'manual:db': true });
      assert.deepStrictEqual(Object.keys(cfg.exposedTargets), [project]);
      assert.strictEqual(cfg.bind, 'wildcard', 'the user\'s own settings are kept');
    }

    // Nor are they accepted later.
    reg.setExposed(home, true, target);
    reg.setPrimaryPort('/', 3000);
    assert.strictEqual(reg.isExposed(home), false);
    assert.strictEqual(reg.primaryPort('/'), null);
    assert.strictEqual(reg.rename(home, 'me').ok, false);
    assert.strictEqual(Object.hasOwn(reg.config.renames, home), false);
  } finally {
    process.env.HOME = savedHome;
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('rename: refusing the filesystem root or the home folder answers with a defined code like every rename refusal', async () => {
  const dir = tmpDir('rename-roots');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'pn-hard-home-'));
  const savedHome = process.env.HOME;
  process.env.HOME = home;
  const listener = (pid, root, name) => ({
    pid, port: 40000 + pid, processKey: `${pid}:a`, command: 'node', cwd: root, root, external: false, suggestedName: name,
  });
  const daemon = new Daemon({
    dir,
    config: { bind: 'loopback', port: 0, loopbackPort: 0, control: false },
    listListeners: async () => [listener(1, '/', 'slash'), listener(2, home, 'me')],
  });
  try {
    await daemon.start();
    for (const name of ['slash', 'me']) {
      assert.ok(daemon.routesByName.has(name), `precondition: a route named ${name}`);
      await assert.rejects(daemon.dispatchControl({ cmd: 'rename', name, newName: 'renamed' }),
        (err) => err.code === 'INVALID_REQUEST' && /never a project/.test(err.message));
    }
    assert.deepStrictEqual(daemon.registry.config.renames, {});
  } finally {
    process.env.HOME = savedHome;
    await daemon.stop();
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});
