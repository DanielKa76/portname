'use strict';

// Test safety shim for `launchctl`.
//
// `launchctl bootout gui/<uid> <plist>` resolves the service by its label,
// not by the plist path: a test that spawns a NON-dry-run install/uninstall
// with the real UID would unload the machine's production Portname
// LaunchAgent even though the plist lives in a temp dir. `bin/portname.js`
// execs launchctl via execFileSync, which resolves through the CHILD's PATH
// (libuv scans the PATH from the passed env). Tests that spawn
// install/uninstall therefore MUST route the child through this stub: a
// `launchctl` shell script on a temp dir that logs every invocation to a
// file and exits 0 — launchd is never touched, and the log doubles as the
// assertion surface that the stub (not the real launchctl) was used.

const fs = require('fs');
const os = require('os');
const path = require('path');

function makeLaunchctlStub() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'portname-launchctl-stub.'));
  const logFile = path.join(dir, 'calls.log');
  fs.writeFileSync(
    path.join(dir, 'launchctl'),
    [
      '#!/bin/sh',
      `printf '%s\\n' "$*" >> ${JSON.stringify(logFile)}`,
      'exit 0',
      '',
    ].join('\n'),
    { mode: 0o755 }
  );
  return {
    dir,
    logFile,
    // Child env with the stub directory FIRST on PATH.
    env(base = process.env) {
      return { ...base, PATH: `${dir}${path.delimiter}${base.PATH || ''}` };
    },
    // One entry per stub invocation (arguments joined with single spaces).
    calls() {
      if (!fs.existsSync(logFile)) return [];
      return fs
        .readFileSync(logFile, 'utf8')
        .split('\n')
        .filter((line) => line.length > 0);
    },
    dispose() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

module.exports = { makeLaunchctlStub };
