'use strict';

// Release gate before anything is signed (scripts/release-package.sh): the
// bundle's payload must be exactly what scripts/bundle-macos.sh produced
// under the CURRENT runtime pins. Signing, and the manifest regeneration
// after it, would otherwise carry into a notarized release whatever sits in
// dist/Portname.app — a payload edited after the build, an unlisted file, a
// swapped runtime binary, or a bundle built under an older pin that a
// security release has since superseded.
//
// The prior channel (PortnameBuildChannel before the release marker is set)
// decides how far the binaries can be checked:
//   beta-adhoc  unsigned output of bundle-macos.sh: runtime/bin/node must
//               hash to the binary procured from the pinned tarball,
//               runtime/bin/cloudflared to the pinned binary SHA-256;
//   release     signed by an earlier run of release-package.sh (a
//               re-notarization): signing rewrote the binaries, so the
//               manifest regenerated over the signed bytes and the recorded
//               component pins are what can be compared;
//   anything else is refused.
//
// CLI: release-preflight.js <resources-dir> <runtime-pin.env> <prior-channel>
//   exit 0  payload matches its manifest and the pins
//   exit 1  problems (printed)
// Node stdlib only.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { verifyManifest, unlistedFiles, readManifestFile } = require('./payload-manifest');

const BUNDLE_ID = 'dev.portname.app';
const KNOWN_PRIOR_CHANNELS = ['beta-adhoc', 'release'];

// KEY=value lines of scripts/runtime-pin.env (a sourced shell file without
// expansions); comments and blank lines are skipped.
function parsePinEnv(text) {
  const pins = {};
  for (const line of String(text).split('\n')) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (m) pins[m[1]] = m[2];
  }
  return pins;
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function preflightProblems({ root, pins, channel }) {
  if (!KNOWN_PRIOR_CHANNELS.includes(channel)) {
    return [`build channel '${channel || '(none)'}' is not a bundle-macos.sh build (expected ${KNOWN_PRIOR_CHANNELS.join(' or ')})`];
  }
  const problems = [];
  const pin = (key, shape) => {
    const value = pins[key];
    if (typeof value !== 'string' || !shape.test(value)) {
      problems.push(`runtime pin ${key} is not set in scripts/runtime-pin.env`);
      return null;
    }
    return value;
  };
  const SHA256 = /^[0-9a-f]{64}$/;
  const NONEMPTY = /\S/;

  const manifest = readManifestFile(root);
  problems.push(...verifyManifest(root, manifest).errors);
  if (!manifest || !Array.isArray(manifest.files)) return problems;
  if (manifest.bundleId !== BUNDLE_ID) problems.push(`manifest bundle id '${manifest.bundleId}' is not ${BUNDLE_ID}`);
  for (const p of unlistedFiles(root, manifest)) problems.push(`${p}: not in the manifest`);

  const unsigned = channel === 'beta-adhoc';
  const components = manifest.components || {};
  const node = components.nodeRuntime || {};
  for (const [field, key, shape] of [
    ['version', 'NODE_RUNTIME_VERSION', NONEMPTY],
    ['platform', 'NODE_RUNTIME_PLATFORM', NONEMPTY],
    ['tarballSha256', 'NODE_RUNTIME_TARBALL_SHA256', SHA256],
  ]) {
    const expected = pin(key, shape);
    if (expected !== null && node[field] !== expected) {
      problems.push(`node runtime ${field} '${node[field]}' does not match the pin ${key}=${expected}`);
    }
  }
  const nodeBin = path.join(root, 'runtime', 'bin', 'node');
  if (!fs.existsSync(nodeBin)) {
    problems.push('runtime/bin/node: missing');
  } else if (unsigned && sha256File(nodeBin) !== node.binarySha256) {
    problems.push('runtime/bin/node: SHA-256 differs from the binary procured from the pinned tarball');
  }

  const cfBin = path.join(root, 'runtime', 'bin', 'cloudflared');
  if (fs.existsSync(cfBin)) {
    const cf = components.cloudflared;
    if (!cf || typeof cf !== 'object') {
      problems.push('runtime/bin/cloudflared: shipped without a pinned cloudflared component in the manifest');
    } else {
      for (const [field, key, shape] of [
        ['version', 'CLOUDFLARED_VERSION', NONEMPTY],
        ['tarballSha256', 'CLOUDFLARED_TARBALL_SHA256', SHA256],
        ['binarySha256', 'CLOUDFLARED_BINARY_SHA256', SHA256],
      ]) {
        const expected = pin(key, shape);
        if (expected !== null && cf[field] !== expected) {
          problems.push(`cloudflared ${field} '${cf[field]}' does not match the pin ${key}=${expected}`);
        }
      }
    }
    if (unsigned && sha256File(cfBin) !== pins.CLOUDFLARED_BINARY_SHA256) {
      problems.push('runtime/bin/cloudflared: SHA-256 differs from the pinned binary');
    }
  }
  return problems;
}

function main(argv) {
  const [root, pinFile, channel] = argv;
  if (!root || !pinFile) {
    console.error('usage: release-preflight.js <resources-dir> <runtime-pin.env> <prior-channel>');
    return 2;
  }
  const problems = preflightProblems({ root, pins: parsePinEnv(fs.readFileSync(pinFile, 'utf8')), channel });
  if (problems.length === 0) {
    console.log(`payload matches its manifest and the runtime pins (prior channel ${channel}): ${root}`);
    return 0;
  }
  console.error(`release preflight FAILED for ${root}:`);
  for (const p of problems) console.error(`  - ${p}`);
  return 1;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = { KNOWN_PRIOR_CHANNELS, parsePinEnv, preflightProblems };
