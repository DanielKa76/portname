'use strict';

// Release gate: is the bundled Node runtime pinned in scripts/runtime-pin.env
// still the newest security release of its major line? The bundle has no
// auto-update, so a shipped runtime stays frozen until the next app release;
// scripts/release-check.sh runs this against nodejs.org's release index.
//
// CLI: node-pin-freshness.js <pinned-version> [--index FILE]
//   exit 0  no newer security release in the pinned line
//   exit 1  a newer security release exists — re-pin before releasing
//   exit 3  the index could not be read (offline): NOT checked
// Node stdlib only.

const fs = require('fs');

const INDEX_URL = 'https://nodejs.org/dist/index.json';

function parseVersion(v) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(v).trim());
  return m ? m.slice(1).map(Number) : null;
}

function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

// Releases of the pinned major line that are newer than the pin. `security`
// lists those the index flags as security releases; `latest` is the newest
// release of the line (the pin itself when nothing is newer).
function assessPin(index, pinned) {
  const pin = parseVersion(pinned);
  if (!pin) throw new Error(`unparseable pinned version '${pinned}'`);
  if (!Array.isArray(index)) throw new Error('release index is not a list');
  const newer = index
    .map((e) => ({ version: e && e.version, parsed: parseVersion(e && e.version), security: Boolean(e && e.security === true) }))
    .filter((e) => e.parsed && e.parsed[0] === pin[0] && compareVersions(e.parsed, pin) > 0)
    .sort((a, b) => compareVersions(b.parsed, a.parsed));
  return {
    latest: newer.length ? newer[0].version : `v${pin.join('.')}`,
    security: newer.filter((e) => e.security).map((e) => e.version),
  };
}

async function readIndex(file) {
  if (file) return JSON.parse(fs.readFileSync(file, 'utf8'));
  const res = await fetch(INDEX_URL, { signal: AbortSignal.timeout(15000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function main(argv) {
  const pinned = argv[0];
  const i = argv.indexOf('--index');
  let result;
  try {
    result = assessPin(await readIndex(i === -1 ? null : argv[i + 1]), pinned);
  } catch (err) {
    console.error(`could not check the Node release index (${err.message}); pin freshness NOT verified`);
    return 3;
  }
  if (result.security.length > 0) {
    console.error(`pinned Node v${pinned} is behind security release(s) ${result.security.join(', ')} of its line; ` +
      `re-pin scripts/runtime-pin.env (latest: ${result.latest})`);
    return 1;
  }
  console.log(`pinned Node v${pinned}: no newer security release in its line (latest: ${result.latest})`);
  return 0;
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}

module.exports = { assessPin, parseVersion };
