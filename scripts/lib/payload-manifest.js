'use strict';

// Generates and verifies the payload MANIFEST.json shipped inside the macOS
// app bundle (Contents/Resources/MANIFEST.json) and, after install, in the
// stable payload directory. The manifest is the component inventory required
// for the distributable artifact: every shipped file with size, mode and
// SHA-256, plus the component versions (app, node runtime, cloudflared).
//
// Shared by:
//   - scripts/bundle-macos.sh  (generation at build time, via `generate`)
//   - lib/bundleinstall.js     (verification, via the same schema)
//   - scripts/release-check.sh (post-build + post-install verification)
//   - scripts/release-package.sh (pre-sign gate, post-sign regeneration)
// Node stdlib only.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MANIFEST_SCHEMA = 'portname.payload-manifest/1';
const MANIFEST_NAME = 'MANIFEST.json';

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = canonicalize(value[k]);
    return out;
  }
  return value;
}

function payloadIdOf(files) {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(files))).digest('hex');
}

function walkFiles(root, rel = '', out = []) {
  const abs = rel ? path.join(root, rel) : root;
  for (const name of fs.readdirSync(abs).sort()) {
    const relChild = rel ? path.join(rel, name) : name;
    const absChild = path.join(root, relChild);
    const stat = fs.statSync(absChild);
    if (stat.isDirectory()) {
      walkFiles(root, relChild, out);
    } else {
      out.push({ path: relChild, size: stat.size, mode: stat.mode & 0o777 });
    }
  }
  return out;
}

function fileEntry(root, f) {
  return {
    path: f.path,
    size: f.size,
    mode: f.mode,
    sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(root, f.path))).digest('hex'),
  };
}

// Generates the manifest object for a payload root. `files` covers every
// regular file under root except the manifest itself (which is copied
// alongside, never self-listed — that would be circular).
function generateManifest({ root, components, bundleId }) {
  const files = walkFiles(root)
    .filter((f) => f.path !== MANIFEST_NAME)
    .map((f) => fileEntry(root, f))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return {
    schema: MANIFEST_SCHEMA,
    bundleId,
    payloadId: payloadIdOf(files),
    generatedAt: new Date().toISOString(),
    components,
    files,
  };
}

function verifyManifest(root, manifest = readManifestFile(root)) {
  if (!manifest) return { ok: false, errors: [`${MANIFEST_NAME} missing or unreadable`] };
  if (manifest.schema !== MANIFEST_SCHEMA) {
    return { ok: false, errors: [`unsupported manifest schema '${manifest.schema}'`] };
  }
  const errors = [];
  for (const entry of manifest.files) {
    const file = path.join(root, entry.path);
    let stat;
    try {
      stat = fs.statSync(file);
    } catch {
      errors.push(`${entry.path}: missing`);
      continue;
    }
    if (stat.size !== entry.size) {
      errors.push(`${entry.path}: size mismatch`);
      continue;
    }
    const actual = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if (actual !== entry.sha256) errors.push(`${entry.path}: sha256 mismatch`);
    // Mode is recorded in the manifest and must be verified too: a demoted
    // executable bit (e.g. `chmod -x runtime/bin/node`) would otherwise pass
    // silently and the install repair path would never restore it. Same
    // check as lib/bundleinstall.js — keep the two verifiers consistent.
    if (typeof entry.mode === 'number' && (stat.mode & 0o777) !== entry.mode) {
      errors.push(`${entry.path}: mode mismatch`);
    }
  }
  // Only listed files are checked: the manifest is the inventory of what is
  // shipped, and the payloadId equality check in lib/bundleinstall.js keys on
  // exactly this list.
  return { ok: errors.length === 0, errors };
}

// Files under root that the manifest does not list (the manifest itself
// aside). verifyManifest checks listed files only; a release gate must also
// notice what was added.
function unlistedFiles(root, manifest) {
  const listed = new Set(manifest.files.map((f) => f.path));
  return walkFiles(root)
    .map((f) => f.path)
    .filter((p) => p !== MANIFEST_NAME && !listed.has(p));
}

// Release path: Developer ID signing rewrites the runtime binaries in place,
// so their entries must be recomputed after signing. Only the `refresh`
// paths are recomputed; every other entry must still match the disk (size,
// SHA-256, mode) and no file may have been added or removed — a full
// re-inventory would silently bless any drift since the bundle was built.
// Bundle id and component metadata are kept verbatim. Throws with every
// problem listed; nothing is written here.
function regenerateManifest({ root, refresh, manifest = readManifestFile(root) }) {
  if (!manifest || manifest.schema !== MANIFEST_SCHEMA || !Array.isArray(manifest.files)) {
    throw new Error(`${MANIFEST_NAME} missing, unreadable or of an unsupported schema`);
  }
  if (!manifest.bundleId) throw new Error(`${MANIFEST_NAME} has no bundleId`);
  const refreshSet = new Set(refresh);
  const onDisk = new Map(walkFiles(root).map((f) => [f.path, f]));
  const problems = unlistedFiles(root, manifest).map((p) => `${p}: not in the manifest`);
  const files = manifest.files.map((entry) => {
    const stat = onDisk.get(entry.path);
    if (!stat) {
      problems.push(`${entry.path}: missing`);
      return entry;
    }
    const current = fileEntry(root, stat);
    if (refreshSet.has(entry.path)) return current;
    if (current.size !== entry.size || current.sha256 !== entry.sha256 || current.mode !== entry.mode) {
      problems.push(`${entry.path}: changed since the manifest was generated`);
    }
    return entry;
  });
  if (problems.length > 0) {
    throw new Error(`refusing to regenerate the manifest:\n  - ${problems.join('\n  - ')}`);
  }
  return { ...manifest, payloadId: payloadIdOf(files), generatedAt: new Date().toISOString(), files };
}

function readManifestFile(root) {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, MANIFEST_NAME), 'utf8'));
  } catch {
    return null;
  }
}

// CLI: generate <root> --bundle-id <id> --components-json <json> [--out FILE]
//      verify   <root> [--manifest FILE]   exit 0 ok / 1 damaged
//      regen    <root> --refresh PATH [--refresh PATH ...]
//                                          exit 0 rewritten / 1 refused
function main(argv) {
  const [cmd, root, ...rest] = argv;
  const arg = (name) => {
    const i = rest.indexOf(name);
    return i === -1 ? undefined : rest[i + 1];
  };
  if (cmd === 'generate') {
    const manifest = generateManifest({
      root,
      bundleId: arg('--bundle-id'),
      components: JSON.parse(arg('--components-json') || '{}'),
    });
    const out = arg('--out') || path.join(root, MANIFEST_NAME);
    fs.writeFileSync(out, JSON.stringify(manifest, null, 2) + '\n');
    console.log(`manifest written: ${out} (${manifest.files.length} files, payloadId ${manifest.payloadId.slice(0, 12)}…)`);
    return 0;
  }
  if (cmd === 'regen') {
    const refresh = rest.filter((_, i) => rest[i - 1] === '--refresh');
    let manifest;
    try {
      manifest = regenerateManifest({ root, refresh });
    } catch (err) {
      console.error(`regen: ${err.message}`);
      return 1;
    }
    const out = path.join(root, MANIFEST_NAME);
    fs.writeFileSync(out, JSON.stringify(manifest, null, 2) + '\n');
    console.log(`manifest regenerated: ${out} (refreshed ${refresh.join(', ')}; payloadId ${manifest.payloadId.slice(0, 12)}…)`);
    return 0;
  }
  if (cmd === 'verify') {
    const manifest = arg('--manifest') ? JSON.parse(fs.readFileSync(arg('--manifest'), 'utf8')) : undefined;
    const result = verifyManifest(root, manifest);
    if (result.ok) {
      console.log(`payload verified: ${root}`);
      return 0;
    }
    console.error(`payload verification FAILED for ${root}:`);
    for (const e of result.errors) console.error(`  - ${e}`);
    return 1;
  }
  console.error('usage: payload-manifest.js generate <root> --bundle-id <id> --components-json <json> [--out FILE]');
  console.error('       payload-manifest.js verify <root> [--manifest FILE]');
  console.error('       payload-manifest.js regen <root> --refresh PATH [--refresh PATH ...]');
  return 2;
}

if (require.main === module) {
  process.exit(main(process.argv.slice(2)));
}

module.exports = {
  MANIFEST_SCHEMA,
  MANIFEST_NAME,
  generateManifest,
  verifyManifest,
  regenerateManifest,
  unlistedFiles,
  readManifestFile,
  payloadIdOf,
};
