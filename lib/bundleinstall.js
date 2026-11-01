'use strict';

// Self-contained install payload support for the macOS app bundle.
//
// The bundle ships the daemon plus a pinned node runtime inside
// Portname.app/Contents/Resources. A LaunchAgent must not point into the
// bundle (the user can move or delete the .app), nor into a Homebrew Cellar
// version path, nor into a temp/download dir. Therefore `portname install`,
// when it runs from inside a bundle, first copies the payload to a stable
// per-user location that survives app moves:
//
//   ~/Library/Application Support/Portname/
//     MANIFEST.json          generated inventory (versions + SHA-256 per file)
//     daemon/…               daemon payload (bin/portname.js, lib/*.js, package.json)
//     runtime/bin/node       bundled, checksum-pinned node runtime
//     runtime/bin/cloudflared  optional bundled tunnel binary
//     bin/portname           user-facing wrapper script
//
// The LaunchAgent then references only files under that stable directory.
// Sync is idempotent: an intact payload whose manifest matches the source is
// left untouched; a damaged or outdated one is replaced atomically (temp dir
// + rename, old copy removed only after the new one verified). An existing
// target is only ever replaced when it is verifiably ours (valid manifest,
// our bundle id) — foreign directories, symlinks and plain files are left
// untouched and the install is refused (same ownership rule as uninstall).
// Everything here is Node stdlib and unit-tested (test/bundleinstall.test.js).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PAYLOAD_BUNDLE_ID = 'dev.portname.app';
const APP_SUPPORT_RELATIVE = path.join('Library', 'Application Support', 'Portname');

// Stable per-user payload location (never a checkout, Cellar or temp path).
function stablePayloadDir(home = os.homedir()) {
  return path.join(home, APP_SUPPORT_RELATIVE);
}

// Detects whether entryDir lives inside an app bundle's Resources
// (.../Some.app/Contents/Resources/...). Pure path logic, no filesystem.
function appBundleLayout(entryDir) {
  const marker = `${path.sep}Contents${path.sep}Resources${path.sep}`;
  const s = String(entryDir);
  const i = s.indexOf(marker);
  if (i === -1) return { isBundle: false };
  const appPath = s.slice(0, i);
  if (!appPath.endsWith('.app')) return { isBundle: false };
  return { isBundle: true, appPath, resourcesDir: s.slice(0, i + marker.length - 1) };
}

// True when entryDir is inside the stable payload's daemon directory, i.e.
// the CLI was started from the installed payload (bundled wrapper or agent).
function isStablePayloadEntry(entryDir, home = os.homedir()) {
  const rel = path.relative(stablePayloadDir(home), String(entryDir));
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function hashFile(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function readManifest(dir) {
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(dir, 'MANIFEST.json'), 'utf8'));
    if (!parsed || parsed.schema !== 'portname.payload-manifest/1' || !Array.isArray(parsed.files)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

// Recomputes size + SHA-256 for every file listed in the manifest.
function verifyManifest(root, manifest = readManifest(root)) {
  if (!manifest) return { ok: false, errors: ['MANIFEST.json missing or unreadable'] };
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
    if (hashFile(file) !== entry.sha256) {
      errors.push(`${entry.path}: sha256 mismatch`);
    }
    // Mode is part of the manifest inventory: a demoted executable bit
    // (e.g. `chmod -x runtime/bin/node`) would otherwise go undetected and
    // the repair path would never restore it. Same check as
    // scripts/lib/payload-manifest.js — keep the two verifiers consistent.
    if (typeof entry.mode === 'number' && (stat.mode & 0o777) !== entry.mode) {
      errors.push(`${entry.path}: mode mismatch`);
    }
  }
  return { ok: errors.length === 0, errors };
}

// Copies exactly the files listed in the manifest (source layout = dest
// layout), creating parents and restoring recorded modes.
function copyManifestedFiles({ sourceRoot, manifest, destRoot }) {
  for (const entry of manifest.files) {
    const from = path.join(sourceRoot, entry.path);
    const to = path.join(destRoot, entry.path);
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.copyFileSync(from, to);
    fs.chmodSync(to, entry.mode || 0o644);
  }
  fs.copyFileSync(path.join(sourceRoot, 'MANIFEST.json'), path.join(destRoot, 'MANIFEST.json'));
}

// Idempotent sync from a bundle's Resources dir to the stable payload dir.
// Returns { changed, destDir, manifest, verify } — changed=false means an
// intact payload with the same content id was already present (repair is a
// plain re-run of `portname install`).
function syncPayload({ sourceRoot, home = os.homedir(), log = () => {} } = {}) {
  const manifest = readManifest(sourceRoot);
  if (!manifest) {
    throw new Error(`no valid MANIFEST.json under ${sourceRoot}; not a portname bundle payload`);
  }
  if (manifest.bundleId !== PAYLOAD_BUNDLE_ID) {
    throw new Error(`unexpected bundle id '${manifest.bundleId}'; refusing to install payload`);
  }
  const destDir = stablePayloadDir(home);
  // Before touching an existing target in ANY way (rename, replace, delete):
  // classify it. Only a directory carrying a valid portname payload manifest
  // with our own bundle id may ever be replaced — the same ownership rule
  // removePayloadIfOurs applies. Damage is a repair condition, not an
  // ownership proof, so it is checked AFTER identity, not instead of it.
  let destManifest = null;
  let st = null;
  try {
    st = fs.lstatSync(destDir);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  if (st) {
    if (st.isSymbolicLink()) {
      throw new Error(
        `refusing to install: ${destDir} is a symlink; portname never replaces a symlinked install target. Remove the symlink, then re-run install.`
      );
    }
    if (!st.isDirectory()) {
      throw new Error(
        `refusing to install: ${destDir} exists and is not a directory; portname never overwrites it. Move the file away, then re-run install.`
      );
    }
    destManifest = readManifest(destDir);
    if (!destManifest) {
      throw new Error(
        `refusing to install: ${destDir} already exists and is not a recognizable portname payload (no valid MANIFEST.json). portname never replaces or deletes a directory it cannot identify as its own; move it away, then re-run install.`
      );
    }
    if (destManifest.bundleId !== PAYLOAD_BUNDLE_ID) {
      throw new Error(
        `refusing to install: ${destDir} holds a payload of bundle id '${destManifest.bundleId}' (expected '${PAYLOAD_BUNDLE_ID}'); portname never replaces another bundle's directory.`
      );
    }
  }
  if (destManifest && destManifest.payloadId === manifest.payloadId) {
    const check = verifyManifest(destDir, destManifest);
    if (check.ok) {
      return { changed: false, destDir, manifest, verify: check };
    }
    // Verifiably own payload (valid manifest, our bundle id) with damaged
    // files: the documented repair path replaces it atomically.
    log(`existing payload is damaged (${check.errors.join('; ')}); repairing`);
  }
  const parent = path.dirname(destDir);
  fs.mkdirSync(parent, { recursive: true });
  const tmp = path.join(parent, `.Portname.sync-${process.pid}-${Date.now()}`);
  fs.mkdirSync(tmp, { recursive: true, mode: 0o700 });
  try {
    copyManifestedFiles({ sourceRoot, manifest, destRoot: tmp });
    const check = verifyManifest(tmp, manifest);
    if (!check.ok) {
      throw new Error(`copied payload failed verification: ${check.errors.join('; ')}`);
    }
    const backup = path.join(parent, `.Portname.old-${process.pid}-${Date.now()}`);
    let hadOld = false;
    try {
      fs.rmSync(backup, { recursive: true, force: true });
      fs.renameSync(destDir, backup);
      hadOld = true;
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    try {
      fs.renameSync(tmp, destDir);
    } catch (err) {
      if (hadOld) fs.renameSync(backup, destDir);
      throw err;
    }
    if (hadOld) fs.rmSync(backup, { recursive: true, force: true });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  return { changed: true, destDir, manifest, verify: { ok: true, errors: [] } };
}

// LaunchAgent references for an installed payload: every path is inside the
// stable payload dir — never the .app, a checkout, Cellar or a temp dir.
function payloadInstallArgs(destDir = stablePayloadDir()) {
  return {
    nodePath: path.join(destDir, 'runtime', 'bin', 'node'),
    entryPath: path.join(destDir, 'daemon', 'bin', 'portname.js'),
    extraPath: path.join(destDir, 'runtime', 'bin'),
  };
}

// Removes the stable payload only when it is verifiably ours (manifest bundle
// id). The user's state directory (~/.portname) is never touched here.
function removePayloadIfOurs(dir = stablePayloadDir()) {
  const manifest = readManifest(dir);
  if (!manifest || manifest.bundleId !== PAYLOAD_BUNDLE_ID) return false;
  fs.rmSync(dir, { recursive: true, force: true });
  return true;
}

module.exports = {
  PAYLOAD_BUNDLE_ID,
  stablePayloadDir,
  appBundleLayout,
  isStablePayloadEntry,
  readManifest,
  verifyManifest,
  syncPayload,
  payloadInstallArgs,
  removePayloadIfOurs,
  hashFile,
};
