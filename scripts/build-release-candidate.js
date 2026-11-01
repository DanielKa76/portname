#!/usr/bin/env node
'use strict';

/**
 * Build the local release candidate under .release-staging/.
 *
 * - Copies exactly the files matched by the positive list in
 *   scripts/release-candidate-list.js (fail-closed: any file at HEAD that
 *   matches neither an include nor an exclusion rule aborts the run).
 * - Stages the committed bytes of HEAD, never the working tree: the
 *   manifest's source.head describes exactly what was copied, and an
 *   uncommitted edit or an untracked file never reaches the candidate. An
 *   included path that is not a regular file at HEAD (a symlink, a
 *   submodule) aborts the run instead of being followed.
 * - Writes .release-staging/MANIFEST.json with the file list, SHA-256
 *   checksums, byte sizes, and the documented source HEAD.
 * - Publishes nothing: output stays inside .release-staging/ (gitignored).
 *
 * Usage: node scripts/build-release-candidate.js [--output DIR]
 *   --output DIR  replaced wholesale, so it must be new, empty or a previous
 *                 candidate (a directory named *candidate); the repository,
 *                 an ancestor of it, anything inside .git and any other
 *                 non-empty directory are refused. The manifest is written
 *                 next to it (DIR/../MANIFEST.json) and never replaces a
 *                 file that is not a candidate manifest.
 */

const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { classifyFiles } = require('./release-candidate-list.js');

function git(args, options = {}) {
  return execFileSync('git', args, {
    maxBuffer: 64 * 1024 * 1024,
    encoding: 'utf8',
    ...options,
  });
}

function parseArgs(argv) {
  const args = { output: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--output') {
      args.output = argv[++i];
    } else {
      throw new Error(`unknown argument: ${argv[i]}`);
    }
  }
  return args;
}

const MANIFEST_SCHEMA = 'portname-release-candidate-manifest/1';

function fail(message, details = []) {
  process.stderr.write(`FAIL: ${message}\n`);
  for (const line of details) process.stderr.write(`  ${line}\n`);
  process.exit(1);
}

function isSameOrInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

// Resolves symlinks of the deepest existing ancestor, so a link to the
// repository (or a path through one) is recognized as what it points to.
function physical(p) {
  let existing = p;
  const rest = [];
  while (!fs.existsSync(existing)) {
    rest.unshift(path.basename(existing));
    const parent = path.dirname(existing);
    if (parent === existing) break;
    existing = parent;
  }
  return path.join(fs.realpathSync(existing), ...rest);
}

// The output directory is removed recursively before staging and the
// manifest written next to it: refuse anything whose loss is not the loss
// of a previous candidate.
function outputProblem(stagingRoot, repoRoot) {
  const target = physical(stagingRoot);
  const repo = fs.realpathSync(repoRoot);
  if (isSameOrInside(repo, target)) return `--output ${stagingRoot} is the repository or one of its ancestors`;
  if (isSameOrInside(target, path.join(repo, '.git'))) return `--output ${stagingRoot} is inside .git`;
  let st = null;
  try {
    st = fs.lstatSync(stagingRoot);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  if (st) {
    if (st.isSymbolicLink()) return `--output ${stagingRoot} is a symlink`;
    if (!st.isDirectory()) return `--output ${stagingRoot} exists and is not a directory`;
    if (fs.readdirSync(stagingRoot).length > 0 && !/(?:^|-)candidate$/.test(path.basename(stagingRoot))) {
      return `--output ${stagingRoot} is a non-empty directory that is not a previous candidate (*candidate)`;
    }
  }
  const manifest = manifestPath(stagingRoot);
  if (fs.existsSync(manifest)) {
    let schema;
    try {
      schema = JSON.parse(fs.readFileSync(manifest, 'utf8')).schema;
    } catch {
      schema = undefined;
    }
    if (schema !== MANIFEST_SCHEMA) return `${manifest} exists and is not a release-candidate manifest`;
  }
  return null;
}

// Every file at HEAD: mode, object id and path (`git ls-tree -r -z`).
function headEntries(repoRoot) {
  return git(['ls-tree', '-r', '-z', '--full-tree', 'HEAD'], { cwd: repoRoot })
    .split('\0')
    .filter(Boolean)
    .map((record) => {
      const tab = record.indexOf('\t');
      const [mode, type, object] = record.slice(0, tab).split(' ');
      return { mode, type, object, path: record.slice(tab + 1) };
    });
}

// Blob contents for object ids, in one `git cat-file --batch` round trip.
function readBlobs(repoRoot, objects) {
  const out = execFileSync('git', ['cat-file', '--batch'], {
    cwd: repoRoot,
    input: objects.join('\n') + '\n',
    maxBuffer: 1024 * 1024 * 1024,
  });
  const blobs = new Map();
  let pos = 0;
  for (const object of objects) {
    const nl = out.indexOf(0x0a, pos);
    const [id, type, size] = out.subarray(pos, nl).toString('latin1').split(' ');
    if (id !== object || type !== 'blob') throw new Error(`git cat-file returned '${id} ${type}' for ${object}`);
    const start = nl + 1;
    blobs.set(object, out.subarray(start, start + Number(size)));
    pos = start + Number(size) + 1;
  }
  return blobs;
}

function main() {
  const repoRoot = path.resolve(__dirname, '..');
  const parsed = parseArgs(process.argv.slice(2));
  const stagingRoot = path.resolve(
    repoRoot,
    parsed.output || path.join('.release-staging', `portname-${version(repoRoot)}-candidate`)
  );
  const outputRefusal = outputProblem(stagingRoot, repoRoot);
  if (outputRefusal) fail(`${outputRefusal}; nothing was removed or staged.`);

  const entries = headEntries(repoRoot);
  const byPath = new Map(entries.map((e) => [e.path, e]));
  const tracked = entries.map((e) => e.path);
  const { included, excluded, unclassified } = classifyFiles(tracked);

  if (unclassified.length > 0) {
    process.stderr.write(
      'FAIL: tracked files match neither an include nor an exclusion rule.\n' +
        'Extend scripts/release-candidate-list.js deliberately before staging.\n'
    );
    for (const entry of unclassified) {
      process.stderr.write(`  UNCLASSIFIED ${entry.path}\n`);
    }
    process.exit(1);
  }
  const notRegular = included.filter((e) => !['100644', '100755'].includes(byPath.get(e.path).mode));
  if (notRegular.length > 0) {
    fail('included paths are not regular files at HEAD (symlink or submodule); the candidate never follows them.',
      notRegular.map((e) => `${byPath.get(e.path).mode} ${e.path}`));
  }

  const sourceHead = git(['rev-parse', 'HEAD'], { cwd: repoRoot }).trim();
  const headSubject = git(['log', '-1', '--format=%s'], { cwd: repoRoot }).trim();
  const blobs = readBlobs(repoRoot, included.map((e) => byPath.get(e.path).object));

  fs.rmSync(stagingRoot, { recursive: true, force: true });
  const manifestFiles = [];
  for (const entry of included) {
    const { mode, object } = byPath.get(entry.path);
    const dest = path.join(stagingRoot, entry.path);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    const data = blobs.get(object);
    fs.writeFileSync(dest, data);
    fs.chmodSync(dest, mode === '100755' ? 0o755 : 0o644);
    manifestFiles.push({
      path: entry.path,
      sha256: createHash('sha256').update(data).digest('hex'),
      bytes: data.length,
      executable: mode === '100755',
    });
  }
  manifestFiles.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  const manifest = {
    schema: MANIFEST_SCHEMA,
    generatedAt: new Date().toISOString(),
    source: {
      head: sourceHead,
      headSubject,
      trackedFilesTotal: tracked.length,
    },
    totals: {
      files: manifestFiles.length,
      bytes: manifestFiles.reduce((n, f) => n + f.bytes, 0),
      excluded: excluded.length,
    },
    positiveList: {
      script: 'scripts/release-candidate-list.js',
      excludedFiles: excluded.map((e) => ({ path: e.path, reason: e.reason })),
    },
    files: manifestFiles,
  };

  fs.mkdirSync(path.dirname(manifestPath(stagingRoot)), { recursive: true });
  fs.writeFileSync(
    manifestPath(stagingRoot),
    JSON.stringify(manifest, null, 2) + '\n'
  );

  process.stdout.write(
    `staged ${manifestFiles.length} files (${manifest.totals.bytes} bytes) ` +
      `from HEAD ${sourceHead.slice(0, 12)} -> ${path.relative(repoRoot, stagingRoot)}\n` +
      `excluded ${excluded.length} tracked files by rule; manifest: ` +
      `${path.relative(repoRoot, manifestPath(stagingRoot))}\n` +
      'nothing was pushed, published, or removed; history untouched\n'
  );
  const dirty = git(['status', '--porcelain', '--untracked-files=no'], { cwd: repoRoot }).trim();
  if (dirty) {
    process.stderr.write(
      `note: uncommitted changes are not part of the candidate (staged from HEAD ${sourceHead.slice(0, 12)})\n`
    );
  }
}

function manifestPath(stagingRoot) {
  return path.join(stagingRoot, '..', 'MANIFEST.json');
}

function version(repoRoot) {
  try {
    return JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')).version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

if (require.main === module) main();

module.exports = { main };
