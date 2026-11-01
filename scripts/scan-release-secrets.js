#!/usr/bin/env node
'use strict';

/**
 * Release-readiness scanner (Node stdlib only, own pattern set, manual
 * review of every hit is still required).
 *
 * Scanned areas:
 *   1. worktree  — every git-tracked file, line by line
 *   2. staging   — the generated .release-staging candidate copy, if present
 *                  (verifies the staged bytes, not just the source)
 *   3. history   — every commit reachable from any local ref
 *                  (refs/heads, refs/remotes, refs/tags), merges included:
 *                  added lines of `git log --all -p --diff-merges=remerge`,
 *                  octopus merges against their first parent
 *   4. metadata  — author/committer names and emails, commit message
 *                  trailers (Co-Authored-by, Signed-off-by), refs and tags
 *   5. commit-message — full message (subject + body) of every reachable
 *                  commit, with the same content rules
 *   6. filenames — credential-shaped file names anywhere tracked
 *
 * Not covered: GitHub texts (PR bodies, review comments, issues) — check
 * those separately before an existing repository is made public.
 *
 * Output is REDACTED by design: matches are shown as category + location +
 * short redacted prefix; the scanner never prints full secret material.
 * Findings are advisory for manual review; exit code is 2 when
 * severity=critical findings exist, 0 otherwise (review findings do not
 * fail the run by themselves).
 *
 * Usage: node scripts/scan-release-secrets.js [--repo PATH] [--json PATH]
 *   --repo PATH  root of the git work tree to scan (default: this script's
 *                repository); anything else — a subdirectory, a plain
 *                directory inside another repository — is refused rather
 *                than silently scanning the enclosing repository. Inherited
 *                GIT_* variables (GIT_DIR from a hook, …) never redirect it.
 */

const { execFileSync, spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// ---------------------------------------------------------------------------
// Pattern set. Deliberately broader than token prefixes: key/value shapes,
// key material, credential files, personal paths, private-source links,
// internal process references.
// ---------------------------------------------------------------------------

// Key names of key/value secrets: the secret word may carry word-ish
// prefixes and `_`, camelCase or digit suffixes (DB_PASSWORD, SECRET_KEY,
// GITHUB_API_KEY, MY_AUTH_TOKEN, dbPassword, apiSecret, secretKey), so `_`
// and camelCase joints are not word boundaries here. The match is case
// sensitive: each word is lower, Capitalized or UPPER case, and a suffix
// starts with `_`, an upper-case letter or a digit. A lower-case
// continuation makes another word (plurals, passwordless, secretary), so a
// prose line such as a "Secrets" heading or a test named after this script
// is no key. A `-` suffix is left out: such names are header names
// (`x-secret-hop`), not keys holding the secret.
const caseForms = (word) => `(?:[${word[0]}${word[0].toUpperCase()}]${word.slice(1)}|${word.toUpperCase()})`;
const CREDENTIAL_WORD = [
  `${caseForms('pass')}(?:${caseForms('word')}|${caseForms('wd')})`,
  caseForms('secret'),
  `${caseForms('api')}[_-]?${caseForms('key')}`,
  `${caseForms('access')}[_-]?${caseForms('token')}`,
  `${caseForms('auth')}[_-]?${caseForms('token')}`,
].join('|');
const CREDENTIAL_KEY = String.raw`(?<![A-Za-z0-9_-])[A-Za-z0-9_-]*?(?:${CREDENTIAL_WORD})(?:_[A-Za-z0-9_]*|[A-Z0-9][A-Za-z0-9_]*)?`;

const CONTENT_RULES = [
  { id: 'private-key-block', severity: 'critical', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g },
  { id: 'aws-access-key', severity: 'critical', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: 'aws-secret-assignment', severity: 'critical', re: /\baws_secret_access_key\b\s*[=:]\s*\S{8,}/gi },
  { id: 'github-token', severity: 'critical', re: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g },
  { id: 'github-pat', severity: 'critical', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { id: 'slack-token', severity: 'critical', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { id: 'stripe-key', severity: 'critical', re: /\b[sp]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { id: 'google-api-key', severity: 'critical', re: /\bAIza[0-9A-Za-z_-]{30,}\b/g },
  { id: 'openai-key', severity: 'critical', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: 'anthropic-key', severity: 'critical', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'npm-token', severity: 'critical', re: /\bnpm_[A-Za-z0-9]{30,}\b/g },
  { id: 'jwt', severity: 'critical', re: /\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: 'bearer-token', severity: 'critical', re: /\b(?:Bearer|token)\s+[A-Za-z0-9_.\-+=]{24,}/g },
  { id: 'key-value-secret', severity: 'critical', re: new RegExp(String.raw`${CREDENTIAL_KEY}['"]?\s*[:=]>?\s*['"][^'"\s]{8,}['"]`, 'g') },
  // Same shape with an unquoted value (env/shell/ini/YAML style: the value
  // follows `=` or `:` directly). Placeholders such as `${VAR}` or short
  // values do not match; advisory output is reviewed manually anyway.
  { id: 'key-value-secret', severity: 'critical', re: new RegExp(String.raw`${CREDENTIAL_KEY}\s*[:=]>?\s*(?!['"])[A-Za-z0-9_+/=.:~@-]{8,}`, 'g') },
  { id: 'cf-tunnel-credential', severity: 'critical', re: /"(?:AccountTag|TunnelSecret|TunnelID)"\s*:/g },
  { id: 'pkcs8-header', severity: 'critical', re: /\bMIIEv[A-Za-z0-9+/]{40,}\b/g },

  // Review-level: provenance/privacy signals, not secrets per se.
  { id: 'email-address', severity: 'review', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { id: 'personal-home-path', severity: 'review', re: /\/Users\/[A-Za-z0-9._-]+(?:\/[^\s'"`)\]]*)?/g },
  { id: 'private-chat-link', severity: 'review', re: /\b(?:chatgpt\.com|chat\.openai\.com|claude\.ai|gemini\.google\.com|notion\.so|notion\.site)\/\S*/gi },
  // Internal process references: change-request and prompt numbers (with a
  // hyphen, a space or neither), review-round tags, audit finding ids, bare
  // review finding tags (an F plus a number) in a comment or a test name,
  // and working-copy paths. A flag such as lsof's `-F0` is not a tag. The
  // candidate guard in test/release-candidate-list.test.js uses the same
  // pattern, so it is written (`[.]`, escapes) not to match its own source.
  { id: 'internal-reference', severity: 'review', re: /Prompt[- ]?\d|PR #\d+|\bthis PR\b|\bdiese[sn]? PRs?\b|[.]video_agent|[.]v2c\b|\b[Rr]eview (?:BLOCKER|MAJOR|MINOR|NIT|NOTE|F\d)|\b(?:sec-[a-z-]+|robustness|performance|currency|publication|critic)#\d|\bscratchpad\/|(?:\/\/|#|\*|<!--|\btest\()[^\n]*?(?<![-\w/.])F\d{1,2}\b/g },
];

const FILENAME_RULES = [
  { id: 'env-file', severity: 'critical', re: /(?:^|\/)\.env(?:\..*)?$/ },
  { id: 'key-file', severity: 'critical', re: /\.(?:pem|p12|pfx|key)$|(^|\/)id_(?:rsa|ed25519|ecdsa)(?:\.|$)/ },
  { id: 'credential-file', severity: 'review', re: /(?:^|\/)(?:credentials?|secrets?|\.netrc)(?:[._-][^/]*|$)/i },
];

// ---------------------------------------------------------------------------

function redact(text) {
  const t = String(text).trim();
  const head = t.slice(0, 8).replace(/[^\w./:@-]/g, '?');
  return `${head}…[REDACTED len=${t.length}]`;
}

function redactEmail(match) {
  const at = match.indexOf('@');
  const local = match.slice(0, at);
  const domain = match.slice(at + 1);
  return `${local.slice(0, 2)}***@${domain}[REDACTED]`;
}

function redactFor(ruleId, match) {
  if (ruleId === 'email-address') return redactEmail(match);
  if (ruleId === 'personal-home-path') return match.replace(/^\/Users\/[^/]+/, '/Users/[REDACTED]').slice(0, 60) + '…[REDACTED]';
  if (ruleId === 'private-chat-link') return match.split('/').slice(0, 2).join('/') + '/…[REDACTED]';
  return redact(match);
}

// Every git child finds its repository from cwd alone. Git exports GIT_DIR
// (pre-commit also GIT_INDEX_FILE) to hooks and `git rebase -x` in a linked
// worktree; inherited, it made `rev-parse --show-toplevel` accept any --repo
// path while ls-files, log and for-each-ref read the inherited repository —
// a different tree reported as clean. The user's global and the system git
// config are not read at all (git >= 2.32 honors GIT_CONFIG_GLOBAL); the
// repository's own config is still read, hence the pins below.
function gitEnv() {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_')));
  return Object.assign(env, { GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' });
}

// No git config must change what the scanner parses: color.ui/color.diff=
// always put an escape sequence before every added line's `+`,
// log.showRoot=false drops the root commit's patch, i18n.logOutputEncoding
// re-encodes commit messages (UTF-16 hid every subject and body), an
// external diff or textconv driver replaces the patch — each reported a
// clean history without an error. Pinned on every git child; the history
// log also passes --text, because a `-diff`/`binary` attribute or
// core.bigFileThreshold turn a patch into "Binary files differ".
const GIT_PINNED_CONFIG = [
  '-c', 'color.ui=never',
  '-c', 'log.showRoot=true',
  '-c', 'log.showSignature=false',
  '-c', 'core.quotePath=true',
  '-c', 'i18n.logOutputEncoding=UTF-8',
];

function git(repo, args) {
  return execFileSync('git', [...GIT_PINNED_CONFIG, ...args], {
    cwd: repo, env: gitEnv(), maxBuffer: 256 * 1024 * 1024, encoding: 'utf8',
  });
}

// `git log -p` prints no patch for a merge commit, so a line that exists
// only in a merge result (a conflict resolution, an "evil merge") was never
// scanned. remerge (git >= 2.36) shows exactly what the merge changed
// against an automatic re-merge; older git diffs the merge against its
// first parent, which repeats the merged branch's lines but misses nothing.
function mergeDiffArg(versionText) {
  const m = /(\d+)\.(\d+)/.exec(String(versionText));
  const major = m ? Number(m[1]) : 0;
  const minor = m ? Number(m[2]) : 0;
  return major > 2 || (major === 2 && minor >= 36) ? '--diff-merges=remerge' : '--diff-merges=first-parent';
}

// The history scan's `git log` passes. remerge skips merges with more than
// two parents (a warning line, no patch), so with remerge a second pass
// diffs exactly those octopus merges against their first parent.
function historyLogArgs(versionText) {
  const common = [
    'log', '--all', '-p', '--text', '--no-color', '--no-ext-diff', '--no-textconv', '--format=%x1e%H%x1f%s',
  ];
  const mergeDiff = mergeDiffArg(versionText);
  const passes = [[...common, mergeDiff]];
  if (mergeDiff === '--diff-merges=remerge') passes.push([...common, '--min-parents=3', '--diff-merges=first-parent']);
  return passes;
}

function scanText(area, label, text, findings) {
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const rule of CONTENT_RULES) {
      rule.re.lastIndex = 0;
      let m = rule.re.exec(line);
      while (m !== null) {
        findings.push({
          area,
          location: `${label}:${i + 1}`,
          rule: rule.id,
          severity: rule.severity,
          redacted: redactFor(rule.id, m[0]),
        });
        m = rule.re.exec(line);
      }
    }
  }
}

function scanWorktree(repo, area, files, findings) {
  for (const rel of files) {
    const abs = path.join(repo, rel);
    let stat;
    try {
      stat = fs.statSync(abs);
    } catch {
      continue; // deleted in worktree; history scan still covers it
    }
    if (!stat.isFile()) continue;
    const text = fs.readFileSync(abs, 'utf8');
    scanText(area, rel, text, findings);
  }
}

async function scanHistory(repo, findings) {
  // Stream added lines of every commit reachable from any local ref,
  // merge commits included.
  for (const args of historyLogArgs(git(repo, ['--version']))) {
    await scanLogPatches(repo, args, findings);
  }
}

function scanLogPatches(repo, args, findings) {
  const child = spawn('git', [...GIT_PINNED_CONFIG, ...args], {
    cwd: repo,
    env: gitEnv(),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return new Promise((resolve, reject) => {
    // Drained so a chatty git cannot block on a full pipe; the tail
    // explains a failure.
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      stderr = (stderr + chunk).slice(-2000);
    });
    let buf = '';
    let commit = '(unknown)';
    const handleLine = (rawLine) => {
      const line = rawLine.replace(/\r$/, '');
      const hdr = line.match(/^\x1e([0-9a-f]{40})\x1f(.*)$/);
      if (hdr) {
        commit = hdr[1].slice(0, 12);
        return;
      }
      if (!line.startsWith('+') || line.startsWith('+++')) return;
      const content = line.slice(1);
      for (const rule of CONTENT_RULES) {
        rule.re.lastIndex = 0;
        let m = rule.re.exec(content);
        while (m !== null) {
          findings.push({
            area: 'history',
            location: `${commit} (added line)`,
            rule: rule.id,
            severity: rule.severity,
            redacted: redactFor(rule.id, m[0]),
          });
          m = rule.re.exec(content);
        }
      }
    };
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      buf += chunk;
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        handleLine(buf.slice(0, idx));
        buf = buf.slice(idx + 1);
      }
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (buf) handleLine(buf);
      const detail = stderr.trim().split('\n').pop();
      if (code !== 0) reject(new Error(`git log exited with ${code}${detail ? `: ${detail}` : ''}`));
      else resolve();
    });
  });
}

function scanMetadata(repo, findings) {
  const identities = [...new Set(git(repo, ['log', '--all', '--format=%an <%ae>%n%cn <%ce>']).split('\n'))]
    .filter(Boolean)
    .sort();
  for (const identity of identities) {
    findings.push({
      area: 'metadata',
      location: 'commit identities (--all)',
      rule: 'git-author-identity',
      severity: 'review',
      redacted: redactEmail(identity),
    });
  }
  const trailers = [...new Set(
    git(repo, ['log', '--all', '--format=%b'])
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => /^(co-authored-by|signed-off-by):/i.test(l))
  )].sort();
  for (const t of trailers) {
    findings.push({
      area: 'metadata',
      location: 'commit message trailers',
      rule: 'commit-trailer',
      severity: 'review',
      redacted: redact(t),
    });
  }
}

function scanCommitMessages(repo, findings) {
  // The history scan only sees diff lines and the metadata scan only
  // trailers; subjects and bodies need their own pass.
  const out = git(repo, ['log', '--all', '--format=%x1e%H%n%B']);
  for (const record of out.split('\x1e')) {
    if (!record.trim()) continue;
    const nl = record.indexOf('\n');
    const sha = nl === -1 ? record : record.slice(0, nl);
    scanText('commit-message', sha.slice(0, 12), nl === -1 ? '' : record.slice(nl + 1), findings);
  }
}

// --repo must name the root of a git work tree. Resolving it any other way
// (the old code appended '..') or letting git walk up to an enclosing
// repository would scan a different tree and report it as clean.
function resolveRepo(repoArg) {
  const repo = repoArg ? path.resolve(repoArg) : path.resolve(__dirname, '..');
  let top;
  try {
    top = git(repo, ['rev-parse', '--show-toplevel']).trim();
  } catch {
    throw new Error(`${repo} is not inside a git work tree`);
  }
  if (fs.realpathSync(top) !== fs.realpathSync(repo)) {
    throw new Error(`${repo} is not the root of its git work tree (${top}); pass the repository root with --repo`);
  }
  return repo;
}

function inventoryRefs(repo, findings) {
  const refs = git(repo, ['for-each-ref', '--format=%(refname)']).trim().split('\n').filter(Boolean);
  const tags = refs.filter((r) => r.startsWith('refs/tags/'));
  const summary = {
    totalRefs: refs.length,
    branches: refs.filter((r) => r.startsWith('refs/heads/')).length,
    remoteTracking: refs.filter((r) => r.startsWith('refs/remotes/')).length,
    tags: tags.length,
    refList: refs,
  };
  for (const tag of tags) {
    findings.push({
      area: 'metadata',
      location: tag,
      rule: 'tag-present',
      severity: 'review',
      redacted: '(git tag; inspect manually)',
    });
  }
  return summary;
}

function dedupe(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    const key = `${f.area}|${f.location}|${f.rule}|${f.redacted}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function main() {
  const argv = process.argv.slice(2);
  const repo = resolveRepo(extractArg(argv, '--repo'));
  const jsonOut = extractArg(argv, '--json');
  process.stdout.write(`scanning: ${repo}\n`);

  const tracked = git(repo, ['ls-files', '-z']).split('\0').filter(Boolean);

  const findings = [];
  scanWorktree(repo, 'worktree', tracked, findings);

  const stagingRoot = path.join(repo, '.release-staging');
  const stagedFiles = [];
  if (fs.existsSync(stagingRoot)) {
    // Scan the candidate copies only — not scanner output (e.g. a previous
    // scan-results.json) sitting next to them, which would self-report its
    // own redacted findings.
    for (const entry of fs.readdirSync(stagingRoot, { withFileTypes: true })) {
      if (entry.isDirectory() && /^portname-.*-candidate$/.test(entry.name)) {
        stagedFiles.push(
          ...walk(path.join(stagingRoot, entry.name)).map((rel) => path.join(entry.name, rel))
        );
      }
    }
  }
  scanWorktree(stagingRoot, 'staging', stagedFiles, findings);

  await scanHistory(repo, findings);
  scanMetadata(repo, findings);
  scanCommitMessages(repo, findings);
  const refSummary = inventoryRefs(repo, findings);

  // Filename-based checks on tracked paths (and any refs' tips are covered
  // by the history scan; filenames are checked on current tree + refs list).
  for (const rel of tracked) {
    for (const rule of FILENAME_RULES) {
      if (rule.re.test(rel)) {
        findings.push({
          area: 'filenames',
          location: rel,
          rule: rule.id,
          severity: rule.severity,
          redacted: '(credential-shaped filename)',
        });
      }
    }
  }

  const all = dedupe(findings).sort(byFinding);
  const counts = {
    total: all.length,
    critical: all.filter((f) => f.severity === 'critical').length,
    review: all.filter((f) => f.severity === 'review').length,
  };

  process.stdout.write(`scan complete: ${counts.total} findings (critical: ${counts.critical}, review: ${counts.review})\n`);
  process.stdout.write(`refs: ${refSummary.totalRefs} total (${refSummary.branches} local branches, ${refSummary.remoteTracking} remote-tracking, ${refSummary.tags} tags)\n`);
  const byArea = {};
  for (const f of all) byArea[f.area] = (byArea[f.area] || 0) + 1;
  for (const [area, n] of Object.entries(byArea).sort()) {
    process.stdout.write(`  ${area}: ${n} findings\n`);
  }
  if (jsonOut) {
    fs.mkdirSync(path.dirname(path.resolve(jsonOut)), { recursive: true });
    fs.writeFileSync(jsonOut, JSON.stringify({ counts, refs: refSummary, findings: all }, null, 2) + '\n');
    process.stdout.write(`details written: ${jsonOut} (redacted)\n`);
  }
  if (counts.critical > 0) process.exit(2);
}

function extractArg(argv, flag) {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : null;
}

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(abs).map((rel) => path.join(entry.name, rel)));
    else out.push(entry.name);
  }
  return out.sort();
}

function byFinding(a, b) {
  const order = ['critical', 'review'];
  const s = order.indexOf(a.severity) - order.indexOf(b.severity);
  if (s !== 0) return s;
  return (a.area + a.location + a.rule).localeCompare(b.area + b.location + b.rule);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`scan failed: ${err.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { scanText, redactFor, dedupe, walk, CONTENT_RULES, FILENAME_RULES, scanWorktree, inventoryRefs, resolveRepo, mergeDiffArg, historyLogArgs };
