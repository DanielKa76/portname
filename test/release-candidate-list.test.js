'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

// This file also ships in the public release candidate, which is a plain
// file tree or a fresh repository without the private notes — tests must
// not depend on files that only exist in the private repository.
function isOwnGitWorkTree() {
  try {
    const top = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return fs.realpathSync(top) === fs.realpathSync(ROOT);
  } catch {
    return false;
  }
}

function trackedFiles() {
  return execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8' })
    .split('\0')
    .filter(Boolean);
}

// Environment for every git or node child that works in a scratch
// repository. Git exports GIT_DIR (pre-commit also GIT_INDEX_FILE) to what it
// runs from a linked worktree — hooks, `git rebase -x 'npm test'` — so an
// inherited GIT_* variable would point the scratch `git add`/`commit` at the
// developer's real branch. XDG_CONFIG_HOME would still load the owner's git
// config (hooks path, signing) despite the temporary HOME.
function isolatedGitEnv(home) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_')));
  Object.assign(env, { HOME: home, GIT_CONFIG_NOSYSTEM: '1' });
  delete env.XDG_CONFIG_HOME;
  delete env.NODE_TEST_CONTEXT; // a nested `node --test` must report on its own
  return env;
}

const {
  INCLUDE_RULES,
  EXCLUDE_RULES,
  classifyFiles,
  globMatch,
} = require('../scripts/release-candidate-list.js');
const {
  looksBinary,
  scanText,
  scanWorktree,
  dedupe,
  redactFor,
  CONTENT_RULES,
} = require('../scripts/scan-release-secrets.js');

test('globMatch: * stays within one segment, ** crosses segments', () => {
  assert.equal(globMatch('lib/*.js', 'lib/proxy.js'), true);
  assert.equal(globMatch('lib/*.js', 'lib/sub/proxy.js'), false);
  assert.equal(globMatch('macos/Sources/**', 'macos/Sources/PortnameApp/X.swift'), true);
  assert.equal(globMatch('macos/Sources/**', 'macos/Package.swift'), false);
  assert.equal(globMatch('.git/**', '.git/config'), true);
  assert.equal(globMatch('docs/release/*.md', 'docs/release/scan-report.md'), true);
  assert.equal(globMatch('docs/release/*.md', 'docs/release/sub/x.md'), false);
  assert.equal(globMatch('README.md', 'README.md'), true);
  assert.equal(globMatch('docs/plans/**', 'docs/plans/portname-plan.md'), true);
});

test('classifyFiles: product files are included with a rule reason', () => {
  const r = classifyFiles(['bin/portname.js', 'lib/proxy.js', 'test/cli.test.js']);
  assert.deepEqual(r.unclassified, []);
  assert.deepEqual(r.excluded, []);
  assert.deepEqual(r.included.map((e) => e.path), ['bin/portname.js', 'lib/proxy.js', 'test/cli.test.js']);
  for (const e of r.included) assert.ok(e.reason.length > 0);
});

test('classifyFiles: private planning notes and agent rules are excluded', () => {
  const r = classifyFiles([
    'docs/plans/portname-plan.md',
    'docs/plans/portname-provenance.md',
    'AGENTS.md',
    '.git/config',
  ]);
  assert.deepEqual(r.unclassified, []);
  assert.deepEqual(r.included, []);
  const byPath = Object.fromEntries(r.excluded.map((e) => [e.path, e.reason]));
  assert.match(byPath['docs/plans/portname-plan.md'], /private planning/);
  assert.match(byPath['AGENTS.md'], /internal agent working rules/);
  assert.match(byPath['.git/config'], /git internals/);
});

test('classifyFiles: release packaging files from the macOS bundle work are included deliberately', () => {
  // Files added by the macOS-bundle/release workstream. Each is a product
  // build helper, a test helper, or product/release documentation, so each
  // gets an explicit include rule here to pin that decision.
  const r = classifyFiles([
    'scripts/bundle-macos.sh',
    'scripts/release-check.sh',
    'scripts/release-package.sh',
    'scripts/lib/payload-manifest.js',
    'scripts/lib/regen-payload-manifest.sh',
    'scripts/runtime-pin.env',
    'scripts/release/entitlements-cloudflared.plist',
    'scripts/release/entitlements-gui.plist',
    'scripts/release/entitlements-node.plist',
    'docs/macos-bundle.md',
    'docs/release-checklist.md',
    'test/bundleinstall.test.js',
    'test/release-package.test.js',
    'test/helpers/launchctl-stub.js',
  ]);
  assert.deepEqual(r.unclassified, []);
  assert.deepEqual(r.excluded, []);
  assert.equal(r.included.length, 14);
  const byPath = Object.fromEntries(r.included.map((e) => [e.path, e]));
  assert.match(byPath['scripts/bundle-macos.sh'].reason, /bundle/);
  assert.match(byPath['scripts/release/entitlements-gui.plist'].reason, /entitlements/);
  assert.match(byPath['scripts/runtime-pin.env'].reason, /runtime/);
  assert.match(byPath['test/helpers/launchctl-stub.js'].reason, /test/);
});

test('classifyFiles: internal release material under docs/release/ never reaches the candidate', () => {
  // Drafts with open owner decisions, a dated audit snapshot and an internal
  // license deliberation are not product documentation.
  const files = [
    'docs/release/install-and-support.md',
    'docs/release/license-options.md',
    'docs/release/privacy-draft.md',
    'docs/release/scan-report.md',
    'docs/release/security-draft.md',
  ];
  const r = classifyFiles(files);
  assert.deepEqual(r.included, []);
  assert.deepEqual(r.excluded.map((e) => e.path), files);
  for (const e of r.excluded) assert.match(e.reason, /internal pre-publication/);
});

// The scanner's rule, applied line by line as the scanner does.
const INTERNAL_REFERENCE = new RegExp(CONTENT_RULES.find((r) => r.id === 'internal-reference').re.source);

// Made-up home folders the test fixtures use. Any other folder name right
// below /Users/ in a published file is taken for a real one (placeholders
// such as `<name>` or a redaction marker do not start with a letter).
const FIXTURE_HOMES = new Set(['demo', 'me', 'mé', 'u', 'x', 'some', 'Jane']);

function realHomeFolders(text) {
  const found = [];
  for (const [, name] of text.matchAll(/\/Users\/([\p{L}\p{M}\p{N}._-]+)/gu)) {
    if (/^\p{L}/u.test(name) && !FIXTURE_HOMES.has(name.normalize('NFC'))) found.push(name);
  }
  return found;
}

test('candidate files carry no internal process references and no real home folder', (t) => {
  if (!isOwnGitWorkTree()) return t.skip('not a git work tree of this checkout');
  // Every published file, tests and fixtures included: change-request and
  // prompt numbers, review-round tags, finding ids and working-copy paths
  // (the scanner's rule; nothing is allowed, not even a pending count), and
  // home folders other than the fixtures' made-up ones (the scanner lists
  // every /Users/ path for review).
  const hits = [];
  for (const { path: p } of classifyFiles(trackedFiles()).included) {
    const buf = fs.readFileSync(path.join(ROOT, p));
    const text = buf.toString('utf8');
    // Images carry no prose; random bytes would match the prose rule.
    if (!looksBinary(buf)) {
      text.split('\n').forEach((line, i) => {
        if (INTERNAL_REFERENCE.test(line)) hits.push(`${p}:${i + 1}: internal reference`);
      });
    }
    const homes = realHomeFolders(text).length;
    if (homes > 0) hits.push(`${p}: ${homes} home folder(s) outside the fixture names`);
  }
  assert.deepEqual(hits, [], 'internal process references or workstation folder names in published files');
});

test('realHomeFolders: only the fixtures\' made-up names and placeholders pass', () => {
  // Assembled at runtime so this source does not carry the paths it tests.
  const home = (name, rest = 'Code') => ['', 'Users', name, rest].join('/');
  for (const name of FIXTURE_HOMES) assert.deepEqual(realHomeFolders(`x ${home(name)} y`), [], name);
  assert.deepEqual(realHomeFolders(home('<name>')), []);
  assert.deepEqual(realHomeFolders(['', 'Users', '[REDACTED]'].join('/')), []);
  assert.deepEqual(realHomeFolders(`"${home('alice')}"\n${home('Mara Ölz')}`), ['alice', 'Mara']);
  // A made-up name is matched as a whole segment, not as a prefix.
  assert.deepEqual(realHomeFolders(home('demonstrator')), ['demonstrator']);
  assert.deepEqual(realHomeFolders(home('mée')), ['mée']);
});

test('classifyFiles: fail-closed — unknown tracked files stay unclassified', () => {
  const r = classifyFiles(['some/new/dir/thing.txt']);
  assert.deepEqual(r.included, []);
  assert.deepEqual(r.excluded, []);
  assert.deepEqual(r.unclassified.map((e) => e.path), ['some/new/dir/thing.txt']);
});

test('invariant: exclusion rules are evaluated first and always win over include rules', () => {
  // A hypothetical future include rule broad enough to cover docs/plans/
  // must NOT pull the private provenance notes into the candidate.
  const broadDocsInclude = [{ pattern: 'docs/**', reason: 'hypothetical broad documentation rule' }];
  const r = classifyFiles(
    ['docs/control-protocol.md', 'docs/plans/portname-provenance.md'],
    broadDocsInclude,
    EXCLUDE_RULES
  );
  assert.deepEqual(r.included.map((e) => e.path), ['docs/control-protocol.md']);
  assert.deepEqual(r.excluded.map((e) => e.path), ['docs/plans/portname-provenance.md']);
  assert.match(r.excluded[0].reason, /private planning/);
  assert.deepEqual(r.unclassified, []);
  // Sanity: with the real INCLUDE_RULES nothing currently overlaps, so the
  // exclude-first reordering did not change the shipped classification.
  const prod = classifyFiles(['docs/plans/portname-provenance.md']);
  assert.deepEqual(prod.included, []);
  assert.equal(prod.excluded.length, 1);
  assert.ok(INCLUDE_RULES.every((rule) => !globMatch(rule.pattern, 'docs/plans/portname-provenance.md')));
});

test('invariant: every git-tracked file classifies without unclassified entries', (t) => {
  if (!isOwnGitWorkTree()) return t.skip('not a git work tree of this checkout (e.g. the staged candidate file tree)');
  const tracked = trackedFiles();
  const r = classifyFiles(tracked);
  assert.deepEqual(
    r.unclassified.map((e) => e.path),
    [],
    'new tracked files must be added deliberately to the positive list'
  );
  assert.ok(r.included.length > 60);
  // The private notes exist only in the private repository; wherever they
  // are tracked, every one of them must be excluded.
  const trackedPlans = tracked.filter((p) => p.startsWith('docs/plans/')).sort();
  const excludedPlans = r.excluded.filter((e) => e.path.startsWith('docs/plans/')).map((e) => e.path);
  assert.deepEqual(excludedPlans, trackedPlans, 'private plan notes must be excluded');
  assert.ok(!r.included.some((e) => e.path.startsWith('docs/plans/')));
});

test('the staged release candidate passes this test file without the private files (plain tree and fresh repo)', (t) => {
  // Building a candidate needs `git ls-files`, so a plain tree (source
  // archive, the staged candidate itself) skips this like the other
  // git-dependent tests instead of failing.
  if (!isOwnGitWorkTree()) return t.skip('not a git work tree of this checkout');
  // The nested fresh-repository run executes this same file inside a git
  // work tree; it must not recurse into building yet another candidate.
  if (process.env.PORTNAME_CANDIDATE_SELFTEST === '1') return t.skip('nested candidate run');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'release-candidate-selftest.'));
  try {
    const cand = path.join(tmp, 'stage', 'candidate');
    execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'build-release-candidate.js'), '--output', cand],
      { cwd: ROOT, stdio: 'pipe' });
    assert.ok(!fs.existsSync(path.join(cand, 'docs', 'plans')), 'the candidate must not contain the private notes');
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home);
    // An inherited GIT_DIR would also make the plain tree look like a work tree.
    const env = isolatedGitEnv(home);
    delete env.PORTNAME_CANDIDATE_SELFTEST;
    const runSuite = (label, extraEnv) => {
      try {
        return execFileSync(process.execPath, ['--test', '--test-reporter=tap', 'test/release-candidate-list.test.js'],
          { cwd: cand, env: { ...env, ...extraEnv }, stdio: 'pipe' }).toString();
      } catch (err) {
        assert.fail(`${label}: candidate test run failed:\n${String(err.stdout).slice(-3000)}`);
      }
    };
    // No recursion guard here: every test must pass or skip on its own in a
    // plain tree, exactly as after a "Download ZIP".
    const plain = runSuite('plain file tree (no .git)', {});
    assert.match(plain, /^# fail 0$/m);
    assert.match(plain, /^ok \d+ - the staged release candidate .*# SKIP not a git work tree/m);
    const git = (...args) => execFileSync('git', ['-c', 'user.name=portname-test', '-c', 'user.email=test@example.invalid',
      '-c', 'commit.gpgsign=false', ...args], { cwd: cand, env, stdio: 'pipe' });
    git('init', '-q');
    git('add', '-A');
    git('commit', '-q', '-m', 'release candidate');
    runSuite('fresh repository', { PORTNAME_CANDIDATE_SELFTEST: '1' });
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('scanText: flags a credential-shaped value with a redacted match only', () => {
  // Assembled at runtime so the static source of this test does not itself
  // trip the scanner (verified: scan of the tree reports 0 critical hits).
  const findings = [];
  const fake = ['aws_secret_', 'access_key = ', 'wJalr', 'XUtnFEMI/', 'K7MDENG', '/bPxRfiCYEXAMPLEKEY'].join('');
  scanText('worktree', 'fixture.txt', fake + '\n', findings);
  // The generic key/value rule reports the same line as well.
  assert.deepEqual(findings.map((f) => f.rule).sort(), ['aws-secret-assignment', 'key-value-secret']);
  for (const f of findings) {
    assert.equal(f.severity, 'critical');
    assert.ok(f.redacted.includes('REDACTED'));
    assert.ok(!f.redacted.includes('wJalrXUtnFEMI'), 'full secret must never be printed');
  }
});

test('scanText: flags unquoted secret assignments, not placeholders or short values', () => {
  // Assembled at runtime so the static source of this test does not itself
  // trip the scanner (same reason as the quoted fixtures above).
  const findings = [];
  const envStyle = ['SECRET', 'hunter2hunter2'].join('=');
  const yamlStyle = ['api_key', 'Zk9w2mQ7xR4tY1u6'].join(': ');
  scanText('worktree', 'fixture.env', envStyle + '\n', findings);
  scanText('worktree', 'fixture.yaml', yamlStyle + '\n', findings);
  assert.equal(findings.length, 2);
  for (const f of findings) {
    assert.equal(f.rule, 'key-value-secret');
    assert.equal(f.severity, 'critical');
    assert.ok(f.redacted.includes('REDACTED'));
    assert.ok(!f.redacted.includes('hunter2hunter2'), 'full secret must never be printed');
  }
  // Quoted assignments keep matching via the original variant.
  const quoted = [];
  const quotedLine = ['password', 's3cr3tvalu3'].join(': "') + '"';
  scanText('worktree', 'fixture.json', quotedLine + '\n', quoted);
  assert.equal(quoted.length, 1);
  assert.equal(quoted[0].rule, 'key-value-secret');
  // Negatives: value too short, or a template placeholder instead of material.
  const benign = [
    ['SECRET', 'abc'].join('='),
    ['password', '${SECRET_VALUE}'].join(': '),
  ].join('\n');
  const none = [];
  scanText('worktree', 'benign.env', benign + '\n', none);
  assert.equal(dedupe(none).length, 0);
});

test('scanText: secret key names with prefixes, suffixes or camelCase joints are flagged', () => {
  // `_` and a camelCase joint are no word boundary: the common env and
  // config names used to slip past both key/value rules. Assembled at
  // runtime so this source does not itself trip the scanner.
  const value = ['Zk9w2mQ7', 'xR4tY1u6q'].join('');
  const lines = [
    ['DB_PASSWORD', value].join('='),
    ['DATABASE_PASSWORD', value].join('='),
    ['export STRIPE_SECRET', value].join('='),
    ['SECRET_KEY', value].join('='),
    ['GITHUB_API_KEY', value].join('='),
    ['OPENAI_API_KEY', value].join('='),
    ['GOOGLE_CLIENT_SECRET', value].join('='),
    ['MY_AUTH_TOKEN', value].join('='),
    ['POSTGRES_PASSWORD', value].join(': '),
    ['dbPassword', value].join('='),
    ['secretKey', value].join(': '),
    ['db_password', `"${value}"`].join(': '),
    [JSON.stringify('dbPassword'), JSON.stringify(value)].join(': '),
    ['const apiSecret', `"${value}"`].join(' = '),
    ['let APIKey', `"${value}"`].join(' = '),
    ['ACCESS_TOKEN', value].join('='),
    ['authToken', value].join(': '),
    ['X-Api-Key', value].join(': '),
    ['SECRET2', value].join('='),
  ];
  for (const line of lines) {
    const findings = [];
    scanText('worktree', 'fixture.env', line + '\n', findings);
    assert.deepEqual(findings.map((f) => [f.rule, f.severity]), [['key-value-secret', 'critical']], line);
    assert.ok(!findings[0].redacted.includes(value), 'full secret must never be printed');
  }
  // Still no hit: short values, placeholders, and a header name whose
  // secret word only starts a kebab-case name.
  const benign = [
    ['DB_PASSWORD', 'abc'].join('='),
    ['DB_PASSWORD', '${DB_PASSWORD}'].join('='),
    [`'x-${'secret'}-hop'`, "'secret-value'"].join(': '),
  ];
  const none = [];
  scanText('worktree', 'benign.env', benign.join('\n') + '\n', none);
  assert.deepEqual(none, []);
});

test('scanText: a secret word continued in lower case is prose, not a key', () => {
  // Plurals and longer words (secrets, passwordless, secretary) are no key
  // name; this script's own name in a test title or a commit subject must
  // not become a permanent critical history finding. Assembled at runtime so
  // no static line here puts a secret word right before the colon.
  const prose = [
    ["test('scan-release-secrets", " tolerates shallow clones', () => {"].join(':'),
    ['scan-release-secrets', 'tolerates shallow clones'].join(': '),
    ['scan-release-secrets', 'scanning'].join(': '),
    ['- Secrets', 'everything stays in memory'].join(': '),
    ['## Secrets', 'overview'].join(': '),
    ['Passwords', 'none-are-stored'].join(': '),
    ['passwordless', 'enabled_by_default'].join(': '),
    ['secretary', 'appointments-only'].join(': '),
  ];
  for (const line of prose) {
    const findings = [];
    scanText('commit-message', 'abc123', line + '\n', findings);
    assert.deepEqual(findings, [], line);
  }
});

test('scanText: no findings for benign product content', () => {
  const findings = [];
  scanText('worktree', 'fixture.txt', 'const port = 3000; // see docs/control-protocol.md\n', findings);
  assert.equal(dedupe(findings).length, 0);
});

test('redactFor: emails and chat links are redacted to non-reversible previews', () => {
  const email = redactFor('email-address', 'someone@example.org');
  assert.match(email, /\*\*\*@example\.org/);
  assert.ok(!email.includes('someone@'));
  const link = redactFor('private-chat-link', 'https://chatgpt.com/g/g-abc123/x');
  assert.ok(link.includes('REDACTED'));
  assert.ok(!link.includes('g-abc123'));
});

test('scanText: fixtures under /Users/demo are review-level, not critical', () => {
  const findings = [];
  scanText('worktree', 't.swift', 'let root = "/Users/demo/shop"\n', findings);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule, 'personal-home-path');
  assert.equal(findings[0].severity, 'review');
  assert.ok(findings[0].redacted.startsWith('/Users/[REDACTED]'));
  assert.ok(!findings[0].redacted.includes('demo/shop'));
});

test('scanText: internal process references are review-level, not critical', () => {
  // Assembled at runtime: this file ships in the candidate, whose guard
  // above rejects these shapes.
  const refs = [
    ['PR', '#7'].join(' '),
    ['review', 'BLOCKER 1'].join(' '),
    ['sec-share', '2'].join('#'),
    ['robustness', '6'].join('#'),
    ['/tmp/x/', 'scratchpad', '/wt'].join(''),
    ['Prompt', '05'].join('-'),
    ['(Prompt', '05)'].join(' '),
    ['F', '7: notarytool only accepts archives'].join(''),
    ['as in ', 'F', '12 above'].join(''),
  ];
  const findings = [];
  scanText('staging', 'lib/x.js', refs.map((r) => `// ${r}`).join('\n') + '\n', findings);
  assert.deepEqual(findings.map((f) => [f.location, f.rule, f.severity]),
    refs.map((_, i) => [`lib/x.js:${i + 1}`, 'internal-reference', 'review']));
  // Bare tags count in comments of every syntax and in test names.
  const tagged = [
    ['# ', 'F', '3 — install target'],
    [' * ', 'F', '3 — install target'],
    ['<!-- ', 'F', '3 -->'],
    ["test('", 'F', "3: refuses a foreign target', () => {"],
  ].map((parts) => parts.join(''));
  const tagFindings = [];
  scanText('staging', 'lib/t.js', tagged.join('\n') + '\n', tagFindings);
  assert.deepEqual(tagFindings.map((f) => f.location), tagged.map((_, i) => `lib/t.js:${i + 1}`));
  const none = [];
  scanText('staging', 'lib/y.js', [
    '// review the diff; robustness first; "serviceId": "/wt/main/proj#3333"',
    '// lsof -F0 field separator; Prompt the user; prompts 2 times',
    ['const ', 'F', '1 = 2; // a key name in code, not a tag'].join(''),
  ].join('\n') + '\n', none);
  assert.deepEqual(none, []);
});

test('dedupe collapses identical findings', () => {
  const f = [];
  const line = ['token ', '0123456789abcdef', '0123456789'].join('');
  scanText('worktree', 'a.txt', line + '\n', f);
  scanText('worktree', 'a.txt', line + '\n', f);
  assert.equal(f.length, 2);
  assert.equal(dedupe(f).length, 1);
});

// ---------------------------------------------------------------------------
// scan-release-secrets.js --repo: the old code resolved `<PATH>/..`, so the
// documented option scanned the PARENT of the requested repository — inside
// another repository that meant a silent "critical: 0" for the wrong tree.
// Commit messages were not scanned at all (only diff lines and trailers).
// ---------------------------------------------------------------------------

const SCANNER = path.join(ROOT, 'scripts', 'scan-release-secrets.js');

function runScanner(env, ...args) {
  try {
    const stdout = execFileSync(process.execPath, [SCANNER, ...args], { env, stdio: 'pipe' }).toString();
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    return { code: err.status, stdout: String(err.stdout), stderr: String(err.stderr) };
  }
}

function scratchGit(home) {
  const env = isolatedGitEnv(home);
  const git = (cwd, ...args) => execFileSync('git', ['-c', 'user.name=portname-test',
    '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, env, stdio: 'pipe' });
  const scan = (...args) => runScanner(env, ...args);
  return { git, scan };
}

test('scan-release-secrets: --repo scans exactly that repository, never its parent', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-repo.'));
  try {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home);
    const { git, scan } = scratchGit(home);
    // A clean outer repository with a nested repository holding a secret.
    const outer = path.join(tmp, 'outer');
    const inner = path.join(outer, 'inner');
    fs.mkdirSync(inner, { recursive: true });
    git(outer, 'init', '-q');
    fs.writeFileSync(path.join(outer, 'README.md'), 'clean\n');
    git(outer, 'add', 'README.md');
    git(outer, 'commit', '-q', '-m', 'outer');
    git(inner, 'init', '-q');
    // Assembled at runtime so this source does not itself trip the scanner.
    fs.writeFileSync(path.join(inner, 'leak.txt'), `k=${['AKIA', '0123456789ABCDEF'].join('')}\n`);
    git(inner, 'add', 'leak.txt');
    git(inner, 'commit', '-q', '-m', 'inner');

    const json = path.join(tmp, 'out.json');
    const r = scan('--repo', inner, '--json', json);
    assert.strictEqual(r.code, 2, `the inner repository's secret must be reported: ${r.stdout}${r.stderr}`);
    assert.match(r.stdout, new RegExp(`scanning: ${inner.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    const { findings } = JSON.parse(fs.readFileSync(json, 'utf8'));
    assert.ok(findings.some((f) => f.area === 'worktree' && f.severity === 'critical' && f.location.startsWith('leak.txt')));

    // A path that is not a work-tree root is refused instead of resolved upward.
    fs.mkdirSync(path.join(inner, 'sub'));
    const sub = scan('--repo', path.join(inner, 'sub'));
    assert.strictEqual(sub.code, 1);
    assert.match(sub.stderr, /not the root of its git work tree/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('scan-release-secrets: commit message subjects and bodies are scanned', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-msg.'));
  try {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home);
    const { git, scan } = scratchGit(home);
    const repo = path.join(tmp, 'repo');
    fs.mkdirSync(repo);
    git(repo, 'init', '-q');
    fs.writeFileSync(path.join(repo, 'README.md'), 'clean\n');
    git(repo, 'add', 'README.md');
    const key = ['AKIA', 'ABCDEF0123456789'].join('');
    git(repo, 'commit', '-q', '-m', 'add readme', '-m', `debug notes: key ${key}`);

    const json = path.join(tmp, 'out.json');
    const r = scan('--repo', repo, '--json', json);
    assert.strictEqual(r.code, 2, `a secret in a commit message is critical: ${r.stdout}`);
    const { findings } = JSON.parse(fs.readFileSync(json, 'utf8'));
    const hit = findings.find((f) => f.area === 'commit-message');
    assert.ok(hit, 'expected a commit-message finding');
    assert.strictEqual(hit.severity, 'critical');
    assert.ok(!JSON.stringify(findings).includes(key), 'the secret itself must never be printed');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// A scratch repository with an "evil merge": the merge commit alone adds a
// file (no parent has it) that a later commit deletes again, so it exists
// neither in the worktree nor as an added line of any ordinary commit.
test('scan-release-secrets: lines that only a merge commit adds are scanned', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-merge.'));
  try {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home);
    const { git, scan } = scratchGit(home);
    const repo = path.join(tmp, 'repo');
    fs.mkdirSync(repo);
    const commitFile = (name, text, msg) => {
      fs.writeFileSync(path.join(repo, name), text);
      git(repo, 'add', name);
      git(repo, 'commit', '-q', '-m', msg);
    };
    git(repo, 'init', '-q', '-b', 'main');
    commitFile('README.md', 'base\n', 'base');
    git(repo, 'checkout', '-q', '-b', 'side');
    commitFile('side.txt', 'side\n', 'side');
    git(repo, 'checkout', '-q', 'main');
    commitFile('main.txt', 'main\n', 'main');
    git(repo, 'merge', '-q', '--no-ff', '--no-commit', 'side');
    const key = ['AKIA', 'FEDCBA9876543210'].join('');
    fs.writeFileSync(path.join(repo, 'merged.txt'), `k=${key}\n`);
    git(repo, 'add', 'merged.txt');
    git(repo, 'commit', '-q', '-m', 'merge side');
    git(repo, 'rm', '-q', 'merged.txt');
    git(repo, 'commit', '-q', '-m', 'drop merged.txt');

    const json = path.join(tmp, 'out.json');
    const r = scan('--repo', repo, '--json', json);
    assert.strictEqual(r.code, 2, `a secret added by a merge commit is critical: ${r.stdout}${r.stderr}`);
    const { findings } = JSON.parse(fs.readFileSync(json, 'utf8'));
    const merge = git(repo, 'rev-parse', 'HEAD~1').toString().trim().slice(0, 12);
    assert.ok(findings.some((f) => f.area === 'history' && f.severity === 'critical' && f.location.startsWith(merge)),
      `expected a history finding in the merge commit ${merge}`);
    assert.ok(!JSON.stringify(findings).includes(key), 'the secret itself must never be printed');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// remerge skips merges with more than two parents: an octopus merge that
// alone adds a file printed no patch at all.
test('scan-release-secrets: lines that only an octopus merge adds are scanned', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-octopus.'));
  try {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home);
    const { git, scan } = scratchGit(home);
    const repo = path.join(tmp, 'repo');
    fs.mkdirSync(repo);
    const commitFile = (name, text, msg) => {
      fs.writeFileSync(path.join(repo, name), text);
      git(repo, 'add', name);
      git(repo, 'commit', '-q', '-m', msg);
    };
    git(repo, 'init', '-q', '-b', 'main');
    commitFile('README.md', 'base\n', 'base');
    git(repo, 'checkout', '-q', '-b', 'a');
    commitFile('a.txt', 'a\n', 'a');
    git(repo, 'checkout', '-q', '-b', 'c', 'main');
    commitFile('c.txt', 'c\n', 'c');
    git(repo, 'checkout', '-q', 'main');
    git(repo, 'merge', '-q', '--no-ff', '--no-commit', 'a', 'c');
    const key = ['AKIA', '2468ACE013579BDF'].join('');
    fs.writeFileSync(path.join(repo, 'evil.txt'), `k=${key}\n`);
    git(repo, 'add', 'evil.txt');
    git(repo, 'commit', '-q', '-m', 'octopus');
    git(repo, 'rm', '-q', 'evil.txt');
    git(repo, 'commit', '-q', '-m', 'drop evil.txt');

    const octopus = git(repo, 'rev-parse', 'HEAD~1').toString().trim();
    assert.equal(git(repo, 'rev-list', '--parents', '-n', '1', octopus).toString().trim().split(' ').length, 4,
      'fixture: a merge with three parents');
    const json = path.join(tmp, 'out.json');
    const r = scan('--repo', repo, '--json', json);
    assert.strictEqual(r.code, 2, `a secret added by an octopus merge is critical: ${r.stdout}${r.stderr}`);
    const { findings } = JSON.parse(fs.readFileSync(json, 'utf8'));
    assert.ok(findings.some((f) => f.area === 'history' && f.severity === 'critical' && f.location.startsWith(octopus.slice(0, 12))),
      `expected a history finding in the octopus merge ${octopus.slice(0, 12)}`);
    assert.ok(!JSON.stringify(findings).includes(key), 'the secret itself must never be printed');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Compressed image data contains comment-like byte runs by chance.
function binaryWithProseShape() {
  const tag = ['# ', 'F', '12'].join('');
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]), Buffer.from(`\n${tag}\n`)]);
}

test('scanWorktree: binary files skip the prose rule but keep the credential rules', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-binary.'));
  try {
    const key = ['AKIA', '13579BDF2468ACE0'].join('');
    fs.writeFileSync(path.join(tmp, 'shot.png'), binaryWithProseShape());
    fs.writeFileSync(path.join(tmp, 'key.png'), Buffer.concat([binaryWithProseShape(), Buffer.from(`k=${key}\n`)]));
    fs.writeFileSync(path.join(tmp, 'notes.md'), binaryWithProseShape().subarray(12).toString('utf8'));
    assert.ok(looksBinary(fs.readFileSync(path.join(tmp, 'shot.png'))));
    assert.ok(!looksBinary(fs.readFileSync(path.join(tmp, 'notes.md'))));
    const findings = [];
    scanWorktree(tmp, 'staging', ['shot.png', 'key.png', 'notes.md'], findings);
    assert.deepEqual(findings.filter((f) => f.rule === 'internal-reference').map((f) => f.location), ['notes.md:2']);
    assert.ok(findings.some((f) => f.location.startsWith('key.png') && f.severity === 'critical'),
      'a credential inside a binary file is still critical');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('scan-release-secrets: added images in history skip the prose rule', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-binary-history.'));
  try {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home);
    const { git, scan } = scratchGit(home);
    const repo = path.join(tmp, 'repo');
    fs.mkdirSync(repo);
    git(repo, 'init', '-q', '-b', 'main');
    fs.writeFileSync(path.join(repo, 'shot.png'), binaryWithProseShape());
    git(repo, 'add', 'shot.png');
    git(repo, 'commit', '-q', '-m', 'screenshot');
    fs.rmSync(path.join(repo, 'shot.png'));
    git(repo, 'add', '-A');
    git(repo, 'commit', '-q', '-m', 'drop screenshot');
    const json = path.join(tmp, 'out.json');
    scan('--repo', repo, '--json', json);
    const { findings } = JSON.parse(fs.readFileSync(json, 'utf8'));
    assert.deepEqual(findings.filter((f) => f.area === 'history' && f.rule === 'internal-reference'), []);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('mergeDiffArg: remerge from git 2.36 on, first-parent before', () => {
  const { mergeDiffArg } = require('../scripts/scan-release-secrets.js');
  assert.equal(mergeDiffArg('git version 2.35.8'), '--diff-merges=first-parent');
  assert.equal(mergeDiffArg('git version 2.36.0'), '--diff-merges=remerge');
  assert.equal(mergeDiffArg('git version 2.39.5 (Apple Git-154)'), '--diff-merges=remerge');
  assert.equal(mergeDiffArg('git version 3.0.0'), '--diff-merges=remerge');
  assert.equal(mergeDiffArg('unparseable'), '--diff-merges=first-parent');
});

test('historyLogArgs: remerge adds a first-parent pass for octopus merges; every pass prints text patches', () => {
  const { historyLogArgs } = require('../scripts/scan-release-secrets.js');
  const remerge = historyLogArgs('git version 2.39.5 (Apple Git-154)');
  assert.equal(remerge.length, 2);
  assert.ok(remerge[0].includes('--diff-merges=remerge') && !remerge[0].includes('--min-parents=3'));
  assert.ok(remerge[1].includes('--min-parents=3') && remerge[1].includes('--diff-merges=first-parent'));
  // First-parent already covers every merge, octopus included.
  const firstParent = historyLogArgs('git version 2.35.8');
  assert.equal(firstParent.length, 1);
  assert.ok(firstParent[0].includes('--diff-merges=first-parent') && !firstParent[0].includes('--min-parents=3'));
  for (const args of [...remerge, ...firstParent]) {
    for (const flag of ['--all', '-p', '--text', '--no-color', '--no-ext-diff', '--no-textconv']) {
      assert.ok(args.includes(flag), `${flag} in ${args.join(' ')}`);
    }
  }
});

// The scanner parses `git log -p` and `git log --format` output; git config
// and attributes used to shape it: color=always prefixed every added line
// with an escape sequence, log.showRoot=false dropped the root commit's
// patch, a `-diff`/`binary` attribute or core.bigFileThreshold printed
// "Binary files differ" instead of the patch, and i18n.logOutputEncoding=
// UTF-16 re-encoded every commit message — each a silent "critical: 0".
// The user's config and the repository's own config and attributes count.
test('scan-release-secrets: git config and attributes cannot blind the history or commit-message scan', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-gitconfig.'));
  try {
    const key = ['AKIA', '13579BDF02468ACE'].join('');
    const userConfig = (home, text) => fs.writeFileSync(path.join(home, '.gitconfig'), text);
    const setups = {
      color: (home) => userConfig(home, '[color]\n\tui = always\n\tdiff = always\n'),
      showRoot: (home) => userConfig(home, '[log]\n\tshowRoot = false\n'),
      userAttributesFile: (home) => {
        fs.writeFileSync(path.join(home, 'attributes'), '* -diff\n');
        userConfig(home, `[core]\n\tattributesFile = ${path.join(home, 'attributes')}\n`);
      },
      userBigFileThreshold: (home) => userConfig(home, '[core]\n\tbigFileThreshold = 1\n'),
      userLogOutputEncoding: (home) => userConfig(home, '[i18n]\n\tlogOutputEncoding = UTF-16\n'),
      repoInfoAttributes: (home, repo) => {
        fs.mkdirSync(path.join(repo, '.git', 'info'), { recursive: true });
        fs.writeFileSync(path.join(repo, '.git', 'info', 'attributes'), '* binary\n');
      },
      repoBigFileThreshold: (home, repo, git) => git(repo, 'config', 'core.bigFileThreshold', '1'),
      repoLogOutputEncoding: (home, repo, git) => git(repo, 'config', 'i18n.logOutputEncoding', 'UTF-16'),
    };
    const blinded = [];
    for (const [label, setup] of Object.entries(setups)) {
      const home = path.join(tmp, `home-${label}`);
      fs.mkdirSync(home);
      const { git, scan } = scratchGit(home);
      const repo = path.join(tmp, `repo-${label}`);
      fs.mkdirSync(repo);
      git(repo, 'init', '-q');
      setup(home, repo, git);
      // The root commit adds the secret, the next one deletes it: only the
      // history scan can see it. The root commit's message carries it too.
      fs.writeFileSync(path.join(repo, 'leak.txt'), `k=${key}\n`);
      git(repo, 'add', 'leak.txt');
      git(repo, 'commit', '-q', '-m', 'root', '-m', `debug notes: key ${key}`);
      git(repo, 'rm', '-q', 'leak.txt');
      git(repo, 'commit', '-q', '-m', 'drop leak.txt');

      const json = path.join(tmp, `out-${label}.json`);
      const r = scan('--repo', repo, '--json', json);
      assert.strictEqual(r.code, 2, `${label}: the secret must be reported: ${r.stdout}${r.stderr}`);
      const { findings } = JSON.parse(fs.readFileSync(json, 'utf8'));
      for (const area of ['history', 'commit-message']) {
        if (!findings.some((f) => f.area === area && f.severity === 'critical')) blinded.push(`${label}: ${area}`);
      }
      assert.ok(!JSON.stringify(findings).includes(key), `${label}: the secret itself must never be printed`);
    }
    assert.deepEqual(blinded, []);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// build-release-candidate.js used to rm -rf its --output unguarded (`.`
// wiped the checkout, `..` its parent) and copied working-tree bytes,
// symlink targets included, while the manifest named the clean HEAD. A
// scratch repository carries its own copy of the two staging scripts.
function makeCandidateRepo(tmp) {
  const home = path.join(tmp, 'home');
  fs.mkdirSync(home);
  const { git } = scratchGit(home);
  const repo = path.join(tmp, 'repo');
  fs.mkdirSync(path.join(repo, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(repo, 'lib'));
  for (const f of ['build-release-candidate.js', 'release-candidate-list.js']) {
    fs.copyFileSync(path.join(ROOT, 'scripts', f), path.join(repo, 'scripts', f));
  }
  fs.writeFileSync(path.join(repo, 'package.json'), '{"version":"9.9.9"}\n');
  fs.writeFileSync(path.join(repo, 'README.md'), 'readme\n');
  fs.writeFileSync(path.join(repo, 'lib', 'a.js'), 'committed\n');
  git(repo, 'init', '-q');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'base');
  const build = (...args) => {
    const r = spawnSync(process.execPath, [path.join(repo, 'scripts', 'build-release-candidate.js'), ...args],
      { cwd: repo, env: isolatedGitEnv(home), encoding: 'utf8' });
    return { code: r.status, stdout: r.stdout, stderr: r.stderr };
  };
  return { repo, git, build };
}

test('build-release-candidate: stages the committed bytes of HEAD, never the working tree', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'candidate-head.'));
  try {
    const { repo, git, build } = makeCandidateRepo(tmp);
    fs.writeFileSync(path.join(repo, 'lib', 'a.js'), 'uncommitted debug edit\n');
    fs.writeFileSync(path.join(repo, 'lib', 'untracked.js'), 'never staged\n');
    const out = path.join(tmp, 'stage', 'candidate');
    const r = build('--output', out);
    assert.strictEqual(r.code, 0, r.stderr);
    assert.strictEqual(fs.readFileSync(path.join(out, 'lib', 'a.js'), 'utf8'), 'committed\n');
    assert.ok(!fs.existsSync(path.join(out, 'lib', 'untracked.js')));
    assert.match(r.stderr, /uncommitted changes are not part of the candidate/);
    const manifest = JSON.parse(fs.readFileSync(path.join(tmp, 'stage', 'MANIFEST.json'), 'utf8'));
    assert.strictEqual(manifest.source.head, git(repo, 'rev-parse', 'HEAD').toString().trim());
    const entry = manifest.files.find((f) => f.path === 'lib/a.js');
    assert.strictEqual(entry.sha256, crypto.createHash('sha256').update('committed\n').digest('hex'));
    assert.strictEqual(fs.statSync(path.join(out, 'scripts', 'build-release-candidate.js')).mode & 0o777,
      (fs.statSync(path.join(ROOT, 'scripts', 'build-release-candidate.js')).mode & 0o100) ? 0o755 : 0o644);

    // A tracked symlink under an included path is refused, never followed.
    fs.writeFileSync(path.join(repo, 'lib', 'a.js'), 'committed\n');
    fs.symlinkSync('../README.md', path.join(repo, 'lib', 'link.js'));
    git(repo, 'add', 'lib/link.js');
    git(repo, 'commit', '-q', '-m', 'link');
    const linked = build('--output', path.join(tmp, 'stage2', 'candidate'));
    assert.strictEqual(linked.code, 1);
    assert.match(linked.stderr, /not regular files at HEAD[\s\S]*120000 lib\/link\.js/);
    assert.ok(!fs.existsSync(path.join(tmp, 'stage2', 'candidate')), 'nothing is staged');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('build-release-candidate: --output never removes the repository, an ancestor or unrelated data', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'candidate-output.'));
  try {
    const { repo, build } = makeCandidateRepo(tmp);
    const keep = path.join(tmp, 'keep');
    fs.mkdirSync(keep);
    fs.writeFileSync(path.join(keep, 'notes.txt'), 'mine\n');
    const resources = path.join(tmp, 'Resources');
    fs.mkdirSync(resources);
    fs.writeFileSync(path.join(resources, 'MANIFEST.json'), '{"schema":"portname.payload-manifest/1"}\n');
    fs.symlinkSync(repo, path.join(tmp, 'repo-link'));
    const refusals = {
      '.': /is the repository or one of its ancestors/,
      '..': /is the repository or one of its ancestors/,
      [path.join(tmp, 'repo-link')]: /is the repository or one of its ancestors/,
      '.git/candidate': /is inside \.git/,
      [keep]: /non-empty directory that is not a previous candidate/,
      [path.join(resources, 'candidate')]: /MANIFEST\.json exists and is not a release-candidate manifest/,
    };
    for (const [output, reason] of Object.entries(refusals)) {
      const r = build('--output', output);
      assert.strictEqual(r.code, 1, `${output}: must be refused`);
      assert.match(r.stderr, reason, output);
      assert.match(r.stderr, /nothing was removed or staged/);
    }
    assert.ok(fs.existsSync(path.join(repo, '.git')) && fs.existsSync(path.join(repo, 'README.md')), 'the repository survives');
    assert.strictEqual(fs.readFileSync(path.join(keep, 'notes.txt'), 'utf8'), 'mine\n');
    assert.match(fs.readFileSync(path.join(resources, 'MANIFEST.json'), 'utf8'), /payload-manifest/);

    // The default location and a previous candidate are replaced as before.
    assert.strictEqual(build().code, 0);
    const previous = path.join(repo, '.release-staging', 'portname-9.9.9-candidate');
    fs.writeFileSync(path.join(previous, 'stale.txt'), 'from an older run\n');
    const again = build();
    assert.strictEqual(again.code, 0, again.stderr);
    assert.ok(!fs.existsSync(path.join(previous, 'stale.txt')));
    assert.ok(fs.existsSync(path.join(previous, 'lib', 'a.js')));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

function withEnv(vars, fn) {
  const saved = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  Object.assign(process.env, vars);
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('an inherited GIT_DIR neither receives scratch commits nor redirects the scanner', () => {
  // `npm test` from a pre-commit/pre-push hook or `git rebase -x` in a
  // linked worktree inherits GIT_DIR (pre-commit also GIT_INDEX_FILE); the
  // scratch commits above must not land in that checkout's branch, and a
  // scanner started from such a hook must still scan exactly --repo.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-gitdir.'));
  try {
    const home = path.join(tmp, 'home');
    fs.mkdirSync(home);
    const { git } = scratchGit(home);
    const main = path.join(tmp, 'main');
    const linked = path.join(tmp, 'linked');
    fs.mkdirSync(main);
    git(main, 'init', '-q');
    fs.writeFileSync(path.join(main, 'README.md'), 'mine\n');
    git(main, 'add', 'README.md');
    git(main, 'commit', '-q', '-m', 'mine');
    git(main, 'worktree', 'add', '-q', '-b', 'feature', linked);
    const state = () => [
      git(linked, 'log', '--format=%H %s', 'feature').toString(),
      git(linked, 'ls-files', '--stage').toString(),
    ];
    const before = state();
    const gitDir = git(linked, 'rev-parse', '--absolute-git-dir').toString().trim();

    const repo = path.join(tmp, 'repo');
    fs.mkdirSync(repo);
    const json = path.join(tmp, 'out.json');
    const inherited = { GIT_DIR: gitDir, GIT_INDEX_FILE: path.join(gitDir, 'index') };
    withEnv(inherited, () => {
      const hooked = scratchGit(home);
      hooked.git(repo, 'init', '-q');
      fs.writeFileSync(path.join(repo, 'leak.txt'), `k=${['AKIA', '0123456789ABCDEF'].join('')}\n`);
      hooked.git(repo, 'add', 'leak.txt');
      hooked.git(repo, 'commit', '-q', '-m', 'scratch');
    });
    // Not through scratchGit: the scanner itself must drop the inherited
    // variables, so it runs with them still in its environment.
    const r = runScanner({ ...isolatedGitEnv(home), ...inherited }, '--repo', repo, '--json', json);

    assert.deepEqual(state(), before, 'the inherited repository gained commits or index entries');
    assert.strictEqual(git(repo, 'log', '--format=%s').toString(), 'scratch\n');
    assert.strictEqual(r.code, 2, `the scratch repository itself must be scanned: ${r.stdout}${r.stderr}`);
    const { refs, findings } = JSON.parse(fs.readFileSync(json, 'utf8'));
    assert.ok(!refs.refList.includes('refs/heads/feature'), 'the scanner read the inherited repository');
    assert.strictEqual(refs.refList.length, 1, `only the scratch repository's branch: ${refs.refList}`);
    assert.ok(findings.some((f) => f.area === 'worktree' && f.severity === 'critical' && f.location.startsWith('leak.txt')));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('isolatedGitEnv: no inherited GIT_* variable or owner git config reaches a scratch run', () => {
  const env = withEnv({
    GIT_DIR: '/dev/null/.git/worktrees/x',
    GIT_WORK_TREE: '/dev/null',
    GIT_INDEX_FILE: '/dev/null/.git/index',
    GIT_CONFIG_PARAMETERS: "'core.hookspath'='/dev/null'",
    XDG_CONFIG_HOME: '/dev/null/.config',
  }, () => isolatedGitEnv('/scratch/home'));
  assert.deepEqual(Object.keys(env).filter((k) => k.startsWith('GIT_')), ['GIT_CONFIG_NOSYSTEM']);
  assert.strictEqual(env.GIT_CONFIG_NOSYSTEM, '1');
  assert.strictEqual(env.HOME, '/scratch/home');
  assert.ok(!('XDG_CONFIG_HOME' in env));
  assert.ok(!('NODE_TEST_CONTEXT' in env));
});

test('positive list module is deterministic regardless of input order', () => {
  const a = classifyFiles(['README.md', 'docs/plans/x.md']);
  const b = classifyFiles(['docs/plans/x.md', 'README.md']);
  assert.deepEqual(a.included.map((e) => e.path), b.included.map((e) => e.path));
  assert.deepEqual(a.excluded.map((e) => e.path), b.excluded.map((e) => e.path));
  assert.deepEqual(classifyFiles([]), { included: [], excluded: [], unclassified: [] });
});
