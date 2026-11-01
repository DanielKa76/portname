'use strict';

/**
 * Explicit positive list for the public release candidate.
 *
 * Design rules:
 * - Include by explicit, reviewed rules only. There is deliberately no
 *   "copy everything except ..." fallback: every tracked file must either
 *   match an include rule or an explicit exclusion rule. Anything else is
 *   reported as UNCLASSIFIED and fails the staging run (fail-closed).
 * - Never included: git internals, private planning notes (docs/plans/),
 *   chat/review protocols, personal files, local state/log/build caches.
 *   This is an invariant, not a convention: exclusion rules are evaluated
 *   BEFORE include rules and always win. A future broad include rule
 *   (e.g. `docs/**`) can therefore never silently pull docs/plans/ or any
 *   other protected path into the candidate.
 * - Exclusions are deliberate and carry a reason string so the list can be
 *   audited without reading the excluded content.
 */

const INCLUDE_RULES = [
  // Root product files
  { pattern: 'README.md', reason: 'product readme' },
  { pattern: 'LICENSE', reason: 'MIT license text' },
  { pattern: 'SECURITY.md', reason: 'security policy: how to report vulnerabilities' },
  { pattern: 'package.json', reason: 'package manifest (no runtime dependencies)' },
  { pattern: '.gitignore', reason: 'repo hygiene list' },

  // CLI and daemon library
  { pattern: 'bin/portname.js', reason: 'CLI entry point' },
  { pattern: 'lib/*.js', reason: 'daemon library modules' },

  // Test suite
  { pattern: 'test/*.test.js', reason: 'node --test suite' },
  { pattern: 'test/helpers/**', reason: 'shared test helpers/stubs for the node --test suite' },

  // Developer and build helpers
  { pattern: 'scripts/bench-discovery.js', reason: 'discovery benchmark tool' },
  { pattern: 'scripts/build-macos-app.sh', reason: 'macOS app bundle build helper' },
  { pattern: 'scripts/install-macos-app.sh', reason: 'macOS app install helper' },
  { pattern: 'scripts/test-macos-app.sh', reason: 'macOS app test helper' },
  { pattern: 'scripts/bundle-macos.sh', reason: 'macOS distributable bundle builder (payload staging, runtime pinning, codesign)' },
  { pattern: 'scripts/release-package.sh', reason: 'release package builder for the versioned payload directory' },
  { pattern: 'scripts/release-check.sh', reason: 'pre-release verification helper (payload manifest + install check)' },
  { pattern: 'scripts/build-release-candidate.js', reason: 'release staging tool (this pipeline)' },
  { pattern: 'scripts/scan-release-secrets.js', reason: 'release secret scanner' },
  { pattern: 'scripts/release-candidate-list.js', reason: 'positive list definition (this module)' },
  { pattern: 'scripts/lib/payload-manifest.js', reason: 'payload manifest generator/verifier shared by bundling, install and release check' },
  { pattern: 'scripts/lib/regen-payload-manifest.sh', reason: 'helper to regenerate the shipped payload manifest' },
  { pattern: 'scripts/lib/release-preflight.js', reason: 'release-package gate: bundle payload vs. its manifest and the runtime pins before signing' },
  { pattern: 'scripts/lib/app-pids.sh', reason: 'exact (anchored, escaped) GUI process lookup sourced by install-macos-app.sh' },
  { pattern: 'scripts/lib/cli-wrapper.sh', reason: 'generator for the bundled CLI wrappers (symlink-safe), sourced by bundle-macos.sh' },
  { pattern: 'scripts/lib/pinned-fetch.sh', reason: 'checksum-pinned, verify-then-rename download helper sourced by bundle-macos.sh' },
  { pattern: 'scripts/lib/node-pin-freshness.js', reason: 'release-check gate: bundled Node runtime pin vs. newer security releases' },
  { pattern: 'scripts/lib/launch-agent-check.js', reason: 'release-check gate: LaunchAgent respawn policy (KeepAlive + ThrottleInterval), static plist reader' },
  { pattern: 'scripts/runtime-pin.env', reason: 'pinned bundled runtime versions with vendor-published SHA-256 (sourced by bundle-macos.sh)' },
  { pattern: 'scripts/release/entitlements-*.plist', reason: 'codesign entitlements for hardened-runtime bundle binaries (node, cloudflared, GUI shell)' },

  // Native macOS menubar app
  { pattern: 'macos/Package.swift', reason: 'SwiftPM package manifest' },
  { pattern: 'macos/Sources/**', reason: 'menubar app sources and localized resources' },
  { pattern: 'macos/Tests/**', reason: 'XCTest suite' },

  // Product documentation
  { pattern: 'docs/bench-discovery.md', reason: 'benchmark methodology doc' },
  { pattern: 'docs/control-protocol.md', reason: 'control socket protocol doc' },
  { pattern: 'docs/diagnostics.md', reason: 'diagnostics doc' },
  { pattern: 'docs/macos-smoke-checklist.md', reason: 'manual smoke checklist' },
  { pattern: 'docs/macos-bundle.md', reason: 'macOS bundle product documentation (runtime pins, build, install, verification)' },
  { pattern: 'docs/release-checklist.md', reason: 'release checklist documentation' },
  { pattern: 'docs/architecture-notes.md', reason: 're-stated factual architecture decisions (public replacement for private plan notes)' },
  { pattern: 'docs/bind-probe.txt', reason: 'measured unprivileged bind probe referenced by README' },
];

const EXCLUDE_RULES = [
  { pattern: '.git', reason: 'git internals are never staged' },
  { pattern: '.git/**', reason: 'git internals are never staged' },
  { pattern: 'docs/plans/**', reason: 'private planning and provenance notes, not product documentation' },
  { pattern: 'docs/release/**', reason: 'internal pre-publication material (license deliberation, scan report, draft policies, packaging status) — public security/privacy/install text is a separate owner decision' },
  { pattern: 'AGENTS.md', reason: 'internal agent working rules, not product documentation; may later be re-authored as a public CONTRIBUTING guide' },
  { pattern: 'node_modules/', reason: 'untracked dependencies, never published' },
  { pattern: 'node_modules/**', reason: 'untracked dependencies, never published' },
  { pattern: 'dist/', reason: 'local build output cache' },
  { pattern: 'dist/**', reason: 'local build output cache' },
  { pattern: 'macos/.build/**', reason: 'SwiftPM build cache' },
  { pattern: 'macos/.swiftpm/**', reason: 'SwiftPM local state' },
  { pattern: '.release-staging/**', reason: 'staging output itself' },
  { pattern: '.repowise/**', reason: 'local analysis tool state' },
  { pattern: '*.log', reason: 'log files' },
  { pattern: '.DS_Store', reason: 'macOS Finder state' },
  { pattern: '*.xcresult', reason: 'Xcode result bundles' },
];

/**
 * Glob match supporting `*` (within one path segment) and `**`
 * (across segments). Patterns ending in `/` match the directory itself and
 * everything below it.
 */
function globMatch(pattern, filePath) {
  let p = pattern;
  if (p.endsWith('/')) {
    if (!(filePath.startsWith(p) || filePath === p.slice(0, -1))) return false;
    p = p.slice(0, -1) + '/**';
  }
  const re = globToRegExp(p);
  return re.test(filePath);
}

function globToRegExp(pattern) {
  let re = '';
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        // `**` matches across segments; swallow a following slash so that
        // `a/**` also matches the bare file `a/b` (not `a` itself).
        if (pattern[i + 2] === '/') {
          re += '(?:.*/)?';
          i += 3;
          continue;
        }
        re += '.*';
        i += 2;
        continue;
      }
      re += '[^/]*';
      i += 1;
      continue;
    }
    re += c.replace(/[.+^${}()|[\]\\?]/g, '\\$&');
    i += 1;
  }
  return new RegExp('^' + re + '$');
}

function firstMatch(rules, filePath) {
  for (const rule of rules) {
    if (globMatch(rule.pattern, filePath)) return rule;
  }
  return null;
}

/**
 * Classify a list of repo-relative file paths.
 * Returns { included, excluded, unclassified }.
 *
 * Exclusion rules are evaluated first and always win; the rule parameters
 * exist so tests can prove that invariant against hypothetical broad
 * include rules. Production callers use the module rule sets via defaults.
 */
function classifyFiles(files, includeRules = INCLUDE_RULES, excludeRules = EXCLUDE_RULES) {
  const included = [];
  const excluded = [];
  const unclassified = [];
  for (const file of files) {
    const exc = firstMatch(excludeRules, file);
    if (exc) {
      excluded.push({ path: file, rule: exc.pattern, reason: exc.reason });
      continue;
    }
    const inc = firstMatch(includeRules, file);
    if (inc) {
      included.push({ path: file, rule: inc.pattern, reason: inc.reason });
      continue;
    }
    unclassified.push({ path: file });
  }
  const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  included.sort(byPath);
  excluded.sort(byPath);
  unclassified.sort(byPath);
  return { included, excluded, unclassified };
}

module.exports = { INCLUDE_RULES, EXCLUDE_RULES, classifyFiles, globMatch };

if (require.main === module) {
  // CLI: read file paths (one per line) on stdin, print classification JSON.
  const chunks = [];
  process.stdin.on('data', (d) => chunks.push(d));
  process.stdin.on('end', () => {
    const files = Buffer.concat(chunks).toString('utf8').split('\n').filter(Boolean);
    process.stdout.write(JSON.stringify(classifyFiles(files), null, 2) + '\n');
  });
}
