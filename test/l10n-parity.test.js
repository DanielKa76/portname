'use strict';

// Parity harness for the macOS L10n tables: every German string literal
// passed to L10n.text()/L10n.format() in the Swift sources must exist as a
// key in BOTH Localizable.strings tables (de keeps the source text, en
// carries the translation). A literal missing from a table silently falls
// back to the German source in that localization — this pins the gap
// class-wise instead of per code review.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const SOURCES_DIR = path.resolve(__dirname, '../macos/Sources');
const TABLES = [
  path.join(SOURCES_DIR, 'PortnameCore/Resources/de.lproj/Localizable.strings'),
  path.join(SOURCES_DIR, 'PortnameCore/Resources/en.lproj/Localizable.strings'),
];

function swiftFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) swiftFiles(p, out);
    else if (p.endsWith('.swift')) out.push(p);
  }
  return out;
}

// First argument of L10n.text("…") / L10n.format("…") when it is a plain
// literal. Dynamic call sites (e.g. L10n.text(choice.label)) are skipped
// naturally: a quote must follow the opening paren. Swift interpolation
// inside the literal is skipped explicitly — interpolated strings must go
// through L10n.format with a %@/%ld pattern instead.
const CALL_SITE = /L10n\.(?:text|format)\(\s*"((?:\\.|[^"\\])*)"/g;

function callSiteLiterals() {
  const literals = new Map(); // unescaped literal -> first source file
  for (const file of swiftFiles(SOURCES_DIR)) {
    const src = fs.readFileSync(file, 'utf8');
    let match;
    while ((match = CALL_SITE.exec(src))) {
      if (match[1].includes('\\(')) continue;
      const literal = match[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      if (!literals.has(literal)) literals.set(literal, path.basename(file));
    }
  }
  return literals;
}

function tableKeys(file) {
  const xml = fs.readFileSync(file, 'utf8');
  const keys = new Set();
  const re = /<key>([\s\S]*?)<\/key>/g;
  let match;
  while ((match = re.exec(xml))) {
    keys.add(match[1]
      .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'));
  }
  return keys;
}

test('every L10n call-site literal is a key in the de and en tables', () => {
  const literals = callSiteLiterals();
  assert.ok(literals.size >= 160, `harness must see the call sites (found ${literals.size})`);
  const [deKeys, enKeys] = TABLES.map(tableKeys);
  assert.strictEqual(deKeys.size, enKeys.size, 'both tables must keep key parity');
  const missing = [...literals]
    .filter(([key]) => !deKeys.has(key) || !enKeys.has(key))
    .map(([key, file]) => `${JSON.stringify(key)} (${file})`);
  assert.deepStrictEqual(missing, [], 'L10n literals missing from a table');
});

// Release blocker guard: the generated `Bundle.module` accessor only finds
// the resource bundle at the .app root or at the build machine's absolute
// .build path and traps otherwise — the shipped app crashed on every other
// Mac. L10n must resolve the bundle explicitly (Contents/Resources first)
// and may touch Bundle.module only in DEBUG builds (swift test).
test('L10n never reaches Bundle.module outside DEBUG and names the shipped bundle', () => {
  const l10n = fs.readFileSync(path.join(SOURCES_DIR, 'PortnameCore/L10n.swift'), 'utf8');
  const code = l10n.split('\n').filter((line) => !line.trim().startsWith('//')).join('\n');
  const releaseCode = code.replace(/#if DEBUG[\s\S]*?(?=#else|#endif)/g, '');
  assert.ok(!releaseCode.includes('Bundle.module'), 'Bundle.module must stay inside #if DEBUG');
  assert.match(code, /Bundle\.main\.resourceURL/, 'the shipped layout (Contents/Resources) must be searched');

  // The bundle name is SwiftPM's "<package>_<target>.bundle"; the resolver
  // and the build script that copies it must agree with Package.swift.
  const manifest = fs.readFileSync(path.resolve(SOURCES_DIR, '../Package.swift'), 'utf8');
  const pkgName = manifest.match(/name:\s*"([^"]+)"/)[1];
  const bundleName = `${pkgName}_PortnameCore.bundle`;
  assert.ok(code.includes(`"${bundleName}"`), `L10n must resolve ${bundleName}`);
  const buildScript = fs.readFileSync(path.resolve(__dirname, '../scripts/build-macos-app.sh'), 'utf8');
  assert.ok(buildScript.includes(`"${bundleName}"`), `build-macos-app.sh must ship ${bundleName}`);
});

// `swift test` builds DEBUG, where the resolver's last resort is
// Bundle.module — a bundle with the very file name the explicit search looks
// for. A test that only checks the resolved bundle's name passes even when
// every explicit candidate is broken, and the shipped app (which has no
// such fallback) silently reads no table at all. The explicit search is
// therefore a function of its own without any fallback, and the Swift test
// asserts that it finds the bundle.
test('the explicit resource bundle search has no fallback and is tested on its own', () => {
  const l10n = fs.readFileSync(path.join(SOURCES_DIR, 'PortnameCore/L10n.swift'), 'utf8')
    .split('\n').filter((line) => !line.trim().startsWith('//')).join('\n');
  const search = l10n.match(/static func explicitResourceBundle\(\) -> Bundle\? \{([\s\S]*?)\n {4}\}\n/);
  assert.ok(search, 'L10n.explicitResourceBundle() must exist');
  assert.ok(!search[1].includes('Bundle.module'), 'the explicit search must not fall back to Bundle.module');
  assert.ok(!/return Bundle\./.test(search[1]), 'the explicit search must not fall back to another bundle');
  assert.match(search[1], /return nil/, 'the explicit search reports a miss as nil');
  const locate = l10n.match(/static func locateResourceBundle\(\) -> Bundle \{([\s\S]*?)\n {4}\}\n/);
  assert.ok(locate, 'L10n.locateResourceBundle() must exist');
  assert.match(locate[1], /^\s*if let bundle = explicitResourceBundle\(\) \{\s*return bundle\s*\}/,
    'the resolver tries the explicit search first');

  const tests = fs.readFileSync(path.resolve(SOURCES_DIR, '../Tests/PortnameCoreTests/DiagnosticsLocalizationTests.swift'), 'utf8');
  assert.match(tests, /guard let \w+ = L10n\.explicitResourceBundle\(\) else \{\s*return XCTFail\(/,
    'the Swift resolver test must fail when the explicit search finds nothing');
});

// The tables live in a nested bundle, and CoreFoundation reads a nested
// bundle in the language it chose for the APP — among the localizations the
// app's Info.plist declares (no .lproj sits in the app's own
// Contents/Resources). A table the plist does not list is never read (the
// app stays German for everyone); a listed language without a table falls
// back to German silently. The generated plist must declare exactly the
// shipped tables, with the development region among them.
test('the generated app Info.plist declares exactly the shipped localizations', () => {
  const shipped = fs.readdirSync(path.join(SOURCES_DIR, 'PortnameCore/Resources'))
    .filter((name) => name.endsWith('.lproj'))
    .map((name) => name.slice(0, -'.lproj'.length))
    .sort();
  assert.ok(shipped.length >= 2, `expected the de and en tables (found ${shipped.join(', ')})`);

  const buildScript = fs.readFileSync(path.resolve(__dirname, '../scripts/build-macos-app.sh'), 'utf8');
  const plist = buildScript.match(/<plist version="1\.0">([\s\S]*?)<\/plist>/);
  assert.ok(plist, 'build-macos-app.sh must generate the Info.plist');
  const declared = plist[1].match(/<key>CFBundleLocalizations<\/key>\s*<array>([\s\S]*?)<\/array>/);
  assert.ok(declared, 'the Info.plist must declare CFBundleLocalizations');
  const languages = [...declared[1].matchAll(/<string>([^<]*)<\/string>/g)].map((m) => m[1]).sort();
  assert.deepStrictEqual(languages, shipped, 'CFBundleLocalizations must list exactly the shipped .lproj tables');

  const devRegion = plist[1].match(/<key>CFBundleDevelopmentRegion<\/key>\s*<string>([^<]*)<\/string>/);
  assert.ok(devRegion && languages.includes(devRegion[1]), 'the development region must be a declared localization');
  const manifest = fs.readFileSync(path.resolve(SOURCES_DIR, '../Package.swift'), 'utf8');
  assert.strictEqual(manifest.match(/defaultLocalization:\s*"([^"]+)"/)[1], devRegion[1],
    'the package default localization and the app development region must agree');

  // The bundle invariant checks the same tables the plist declares.
  const checked = buildScript.match(/for lang in ([a-z ]+); do/);
  assert.ok(checked, 'build-macos-app.sh must check the tables it ships');
  assert.deepStrictEqual(checked[1].trim().split(/\s+/).sort(), shipped);
});
