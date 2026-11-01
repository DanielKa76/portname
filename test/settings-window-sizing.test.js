// Guards for the settings window (SettingsWindowController.swift), which is
// pure AppKit hosting of the SwiftUI SettingsView and the window the user
// opens from the panel's gear entry.
//
// Regression background (crash on the gear click):
// NSHostingController.sizingOptions containing
// .preferredContentSize wires the SwiftUI size query into AppKit's
// constraint pass. While the window runs its updateConstraints pass, AppKit
// asks the hosting controller for preferredContentSize; the SwiftUI answer
// invalidates the same window's constraints
// (NSHostingView requestUpdate -> setNeedsUpdateConstraints ->
// -[NSWindow _postWindowNeedsUpdateConstraints]) and AppKit throws
// NSGenericException ("The window has been marked as needing another Update
// Constraints in Window pass, but it has already had more Update Constraints
// in Window passes than there are views in the window."). The app dies on
// the gear click. Window size is therefore set once, manually, via
// setContentSize(fittingSize) — and that manual sizing must stay.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert');
const test = require('node:test');

const ROOT = path.join(__dirname, '..');
const CONTROLLER = path.join(ROOT, 'macos', 'Sources', 'PortnameApp',
  'SettingsWindowController.swift');

// Comments in the controller deliberately document the crash mechanism by
// naming the option; only CODE may not use it. Strip `//` line comments
// before asserting (the file has no block comments).
function codeLines(src) {
  return src.split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');
}

test('settings window: sizingOptions must not re-introduce the preferredContentSize re-entrancy crash', () => {
  const src = fs.readFileSync(CONTROLLER, 'utf8');
  const code = codeLines(src);
  assert.ok(
    !code.includes('.preferredContentSize'),
    'SettingsWindowController.swift must not use .preferredContentSize — ' +
    'that sizingOption queries SwiftUI size inside the AppKit constraint pass, ' +
    'which invalidates the same window\'s constraints mid-pass and throws ' +
    'NSGenericException (gear-click crash, 2026-09-22)');
  assert.ok(
    !/sizingOptions\s*=/.test(code),
    'sizingOptions must stay at its default — no assignment, not even a subset');
});

test('settings window: manual sizing via setContentSize(fittingSize) must stay', () => {
  const code = codeLines(fs.readFileSync(CONTROLLER, 'utf8'));
  assert.ok(
    code.includes('setContentSize(host.view.fittingSize)'),
    'the one-time manual sizing setContentSize(host.view.fittingSize) must remain — ' +
    'it is what keeps the 520pt width and the exact first-open placement without ' +
    'sizingOptions');
});

test('settings window: resize re-anchor must not mutate the frame synchronously inside the resize callback', () => {
  const code = codeLines(fs.readFileSync(CONTROLLER, 'utf8'));
  const observer = code.slice(code.indexOf('didResizeNotification'));
  assert.ok(observer.includes('DispatchQueue.main.async'),
    'the didResize observer must defer applySlideOutFrame to the next runloop tick ' +
    '(synchronous frame mutation inside resize handling re-enters the layout pass)');
});

test('settings window: activation uses the macOS 14 API, not the deprecated ignoringOtherApps variant', () => {
  const code = codeLines(fs.readFileSync(CONTROLLER, 'utf8'));
  assert.ok(!code.includes('activate(ignoringOtherApps'),
    'NSApp.activate(ignoringOtherApps:) is deprecated since the macOS 14 SDK (deployment target 14)');
  assert.ok(code.includes('NSApp.activate()'),
    'the settings window must still activate the app explicitly (LSUIElement apps are not activated by ordering front)');
});
