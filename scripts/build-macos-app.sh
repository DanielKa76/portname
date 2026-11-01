#!/bin/bash
# Build dist/Portname.app from the SwiftPM release binary.
# Works from any current directory; locates the repo root itself.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MACOS_DIR="$ROOT/macos"
APP_NAME="Portname"
BUNDLE_ID="dev.portname.app"
APP_VERSION="$(node -p "require('$ROOT/package.json').version" 2>/dev/null || echo 0.1.0)"
DIST_DIR="$ROOT/dist"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
# SwiftPM resource bundle of PortnameCore (the Localizable tables). It must
# ship in Contents/Resources: L10n resolves it there; without it the app
# falls back to German-only text (and older builds crashed on launch).
L10N_BUNDLE_NAME="portname-macos_PortnameCore.bundle"

echo "==> Building SwiftPM release binary"
cd "$MACOS_DIR"
swift build -c release

# Ask SwiftPM where the products are instead of assuming .build/release —
# the layout differs between build systems (native vs. swiftbuild).
BIN_DIR="$(swift build -c release --show-bin-path)"
BIN="$BIN_DIR/$APP_NAME"
test -x "$BIN" || { echo "error: release binary not found at $BIN" >&2; exit 1; }
L10N_BUNDLE="$BIN_DIR/$L10N_BUNDLE_NAME"
[ -d "$L10N_BUNDLE" ] || { echo "error: SwiftPM resource bundle not found at $L10N_BUNDLE" >&2; exit 1; }

# Both localization tables, in either bundle layout (flat or Contents/Resources).
has_l10n_tables() {
  for lang in de en; do
    [ -f "$1/$lang.lproj/Localizable.strings" ] \
      || [ -f "$1/Contents/Resources/$lang.lproj/Localizable.strings" ] \
      || return 1
  done
}

echo "==> Assembling $APP_BUNDLE"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

cat > "$APP_BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$APP_NAME</string>
  <key>CFBundleDisplayName</key><string>portname</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundleExecutable</key><string>$APP_NAME</string>
  <key>CFBundleShortVersionString</key><string>$APP_VERSION</string>
  <key>CFBundleVersion</key><string>$APP_VERSION</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>CFBundleDevelopmentRegion</key><string>de</string>
  <key>CFBundleLocalizations</key><array><string>de</string><string>en</string></array>
  <key>PortnameBuildChannel</key><string>dev-adhoc</string>
</dict>
</plist>
PLIST

cp "$BIN" "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
chmod 755 "$APP_BUNDLE/Contents/MacOS/$APP_NAME"
# Before signing, so the bundle seal covers the tables. Contents/Resources,
# never the .app root: content there breaks `codesign --verify --strict`.
cp -R "$L10N_BUNDLE" "$APP_BUNDLE/Contents/Resources/$L10N_BUNDLE_NAME"

echo "==> Ad-hoc signing"
codesign --force --sign - "$APP_BUNDLE"

echo "==> Verifying signature and bundle invariants"
codesign --verify --strict --verbose=1 "$APP_BUNDLE"
has_l10n_tables "$APP_BUNDLE/Contents/Resources/$L10N_BUNDLE_NAME" \
  || { echo "error: $L10N_BUNDLE_NAME with de/en Localizable.strings missing from Contents/Resources" >&2; exit 1; }
plutil -lint "$APP_BUNDLE/Contents/Info.plist"
INVARIANT="$(plutil -extract LSUIElement raw "$APP_BUNDLE/Contents/Info.plist" 2>/dev/null || echo missing)"
[ "$INVARIANT" = "true" ] || { echo "error: LSUIElement must be true" >&2; exit 1; }
INVARIANT="$(plutil -extract CFBundleIdentifier raw "$APP_BUNDLE/Contents/Info.plist")"
[ "$INVARIANT" = "$BUNDLE_ID" ] || { echo "error: wrong CFBundleIdentifier '$INVARIANT'" >&2; exit 1; }
INVARIANT="$(plutil -extract CFBundleExecutable raw "$APP_BUNDLE/Contents/Info.plist")"
[ "$INVARIANT" = "$APP_NAME" ] || { echo "error: wrong CFBundleExecutable '$INVARIANT'" >&2; exit 1; }
# This script only ever produces the developer artifact. Ad-hoc signing is a
# dev-only marker; the distributable path is scripts/release-package.sh.
INVARIANT="$(plutil -extract PortnameBuildChannel raw "$APP_BUNDLE/Contents/Info.plist")"
[ "$INVARIANT" = "dev-adhoc" ] || { echo "error: wrong build channel '$INVARIANT'" >&2; exit 1; }

echo "Built (dev-adhoc — developer artifact, not for distribution): $APP_BUNDLE"
