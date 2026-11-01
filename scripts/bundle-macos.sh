#!/bin/bash
# Assemble the self-contained macOS beta artifact: dist/Portname.app with the
# GUI plus a bundled, checksum-pinned node runtime and the daemon payload
# (Resources/daemon, Resources/runtime), a generated MANIFEST.json inventory
# and third-party license copies.
#
# The result is an UNSIGNED (ad-hoc) BETA artifact for local testing.
# It is NOT distributable: Gatekeeper will block it. The release path
# (Developer ID + notarization) lives in scripts/release-package.sh.
#
# Usage:
#   scripts/bundle-macos.sh [--node-tarball FILE] [--cloudflared-tarball FILE]
#                           [--cloudflared-license FILE] [--skip-cloudflared]
#
# Offline builds: every pinned input accepts a verified local copy (checked
# against its pin before use) — --node-tarball, --cloudflared-tarball and
# --cloudflared-license (the LICENSE text of the pinned cloudflared tag).
# Alternatively pre-seed dist/cache with the verified files under their
# cache names (node-v<version>-darwin-arm64.tar.gz,
# cloudflared-<version>-cloudflared-darwin-arm64.tgz,
# cloudflared-<version>-LICENSE); a cached file that matches its pin is
# never downloaded again.
#
# Node runtime procurement (controlled, no download-and-execute):
#   1. version + platform + SHA-256 are pinned in scripts/runtime-pin.env;
#   2. the tarball comes from the cache (dist/cache) or is downloaded once
#      from the official nodejs.org dist server over HTTPS — into a temp
#      file that is renamed into the cache only after verification
#      (scripts/lib/pinned-fetch.sh);
#   3. the SHA-256 is ALWAYS verified against the pin before extraction;
#      a mismatch aborts the build. Only bin/node and the LICENSE are
#      extracted — the pinned binary is self-contained (system libs only),
#      unlike Homebrew's keg-linked node.
#
# cloudflared procurement (same contract, optional component): version and
# SHA-256 of the official cloudflare/cloudflared release asset are pinned in
# scripts/runtime-pin.env; archive and extracted binary are verified against
# the pin, the license comes from the same release tag. Any mismatch aborts
# the build — there is no fallback to whatever a local Homebrew has.
# --skip-cloudflared builds without it (public links then need a
# user-installed cloudflared).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_NAME="Portname"
BUNDLE_ID="dev.portname.app"
DIST_DIR="$ROOT/dist"
CACHE_DIR="$DIST_DIR/cache"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
RESOURCES="$APP_BUNDLE/Contents/Resources"

echo_err() { echo "error: $*" >&2; exit 1; }

[ "$(uname)" = "Darwin" ] || echo_err "bundle-macos.sh builds a macOS artifact; this is not macOS."
ARCH="$(uname -m)"
[ "$ARCH" = "arm64" ] || echo_err "only arm64 is built and tested (see docs/macos-bundle.md); refusing to ship an untested arch ('$ARCH')."

NODE_TARBALL_OVERRIDE=""
CF_TARBALL_OVERRIDE=""
CF_LICENSE_OVERRIDE=""
SKIP_CLOUDFLARED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --node-tarball) NODE_TARBALL_OVERRIDE="$2"; shift 2 ;;
    --cloudflared-tarball) CF_TARBALL_OVERRIDE="$2"; shift 2 ;;
    --cloudflared-license) CF_LICENSE_OVERRIDE="$2"; shift 2 ;;
    --skip-cloudflared) SKIP_CLOUDFLARED=1; shift ;;
    *) echo_err "unknown option: $1" ;;
  esac
done

command -v node >/dev/null || echo_err "node is required at build time (build machine only, not shipped)."
command -v shasum >/dev/null || echo_err "shasum is required to verify the pinned runtime checksums."

# --- 1. Procure + verify the pinned node runtime -----------------------------
source "$SCRIPT_DIR/runtime-pin.env"
source "$SCRIPT_DIR/lib/pinned-fetch.sh"

mkdir -p "$CACHE_DIR"
TARBALL="$CACHE_DIR/$NODE_RUNTIME_TARBALL"
# Cache entries only ever hold verified content (temp file + rename): an
# aborted download or a wrong --node-tarball can never poison the cache.
fetch_pinned "node runtime v$NODE_RUNTIME_VERSION ($NODE_RUNTIME_PLATFORM)" \
  "https://nodejs.org/dist/v$NODE_RUNTIME_VERSION/$NODE_RUNTIME_TARBALL" \
  "$TARBALL" "$NODE_RUNTIME_TARBALL_SHA256" "$NODE_TARBALL_OVERRIDE" \
  || echo_err "could not procure the pinned node runtime (--node-tarball FILE accepts a verified local copy)"
echo "==> Verifying pinned node runtime SHA-256"
echo "$NODE_RUNTIME_TARBALL_SHA256  $TARBALL" | shasum -a 256 -c - \
  || echo_err "node tarball checksum mismatch; refusing to bundle unverified content"

echo "==> Extracting node binary and license"
NODE_ROOT="node-v$NODE_RUNTIME_VERSION-$NODE_RUNTIME_PLATFORM"
EXTRACT="$CACHE_DIR/extract-v$NODE_RUNTIME_VERSION"
rm -rf "$EXTRACT"
mkdir -p "$EXTRACT"
tar -xzf "$TARBALL" -C "$EXTRACT" \
  "$NODE_ROOT/bin/node" \
  "$NODE_ROOT/LICENSE"
NODE_BIN="$EXTRACT/$NODE_ROOT/bin/node"
NODE_LICENSE="$EXTRACT/$NODE_ROOT/LICENSE"
NODE_SHA256="$(shasum -a 256 "$NODE_BIN" | cut -d' ' -f1)"

echo "==> Checking bundled node linkage is system-only (self-contained)"
# The pinned runtime must depend on macOS system libraries only; anything
# else (Homebrew keg paths, @rpath, third-party dylibs) would break the
# "works without Homebrew" guarantee on the target machine.
command -v otool >/dev/null 2>&1 \
  || echo_err "otool is required to verify the bundled runtime is self-contained (install the Xcode command line tools)."
NON_SYSTEM="$(otool -L "$NODE_BIN" | awk 'NR>1 {print $1}' | grep -v '^/usr/lib/' | grep -v '^/System/' || true)"
if [ -n "$NON_SYSTEM" ]; then
  echo_err "bundled node links non-system libraries — not self-contained:
$NON_SYSTEM"
fi

# --- 1b. Procure + verify the pinned cloudflared (optional component) --------
CF_BIN=""
CF_LICENSE=""
if [ "$SKIP_CLOUDFLARED" = "0" ]; then
  CF_TARBALL="$CACHE_DIR/cloudflared-$CLOUDFLARED_VERSION-$CLOUDFLARED_TARBALL"
  fetch_pinned "cloudflared $CLOUDFLARED_VERSION" \
    "https://github.com/cloudflare/cloudflared/releases/download/$CLOUDFLARED_VERSION/$CLOUDFLARED_TARBALL" \
    "$CF_TARBALL" "$CLOUDFLARED_TARBALL_SHA256" "$CF_TARBALL_OVERRIDE" \
    || echo_err "could not procure the pinned cloudflared (--cloudflared-tarball FILE accepts a verified local copy; --skip-cloudflared builds without public links)"
  # Apache-2.0 §4(a): the license text must ship with the binary — fatal.
  CF_LICENSE="$CACHE_DIR/cloudflared-$CLOUDFLARED_VERSION-LICENSE"
  fetch_pinned "cloudflared $CLOUDFLARED_VERSION LICENSE" \
    "https://raw.githubusercontent.com/cloudflare/cloudflared/$CLOUDFLARED_VERSION/LICENSE" \
    "$CF_LICENSE" "$CLOUDFLARED_LICENSE_SHA256" "$CF_LICENSE_OVERRIDE" \
    || echo_err "could not procure the pinned cloudflared license text (--cloudflared-license FILE accepts a verified local copy); refusing to bundle cloudflared without it"

  echo "==> Extracting cloudflared and verifying it against the vendor-published SHA-256"
  CF_EXTRACT="$CACHE_DIR/extract-cloudflared-$CLOUDFLARED_VERSION"
  rm -rf "$CF_EXTRACT"
  mkdir -p "$CF_EXTRACT"
  tar -xzf "$CF_TARBALL" -C "$CF_EXTRACT" cloudflared
  CF_BIN="$CF_EXTRACT/cloudflared"
  echo "$CLOUDFLARED_BINARY_SHA256  $CF_BIN" | shasum -a 256 -c - \
    || echo_err "cloudflared binary checksum mismatch; refusing to bundle unverified content"
  CF_NON_SYSTEM="$(otool -L "$CF_BIN" | awk 'NR>1 {print $1}' | grep -v '^/usr/lib/' | grep -v '^/System/' || true)"
  if [ -n "$CF_NON_SYSTEM" ]; then
    echo_err "bundled cloudflared links non-system libraries — not self-contained:
$CF_NON_SYSTEM"
  fi
  CF_REPORTED="$("$CF_BIN" --version 2>/dev/null | awk '{print $3}')"
  [ "$CF_REPORTED" = "$CLOUDFLARED_VERSION" ] \
    || echo_err "cloudflared reports version '$CF_REPORTED' but $CLOUDFLARED_VERSION is pinned"
fi

# --- 2. Build the GUI app (dev/ad-hoc base) ----------------------------------
"$SCRIPT_DIR/build-macos-app.sh"

# --- 3. Inject daemon payload, runtime, wrappers, licenses -------------------
APP_VERSION="$(node -p "require('$ROOT/package.json').version")"

echo "==> Staging daemon payload and runtime into Resources"
rm -rf "$RESOURCES/daemon" "$RESOURCES/runtime" "$RESOURCES/bin" "$RESOURCES/LICENSES" "$RESOURCES/MANIFEST.json"
mkdir -p "$RESOURCES/daemon/bin" "$RESOURCES/daemon/lib" "$RESOURCES/runtime/bin" "$RESOURCES/bin" "$RESOURCES/LICENSES"

cp "$ROOT/bin/portname.js" "$RESOURCES/daemon/bin/portname.js"
cp "$ROOT"/lib/*.js "$RESOURCES/daemon/lib/"
cp "$ROOT/package.json" "$RESOURCES/daemon/package.json"
cp "$NODE_BIN" "$RESOURCES/runtime/bin/node"
chmod 755 "$RESOURCES/runtime/bin/node"

CLOUDFLARED_JSON="null"
if [ -n "$CF_BIN" ]; then
  cp "$CF_BIN" "$RESOURCES/runtime/bin/cloudflared"
  chmod 755 "$RESOURCES/runtime/bin/cloudflared"
  cp "$CF_LICENSE" "$RESOURCES/LICENSES/cloudflared-LICENSE.txt"
  CLOUDFLARED_JSON="{\"version\":\"$CLOUDFLARED_VERSION\",\"source\":\"official cloudflare/cloudflared release asset $CLOUDFLARED_TARBALL, checksum-pinned in scripts/runtime-pin.env\",\"tarballSha256\":\"$CLOUDFLARED_TARBALL_SHA256\",\"binarySha256\":\"$CLOUDFLARED_BINARY_SHA256\",\"optional\":true}"
else
  echo "==> Skipping cloudflared (--skip-cloudflared); public links need a user-installed cloudflared"
fi

cp "$NODE_LICENSE" "$RESOURCES/LICENSES/nodejs-LICENSE.txt"
cp "$ROOT/LICENSE" "$RESOURCES/LICENSES/portname-LICENSE.txt"
{
  cat <<NOTICE
portname — MIT license, see portname-LICENSE.txt.
Bundled third-party components:
  - Node.js v$NODE_RUNTIME_VERSION (official darwin-arm64 distribution):
    MIT-style license, see nodejs-LICENSE.txt. Pinned tarball SHA-256:
    $NODE_RUNTIME_TARBALL_SHA256
NOTICE
  # Only name what actually ships.
  if [ -n "$CF_BIN" ]; then
    cat <<NOTICE
  - cloudflared $CLOUDFLARED_VERSION (optional, for public links): Apache
    License 2.0, see cloudflared-LICENSE.txt. Pinned binary SHA-256:
    $CLOUDFLARED_BINARY_SHA256 — https://github.com/cloudflare/cloudflared
NOTICE
  fi
} > "$RESOURCES/LICENSES/portname-NOTICE.txt"

# Both wrappers resolve symlinks before locating the runtime, so linking
# them into a PATH directory works (scripts/lib/cli-wrapper.sh).
source "$SCRIPT_DIR/lib/cli-wrapper.sh"

# CLI wrapper inside the app (works without any system node): first-run
# install/repair entry point documented for users. It lives under Resources/
# because Contents/MacOS must contain signed Mach-O code only; as a sealed
# resource the wrapper is still integrity-covered by the bundle signature.
write_cli_wrapper "$RESOURCES/bin/portname-cli" \
  "Runs the bundled portname CLI with the bundled node runtime."

# Payload wrapper: lands in the stable install location
# (~/Library/Application Support/Portname/bin/portname) via the install sync
# and runs the CLI against the payload's own runtime — the recommended way to
# control the installed background service.
write_cli_wrapper "$RESOURCES/bin/portname" \
  "Installed portname CLI (stable payload location; works without system node)."

# --- 4. Generate the component inventory (MANIFEST.json) ---------------------
echo "==> Generating MANIFEST.json (inventory + SHA-256 of every shipped file)"
COMPONENTS="$(node -e "
const pkg = require('$ROOT/package.json');
const cf = $CLOUDFLARED_JSON;
console.log(JSON.stringify({
  app: { name: 'portname', version: pkg.version, bundleId: '$BUNDLE_ID', arch: '$ARCH', minMacos: '14.0' },
  channel: 'beta-adhoc',
  nodeRuntime: { version: '$NODE_RUNTIME_VERSION', platform: '$NODE_RUNTIME_PLATFORM', tarballSha256: '$NODE_RUNTIME_TARBALL_SHA256', binarySha256: '$NODE_SHA256', source: 'official nodejs.org distribution, checksum-pinned in scripts/runtime-pin.env' },
  cloudflared: cf,
}))")"
node "$SCRIPT_DIR/lib/payload-manifest.js" generate "$RESOURCES" --bundle-id "$BUNDLE_ID" --components-json "$COMPONENTS"

# --- 5. Mark the channel, re-sign (ad-hoc), verify ---------------------------
echo "==> Marking bundle channel 'beta-adhoc' and re-signing (ad-hoc)"
plutil -replace PortnameBuildChannel -string "beta-adhoc" "$APP_BUNDLE/Contents/Info.plist"
codesign --force --sign - "$APP_BUNDLE"

echo "==> Verifying bundle"
codesign --verify --strict --verbose=1 "$APP_BUNDLE" || echo_err "codesign verification failed"
plutil -lint "$APP_BUNDLE/Contents/Info.plist" >/dev/null || echo_err "Info.plist lint failed"
node "$SCRIPT_DIR/lib/payload-manifest.js" verify "$RESOURCES" >/dev/null || echo_err "manifest verification failed"
CHAN="$(plutil -extract PortnameBuildChannel raw "$APP_BUNDLE/Contents/Info.plist")"
[ "$CHAN" = "beta-adhoc" ] || echo_err "unexpected build channel '$CHAN'"
"$RESOURCES/runtime/bin/node" --version >/dev/null || echo_err "bundled node runtime does not run"
"$RESOURCES/bin/portname-cli" help >/dev/null || echo_err "bundled CLI does not run"

echo ""
echo "Beta artifact built: $APP_BUNDLE"
echo "  node runtime:  v$NODE_RUNTIME_VERSION ($NODE_RUNTIME_PLATFORM, tarball sha256 $NODE_RUNTIME_TARBALL_SHA256)"
echo "  cloudflared:   $( [ -n "$CF_BIN" ] && echo "$CLOUDFLARED_VERSION (pinned, binary sha256 $CLOUDFLARED_BINARY_SHA256)" || echo "not bundled (--skip-cloudflared)" )"
echo "  channel:       beta-adhoc — LOCAL TEST ONLY, not distributable (ad-hoc signature; Gatekeeper blocks it)."
echo "  release path:  scripts/release-package.sh (Developer ID + notarization; intentionally not run here)"
