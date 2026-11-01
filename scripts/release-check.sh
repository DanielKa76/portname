#!/bin/bash
# Local release check for the self-contained macOS bundle.
#
# What it verifies ON THIS MACHINE (all pass/fail here):
#   1. node test suite                (npm test, build machine's node)
#   2. swift build                    (macos/)
#   3. dev GUI app                    (build + codesign + plutil + channel marker
#                                      + localization bundle in Contents/Resources)
#   4. self-contained beta bundle     (pin freshness, pinned runtime checksums,
#                                      manifest, bundled CLI)
#   5. node test suite on the BUNDLED runtime (the Node that actually ships;
#      the tests start their children via process.execPath, so those run on
#      it too)
#   6. ISOLATED install             (temp $HOME; a logging launchctl STUB is
#      first on the child PATH — the real launchctl is never invoked and
#      nothing is loaded; the generated LaunchAgent plist is validated with
#      plutil, must keep the respawn throttle (KeepAlive + ThrottleInterval)
#      and must reference only the stable payload, never this
#      checkout, a Cellar path, the .app or a temp/download dir; the full
#      uninstall path runs through the same stub)
#
# What it deliberately does NOT cover (real release gates — see
# docs/release-checklist.md, status OPEN): clean Mac/VM, Gatekeeper/quarantine,
# reboot/login restart, real upgrade/rollback on a user machine, Developer-ID
# signing and notarization runs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_BUNDLE="$ROOT/dist/Portname.app"
RESOURCES="$APP_BUNDLE/Contents/Resources"

step() { printf '\n=== %s ===\n' "$*"; }
fail() { echo "RELEASE CHECK FAILED: $*" >&2; exit 1; }

# The GUI's localization tables must ship inside the app (L10n resolves them
# from Contents/Resources; the SwiftPM build-path fallback only exists on
# this machine and would mask a missing copy here).
L10N_BUNDLE="$RESOURCES/portname-macos_PortnameCore.bundle"
check_l10n_bundle() {
  for lang in de en; do
    [ -f "$L10N_BUNDLE/$lang.lproj/Localizable.strings" ] \
      || [ -f "$L10N_BUNDLE/Contents/Resources/$lang.lproj/Localizable.strings" ] \
      || fail "$1: $lang Localizable.strings missing from $L10N_BUNDLE"
  done
}

[ "$(uname)" = "Darwin" ] || fail "release-check runs on macOS only."
[ -n "${HOME:-}" ] || fail "HOME must be set (sanity)."
REAL_HOME="$HOME"

step "1/7 node test suite (build machine node $(node --version))"
( cd "$ROOT" && npm test ) || fail "npm test"

step "2/7 swift build (macos/)"
( cd "$ROOT/macos" && swift build ) || fail "swift build"

step "3/7 dev GUI app build + invariants"
( "$SCRIPT_DIR/build-macos-app.sh" ) || fail "build-macos-app.sh"
codesign --verify --strict "$APP_BUNDLE" || fail "dev app signature"
plutil -lint "$APP_BUNDLE/Contents/Info.plist" >/dev/null || fail "dev app Info.plist"
[ "$(plutil -extract PortnameBuildChannel raw "$APP_BUNDLE/Contents/Info.plist")" = "dev-adhoc" ] \
  || fail "dev app must be marked dev-adhoc"
check_l10n_bundle "dev app"

step "4/7 self-contained beta bundle"
# The bundle has no auto-update: a runtime with a known security fix pending
# must not ship. Offline, this is only a warning (the pin itself is still
# checksum-verified by bundle-macos.sh).
source "$SCRIPT_DIR/runtime-pin.env"
FRESHNESS=0
node "$SCRIPT_DIR/lib/node-pin-freshness.js" "$NODE_RUNTIME_VERSION" || FRESHNESS=$?
case "$FRESHNESS" in
  0) ;;
  3) echo "WARNING: Node pin freshness not verified (offline?) — check nodejs.org/en/blog/vulnerability before releasing." >&2 ;;
  *) fail "pinned node runtime v$NODE_RUNTIME_VERSION has a newer security release (scripts/runtime-pin.env)" ;;
esac
( "$SCRIPT_DIR/bundle-macos.sh" ) || fail "bundle-macos.sh"
codesign --verify --strict "$APP_BUNDLE" || fail "bundle signature (ad-hoc)"
node "$SCRIPT_DIR/lib/payload-manifest.js" verify "$RESOURCES" || fail "bundle manifest"
[ "$(plutil -extract PortnameBuildChannel raw "$APP_BUNDLE/Contents/Info.plist")" = "beta-adhoc" ] \
  || fail "bundle must be marked beta-adhoc"
check_l10n_bundle "beta bundle"
BUNDLED_NODE_VERSION="$("$RESOURCES/runtime/bin/node" --version)" || fail "bundled node does not run"
echo "bundled node runtime: $BUNDLED_NODE_VERSION"

step "5/7 node test suite on the bundled runtime ($BUNDLED_NODE_VERSION)"
# Step 1 ran on whatever node is on PATH; this is the runtime users get.
( cd "$ROOT" && "$RESOURCES/runtime/bin/node" --test 'test/**/*.test.js' ) \
  || fail "node test suite on bundled runtime $BUNDLED_NODE_VERSION"

step "6/7 isolated install (temp HOME; launchctl is a logging stub, never real)"
# A short root, not $TMPDIR: macOS's per-user /var/folders/<2>/<30>/T/ alone
# is 49 bytes and pushes <root>/home/.portname/daemon.sock past the 103-byte
# Unix socket path limit that `install` enforces (lib/config.js
# MAX_SOCKET_PATH_BYTES). Canonicalized PHYSICALLY (/tmp is a symlink to
# /private/tmp): the payload wrapper and node resolve their own location
# physically, so a logical HOME would make the installed CLI miss its
# stable payload and the reinstall below take the checkout branch.
ISOTMP="$(mktemp -d /tmp/pnrc.XXXXXX)"
ISOTMP="$(cd "$ISOTMP" && pwd -P)"
trap 'rm -rf "$ISOTMP"' EXIT
ISO_HOME="$ISOTMP/home"
mkdir -p "$ISO_HOME"
export HOME="$ISO_HOME"
export PORTNAME_DIR="$ISO_HOME/.portname"

# launchctl STUB: `launchctl bootout` resolves the service
# by label even when handed a foreign plist path, so this check must never
# reach the real launchctl. The stub is first on the child's PATH
# (execFileSync resolves through the child PATH), logs every invocation to a
# file and exits 0 — launchd is never touched, and the log doubles as the
# proof that the stub (not the real binary) was used.
STUBBIN="$ISOTMP/stubbin"
LC_LOG="$ISOTMP/launchctl-calls.log"
mkdir -p "$STUBBIN"
cat > "$STUBBIN/launchctl" <<STUB
#!/bin/sh
printf '%s\n' "\$*" >> "$LC_LOG"
exit 0
STUB
chmod +x "$STUBBIN/launchctl"
run_stubbed() { PATH="$STUBBIN:$PATH" "$@"; }

PLIST="$ISO_HOME/Library/LaunchAgents/dev.portname.daemon.plist"
UID_N="$(id -u)"

run_stubbed "$RESOURCES/bin/portname-cli" install \
  || fail "bundle install"
grep -qx "bootout gui/$UID_N $PLIST" "$LC_LOG" \
  || fail "stub launchctl did not record the install bootout"
grep -qx "bootstrap gui/$UID_N $PLIST" "$LC_LOG" \
  || fail "stub launchctl did not record the install bootstrap"

plutil -lint "$PLIST" >/dev/null || fail "generated LaunchAgent plist fails plutil"
[ "$(plutil -extract Label raw "$PLIST")" = "dev.portname.daemon" ] || fail "wrong LaunchAgent label"
[ "$(plutil -extract RunAtLoad raw "$PLIST")" = "true" ] || fail "RunAtLoad must be true"
[ "$(plutil -extract KeepAlive raw "$PLIST")" = "true" ] || fail "KeepAlive must be true"
# Respawn throttle: the same static (plutil-free) check the node test suite
# runs against the generated plist.
node "$SCRIPT_DIR/lib/launch-agent-check.js" "$PLIST" || fail "LaunchAgent respawn throttle"

PAYLOAD_DIR="$ISO_HOME/Library/Application Support/Portname"
# Whichever CLI wrote the plist, the agent must reference only the stable
# payload: node and the entry script inside it, and the daemon's PATH led by
# the payload's runtime/bin (the bundled cloudflared). An install that took
# the developer-checkout branch still exits 0, so the exit status alone
# proves nothing.
check_agent_paths() {
  local args_json node_arg entry_arg daemon_path bad
  args_json="$(plutil -extract ProgramArguments json -o - "$PLIST")" || fail "$1: LaunchAgent has no ProgramArguments"
  node_arg="$(node -e "console.log(JSON.parse(process.argv[1])[0])" "$args_json")"
  entry_arg="$(node -e "console.log(JSON.parse(process.argv[1])[1])" "$args_json")"
  case "$node_arg" in "$PAYLOAD_DIR"/*) ;; *) fail "$1: node path not inside stable payload: $node_arg" ;; esac
  case "$entry_arg" in "$PAYLOAD_DIR"/*) ;; *) fail "$1: entry path not inside stable payload: $entry_arg" ;; esac
  for bad in "$ROOT" "Cellar" ".app" "$ISOTMP/cache"; do
    case "$node_arg$entry_arg" in
      *"$bad"*) fail "$1: LaunchAgent references forbidden path component '$bad'" ;;
    esac
  done
  [ -x "$node_arg" ] || fail "$1: pinned node path is not executable: $node_arg"
  [ -f "$entry_arg" ] || fail "$1: daemon entry missing: $entry_arg"
  daemon_path="$(plutil -extract EnvironmentVariables.PATH raw "$PLIST")" \
    || fail "$1: LaunchAgent has no EnvironmentVariables.PATH"
  case "$daemon_path" in
    "$PAYLOAD_DIR/runtime/bin:"*) ;;
    *) fail "$1: daemon PATH does not start with the payload runtime: $daemon_path" ;;
  esac
}
check_agent_paths "bundle install"

node "$SCRIPT_DIR/lib/payload-manifest.js" verify "$PAYLOAD_DIR" || fail "installed payload manifest"
"$PAYLOAD_DIR/bin/portname" help >/dev/null || fail "installed payload CLI does not run"
run_stubbed "$PAYLOAD_DIR/bin/portname" install >/dev/null || fail "payload reinstall (repair path) failed"
check_agent_paths "payload reinstall (repair path)"

# Idempotency: a second install must detect the intact payload and leave it
# untouched (no re-sync, no repair).
SECOND_OUT="$(run_stubbed "$RESOURCES/bin/portname-cli" install)" \
  || fail "second install failed"
echo "$SECOND_OUT" | grep -q "up to date" \
  || fail "second install did not report an intact payload: $SECOND_OUT"

step "7/7 CLI negative check against isolated socket (no daemon started)"
if "$PAYLOAD_DIR/bin/portname" status >/dev/null 2>&1; then
  fail "status unexpectedly succeeded without a daemon"
else
  echo "status fails cleanly without a daemon (expected)."
fi

# Full uninstall path (same stub): removes the agent plist and the installed
# payload — proves the whole install/uninstall lifecycle works launchctl-free.
run_stubbed "$PAYLOAD_DIR/bin/portname" uninstall >/dev/null \
  || fail "uninstall"
grep -qx "bootout gui/$UID_N $PLIST" "$LC_LOG" \
  || fail "stub launchctl did not record the uninstall bootout"
if [ -f "$PLIST" ]; then fail "agent plist survived uninstall"; fi
if [ -d "$PAYLOAD_DIR" ]; then fail "installed payload survived uninstall"; fi
# Only the stubbed launchctl was ever reachable: the log must contain
# nothing but bootout/bootstrap calls for this temp plist.
if grep -qv -e "bootout gui/$UID_N $PLIST" -e "bootstrap gui/$UID_N $PLIST" "$LC_LOG"; then
  fail "unexpected launchctl invocation recorded: $(grep -v -e "bootout gui/$UID_N $PLIST" -e "bootstrap gui/$UID_N $PLIST" "$LC_LOG" | head -3)"
fi

export HOME="$REAL_HOME"
unset PORTNAME_DIR

printf '\n'
echo "RELEASE CHECK PASSED (local, arm64, macOS $(sw_vers -productVersion))."
echo "Verified here: tests (build-machine node + bundled runtime), swift build, dev app,"
echo "bundle+manifest+pinned runtimes, isolated install/uninstall lifecycle with plist validation via a logging"
echo "launchctl stub; the real launchctl was never invoked, nothing was loaded."
echo "Open real-world gates (docs/release-checklist.md): clean Mac/VM, Gatekeeper/"
echo "quarantine, reboot/login, upgrade/rollback on a real machine, Developer-ID"
echo "signing + notarization."
