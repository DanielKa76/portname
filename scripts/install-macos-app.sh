#!/bin/bash
# Install dist/Portname.app into ~/Applications without root.
# - replaces an existing install only if it really is Portname (same bundle id)
# - keeps a backup for rollback
# - quits the GUI if running; NEVER touches the background daemon
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$ROOT/dist/Portname.app"
BUNDLE_ID="dev.portname.app"
APP_NAME="Portname"
DEST_DIR="$HOME/Applications"
DEST="$DEST_DIR/$APP_NAME.app"

if [ ! -d "$SRC" ]; then
  echo "error: $SRC not found. Run scripts/build-macos-app.sh first." >&2
  exit 1
fi

# Sanity: the source must be the Portname bundle we built.
SRC_ID="$(defaults read "$SRC/Contents/Info" CFBundleIdentifier 2>/dev/null || true)"
if [ "$SRC_ID" != "$BUNDLE_ID" ]; then
  echo "error: unexpected bundle id '$SRC_ID' (expected $BUNDLE_ID); refusing to install." >&2
  exit 1
fi

mkdir -p "$DEST_DIR"

# Quit the running GUI if it is our app — addressed by bundle id and the
# exact installed executable path, never by a bare process-name match (a
# foreign process could share the name "Portname"). Only processes of this
# user whose argv[0] IS that path count: a debugger, editor or other tool
# that merely has the path among its arguments is never signalled
# (scripts/lib/app-pids.sh). The daemon (dev.portname.daemon) is a separate
# LaunchAgent and is never touched.
source "$SCRIPT_DIR/lib/app-pids.sh"
APP_EXE="$DEST/Contents/MacOS/$APP_NAME"
RUNNING_PIDS="$(app_pids "$APP_EXE")"
if [ -n "$RUNNING_PIDS" ]; then
  echo "==> Quitting running $APP_NAME (GUI only — daemon keeps running)"
  osascript -e 'tell application id "dev.portname.app" to quit' >/dev/null 2>&1 || true
  sleep 1
  REMAINING="$(app_pids "$APP_EXE")"
  if [ -n "$REMAINING" ]; then
    # Still alive after the graceful quit: kill exactly those pids.
    kill $REMAINING 2>/dev/null || true
    sleep 1
  fi
fi

BACKUP="$DEST_DIR/.$APP_NAME.app.backup-$(date +%Y%m%d-%H%M%S)"

if [ -d "$DEST" ]; then
  DEST_ID="$(defaults read "$DEST/Contents/Info" CFBundleIdentifier 2>/dev/null || true)"
  if [ "$DEST_ID" != "$BUNDLE_ID" ]; then
    echo "error: $DEST exists but is not $APP_NAME (bundle id '$DEST_ID'); refusing to replace." >&2
    exit 1
  fi
  echo "==> Backing up existing install to $BACKUP"
  mv "$DEST" "$BACKUP"
fi

rollback() {
  echo "error: install failed; rolling back." >&2
  rm -rf "$DEST"
  if [ -d "$BACKUP" ]; then
    mv "$BACKUP" "$DEST"
    echo "==> Restored previous install." >&2
  fi
  exit 1
}

echo "==> Installing to $DEST"
ditto "$SRC" "$DEST" || rollback

echo "==> Verifying signature and bundle id"
codesign --verify --strict "$DEST" || rollback
INSTALLED_ID="$(defaults read "$DEST/Contents/Info" CFBundleIdentifier 2>/dev/null || true)"
[ "$INSTALLED_ID" = "$BUNDLE_ID" ] || rollback

# Only remove the backup once the new install verified.
if [ -d "$BACKUP" ]; then
  echo "==> Removing backup (install verified). Keep it? It was: $BACKUP"
  rm -rf "$BACKUP"
fi

echo "Installed: $DEST"
echo "Start it with: open ~/Applications/Portname.app"
echo "Note: this installs the GUI only. The background daemon is managed by 'portname install' (LaunchAgent)."
