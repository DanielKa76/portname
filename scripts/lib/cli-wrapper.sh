# CLI wrapper generator (sourced by scripts/bundle-macos.sh; bash).
#
# write_cli_wrapper <dest> <comment>
#   Writes an executable /bin/sh wrapper that runs the bundled CLI with the
#   bundled node runtime, both located relative to the wrapper's REAL
#   location: <wrapper dir>/../runtime/bin/node and ../daemon/bin/portname.js.
#   Symlinks are resolved first, so a link in a PATH directory (e.g.
#   /usr/local/bin/portname -> …/Portname/bin/portname) works.

write_cli_wrapper() {
  local dest="$1" comment="$2"
  {
    printf '#!/bin/sh\n# %s\n' "$comment"
    cat <<'WRAPPER'
# Resolve symlinks (bounded) so the runtime is found next to the real file,
# not next to a link in a PATH directory.
SELF="$0"
n=0
while [ -L "$SELF" ] && [ "$n" -lt 40 ]; do
  LINK="$(readlink "$SELF")"
  case "$LINK" in
    /*) SELF="$LINK" ;;
    *) SELF="$(dirname "$SELF")/$LINK" ;;
  esac
  n=$((n + 1))
done
DIR="$(cd -P "$(dirname "$SELF")/.." && pwd)"
exec "$DIR/runtime/bin/node" "$DIR/daemon/bin/portname.js" "$@"
WRAPPER
  } > "$dest"
  chmod 755 "$dest"
}
