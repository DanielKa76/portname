# Exact process lookup for the installed GUI (sourced by
# scripts/install-macos-app.sh; bash).
#
# app_pids <executable-path>
#   Prints the PIDs of the current user's processes whose argv[0] is exactly
#   <executable-path> (optionally followed by arguments). `pgrep -f` matches
#   an unanchored extended regex against the whole argument list, so the bare
#   path would also hit processes that merely mention it (`lldb <path>`),
#   prefixes (`<path>Helper`) and — `.` being a wildcard — look-alike paths.
#   The path is therefore regex-escaped and anchored.
app_pids() {
  local re
  re="$(printf '%s' "$1" | sed 's/[][\.*^$+?(){}|]/\\&/g')"
  pgrep -u "$(id -u)" -f "^${re}( |\$)" 2>/dev/null || true
}
