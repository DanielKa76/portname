# Checksum-pinned procurement for bundled third-party files (sourced by
# scripts/bundle-macos.sh; bash). Invariant: the cache path only ever holds
# content that matched its pinned SHA-256 —
#   - downloads go to a temp file next to the cache entry and are moved into
#     place (atomic rename) only after verification, so an interrupted or
#     truncated transfer can never poison the cache;
#   - an explicit override file is verified BEFORE it is copied, so a wrong
#     file never replaces a good cached copy;
#   - a cached file that fails verification is removed and downloaded again.
#
# fetch_pinned <label> <url> <dest> <sha256> [<override-file>]
#   returns 0 with a verified <dest>, non-zero (message on stderr) otherwise.

pinned_sha256_ok() {
  echo "$2  $1" | shasum -a 256 -c - >/dev/null 2>&1
}

fetch_pinned() {
  local label="$1" url="$2" dest="$3" sha="$4" override="${5:-}"
  local dir base part
  dir="$(dirname "$dest")"
  base="$(basename "$dest")"
  case "$sha" in
    *[!0-9a-f]*|"") echo "error: $label: pinned SHA-256 is not set (got '$sha'); refusing to fetch unpinned content" >&2; return 1 ;;
  esac
  [ "${#sha}" -eq 64 ] || { echo "error: $label: pinned SHA-256 must be 64 hex characters" >&2; return 1; }
  mkdir -p "$dir" || return 1
  # Leftovers of an earlier interrupted run never carry the final name.
  rm -f "$dir/.$base.part."*

  if [ -n "$override" ]; then
    [ -f "$override" ] || { echo "error: $label: override file not found: $override" >&2; return 1; }
    pinned_sha256_ok "$override" "$sha" \
      || { echo "error: $label: $override does not match the pinned SHA-256; refusing to use it (cache left untouched)" >&2; return 1; }
    part="$(mktemp "$dir/.$base.part.XXXXXX")" || return 1
    if ! cp "$override" "$part" || ! mv -f "$part" "$dest"; then
      rm -f "$part"
      return 1
    fi
    return 0
  fi

  if [ -f "$dest" ]; then
    pinned_sha256_ok "$dest" "$sha" && return 0
    echo "warning: cached $label at $dest failed SHA-256 verification (partial or corrupt); removing it and downloading again" >&2
    rm -f "$dest"
  fi

  echo "==> Downloading $label from $url"
  part="$(mktemp "$dir/.$base.part.XXXXXX")" || return 1
  if ! curl -fL --max-time 600 -o "$part" "$url"; then
    rm -f "$part"
    echo "error: $label: download failed; place the verified file at $dest or pass it as an override" >&2
    return 1
  fi
  if ! pinned_sha256_ok "$part" "$sha"; then
    rm -f "$part"
    echo "error: $label: downloaded content does not match the pinned SHA-256; refusing to bundle unverified content" >&2
    return 1
  fi
  mv -f "$part" "$dest"
}
