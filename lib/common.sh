# shellcheck shell=bash
set -Eeuo pipefail
IFS=$'\n\t'
shopt -s inherit_errexit 2>/dev/null || true

log() { printf '%s\n' "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

require_bin() { command -v "$1" >/dev/null || die "missing binary: $1"; }

json_compact() { jq -c . <<<"$1"; }
assert_json() { jq -e . >/dev/null <<<"$1" || die "invalid json"; }

sha256_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
size_of()   { stat -c%s "$1" 2>/dev/null || stat -f%z "$1"; }

add_to_array() {
  # $1 = json array, $2 = json object (must be valid JSON)
  jq --argjson o "$2" '. + [$o]' <<<"$1"
}

redact_arg() {
  local a="$1"
  case "$a" in
    --token=*|--secret=*|--password=*|--passphrase=*|--api-key=*|--apikey=*|--bearer=*)
      printf '%s' "${a%%=*}=[REDACTED]"
      ;;
    *)
      printf '%s' "$a"
      ;;
  esac
}