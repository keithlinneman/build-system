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
  # $1 = json array, $2 = json object
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

ctx_init_if_needed() {
  # testing ways to allow for independent step execution
  if [[ -z "${BUILDCTX_PATH:-}" ]]; then
    : "${PHXI_WORKDIR:?Set PHXI_WORKDIR to the kept workdir}"
    log "==> (common) initializing build context from PHXI_WORKDIR=${PHXI_WORKDIR}"
    export BUILDCTX_PATH="${PHXI_WORKDIR}/state/buildctx.json"
    export DIST="${PHXI_WORKDIR}/dist"
    PHXI_SOURCE_DIR="$(jq -r '.source.local_path // "/src"' "$BUILDCTX_PATH")"
    PHXI_APP_CONFIG="${PHXI_SOURCE_DIR}/build/app.json"

    basepath="${SCRIPT_DIR%/*}"
    source "$basepath/lib/appcfg.sh"
    appcfg_load_json "$PHXI_APP_CONFIG"
    config_resolve_ssm_params
    cd "$PHXI_SOURCE_DIR"
  fi
}