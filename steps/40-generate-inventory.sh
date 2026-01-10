#!/bin/bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'rc=$?; echo "ERROR(rc=$rc) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $rc' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename -- "${BASH_SOURCE[0]}")"

basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/config.sh"
source "$basepath/lib/buildctx.sh"
source "$basepath/lib/inventory.sh"
source "$basepath/lib/signing.sh"
source "$basepath/lib/evidence.sh"

log "==> (build) starting inventory generation"

log "==> (build) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

log "==> (evidence) initializing OCI artifacts maps for inventory"
evidence_init_oci_maps

# Generate release.json, containing sizes, sha256sums, paths, etc
log "==> (build) generating inventory.json"
generate_inventory_json "${SCRIPT_PATH}" "$@" || { die "failed to generate inventory json!"; exit 1; }

# cosign inventory.json
log "==> (sign) signing inventory.json"
if [[ ! -s dist/inventory.json ]];then
  die "Missing/invalid dist/inventory.json - refusing to sign or proceed"
  exit 1
fi
signbinary "dist/inventory.json" || { die "failed to sign inventory.json"; exit 1; }