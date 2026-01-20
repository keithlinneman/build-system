#!/bin/bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# SCRIPT_PATH="${SCRIPT_DIR}/$(basename -- "${BASH_SOURCE[0]}")"

basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/config.sh"
source "$basepath/lib/buildctx.sh"
source "$basepath/lib/inventory.sh"
source "$basepath/lib/signing.sh"
source "$basepath/lib/evidence.sh"
source "$basepath/lib/oras.sh"
source "$basepath/lib/release.sh"

log "==> (release) starting step 40-generate-release"

log "==> (release) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

# generate_release_json
log "==> (release) generating release.json"
generate_release_json || die "failed to generate release json!"

# attest release.json to all component indexes
log "==> (release) attesting release.json to component indexes"
attest_release_json_to_indexes

# sign the release.json for s3 release flow verification
sign_file "${DIST}/release.json"