#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/buildctx.sh"
source "$basepath/lib/preserve.sh"

# Enable independent step execution
ctx_init_if_needed

log "==> (preserve-audit) starting step 50-preserve-audit"

log "==> (preserve-audit) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

log "==> (preserve-audit) preserving audit artifacts to S3"
preserve_audit_artifacts

log "==> (preserve-audit) listing s3 release contents"
list_audit_artifacts