#!/bin/bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'rc=$?; echo "ERROR(rc=$rc) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $rc' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/config.sh"
source "$basepath/lib/buildctx.sh"

buildscript="${1:?expected buildscript path as arg1}"
shift || true

# Generate initial build context
log "==> (init) generating initial build context"
ctx_build_init "$buildscript" "$@" || exit 1

log "==> (init) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

# Init build context for each component
for COMPONENT in ${BUILD_COMPONENTS[@]};do
  log "==> (init) generating initial build context for component ${COMPONENT}"
  ctx_component_init "${COMPONENT}" "${OCI_REGISTRY}" "phxi/${APP}/${COMPONENT}"
  ctx_index_set_tag "${COMPONENT}" "${BUILD_ID_REGISTRY_SAFE}"
done
