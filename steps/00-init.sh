#!/bin/bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/config.sh"
source "$basepath/lib/appcfg.sh"
source "$basepath/lib/buildctx.sh"
source "$basepath/lib/gating.sh"

buildscript="${1:?expected buildscript path as arg1}"
shift || true

# load the app variables for a second time because arrays are not exportable and we use them for initializing buildctx here
appcfg_load_json "${PHXI_APP_CONFIG}"

# Generate initial build context
log "==> (init) generating initial build context"
ctx_build_init "$buildscript" "$@" || exit 1

log "==> (init) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

# Gate: verify source/build repo integrity if track is stable
log "==> (init) gating source/build repos for release_track=${RELEASE_TRACK}"
gate_dirty_source_repo "${RELEASE_TRACK}"
gate_dirty_build_repo "${RELEASE_TRACK}"

if [ "${#BUILD_COMPONENTS[@]}" -eq 0 ]; then
  die "no build components defined in build context!"
fi

log "==> (init) PWD=$(pwd)"
log "==> (init) BUILDCTX_PATH=${BUILDCTX_PATH}"
log "==> (init) BUILDCTX_REAL=$(realpath -m "${BUILDCTX_PATH}" 2>/dev/null || echo "${BUILDCTX_PATH}")"
log "==> (init) build.components=$(jq -c '.build.components' "${BUILDCTX_PATH}")"

# Init build context for each component
for component in "${BUILD_COMPONENTS[@]}";do
  log "==> (init) generating initial build context for component ${component}"
  repo="$( appcfg_component_repo "$component" )"
  ctx_component_init "${component}" "${OCI_REGISTRY}" "${repo}"
  ctx_index_set_tag "${component}" "${BUILD_ID_REGISTRY_SAFE}"
done