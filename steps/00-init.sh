#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
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

# Gate: build-system repo must be clean for stable track (research if attacker could just modify build-system and add a commit, guess they could just edit this script in that case too..)
log "==> (init) gating build-system repo for release_track=${RELEASE_TRACK}"
gate_dirty_source_repo "${RELEASE_TRACK}"

# Gate: app source repo must be clean for stable track
log "==> (init) gating app source repo for release_track=${RELEASE_TRACK}"
gate_dirty_build_repo "${RELEASE_TRACK}"

# Gate: stable track requires tagged commit
log "==> (init) gating stable track tag requirement"
gate_stable_requires_tag "${RELEASE_TRACK}"

# Gate: tagged releases must be built from HEAD on main
log "==> (init) gating tagged release on main HEAD"
gate_tag_on_main_head

if [ "${#BUILD_COMPONENTS[@]}" -eq 0 ]; then
  die "no build components defined in build context!"
fi

log "==> (init) build.components=$(jq -c '.build.components' "${BUILDCTX_PATH}")"

# Init build context for each component
for component in "${BUILD_COMPONENTS[@]}";do
  log "==> (init) generating initial build context for component ${component}"
  repo="$( appcfg_component_repo "$component" )"
  ctx_component_init "${component}" "${OCI_REGISTRY}" "${repo}"
  ctx_index_set_tag "${component}" "${BUILD_ID_REGISTRY_SAFE}"
done