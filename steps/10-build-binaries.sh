#!/bin/bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/config.sh"
source "$basepath/lib/buildctx.sh"
source "$basepath/lib/build.sh"
source "$basepath/lib/evidence.sh"

log "==> (build) starting step 10-build-binaries"

log "==> (build) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

log "==> (build) initializing build environment"
initialize_build_env || exit 1

for component in $( ctx_list_plan_components );do
  log "==> (build) starting component=${component}"

  for platform in $( ctx_list_plan_platforms );do
    # build platform binary
    log "==> (build) building component=${component} platform=${platform}"
    build_component_artifact "${component}" "${platform}"
  done

done