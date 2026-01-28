#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/config.sh"
source "$basepath/lib/buildctx.sh"
source "$basepath/lib/oras.sh"

log "==> (build) starting step 20-push-oci"

log "==> (build) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

log "==> (build) initializing oci environment"
initialize_oci

log "==> (oci) preparing to iterate artifacts to push to registry"
for component in $( ctx_list_components );do
  log "==> (oci) pushing OCI artifacts for component:${component}"
  for platkey in $( ctx_list_realized_platform_keys "${component}" );do
    oci_push_component_artifact "${component}" "${platkey}"
  done

  log "==> (oci) pushing OCI index for component:${component}"
  oci_push_component_index "$component"
done

# Add resolved refs to build context for inventory generation
ctx_materialize_resolved_refs