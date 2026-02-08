#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# SCRIPT_PATH="${SCRIPT_DIR}/$(basename -- "${BASH_SOURCE[0]}")"

basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/buildctx.sh"
source "$basepath/lib/inventory.sh"
source "$basepath/lib/signing.sh"
source "$basepath/lib/evidence.sh"
source "$basepath/lib/oras.sh"
source "$basepath/lib/release.sh"
source "$basepath/lib/summary.sh"
source "$basepath/lib/gating.sh"

# Enable independent step execution
ctx_init_if_needed

log "==> (release) starting step 40-generate-release"

log "==> (release) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

# # generate_release_json
# log "==> (release) generating release.json"
# generate_release_json || die "failed to generate release json!"

# Gate: license compliance
log "==> (release) gating license compliance"
for component in $( ctx_list_plan_components ); do
  src_lic="${DIST}/${component}/license/source/source.licenses.json"
  if [[ -f "$src_lic" ]]; then
    gate_license_compliance "$src_lic" "${RELEASE_TRACK:-warn}"
  else
    # we may want to log here instead or have that as a defined policy option
    # log "[-] WARNING: no source license report found for component=${component} at expected path ${src_lic}, skipping license compliance gate for this component"
    die "no source license report found for component=${component} at expected path ${src_lic}, refusing build"
  fi
done

# Generate per-component release manifest
log "==> (evidence) generating per-component release manifests"
for component in $( ctx_list_plan_components );do
  # generate release.json manifest for component
  generate_component_release_json "$component" || die "failed to generate release manifest for component=${component}!"
  # attest release.json to component index
  log "==> (release) attesting release.json to component indexes"
  attest_release_json_to_component_index "$component" || die "failed to attest release.json to component index for component=${component}!"
  # sign the release.json for s3 release flow verification
  sign_release_json_for_component "$component" || die "failed to sign release.json for component=${component}!"
done

