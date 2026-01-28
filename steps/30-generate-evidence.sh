#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_PATH="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd -P)/$( basename -- "${BASH_SOURCE[0]}" )"

basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/buildctx.sh"
source "$basepath/lib/oras.sh"
source "$basepath/lib/signing.sh"
source "$basepath/lib/evidence.sh"
source "$basepath/lib/inventory.sh"

log "==> (evidence) starting step 30-generate-evidence"

log "==> (evidence) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

log "==> (evidence) initializing evidence environment"
evidence_init

log "==> (evidence) initializing scanner environment"
scanner_init

log "==> (evidence) initializing oci environment"
initialize_oci

# Generate repo-wide evidence
log "==> (evidence) generating app-wide evidence"
evidence_generate_repo_source_sboms

log "==> (evidence) generating repo source scan reports"
evidence_generate_repo_source_scan_reports

## Generate per-component evidence
log "==> (evidence) generating per-component evidence"
for component in $( ctx_list_plan_components );do
  log "==> (evidence) initializing evidence for component=${component}"
  evidence_component_init "$component"
  # get component index ref digest to attest to
  index_subject_ref="$( ctx_get_component_field "$component" '.index.resolved.digest_ref' )"
  log "==> (evidence) generating source evidence for component=${component} (subject_ref=${index_subject_ref})"

  # Generate per-component sboms
  evidence_generate_component_source_sboms "${component}"
  # old local offline attach method
  # attest and attach per-component sboms to component index
  evidence_attest_component_index_sboms "${component}"

  # Generate (and attest) per-component license report from sboms
  evidence_generate_component_source_license_report "$component"

  # Generate per-component scan reports
  evidence_generate_component_source_scan_reports "${component}"
  # old local offline attach method
  ## attest and attach per-component scan reports to component index
  #evidence_attach_component_scan_reports "${component}" "${index_subject_ref}"
  evidence_attest_component_index_scans "${component}"

  #for pkey in $( ctx_list_realized_platform_keys "$component" );do
  for platform in $( ctx_list_plan_platforms );do
    pkey="$( ctx_pkey_from_label "$platform" )"
    artifact_digest="$( ctx_get_artifact_digest "$component" "$pkey" )"
    subject_ref="$(ctx_get_artifact_field "$component" "$pkey" '.resolved.digest_ref')"
    #os="${plat_label%%/*}"; arch="${plat_label##*/}"

    if [[ -z "$artifact_digest" || "$artifact_digest" == "null" ]]; then
      die "==> (evidence) skipping component=${component} platform=${platform} - no artifact digest found"
    fi
    if [[ -z "$subject_ref" || "$subject_ref" == "null" ]]; then
      die "==> (evidence) skipping component=${component} platform=${platform} - no subject ref found"
    fi

    log "==> (evidence) generating artifact evidence for component=${component} platform=${platform} (subject_ref=${subject_ref})"
    # Generate per-artifact sboms
    evidence_generate_component_artifact_sboms "${component}" "${pkey}"
    # old local offline attach method
    # evidence_attach_artifact_sbom "${component}" "${pkey}" "${subject_ref}"
    evidence_attest_component_artifact_sboms "${component}" "${pkey}"

    # Generate per-artifact licenses and attestations
    evidence_generate_component_artifact_license_report "$component" "$pkey"

    # Generate per-artifact scan reports
    evidence_generate_component_artifact_scan_reports "${component}" "${pkey}"
    # old local offline attach method
    # evidence_attach_artifact_scan_reports "${component}" "${pkey}" "${subject_ref}"
    evidence_attest_component_artifact_scan_reports "${component}" "${pkey}"
  done
done

log "==> (evidence) resolving refs (tag_ref/digest_ref)"
ctx_materialize_resolved_refs

log "==> (evidence) initializing OCI artifacts maps for inventory"
evidence_init_oci_maps

# Generate inventory.json, containing sizes, sha256sums, paths, everything for sboms/scans/licenses/signatures/provnence/etc
log "==> (inventory) generating inventory.json"
generate_inventory_json "${SCRIPT_PATH}" "$@" || die "failed to generate inventory json!"

# attest release.json to all component indexes
log "==> (evidence) attesting inventory.json to component indexes"
attest_inventory_json_to_indexes