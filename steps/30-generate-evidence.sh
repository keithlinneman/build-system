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
source "$basepath/lib/oras.sh"
source "$basepath/lib/signing.sh"
source "$basepath/lib/evidence.sh"

log "==> (evidence) starting step 30-generate-evidence"

log "==> (evidence) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

log "==> (evidence) initializing evidence environment"
evidence_init

log "==> (evidence) initializing oci environment"
initialize_oci

# Generate repo-wide evidence
log "==> (evidence) generating app-wide evidence"
evidence_generate_repo_source_sbom
# old local offline attach method
#evidence_attach_repo_source_sbom
# TODO: what do we attest this to now?
#evidence_attest_repo_source_sbom

## Generate per-component evidence
log "==> (evidence) generating per-component evidence"
for component in $( ctx_list_components );do
  # get component index ref digest to attest to
  index_subject_ref="$( ctx_get_component_field "$component" '.index.resolved.digest_ref' )"
  log "==> (evidence) generating source evidence for component=${component} (subject_ref=${index_subject_ref})"

  # Generate per-component sboms
  evidence_generate_component_source_sbom "${component}" "${index_subject_ref}"
  # old local offline attach method
  # attest and attach per-component sboms to component index
  #evidence_attach_component_sbom "${component}" "${index_subject_ref}"
  evidence_attest_component_sbom "${component}" "${index_subject_ref}"

  # Generate per-component scan reports
  evidence_generate_component_source_scan_reports "${component}" "${index_subject_ref}"
  # old local offline attach method
  ## attest and attach per-component scan reports to component index
  #evidence_attach_component_scan_reports "${component}" "${index_subject_ref}"
  evidence_attest_component_scan_reports "${component}" "${index_subject_ref}"

  for pkey in $( ctx_list_realized_platform_keys "$component" );do
    plat_label="$( ctx_get_platform_label_from_key "$component" "$pkey" )"
    artifact_digest="$( ctx_get_artifact_digest "$component" "$pkey" )"
    subject_ref="$(ctx_get_artifact_field "$component" "$pkey" '.resolved.digest_ref')"
    os="${plat_label%%/*}"; arch="${plat_label##*/}"

    if [[ -z "$artifact_digest" || "$artifact_digest" == "null" ]]; then
      die "==> (evidence) skipping component=${component} platform=${plat_label} - no artifact digest found"
      exit 1
    fi

    if [[ -z "$subject_ref" || "$subject_ref" == "null" ]]; then
      die "==> (evidence) skipping component=${component} platform=${plat_label} - no subject ref found"
      exit 1
    fi

    log "==> (evidence) generating artifact evidence for component=${component} platform=${plat_label} (subject_ref=${subject_ref})"

    # Generate per-artifact sboms
    evidence_generate_component_artifact_sbom "${component}" "${pkey}" "${subject_ref}"
    # old local offline attach method
    # evidence_attach_artifact_sbom "${component}" "${pkey}" "${subject_ref}"
    evidence_attest_component_artifact_sbom "${component}" "${pkey}" "${subject_ref}"

    # Generate per-artifact scan reports
    evidence_generate_component_artifact_scan_reports "${component}" "${pkey}" "${subject_ref}"
    # old local offline attach method
    # evidence_attach_artifact_scan_reports "${component}" "${pkey}" "${subject_ref}"
    evidence_attest_component_artifact_scan_reports "${component}" "${pkey}" "${subject_ref}"
  done
done