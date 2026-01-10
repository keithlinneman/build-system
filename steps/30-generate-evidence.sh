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
source "$basepath/lib/signing.sh"
source "$basepath/lib/evidence.sh"

log "==> (evidence) starting step 30-generate-evidence"

log "==> (evidence) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

log "==> (evidence) initializing evidence environment"
evidence_init

# Generate repo-wide evidence
log "==> (evidence) generating app-wide evidence"
evidence_generate_repo_source_sbom
evidence_attach_repo_source_sbom

## Generate per-component evidence
log "==> (evidence) generating per-component evidence"
for component in $( ctx_list_components );do
  # get component index ref digest to attest to
  index_subject_ref="$( ctx_get_component_field "$component" '.index.resolved.digest_ref' )"
  log "==> (evidence) generating evidence for component ${component} (subject_ref=${index_subject_ref})"

  # Generate per-artifact sboms
  evidence_generate_component_sbom "${component}" "${index_subject_ref}"
  evidence_attach_component_sbom "${component}" "${index_subject_ref}"

  # Generate per-artifact scan reports
  evidence_generate_component_scan_reports "${component}" "${index_subject_ref}"
  evidence_attach_component_scan_reports "${component}" "${index_subject_ref}"
done