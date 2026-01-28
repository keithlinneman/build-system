# shellcheck shell=bash

appcfg_load_json() {
  local cfg_path="${1:?cfg_path required}"
  [[ -f "$cfg_path" ]] || die "app config not found: $cfg_path"

  local schema
  schema="$(jq -r '.schema // empty' "$cfg_path")"
  [[ "$schema" == "phxi.appcfg.v1" ]] || die "unsupported app config schema: $schema"

  export APP VERPKG DIST BUILDCTX_PATH
  APP="$(jq -r '.app' "$cfg_path")"
  VERPKG="$(jq -r '.version_pkg' "$cfg_path")"

  # defaults -> bash arrays
  # this is used and unexported because its an array
  # shellcheck disable=SC2034
  mapfile -t BUILD_PLATFORMS < <(jq -r '.defaults.platforms[]' "$cfg_path")
  # shellcheck disable=SC2034
  mapfile -t BUILD_COMPONENTS < <(jq -r '.defaults.components[]' "$cfg_path")

  export OCI_REGISTRY BINARY_ARTIFACT_TYPE INDEX_ARTIFACT_TYPE
  OCI_REGISTRY="$(jq -r '.oci.registry' "$cfg_path")"
  BINARY_ARTIFACT_TYPE="$(jq -r '.oci.artifact_types.binary' "$cfg_path")"
  INDEX_ARTIFACT_TYPE="$(jq -r '.oci.artifact_types.index' "$cfg_path")"

  export DEPLOYMENT_BUCKET SSM_RELEASE_PARAM
  DEPLOYMENT_BUCKET="$(jq -r '.deploy.s3_bucket' "$cfg_path")"
  SSM_RELEASE_PARAM="$(jq -r '.deploy.ssm_release_param' "$cfg_path")"

  #export AWS_BASE_PROFILE AWS_S3_PROFILE AWS_SSM_PROFILE AWS_KMS_SIGNER_PROFILE
  #AWS_BASE_PROFILE="$(jq -r '.aws.profiles.base' "$cfg_path")"
  #AWS_S3_PROFILE="$(jq -r '.aws.profiles.s3' "$cfg_path")"
  #AWS_SSM_PROFILE="$(jq -r '.aws.profiles.ssm' "$cfg_path")"
  #AWS_KMS_SIGNER_PROFILE="$(jq -r '.aws.profiles.kms_signer' "$cfg_path")"

  export PRED_SBOM_SPDX PRED_SBOM_CDX PRED_VULN_TRIVY PRED_VULN_GRYPE PRED_VULN_GOVULNCHECK PRED_LICENSE_REPORT PRED_RELEASE_DESCRIPTOR
  PRED_SBOM_SPDX="$(jq -r '.predicates.sbom_spdx' "$cfg_path")"
  PRED_SBOM_CDX="$(jq -r '.predicates.sbom_cdx' "$cfg_path")"
  PRED_VULN_TRIVY="$(jq -r '.predicates.vuln_trivy' "$cfg_path")"
  PRED_VULN_GRYPE="$(jq -r '.predicates.vuln_grype' "$cfg_path")"
  PRED_VULN_GOVULNCHECK="$(jq -r '.predicates.vuln_govulncheck' "$cfg_path")"
  PRED_LICENSE_REPORT="$(jq -r '.predicates.license_report' "$cfg_path")"
  PRED_RELEASE_DESCRIPTOR="$(jq -r '.predicates.release_descriptor' "$cfg_path")"
  export APP_CFG_PATH="$cfg_path"
}

appcfg_component_repo() {
  local component="${1:?component required}"
  local repo
  repo="$(jq -r --arg c "$component" '.components[$c].repository // empty' "$APP_CFG_PATH")"
  if [[ -n "$repo" ]]; then
    printf '%s' "$repo"
    return 0
  fi
  local prefix
  prefix="$(jq -r '.oci.repository_prefix' "$APP_CFG_PATH")"
  printf '%s/%s' "$prefix" "$component"
}

config_resolve_ssm_params() {
  # Resolve SSM parameters for deployment bucket and release param if they are SSM paths
  if [[ "$DEPLOYMENT_BUCKET" == ssm:* ]]; then
    local param_name="${DEPLOYMENT_BUCKET#ssm:}"
    DEPLOYMENT_BUCKET="$(aws ssm get-parameter --name "$param_name" --query Parameter.Value --output text)"
  fi
  if [[ "$SSM_RELEASE_PARAM" == ssm:* ]]; then
    local param_name="${SSM_RELEASE_PARAM#ssm:}"
    SSM_RELEASE_PARAM="$(aws  ssm get-parameter --name "$param_name" --query Parameter.Value --output text)"
  fi
  ## Get environment name from SSM
  ENV="$(aws ssm get-parameter --name "/platform/env/name" --query Parameter.Value --output text)"
  ## Used for cosign signing of artifacts 
  SIGNER_URI="$(aws ssm get-parameter --name "/platform/signing/${ENV}/cosign/signer" --query Parameter.Value --output text)"
  export ENV SIGNER_URI
}