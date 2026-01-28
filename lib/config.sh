# shellcheck shell=bash

config_resolve_ssm_params() {
  # Resolve SSM parameters for deployment bucket and release param if they are SSM paths
  if [[ "$DEPLOYMENT_BUCKET" == ssm:* ]]; then
    local param_name="${DEPLOYMENT_BUCKET#ssm:}"
    DEPLOYMENT_BUCKET="$(aws ssm get-parameter --name "$param_name" --query Parameter.Value --output text)"
  fi
  if [[ "$SSM_RELEASE_PARAM" == ssm:* ]]; then
    local param_name="${SSM_RELEASE_PARAM#ssm:}"
    SSM_RELEASE_PARAM="$(aws ssm get-parameter --name "$param_name" --query Parameter.Value --output text)"
  fi
}

# App configuration
#APP=sitesuper

# Build configuration
#BUILD_PLATFORMS=(linux/amd64 linux/arm64)
#BUILD_COMPONENTS=(web)
#BUILDCTX_PATH="state/buildctx.json"
#DIST="dist"
#VERPKG=sitesuper/internal/version

## S3 bucket for deployment artifacts
#DEPLOYMENT_BUCKET="phxi-net-prod-use2-deployment-artifacts"
## Parameter store path for the current release ID for deployments
#SSM_RELEASE_PARAM="/app/${APP}/_shared/deploy/primary/release/id"
## OCI registry for OCI artifacts
#OCI_REGISTRY="130677209948.dkr.ecr.us-east-2.amazonaws.com"

## AWS profiles and roles
#AWS_S3_PROFILE="${AWS_S3_PROFILE:-net-prod}"
#AWS_SSM_PROFILE="${AWS_SSM_PROFILE:-sitesuper-prod}"
#AWS_KMS_SIGNER_PROFILE="net-prod-signer"
#AWS_ECR_CANARY_ROLE="phxi-sitesuper-web-publish-canary-prod"
#AWS_BASE_PROFILE="net-prod"

## Get environment name and signer URI from SSM
#ENV="$(aws --profile "${AWS_BASE_PROFILE}" ssm get-parameter --name "/platform/env/name" --query Parameter.Value --output text)"
## Used for cosign signing of artifacts 
#SIGNER_URI="$(aws --profile "${AWS_BASE_PROFILE}" ssm get-parameter --name "/platform/signing/${ENV}/cosign/signer" --query Parameter.Value --output text)"

## OCI configurations
## Artifact media types
#BINARY_ARTIFACT_TYPE="application/vnd.phxi.binary.v1"
## SBOM predicate types (standard)
#PRED_SBOM_SPDX="https://spdx.dev/Document"
#PRED_SBOM_CDX="https://cyclonedx.org/schema"
## Vuln scan report predicate types (no standard existing, using my own stable + explicit types)
#PRED_VULN_TRIVY="https://phxi.net/attestations/trivy/vuln/v1"
#PRED_VULN_GRYPE="https://phxi.net/attestations/grype/vuln/v1"
#PRED_VULN_GOVULNCHECK="https://phxi.net/attestations/govulncheck/vuln/v1"
## License report predicate (need to research standard types)
#PRED_LICENSE_REPORT="https://phxi.net/attestations/licenses/v1"
