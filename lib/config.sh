APP=sitesuper
DEPLOYMENT_BUCKET="phxi-net-prod-use2-deployment-artifacts"
VERPKG=sitesuper/internal/version

AWS_S3_PROFILE="${AWS_S3_PROFILE:-net-prod}"
AWS_SSM_PROFILE="${AWS_SSM_PROFILE:-sitesuper-prod}"
AWS_KMS_SIGNER_PROFILE="net-prod-signer"
AWS_ECR_CANARY_ROLE="phxi-sitesuper-web-publish-canary-prod"
AWS_BASE_PROFILE="net-prod"
BUILDCTX_PATH="build/state/buildctx.json"

ENV="$(aws --profile "${AWS_BASE_PROFILE}" ssm get-parameter --name "/platform/env/name" --query Parameter.Value --output text)"
SIGNER_URI="$(aws --profile "${AWS_BASE_PROFILE}" ssm get-parameter --name "/platform/signing/${ENV}/cosign/signer" --query Parameter.Value --output text)"

SSM_RELEASE_PARAM="/app/${APP}/_shared/deploy/primary/release/id"

BUILD_PLATFORMS=(linux/amd64 linux/arm64)
BUILD_COMPONENTS=(web)
DIST="dist"

BINARY_ARTIFACT_TYPE="application/vnd.phxi.binary.v1"

OCI_REGISTRY="130677209948.dkr.ecr.us-east-2.amazonaws.com"