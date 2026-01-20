# shellcheck shell=bash

preserve_audit_artifacts() {
  local s3_path="s3://${DEPLOYMENT_BUCKET}/apps/${APP}/releases/${RELEASE_VERSION}/${BUILD_ID}/"
  echo "==> (preserve-audit) Uploading release to S3: ${s3_path}"
  aws --profile "${AWS_S3_PROFILE}" s3 cp --recursive "${DIST}/" "${s3_path}"
}

list_audit_artifacts() {
  local s3_path="s3://${DEPLOYMENT_BUCKET}/apps/${APP}/releases/${RELEASE_VERSION}/${BUILD_ID}/"
  echo "==> (preserve-audit) Listing release contents in S3: ${s3_path}"
  aws --profile "${AWS_S3_PROFILE}" s3 ls --recursive --human-readable "${s3_path}"
}

