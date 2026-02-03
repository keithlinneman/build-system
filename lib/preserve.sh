# shellcheck shell=bash

preserve_audit_artifacts() {
  for component in $( ctx_list_components );do
    local s3_path="s3://${EVIDENCE_BUCKET}/apps/${APP}/${component}/releases/${RELEASE_ID}/"
    echo "==> (preserve-audit) Uploading component=${component} release to S3: ${s3_path}"
    aws s3 cp --recursive "${DIST}/${component}" "${s3_path}"
  done
}

list_audit_artifacts() {
  for component in $( ctx_list_components );do
    local s3_path="s3://${EVIDENCE_BUCKET}/apps/${APP}/${component}/releases/${RELEASE_ID}/"
    echo "==> (preserve-audit) Listing release contents component=${component} in S3: ${s3_path}"
    aws s3 ls --recursive --human-readable "${s3_path}"
  done
}
