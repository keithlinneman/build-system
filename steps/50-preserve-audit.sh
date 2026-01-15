#!/bin/bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/config.sh"
source "$basepath/lib/buildctx.sh"


log "==> (preserve-audit) starting step 50-preserve-audit"

log "==> (preserve-audit) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

S3BASE="s3://${DEPLOYMENT_BUCKET}/apps/${APP}/releases/${RELEASE_VERSION}/${BUILD_ID}/"
echo "==> (preserve-audit) Uploading release to ${S3BASE}"
aws --profile "${AWS_S3_PROFILE}" s3 cp --recursive "${DIST}/" "${S3BASE}"

#echo "==> (preserve-audit) Setting desired release in SSM: ${SSM_RELEASE_PARAM} = ${BUILD_ID}"
#aws --profile "${AWS_SSM_PROFILE}" ssm put-parameter --name "${SSM_RELEASE_PARAM}" --type String --value "${BUILD_ID}" --overwrite

echo "==> (preserve-audit) listing s3 release contents"
aws --profile net-prod s3 ls --recursive --human-readable "${S3BASE}"