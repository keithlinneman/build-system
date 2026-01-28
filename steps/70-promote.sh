#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# SCRIPT_PATH="${SCRIPT_DIR}/$(basename -- "${BASH_SOURCE[0]}")"

basepath="${SCRIPT_DIR%/*}"
source "$basepath/lib/common.sh"
source "$basepath/lib/config.sh"
source "$basepath/lib/buildctx.sh"

log "==> (release) starting step 70-promote"

log "==> (release) loading build context from ${BUILDCTX_PATH}"
ctx_export_release_vars

## gate releases on govulncheck reporting 0 vulns ( may change to high/crit at some point)
#log "==> (vuln-scan) scanning source with govulncheck for vulnerabilities"
#govulncheck ./... || gateVulnRelease $?

## gate releases on grype reporting 0 fixable high/crit vulns
## gate on non-fixable+fixable for now in case regressions were introduced that our old versions are safe from
##grype ./ --fail-on high --name sitesuper --only-fixed
##rc=0
#grype ./ --fail-on high --name sitesuper || gateVulnRelease $?
##if [[ "$rc" != "0" ]];then
##  gateVulnRelease
##fi

## TODO: change these to look at the output reports instead of scanning binaries again
#  # review trivy report for vulns (fail if found)
#  log "==> (vuln-scan) analyzing trivy binary report for vulns (fail if found)"
#  trivy convert --format table --severity HIGH,CRITICAL --scanners vuln --exit-code 1 "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.trivy.vuln.json" || gateVulnRelease $?
#
#  # scan binary with grype for vulns (fail if found)
#  log "==> (vuln-scan) scanning binary with grype for vulns (generate json)"
#  grype "./${fname}" --fail-on high --name "${APP}-${COMPONENT}" || gateVulnRelease $?
#
#  # scan binary with govulncheck for vulns (fail if vuln)
#  log "==> (vuln-scan) scanning binary with govulncheck for vulns (fail if found)"
#  govulncheck -mode=binary "./${fname}" || gateVulnRelease $?

# Set the desired release in SSM params for deploy models that use this path
echo "==> (promote) Setting desired release in SSM: ${SSM_RELEASE_PARAM} = ${RELEASE_ID}"
aws ssm put-parameter --name "${SSM_RELEASE_PARAM}" --type String --value "${RELEASE_ID}" --overwrite