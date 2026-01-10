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