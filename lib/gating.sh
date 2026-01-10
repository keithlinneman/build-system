gateVulnRelease()
{
  rc=$1
  if [[ "$rc" == "0" ]];then
    return
  fi
  if [[ "${ALLOW_INSECURE_VULN_BUILD:-false}" != "true" ]]; then
    die "Refusing to publish - working tree contains vulnerabilities. Set ALLOW_INSECURE_VULN_BUILD=true to override"
    exit 1
  else
   printf "[-]\n[-] ###########################\n"
   log "[-] WARNING: continuing vulnerable build due to ALLOW_INSECURE_VULN_BUILD=true override"
   printf "[-] ###########################\n[-]\n"
  fi
}