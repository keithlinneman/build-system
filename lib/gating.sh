# shellcheck shell=bash

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

gate_dirty_source_repo() {
  local track="$1"

  # Only enforce for stable (and maybe rc / prod)
  [[ "$track" == "stable" ]] || return 0

  local src_dirty
  src_dirty="$(jq -r '.source.dirty' "$BUILDCTX_PATH")"

  if [[ "$src_dirty" != "false" ]]; then
    # allow explicit override for emergencies
    if [[ "${ALLOW_DIRTY_SOURCE_STABLE:-}" == "1" ]]; then
      log "[-] ###############################"
      log "[-] WARNING: continuing build on ${track} track with dirty source due to ALLOW_DIRTY_SOURCE_STABLE=1 override"
      log "[-] ###############################"
      sleep 5
      return 0
    fi
    die "Refusing to build - ${track} track requires clean source repo (source.dirty=false), got source.dirty=$src_dirty. set env ALLOW_DIRTY_SOURCE_STABLE=1 to override"
  fi
}

gate_dirty_build_repo() {
  local track="$1"

  # Only enforce for stable (and maybe rc / prod)
  [[ "$track" == "stable" ]] || return 0

  local builder_dirty
  builder_dirty="$(jq -r '.builder.dirty' "$BUILDCTX_PATH")"

  if [[ "$builder_dirty" != "false" ]]; then
    # allow explicit override for emergencies
    if [[ "${ALLOW_DIRTY_BUILDER_STABLE:-}" == "1" ]]; then
      log "[-] ###############################"
      log "[-] WARNING: continuing build on ${track} track with dirty build environment due to ALLOW_DIRTY_BUILDER_STABLE=1 override"
      log "[-] ###############################"
      sleep 5
      return 0
    fi
    die "Refusing to build - ${track} track requires clean builder repo (builder.dirty=false), got builder.dirty=$builder_dirty. set env ALLOW_DIRTY_BUILDER_STABLE=1 to override"
  fi
}