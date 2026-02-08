# shellcheck shell=bash

gate_vuln_release()
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

  # Only enforce for stable
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

  # only enforce for stable
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

gate_stable_requires_tag() {
  local track="$1"
  [[ "$track" == "stable" ]] || return 0

  local tag
  tag="$( ctx_get '.source.tag' )"
  if [[ -z "$tag" || "$tag" == "null" ]]; then
    die "Refusing to build - stable track requires a tagged commit. Current commit has no tag. Either tag the commit or use --track dev"
  fi
}

gate_tag_on_main_head() {
  # tagged releases must be built from HEAD of main
  local tag
  tag="$( ctx_get '.source.tag' )"
  [[ -n "$tag" && "$tag" != "null" ]] || return 0

  local commit
  commit="$( ctx_get '.source.commit' )"
  local src_dir="${PHXI_SOURCE_DIR:-$PWD}"
  local main_head
  main_head="$( git -C "$src_dir" rev-parse "origin/main^{commit}" 2>/dev/null )"

  if [[ -z "$main_head" ]]; then
    die "Refusing to build - could not resolve origin/main HEAD to verify tagged release is on tip of main"
  fi

  if [[ "$commit" != "$main_head" ]]; then
    if [[ "${ALLOW_TAG_OFF_MAIN:-}" == "1" ]]; then
      log "[-] ###############################"
      log "[-] WARNING: tagged release ${tag} is NOT on HEAD of main (commit=${commit} main_head=${main_head}), continuing due to ALLOW_TAG_OFF_MAIN=1"
      log "[-] ###############################"
      sleep 5
      return 0
    fi
    die "Refusing to build - tagged release ${tag} must be built from HEAD of main. commit=${commit} main_head=${main_head}. Set env ALLOW_TAG_OFF_MAIN=1 to override"
  fi
}

# reads a finished license report, checks summary gate counts, pass/fail. called after evidence generation before release finalization
gate_license_compliance() {
  local report_path="$1"
  local enforcement="${2:-warn}"  # "enforce" or "warn"

  [[ -f "$report_path" ]] || die "gate_license_compliance: report not found: $report_path"

  local gate_summary
  gate_summary="$(jq -c '.summary.gate // {}' "$report_path")"

  local denied unknown without_license max_without
  denied="$(jq -r '.denied // 0' <<<"$gate_summary")"
  unknown="$(jq -r '.unknown // 0' <<<"$gate_summary")"
  without_license="$(jq -r '.summary.without_licenses // 0' "$report_path")"

  # read max_without_license from the embedded policy
  max_without="$(jq -r '.policy.max_without_license // 0' "$report_path")"

  local reasons=()

  if (( denied > 0 )); then
    local denied_list
    denied_list="$(jq -r '.denied_licenses | join(", ")' <<<"$gate_summary")"
    reasons+=("${denied} package(s) have denied licenses: ${denied_list}")
  fi

  if (( unknown > 0 )); then
    local unknown_list
    unknown_list="$(jq -r '.unknown_licenses | join(", ")' <<<"$gate_summary")"
    reasons+=("${unknown} package(s) have unknown/unrecognized licenses: ${unknown_list}")
  fi

  if (( without_license > max_without )); then
    reasons+=("${without_license} package(s) have no license declared (max allowed: ${max_without})")
  fi

  if (( ${#reasons[@]} == 0 )); then
    log "==> (gate) license compliance: PASS"
    return 0
  fi

  # report failures
  for r in "${reasons[@]}"; do
    log "[-] (gate) license: $r"
  done

  if [[ "$enforcement" == "enforce" ]]; then
    if [[ "${ALLOW_LICENSE_NONCOMPLIANT:-}" == "1" ]]; then
      log "[-] ###############################"
      log "[-] WARNING: continuing with non-compliant licenses due to ALLOW_LICENSE_NONCOMPLIANT=1 override"
      log "[-] ###############################"
      sleep 5
      return 0
    fi
    die "Refusing to release - license compliance gate failed. Set env ALLOW_LICENSE_NONCOMPLIANT=1 to override"
  else
    log "[-] ###############################"
    log "[-] WARNING: license compliance gate failed (enforcement=${enforcement}, continuing)"
    log "[-] ###############################"
    return 0
  fi
}