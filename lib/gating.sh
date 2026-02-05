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
  # Tagged releases must be built from HEAD of main
  local tag
  tag="$( ctx_get '.source.tag' )"
  [[ -n "$tag" && "$tag" != "null" ]] || return 0

  local commit
  commit="$( ctx_get '.source.commit' )"
  local src_dir="${PHXI_SOURCE_DIR:-$PWD}"
  local main_head=""
  main_head="$(git -C "$src_dir" rev-parse "origin/main^{commit}" 2>/dev/null)" \
    || main_head="$(git -C "$src_dir" rev-parse "origin/master^{commit}" 2>/dev/null)" \
    || true

  if [[ -z "$main_head" ]]; then
    die "Refusing to build - could not resolve origin/main (or origin/master) HEAD to verify tagged release is on tip of main"
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