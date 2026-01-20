#!/bin/bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'RC=$?; echo "ERROR(rc=$RC) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $RC' ERR

SCRIPT_PATH="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd -P)/$( basename -- "${BASH_SOURCE[0]}" )"
BUILD_SYSTEM_ROOT="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}")" && pwd -P )"

# Load common libraries
source "${BUILD_SYSTEM_ROOT}/lib/common.sh"
source "${BUILD_SYSTEM_ROOT}/lib/config.sh"
source "${BUILD_SYSTEM_ROOT}/lib/source.sh"
source "${BUILD_SYSTEM_ROOT}/lib/appcfg.sh"

source "${BUILD_SYSTEM_ROOT}/lib/evidence.sh"
source "${BUILD_SYSTEM_ROOT}/lib/signing.sh"
source "${BUILD_SYSTEM_ROOT}/lib/gating.sh"
source "${BUILD_SYSTEM_ROOT}/lib/build.sh"
source "${BUILD_SYSTEM_ROOT}/lib/buildctx.sh"
source "${BUILD_SYSTEM_ROOT}/lib/inventory.sh"
source "${BUILD_SYSTEM_ROOT}/lib/aws.sh"
source "${BUILD_SYSTEM_ROOT}/lib/oras.sh"
source "${BUILD_SYSTEM_ROOT}/lib/tuf.sh"

# CLI
APP_REPO=""
APP_REF="origin/HEAD"
RELEASE_TRACK_OVERRIDE=""
WORKDIR=""
KEEP_WORKDIR=false
APP_CONFIG_REL="build/app.json"

ORIG_ARGS=("$@")
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)   APP_REPO="${2:?--repo requires value}"; shift 2 ;;
    --ref)    APP_REF="${2:?--ref requires value}"; shift 2 ;;
    --track)  RELEASE_TRACK_OVERRIDE="${2:?--track requires dev|stable}"; shift 2 ;;
    --workdir) WORKDIR="${2:?--workdir requires path}"; shift 2 ;;
    --keep-workdir) KEEP_WORKDIR=true; shift ;;
    --app-config) APP_CONFIG_REL="${2:?--app-config requires path}"; shift 2 ;;
    --) shift; ARGS+=("$@"); break ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

[[ -n "$APP_REPO" ]] || die "missing required --repo <git-url>"

# setup workdir
WORKDIR="$(mktemp -d -t phxi-build.XXXXXX)"
mkdir -p "$WORKDIR"
if [[ "$KEEP_WORKDIR" != "true" ]]; then
  trap 'RC=$?; rm -rf "$WORKDIR"; exit $RC' EXIT
else
  log "==> (build) keeping workdir: $WORKDIR"
fi

export PHXI_WORKDIR="$WORKDIR"
export PHXI_SOURCE_DIR="$WORKDIR/src"
export PHXI_BUILDER_DIR="$BUILD_SYSTEM_ROOT"
export PHXI_APP_CONFIG="${PHXI_SOURCE_DIR}/build/app.json"

export DIST="$WORKDIR/dist"
export BUILDCTX_PATH="$WORKDIR/state/buildctx.json"

mkdir -p "$WORKDIR/state" "$DIST"

log "==> (build) checking out source repo to ${PHXI_SOURCE_DIR}"
source_checkout_repo "$APP_REPO" "$APP_REF" "$PHXI_SOURCE_DIR"

# app repo provides build settings (APP, BUILD_COMPONENTS, BUILD_PLATFORMS, VERPKG, etc.)
if [[ -f "${PHXI_SOURCE_DIR}/${APP_CONFIG_REL}" ]]; then
  # Load app configuration
  appcfg_load_json "${PHXI_APP_CONFIG}"
  config_resolve_ssm_params
else
  die "app config not found: ${PHXI_SOURCE_DIR}/${APP_CONFIG_REL} (pass --app-config to override)"
fi

# Allow CLI override of track (dev/stable) if you want it
if [[ -n "$RELEASE_TRACK_OVERRIDE" ]]; then
  export RELEASE_TRACK_OVERRIDE
fi

# Run steps from inside app repo
cd "$PHXI_SOURCE_DIR"

log "==> (build) starting build-system from builder=${PHXI_BUILDER_DIR} source=${PHXI_SOURCE_DIR}"
log "==> (build) app=${APP} components=(${BUILD_COMPONENTS[*]}) platforms=(${BUILD_PLATFORMS[*]}) ref=${APP_REF}"

# Step 00 init
log "==> (step) starting step 00-init"
"$BUILD_SYSTEM_ROOT/steps/00-init.sh" "$SCRIPT_PATH" "${ORIG_ARGS[@]}"

# Step 10 build binaries
log "==> (step) starting step 10-build-binaries"
"$BUILD_SYSTEM_ROOT/steps/10-build-binaries.sh"

# Step 20 push oci artifacts
log "==> (step) starting step 20-push-oci"
"$BUILD_SYSTEM_ROOT/steps/20-push-oci.sh"

# Step 30 generate evidence
log "==> (step) starting step 30-generate-evidence"
"$BUILD_SYSTEM_ROOT/steps/30-generate-evidence.sh"

# Step 40 generate release
log "==> (step) starting step 40-generate-release"
"$BUILD_SYSTEM_ROOT/steps/40-generate-release.sh"

# Step 50 mirror and save audit records
log "==> (step) starting step 50-preserve-audit"
"$BUILD_SYSTEM_ROOT/steps/50-preserve-audit.sh"

# # Step 60 generate TUF files
# log "==> (step) starting step 60-generate-tuf"
# "$BUILD_SYSTEM_ROOT/steps/60-generate-tuf.sh"

# # Step 70 promote release
# log "==> (step) starting step 70-promote-release"
# "$BUILD_SYSTEM_ROOT/steps/70-promote-release.sh"

## smoke test: pick a component and detect local arch binary to run
#log "==> (build) done. dist=${DIST}"
log "==> (build) build app=${APP} completed successfully. dist=${DIST}"
