#!/bin/bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true
export PS4='+ [sub=${BASH_SUBSHELL:-?}] SOURCE:${BASH_SOURCE:-?} LINENO:${LINENO:-?} FUNC:${FUNCNAME[0]:-MAIN}: '
trap 'rc=$?; echo "ERROR(rc=$rc) at ${BASH_SOURCE[0]:-?}:${LINENO:-?} in ${FUNCNAME[0]:-MAIN}: ${BASH_COMMAND:-?}" >&2; exit $rc' ERR

SCRIPT_PATH="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}") " && pwd -P)/$( basename -- "${BASH_SOURCE[0]}" )"
BUILD_SYSTEM_ROOT="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}")" && pwd -P )"

APP="${APP:-}"
BUILD_COMPONENTS="${BUILD_COMPONENTS[@]:-}"
BUILD_PLATFORMS="${BUILD_PLATFORMS[@]:-}"

# Load common libraries
source "${BUILD_SYSTEM_ROOT}/build/lib/common.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/config.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/source.sh"

source "${BUILD_SYSTEM_ROOT}/build/lib/evidence.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/signing.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/gating.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/build.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/buildctx.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/inventory.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/aws.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/oras.sh"
source "${BUILD_SYSTEM_ROOT}/build/lib/tuf.sh"

# CLI
APP_REPO=""
APP_REF="origin/HEAD"
RELEASE_TRACK_OVERRIDE=""
WORKDIR=""
KEEP_WORKDIR=false
APP_CONFIG_REL="build/app.config.sh"

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

# --- workspace ---
if [[ -z "$WORKDIR" ]]; then
  WORKDIR="$(mktemp -d -t phxi-build.XXXXXX)"
fi
mkdir -p "$WORKDIR"
if [[ "$KEEP_WORKDIR" != "true" ]]; then
  trap 'rc=$?; rm -rf "$WORKDIR"; exit $rc' EXIT
else
  log "==> (build) keeping workdir: $WORKDIR"
fi

export PHXI_WORKDIR="$WORKDIR"
export PHXI_SOURCE_DIR="$WORKDIR/src"
export PHXI_BUILDER_DIR="$BUILD_SYSTEM_ROOT"

log "==> (build) checking out source repo to ${PHXI_SOURCE_DIR}"
source_checkout_repo "$APP_REPO" "$APP_REF" "$PHXI_SOURCE_DIR"

# app repo provides build settings (APP, BUILD_COMPONENTS, BUILD_PLATFORMS, VERPKG, etc.)
if [[ -f "${PHXI_SOURCE_DIR}/${APP_CONFIG_REL}" ]]; then
  # shellcheck disable=SC1090
  source "${PHXI_SOURCE_DIR}/${APP_CONFIG_REL}"
else
  die "app config not found: ${PHXI_SOURCE_DIR}/${APP_CONFIG_REL} (pass --app-config to override)"
fi

# Allow CLI override of track (dev/stable) if you want it
if [[ -n "$RELEASE_TRACK_OVERRIDE" ]]; then
  export RELEASE_TRACK_OVERRIDE
fi

# Run steps from inside app repo so existing "dir:." evidence calls work
cd "$PHXI_SOURCE_DIR"

log "==> (build) starting build-system from builder=${PHXI_BUILDER_DIR} source=${PHXI_SOURCE_DIR}"
log "==> (build) app=${APP} components=(${BUILD_COMPONENTS[*]}) platforms=(${BUILD_PLATFORMS[*]}) ref=${APP_REF}"

# Step 00 init
log "==> (step) starting step 00-init"
"$BUILD_SYSTEM_ROOT/build/steps/00-init.sh" "$SCRIPT_PATH" "${ARGS[@]}"

# Step 10 build binaries
log "==> (step) starting step 10-build-binaries"
"$BUILD_SYSTEM_ROOT/build/steps/10-build-binaries.sh"

# Step 20 push oci artifacts
log "==> (step) starting step 20-push-oci"
"$BUILD_SYSTEM_ROOT/build/steps/20-push-oci.sh"

# Step 30 generate evidence
log "==> (step) starting step 30-generate-evidence"
"$BUILD_SYSTEM_ROOT/build/steps/30-generate-evidence.sh"

# Step 40 generate inventory
log "==> (step) starting step 40-generate-inventory"
"$BUILD_SYSTEM_ROOT/build/steps/40-generate-inventory.sh"

## smoke test: pick a component and detect local arch binary to run
#log "==> (build) done. dist=${DIST}"



log "==> (build) beginning build of app=${APP} components=${BUILD_COMPONENTS} for release_version=${RELEASE_VERSION} build_id=${BUILD_ID} track=${RELEASE_TRACK} platforms=${BUILD_PLATFORMS}"

# Step 00 init
log "==> (step) starting step 00-init"
build/steps/00-init.sh "${SCRIPT_PATH}" "$@"

# Step 10 build binaries
log "==> (step) starting step 10-build-binaries"
build/steps/10-build-binaries.sh

# Step 20 push oci artifacts
log "==> (step) starting step 20-push-oci"
build/steps/20-push-oci.sh

# Step 30 generate evidence
log "==> (step) starting step 30-generate-evidence"
build/steps/30-generate-evidence.sh

# Step 40 generate inventory
log "==> (step) starting step 40-generate-inventory"
build/steps/40-generate-inventory.sh 

# test we can at least run the latest build without error
dist/web/bin/linux/amd64/sitesuper-web -V || exit "Failed to run built binary!"

#S3BASE="s3://${DEPLOYMENT_BUCKET}/apps/${APP}/releases/${VERSION}/${BUILD_ID}/"
#echo "==> (deploy) Uploading release to ${S3BASE}"

#aws --profile "${AWS_S3_PROFILE}" s3 cp --recursive "dist/" "${S3BASE}"

#echo "==> (deploy) Setting desired release in SSM: ${SSM_RELEASE_PARAM} = ${BUILD_ID}"
#aws --profile "${AWS_SSM_PROFILE}" ssm put-parameter --name "${SSM_RELEASE_PARAM}" --type String --value "${BUILD_ID}" --overwrite

#echo "==> (deploy) listing s3 release contents"
#aws --profile net-prod s3 ls --recursive --human-readable "${S3BASE}"
