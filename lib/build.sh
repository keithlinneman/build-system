# shellcheck shell=bash

build_binary() {
  local component="$1" goos="$2" goarch="$3" outfile="$4"
  mkdir -p "$( dirname "${outfile}" )"
  set -x
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -mod=readonly -buildvcs=true \
      -ldflags "${LDFLAGS[*]}" \
      -o "$outfile" "./cmd/${component}"
  set +x
}

initialize_build_env() {
  local whoami
  whoami="$( aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo "unknown" )"

  LDFLAGS=(
    "-X=${VERPKG}.Version=${RELEASE_VERSION}"
    "-X=${VERPKG}.BuildDate=${BUILD_DATE}"
    "-X=${VERPKG}.BuildId=${BUILD_ID}"
    "-X=${VERPKG}.Commit=${COMMIT_SHORT}"
    "-X=${VERPKG}.CommitDate=${COMMIT_DATE}"

    "-X=${VERPKG}.Repository=${REPO_URL}"
    "-X=${VERPKG}.BuildActor=${GITHUB_ACTOR:-unknown}"
    "-X=${VERPKG}.BuildSystem=github-actions"
    "-X=${VERPKG}.BuildRunID=${GITHUB_RUN_ID}"
    "-X=${VERPKG}.BuildRunURL=https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
    "-X=${VERPKG}.BuildRunURL=${GITHUB_RUN_ID:+https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}}"
    "-X=${VERPKG}.BuilderIdentity=${whoami}"
    "-X=${VERPKG}.ReleaseId=${RELEASE_VERSION}"
    "-X=${VERPKG}.EvidenceBucket=${EVIDENCE_BUCKET}"
    "-X=${VERPKG}.EvidencePrefix=apps/${APP}/server/releases/${RELEASE_VERSION}"
    "-X=${VERPKG}.CosignKeyRef=${SIGNER_URI}"

  )

  # ensure we have all required modules downloaded
  log "==> (build) ensuring go modules are downloaded"
  go mod download || { die "failed to download go modules"; return 1; }
 }

 build_component_artifact() {
  local component="$1"
  local platform="$2"
  local os="${platform%%/*}"
  local arch="${platform##*/}"
  local out_file="${DIST}/${component}/bin/${os}/${arch}/${APP}-${component}"

  build_binary "${component}" "${os}" "${arch}" "${out_file}"

  log "==> (build) generating sha256 for ${out_file}"
  ( cd "$(dirname "$out_file")" && sha256sum "$(basename "$out_file")" > "$(basename "$out_file").sha256" )

  local sha256 size
  sha256="$(sha256sum "${out_file}" | awk '{print $1}')"
  size="$(stat -c%s "${out_file}")"

  log "==> (build) built ${component} ${platform} (sha256=${sha256} size=${size} path=${out_file})"

  ctx_artifact_set_local \
    "${component}" "${platform}" "${os}" "${arch}" \
    "binary" "${BINARY_ARTIFACT_TYPE}" \
    "${out_file}" \
    "${sha256}" "${size}" \
    "${BUILD_ID_REGISTRY_SAFE}-${os}-${arch}"
}