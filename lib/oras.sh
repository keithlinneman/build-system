initialize_oci() {
  REPO_URL="$( ctx_get '.source.repo' )"
  BUILD_ID_REGISTRY_SAFE="$(echo -n "${BUILD_ID}" | tr '_+' '-')"
  BASE_TAG=$BUILD_ID_REGISTRY_SAFE
  INDEX_ARTIFACT_TYPE="application/vnd.phxi.binary.index.v1"
  SOURCE_REPO="$( ctx_get '.source.repo' )"

  log "==> (oci) getting oras login credentials"
  aws ecr get-login-password --region us-east-2 --profile "${AWS_BASE_PROFILE}" | \
    oras login --username AWS --password-stdin "${OCI_REGISTRY}"
}

oci_write_default_annotations_json() {
  # args: component platform artifactType, created_at, source_repo, source_commit, release_version, release_id, build_id, build_date 
  donothing="true"
}
oci_push_component_artifact() {
  # args: component platform_key
  # reads: components.<c>.oci.*, artifacts.<p>.* from buildctx
  # calls: oci_push_binary
  # then: ctx_artifact_set_oci_pushed
  local component="$1"
  local pkey="$2"
  
  local registry="$(ctx_get_component_registry "$component")"
  local repo="$(ctx_get_component_repository "$component")"
  
  local path="$( ctx_get_artifact_local_path "${component}" "${pkey}" )"
  local sha256="$( ctx_get_artifact_local_sha256 "${component}" "${pkey}" )"
  local tag="$( ctx_get_artifact_oci_tag "${component}" "${pkey}" )"
  local platform="$( ctx_get_artifact_platform_label "${component}" "${pkey}" )"

  if [[ -z "${path}" || -z "${sha256}" || -z "${tag}" || -z "${platform}" ]];then
    die "Missing push inputs: comp=$component pkey=$pkey path=$path sha=$sha256 tag=$tag platform=$platform"
    exit 1
  fi

  if [ ! -f "${path}" ];then
    die "Built artifact not found for component=${component} pkey=${pkey} path=${path}"
    exit 1
  fi
  log "==> (oci) found built artifact for component=${component} pkey=${pkey} path=${path} sha256=${sha256} tag=${tag}"

  local file_sha256="$( sha256sum "${path}" | awk '{print $1}' )"
  if [[ "${file_sha256}" != "${sha256}" ]];then
    die "Checksum mismatch for component=${component} pkey=${pkey} path=${path} digest=${sha256} tag=${tag} - expected sha256=${sha256} got sha256=${file_sha256}"
    exit 1
  fi

  local existing_digest
  existing_digest="$( ctx_get_artifact_digest "$component" "$pkey" || true )"
  if [[ -n "$existing_digest" && "$existing_digest" != "null" ]]; then
    log "==> (oci) skipping, already pushed: comp=$component pkey=$pkey digest=$existing_digest"
    return 0
  fi

  local result="$( oci_push_binary "$component" "$path" "$registry" "$repo" "$tag" "$BINARY_ARTIFACT_TYPE" "$platform" )"
  local digest mediaType size pushed_at
  IFS=" " read -r digest mediaType size pushed_at <<<"$result"
  log "==> (oci) pushed component=${component} pkey=${pkey} digest=${digest} mediaType=${mediaType} size=${size} pushed_at=${pushed_at}"

  ctx_artifact_set_oci_pushed "$component" "$platform" "$digest" "$mediaType" "$size" "$pushed_at"
}

oci_push_binary() {
  # args: registry repo tag artifactType os arch local_path component
  # prints: digest mediaType descriptor_size pushed_at
  local component="$1"
  local file_path="$2"
  local registry="$3"
  local repo="$4"
  local tag="$5"
  local artifact_type="$6"
  local platform="$7"

  local os=${platform%%/*}
  local arch=${platform##*/}
  local ref="${registry}/${repo}:${tag}"
  local title="${APP}-${component}"

  # use staging dir to keep oras happy
  staging_dir="$( mktemp -d )"
  annotations_file="${staging_dir}/annotations.json"

  # create annotations file in staging dir
  oci_write_default_annotations_json "${annotations_file}" "${component}" "${title}" "${tag}" "binary" "${artifact_type}" "${platform}"

  # copy artifact to staging dir
  cp -f "${file_path}" "${staging_dir}/${title}"

  #log "==> (oci) pushing OCI artifact file:${file_path} component:${component} platform:${platform} to ref:${ref}"
  pushd "${staging_dir}" >/dev/null
  local digest="$(
    oras push "${ref}" \
      --artifact-type "${artifact_type}" \
      --artifact-platform "${platform}" \
      --annotation-file "${annotations_file}" \
      --export-manifest "manifest.json" \
      "${title}:application/octet-stream" \
      --format go-template --template '{{.digest}}'
  )"
  popd >/dev/null

  local subject_digest_ref="${registry}/${repo}@${digest}"
  local subject_desc="$( oras manifest fetch --descriptor "${subject_digest_ref}" --output json )"
  local subject_size="$( echo "${subject_desc}" | jq -r '.size' )"
  local subject_media_type="$( echo "${subject_desc}" | jq -r '.mediaType' )"
  local now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "${digest} ${subject_media_type} ${subject_size} ${now}"
}

oci_write_default_annotations_json() {
  # args:
  # 1 out_file
  # 2 component
  # 3 title
  # 4 ref_name
  # 5 artifact_kind (optional, "" allowed)
  # 6 artifact_type (optional, "" allowed)
  # 7 platform_label (optional, "" allowed)

  local out_file="$1"
  local component="$2"
  local title="$3"
  local ref_name="$4"
  local artifact_kind="${5:-}"
  local artifact_type="${6:-}"
  local platform_label="${7:-}"

  jq -n \
    --arg app "${APP}" \
    --arg component "${component}" \
    --arg title "${title}" \
    --arg release_version "${RELEASE_VERSION}" \
    --arg release_id "${RELEASE_ID}" \
    --arg release_track "${RELEASE_TRACK}" \
    --arg build_id "${BUILD_ID}" \
    --arg build_date "${BUILD_DATE}" \
    --arg repo_url "${SOURCE_REPO}" \
    --arg repo_dirty "${REPO_DIRTY}" \
    --arg commit "${COMMIT}" \
    --arg commit_short "${COMMIT_SHORT}" \
    --arg commit_date "${COMMIT_DATE}" \
    --arg ref_name "${ref_name}" \
    --arg artifact_kind "${artifact_kind}" \
    --arg artifact_type "${artifact_type}" \
    --arg platform "${platform_label}" \
    --arg manifest "\$manifest" \
    '{
      $manifest: (
        {
          "org.opencontainers.image.title": $title,
          "org.opencontainers.image.created": $build_date,
          "org.opencontainers.image.revision": $commit,
          "org.opencontainers.image.source": $repo_url,
          "org.opencontainers.image.version": $release_version,
          "org.opencontainers.image.ref.name": $ref_name,

          "net.phxi.app": $app,
          "net.phxi.component": $component,
          "net.phxi.track": $release_track,
          "net.phxi.build.id": $build_id,
          "net.phxi.release.id": $release_id,

          "net.phxi.source.repo.dirty": $repo_dirty,
          "net.phxi.source.commit.short": $commit_short,
          "net.phxi.source.commit.date": $commit_date
        }
        + (if ($artifact_kind | length) > 0 then {"net.phxi.artifact.kind": $artifact_kind} else {} end)
        + (if ($artifact_type | length) > 0 then {"net.phxi.artifact.type": $artifact_type} else {} end)
        + (if ($platform | length) > 0 then {"net.phxi.platform": $platform} else {} end)
      ),
      $title: {
        "org.opencontainers.image.title": $title
      }
    }' > "${out_file}"
}

oci_create_index() {
  # args:
  # 1 index_ref (registry/repo:tag)
  # 2 index_artifact_type
  # 3 component
  # 4... subject_digest_refs (registry/repo@sha256:...)
  # prints: digest

  local index_ref="$1";shift
  local index_artifact_type="$1";shift
  local component="$1";shift

  local title="${APP}-${component}"

  local out="$(
    oras manifest index create \
      --artifact-type "${index_artifact_type}" \
      --annotation "org.opencontainers.image.title=${title}" \
      --annotation "org.opencontainers.image.created=${BUILD_DATE}" \
      --annotation "org.opencontainers.image.source=${SOURCE_REPO}" \
      --annotation "org.opencontainers.image.version=${RELEASE_VERSION}" \
      --annotation "org.opencontainers.image.revision=${COMMIT}" \
      --annotation "org.opencontainers.image.ref.name=$(ctx_get_index_tag "$component")" \
      --annotation "net.phxi.app=${APP}" \
      --annotation "net.phxi.component=${component}" \
      --annotation "net.phxi.build.id=${BUILD_ID}" \
      --annotation "net.phxi.release.id=${RELEASE_ID}" \
      --annotation "net.phxi.track=${RELEASE_TRACK}" \
      "${index_ref}" \
      "$@" \
  )"

  # Extract digest
  local digest
  digest="$(printf '%s\n' "$out" | awk '/^Digest:/ {print $2; exit}')"
  [[ -z "$digest" ]] && die "Failed to parse index digest from oras output: $out"

  echo "$digest"
}

oci_push_component_index() {
  # args: component
  local component="$1"

  local registry repo index_tag index_ref
  registry="$(ctx_get_component_registry "$component")"
  repo="$(ctx_get_component_repository "$component")"
  index_tag="$(ctx_get_index_tag "$component")"

  [[ -z "$registry" || -z "$repo" || -z "$index_tag" ]] && \
    die "Missing index inputs: registry=$registry repo=$repo index_tag=$index_tag"

  index_ref="${registry}/${repo}:${index_tag}"

  # Ensure manifests are derived from pushed artifacts
  ctx_index_refresh_manifests "$component"

  # Build subject digest refs from ctx manifests
  local subject_refs=()
  local pkey digest
  for pkey in $(ctx_list_platform_keys "$component"); do
    digest="$(ctx_get_artifact_digest "$component" "$pkey")"
    [[ -z "$digest" || "$digest" == "null" ]] && continue
    subject_refs+=( "${registry}/${repo}@${digest}" )
  done

  (( ${#subject_refs[@]} > 0 )) || die "No pushed artifacts found for component=$component; cannot create index"

  # Idempotency: skip if already has digest
  local existing
  existing="$(ctx_get_index_digest "$component" || true)"
  if [[ -n "$existing" && "$existing" != "null" ]]; then
    log "==> (oci) index already set: component=$component digest=$existing"
    return 0
  fi

  log "==> (oci) creating index component=$component ref=$index_ref subjects=${#subject_refs[@]}"

  local index_digest
  index_digest="$(oci_create_index "$index_ref" "$INDEX_ARTIFACT_TYPE" "$component" "${subject_refs[@]}")"

  local index_digest_ref="${registry}/${repo}@${index_digest}"

  # descriptor (size + mediaType)
  local desc size mt now
  desc="$(oras manifest fetch --descriptor "${index_digest_ref}" --output json)"
  size="$(echo "$desc" | jq -r '.size')"
  mt="$(echo "$desc" | jq -r '.mediaType')"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  log "==> (oci) pushed index component=$component digest=$index_digest size=$size mediaType=$mt"

  # Update ctx (this should also refresh manifests, but doing it before+after is fine)
  ctx_index_set_oci_pushed "$component" "$index_digest" "$mt" "$size" "$now"

  # Optional: resolved refs cache
  ctx_materialize_resolved_refs
}
