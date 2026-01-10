# Get a string value from the build context file, with optional default
ctx_get() {
  local jq_expr="$1"
  local default="${2-}"

  local out
  out="$(jq -r "$jq_expr // empty" "$BUILDCTX_PATH" 2>/dev/null)" || out=""

  if [[ -n "$out" ]]; then
    printf '%s' "$out"
  else
    printf '%s' "$default"
  fi
}


# Get a raw JSON value (object/array) without stringifying it
ctx_get_json() {
  local jq_expr="$1"
  jq -c "$jq_expr" "$BUILDCTX_PATH"
}

# Export the vars step scripts commonly need
ctx_export_release_vars() {
  export APP RELEASE_VERSION BUILD_ID BUILD_ID_REGISTRY_SAFE RELEASE_ID RELEASE_TRACK BUILD_DATE BUILD_EPOCH COMMIT_SHORT COMMIT COMMIT_DATE REPO_DIRTY
  APP="$(ctx_get '.app')"
  RELEASE_VERSION="$(ctx_get '.release.version')"
  BUILD_ID="$(ctx_get '.release.build_id')"
  BUILD_ID_REGISTRY_SAFE="$( echo -n "${BUILD_ID}" | tr '_+' '-' )"
  RELEASE_ID="$(ctx_get '.release.release_id')"
  RELEASE_TRACK="$(ctx_get '.release.track')"
  BUILD_DATE="$(ctx_get '.release.created_at')"
  BUILD_EPOCH="$(ctx_get '.release.epoch')"
  COMMIT_SHORT="$(ctx_get '.source.commit_short')"
  COMMIT="$(ctx_get '.source.commit')"
  COMMIT_DATE="$(ctx_get '.source.commit_date')"
  REPO_DIRTY="$(ctx_get '.source.dirty')"
}

ctx_build_init() {
  log "==> (init) clearing out dist/ directory"
  rm -rf dist/*
  mkdir -p {dist/scan/source,dist/attestations}

  log "==> (init) generating values for build context file"

  build_epoch="$( date +%s )"
  build_date="$( date -d @${build_epoch} -u +%Y-%m-%dT%H:%M:%SZ )"
  buildhost="$( hostname )"
  buildscript="${1:-${BASH_SOURCE[0]:-unknown}}"
  shift || true
  ORIGINAL_ARGS=("$@")
  redacted_args=()
  for a in "${ORIGINAL_ARGS[@]:-}";do
  redacted_args+=("$(redact_arg "$a")")
  done
  buildscript_sha256="$( sha256sum "$buildscript" | awk '{ print $1 }' )"
  buildscriptargs_sha256="$( printf '%s\0' "${ORIGINAL_ARGS[@]}" | sha256sum | awk '{print $1}' )"
  buildscriptargs_json="$( printf '%s\0' "${redacted_args[@]}" | jq -Rs 'split("\u0000")[:-1] | map(select(length > 0))' )"
  buildcomponents_json="$(printf '%s\n' "${BUILD_COMPONENTS[@]}" | jq -R . | jq -s .)"
  buildplatforms_json="$(printf '%s\n' "${BUILD_PLATFORMS[@]}" | jq -R . | jq -s .)"

  repo_url="$( git config --get remote.origin.url 2>/dev/null || true )"
  repo_branch="$( git rev-parse --abbrev-ref HEAD 2>/dev/null || true )"
  commit="$( git rev-parse HEAD 2>/dev/null || true )"
  commit_short="$( git rev-parse --short=7 HEAD )"
  commit_date_raw="$( git log -1 --format=%cI || true )"
  commit_date="$( date -d "$commit_date_raw" -u "+%Y-%m-%dT%H:%M:%SZ" )"
  commit_tag="$( git describe --tags --exact-match 2>/dev/null || true )"
  repo_dirty=false
  git diff --quiet || repo_dirty=true
  git diff --cached --quiet || repo_dirty=true
  [ -n "$( git ls-files --others --exclude-standard )" ] && repo_dirty=true

  #buildrepo_url="$( git config --get remote.origin.url 2>/dev/null || true )"
  #buildrepo_branch="$( git rev-parse --abbrev-ref HEAD 2>/dev/null || true )"
  #buildcommit="$( git rev-parse HEAD 2>/dev/null || true )"
  #buildcommit_short="$( git rev-parse --short=7 HEAD )"
  #buildcommit_date_raw="$( git log -1 --format=%cI || true )"
  #buildcommit_date="$( date -d "$buildcommit_date_raw" -u "+%Y-%m-%dT%H:%M:%SZ" )"
  #buildcommit_tag="$( git describe --tags --exact-match 2>/dev/null || true )"
  #buildrepo_dirty=false
  #git diff --quiet || buildrepo_dirty=true
  #git diff --cached --quiet || buildrepo_dirty=true
  #[ -n "$(git ls-files --others --exclude-standard)" ] && buildrepo_dirty=true
  buildrepo_url=${repo_url}
  buildrepo_branch=${repo_branch}
  buildcommit="${commit}"
  buildcommit_short=${commit_short}
  buildcommit_date=${commit_date}
  buildcommit_tag=${commit_tag}
  buildrepo_dirty=${repo_dirty}

  commits_since_tag=""
  if [[ -n "$commit_tag" ]]; then
  release_track="stable"
  base_tag=$commit_tag
  version="$commit_tag"
  if [[ "${repo_dirty}" == "true" && "${ALLOW_DIRTY:-false}" != "true" ]]; then
      die "Refusing to publish version ${version} - working tree is dirty. Set ALLOW_DIRTY=true to override"
      exit 1
  fi
  if [[ "${buildrepo_dirty}" == "true" && "${ALLOW_DIRTY_BUILD_PLATFORM:-false}" != "true" ]]; then
      die "Refusing to publish - build platform working tree is dirty. Set ALLOW_DIRTY_BUILD_PLATFORM=true to override"
      exit 1
  fi
  else
  release_track="dev"
  base_tag="$( git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true )"
  if [[ -n "$base_tag" ]]; then
      commits_since_tag="$( git rev-list --count "${base_tag}..HEAD" )"
      version="${base_tag}-dev.${commits_since_tag}"
  else
      version="v0.0.0-dev.0"
      base_tag=""
  fi    
  fi

  build_id="${release_track}.${build_epoch}+git.${commit_short}"
  release_id="${version}+${build_id}"

  # create build context file
  buildctx_schema="phxi.buildctx.v1"
  artifact="$(jq -n \
  --arg schema "$buildctx_schema" \
  --arg release_track "$release_track" \
  --arg app "$APP" \
  --arg version "$version" \
  --arg build_id "$build_id" \
  --arg build_date "$build_date" \
  --argjson build_epoch "$build_epoch" \
  --arg release_id "$release_id" \
  --arg repo_url "$repo_url" \
  --arg repo_branch "$repo_branch" \
  --argjson repo_dirty "$repo_dirty" \
  --arg commit "$commit" \
  --arg commit_date "$commit_date" \
  --arg commit_short "$commit_short" \
  --arg commit_tag "${commit_tag:-}" \
  --arg base_tag "${base_tag:-}" \
  --arg buildrepo_url "$buildrepo_url" \
  --arg buildrepo_branch "$buildrepo_branch" \
  --argjson buildrepo_dirty "$buildrepo_dirty" \
  --arg commits_since_tag "${commits_since_tag:-}" \
  --arg buildcommit "$buildcommit" \
  --arg buildcommit_date "$buildcommit_date" \
  --arg buildcommit_short "$buildcommit_short" \
  --arg buildcommit_tag "${buildcommit_tag:-}" \
  --argjson buildcomponents "$buildcomponents_json" \
  --argjson buildplatforms "$buildplatforms_json" \
  --arg buildhost "$buildhost" \
  --arg buildscript "$buildscript" \
  --arg buildscript_sha256 "$buildscript_sha256" \
  --arg buildscriptargs_sha256 "$buildscriptargs_sha256" \
  --argjson buildscriptargs_json "$buildscriptargs_json" \
  --arg dist "$DIST" \
  '{
      schema: $schema,
      app: $app,
      release: {
      version: $version,
      build_id: $build_id,
      release_id: $release_id,
      track: $release_track,
      created_at: $build_date,
      epoch: $build_epoch,
      },
      source: ({
      repo: $repo_url,
      branch: $repo_branch,
      commit: $commit,
      commit_short: $commit_short,
      commit_date: $commit_date,
      tag: ($commit_tag | select(length>0) // null),
      base_tag: ($base_tag | select(length>0) // null),
      commits_since_tag: (($commits_since_tag | tonumber?) // null),
      dirty: $repo_dirty
      } | with_entries(select(.value != null))),
      builder: {
      repo: $buildrepo_url,
      branch: $buildrepo_branch,
      commit: $buildcommit,
      commit_short: $buildcommit_short,
      commit_date: $buildcommit_date,
      tag: ($buildcommit_tag | select(length>0) // null),
      dirty: $buildrepo_dirty,
      host: $buildhost,
      script: $buildscript,
      script_sha256: $buildscript_sha256,
      script_args: (if ($buildscriptargs_json|length)>0 then $buildscriptargs_json else null end),
      script_args_sha256: $buildscriptargs_sha256,
      generated_at: $build_date
      } | with_entries(select(.value != null)),
      build: {
      components: $buildcomponents,
      platforms: $buildplatforms,
      dist_dir: $dist
      }
  }'
  )"

  mkdir -p "$(dirname "$BUILDCTX_PATH")"
  log "==> (init) writing build context file ${BUILDCTX_PATH}"
  printf '%s\n' "$artifact" > "$BUILDCTX_PATH"
}

ctx_component_init() {
  local component="$1" registry="$2" repository="$3"

  ctx_jq '
    .components = (.components // {}) |
    .components[$c] = (
      (.components[$c] // {
        component: $c,
        oci: {},
        artifacts: {},
        index: {
          kind: "oci-index",
          artifactType: "application/vnd.phxi.binary.index.v1",
          oci: {
            tag: null,
            digest: null,
            mediaType: "application/vnd.oci.image.index.v1+json",
            descriptor_size: null,
            pushed_at: null,
            manifests: []
          },
          evidence: { inventory: [], policy: [], approval: [] }
        }
      })
      | .oci.registry = (.oci.registry // $reg)
      | .oci.repository = (.oci.repository // $repo)
      | .artifacts = (.artifacts // {})
    )
  ' --arg c "$component" --arg reg "$registry" --arg repo "$repository"
}

ctx_jq() {
  local filter="$1"; shift
  local ctx_dir tmp
  ctx_dir="$(dirname -- "${BUILDCTX_PATH}")"
  tmp="$(mktemp -p "$ctx_dir" .buildctx.XXXXXX)"

  jq "$filter" "$@" "${BUILDCTX_PATH}" > "$tmp"
  mv -f "$tmp" "${BUILDCTX_PATH}"
}

platform_key() {
  local label="$1"
  echo "$label" | tr '/' '_' | tr '-' '_'
}

ctx_pkey_from_label() { platform_key "$1"; }


ctx_artifact_set_local() {
  local component="$1" label="$2" os="$3" arch="$4" kind="$5" atype="$6"
  local path="$7" sha="$8" size="$9" tag="${10}"
  local pkey
  pkey="$(platform_key "$label")"

  ctx_jq '
    .components[$c].artifacts[$p] = (
      (.components[$c].artifacts[$p] // {
        platform: { os: $os, arch: $arch, label: $label, key: $p },
        kind: $kind,
        artifactType: $atype,
        local: {},
        oci: {
          tag: null,
          digest: null,
          mediaType: null,
          descriptor_size: null,
          pushed_at: null
        },
        evidence: { sbom: [], scan: [], provenance: [], sig: [] },
        resolved: {}
      })
      | .platform = { os: $os, arch: $arch, label: $label, key: $p }
      | .kind = $kind
      | .artifactType = $atype
      | .local = { path: $path, sha256: $sha, size: $size }
      | .oci.tag = $tag
    )
  ' \
    --arg c "$component" --arg p "$pkey" \
    --arg os "$os" --arg arch "$arch" --arg label "$label" \
    --arg kind "$kind" --arg atype "$atype" \
    --arg path "$path" --arg sha "$sha" --arg tag "$tag" \
    --argjson size "$size"
}

ctx_artifact_set_oci_pushed() {
  local component="$1" pkey="$2" digest="$3" mediaType="$4" dsize="$5" pushed_at="$6"

  ctx_jq '
    .components[$c].artifacts[$p].oci = (
      (.components[$c].artifacts[$p].oci // {})
      | .digest = $digest
      | .mediaType = $mt
      | .descriptor_size = $ds
      | .pushed_at = $ts
    )
  ' \
    --arg c "$component" --arg p "$pkey" \
    --arg digest "$digest" --arg mt "$mediaType" --arg ts "$pushed_at" \
    --argjson ds "$dsize"
}


ctx_index_set_tag() {
  local component="$1" tag="$2"
  ctx_jq '.components[$c].index.oci.tag = $tag' --arg c "$component" --arg tag "$tag"
}

ctx_index_set_oci_pushed() {
  local component="$1" digest="$2" mediaType="$3" dsize="$4" pushed_at="$5"

  ctx_jq '
    .components[$c].index.oci.digest = $digest |
    (if ($mt | length) > 0 then .components[$c].index.oci.mediaType = $mt else . end) |
    .components[$c].index.oci.descriptor_size = $ds |
    .components[$c].index.oci.pushed_at = $ts
  ' \
    --arg c "$component" --arg digest "$digest" --arg mt "$mediaType" --arg ts "$pushed_at" \
    --argjson ds "$dsize"

  ctx_index_refresh_manifests "$component"
}

ctx_index_refresh_manifests() {
  local component="$1"
  local registry repo
  registry="$(ctx_get_component_registry "$component")"
  repo="$(ctx_get_component_repository "$component")"

  ctx_jq '
    ($registry + "/" + $repo) as $base |
    .components[$c].index.oci.manifests =
      (
        (.components[$c].artifacts // {})
        | to_entries
        | map(select(.value.oci.digest != null))
        | map({
            platform_key: .key,
            platform_label: .value.platform.label,
            digest: .value.oci.digest,
            digest_ref: ($base + "@" + .value.oci.digest),
            mediaType: .value.oci.mediaType,
            artifactType: .value.artifactType,
            descriptor_size: .value.oci.descriptor_size
          })
        | sort_by(.platform_key)
      )
  ' --arg c "$component" --arg registry "$registry" --arg repo "$repo"
}

ctx_artifact_append_evidence() {
  local component="$1" label="$2" slot="$3" kind="$4" pt="$5" ref="$6"
  local signer="${7:-}" signed_at="${8:-}"
  local pkey
  pkey="$(platform_key "$label")"

  ctx_jq '
    .components[$c].artifacts[$p].evidence[$slot] =
      (
        (.components[$c].artifacts[$p].evidence[$slot] // [])
        | map(select(.ref != $ref))
        + [{
            kind: $kind,
            predicateType: $pt,
            ref: $ref,
            signer: (if ($signer | length) > 0 then $signer else null end),
            signed_at: (if ($ts | length) > 0 then $ts else null end)
          }]
      )
  ' \
    --arg c "$component" --arg p "$pkey" --arg slot "$slot" \
    --arg kind "$kind" --arg pt "$pt" --arg ref "$ref" \
    --arg signer "$signer" --arg ts "$signed_at"
}

ctx_index_append_evidence() {

  local component="$1" slot="$2" kind="$3" pt="$4" ref="$5"
  local signer="${6:-}" signed_at="${7:-}"

  ctx_jq '
    .components[$c].index.evidence[$slot] =
      (
        (.components[$c].index.evidence[$slot] // [])
        | map(select(.ref != $ref))
        + [{
            kind: $kind,
            predicateType: $pt,
            ref: $ref,
            signer: (if ($signer | length) > 0 then $signer else null end),
            signed_at: (if ($ts | length) > 0 then $ts else null end)
          }]
      )
  ' \
    --arg c "$component" --arg slot "$slot" \
    --arg kind "$kind" --arg pt "$pt" --arg ref "$ref" \
    --arg signer "$signer" --arg ts "$signed_at"
}

ctx_materialize_resolved_refs() {
  ctx_jq '
    def tag_ref(reg; repo; tag): (reg + "/" + repo + ":" + tag);
    def digest_ref(reg; repo; digest): (reg + "/" + repo + "@" + digest);

    .components = (.components // {}) |
    (.components | to_entries) as $comps |
    reduce $comps[] as $ce (.;
      ($ce.key) as $c |
      ( $ce.value.oci.registry // "" ) as $reg |
      ( $ce.value.oci.repository // "" ) as $repo |

      # artifacts
      .components[$c].artifacts = (.components[$c].artifacts // {}) |
      (.components[$c].artifacts | to_entries) as $arts |
      reduce $arts[] as $ae (.;
        ($ae.key) as $p |
        .components[$c].artifacts[$p].resolved = (.components[$c].artifacts[$p].resolved // {}) |
        (if ($reg|length)>0 and ($repo|length)>0 and (.components[$c].artifacts[$p].oci.tag // null) != null
          then .components[$c].artifacts[$p].resolved.tag_ref = tag_ref($reg; $repo; .components[$c].artifacts[$p].oci.tag)
          else . end) |
        (if ($reg|length)>0 and ($repo|length)>0 and (.components[$c].artifacts[$p].oci.digest // null) != null
          then .components[$c].artifacts[$p].resolved.digest_ref = digest_ref($reg; $repo; .components[$c].artifacts[$p].oci.digest)
          else . end)
      ) |

      # index
      .components[$c].index.resolved = (.components[$c].index.resolved // {}) |
      (if ($reg|length)>0 and ($repo|length)>0 and (.components[$c].index.oci.tag // null) != null
        then .components[$c].index.resolved.tag_ref = tag_ref($reg; $repo; .components[$c].index.oci.tag)
        else . end) |
      (if ($reg|length)>0 and ($repo|length)>0 and (.components[$c].index.oci.digest // null) != null
        then .components[$c].index.resolved.digest_ref = digest_ref($reg; $repo; .components[$c].index.oci.digest)
        else . end)
    )
  '
}

ctx_list_components() {
  jq -r '.components | keys[]' "${BUILDCTX_PATH}"
}

ctx_list_platform_keys() {
  local component="$1"
  jq -r --arg c "$component" '.components[$c].artifacts | keys[]' "${BUILDCTX_PATH}"
}

ctx_list_platform_labels() {
  local component="$1"
  jq -r --arg c "$component" '.components[$c].artifacts | .[] | .platform.label' "${BUILDCTX_PATH}"
}

ctx_list_build_platform_labels() {
  jq -r '.build.platforms[]' "${BUILDCTX_PATH}"
}

ctx_has_artifact() {
  local component="$1" pkey="$2"
  jq -e --arg c "$component" --arg p "$pkey" \
    '.components[$c].artifacts[$p] != null' \
    "${BUILDCTX_PATH}" >/dev/null
}

ctx_get_artifact_field() {
  # args: component platform_key jq_field_path
  local component="$1"
  local pkey="$2"
  local field="$3"

  jq -r --arg c "$component" --arg p "$pkey" \
    ".components[\$c].artifacts[\$p]${field} // empty" \
    "${BUILDCTX_PATH}"
}

ctx_get_artifact_local_sha256() {
  # args: component platform_key
  ctx_get_artifact_field "$1" "$2" '.local.sha256'
}

ctx_get_artifact_local_path() {
  ctx_get_artifact_field "$1" "$2" '.local.path'
}

ctx_get_artifact_oci_tag() {
  ctx_get_artifact_field "$1" "$2" '.oci.tag'
}

ctx_get_component_registry() {
  local component="$1"
  jq -r --arg c "$component" '.components[$c].oci.registry // empty' "${BUILDCTX_PATH}"
}

ctx_get_component_repository() {
  local component="$1"
  jq -r --arg c "$component" '.components[$c].oci.repository // empty' "${BUILDCTX_PATH}"
}

ctx_get_artifact_digest() {
  ctx_get_artifact_field "$1" "$2" '.oci.digest'
}

ctx_get_artifact_media_type() {
  ctx_get_artifact_field "$1" "$2" '.oci.mediaType'
}

ctx_get_artifact_descriptor_size() {
  ctx_get_artifact_field "$1" "$2" '.oci.descriptor_size'
}

ctx_get_artifact_platform_label() {
  ctx_get_artifact_field "$1" "$2" '.platform.label'
}

ctx_get_artifact_type() {
  ctx_get_artifact_field "$1" "$2" '.artifactType'
}

ctx_get_component_field() {
  local component="$1"
  local field="$2"
  jq -r --arg c "$component" \
    ".components[\$c]${field} // empty" \
    "${BUILDCTX_PATH}"
}

ctx_get_index_tag() {
  ctx_get_component_field "$1" '.index.oci.tag'
}

ctx_get_index_digest() {
  ctx_get_component_field "$1" '.index.oci.digest'
}