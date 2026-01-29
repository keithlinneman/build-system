# shellcheck shell=bash

# generate_inventory_json() {
#  for component in $( ctx_list_components ); do
#    log "==> (inventory) generating inventory.json for component=${component}"
#    generate_component_inventory_json "$component" "$@" || die "failed to generate inventory json for component=${component}"
#  done
# }

generate_component_inventory_json() {
  # cache avoids re-hashing the same file over and over
  #declare -A _SHA _SZ
  local component="$1"
  shift || true
  local OUT="${DIST}/inventory.json"

  # get builder information
  build_info="$( ctx_get_json '.builder' )"

  generated_epoch="$( date +%s )"
  generated_date="$( date -d "@${generated_epoch}" -u +%Y-%m-%dT%H:%M:%SZ )"
  generated_host="$( hostname )"
  generated_script="${1:-unknown}"
  shift || true
  ORIGINAL_ARGS=("$@")
  ORIGINAL_ARGS_JSON="$( args_json "${ORIGINAL_ARGS[@]}" )"
  redacted_args=()
  for a in "${ORIGINAL_ARGS[@]}";do
    redacted_args+=("$(redact_arg "$a")")
  done
  generatedscript_sha256="$( sha256sum "$generated_script" | awk '{ print $1 }' )"
  #  generatedscriptargs_json="$( printf '%s\0' "${redacted_args[@]}" | jq -Rs 'split("\u0000")[:-1] | map(select(length > 0))' )"
  #  generatedscriptargs_sha256="$( printf '%s\0' "${ORIGINAL_ARGS[@]}" | sha256sum | awk '{print $1}' )"
  # script_args is JSON array
  #generatedscriptargs_json="$( jq -cn --argjson a "$(printf '%s\n' "${redacted_args[@]}" | jq -R . | jq -s .)" '$a' )"
  #generatedscriptargs_sha256="$( printf '%s\n' "${ORIGINAL_ARGS[@]}" | sha256sum | awk '{print $1}' )"
  #generatedscriptargs_json="$( jq -cn --args '$ARGS.positional' -- "${redacted_args[@]}" )"
  #generatedscriptargs_sha256="$( jq -cn --args '$ARGS.positional' -- "${ORIGINAL_ARGS[@]}" | sha256sum | awk '{print $1}' )"

  # Buildctx-derived maps used now
  # local evidence_by_path oci_summary
  # evidence_by_path="$(ctx_evidence_by_path_json)"
  oci_summary="$(ctx_inventory_oci_summary_json)"

  generatedscriptargs_json="$( args_json "${redacted_args[@]}" )"
  generatedscriptargs_sha256="$( printf '%s' "$ORIGINAL_ARGS_JSON" | sha256sum | awk '{print $1}' )"
 
  generated_by="$( jq -n \
    --arg host "$generated_host" \
    --arg tool "phxi-build" \
    --arg step "40-generate-inventory" \
    --arg script "$generated_script" \
    --arg script_sha256 "$generatedscript_sha256" \
    --argjson scriptargs_json "$generatedscriptargs_json" \
    --arg scriptargs_sha256 "$generatedscriptargs_sha256" \
    --arg epoch "$generated_epoch" \
    --arg date "$generated_date" \
    '{
      host: $host,
      tool: $tool,
      step: $step,
      script: $script,
      script_sha256: $script_sha256,
      script_args: $scriptargs_json,
      script_args_sha256: $scriptargs_sha256,
      timestamp: ($epoch | tonumber),
      generated_at: $date
    }' \
  )"

  # skipping repo-level scans/sboms/etc for now
  # include a pseudo "_repo" component if root-level evidence exists
  # this gets moved to root level source_manifest and source_evidence in final jq, keeps parsing simpler for now
  # if [[ -f "${DIST}/build.json" || -d "${DIST}/sbom" || -d "${DIST}/scan" || -d "${DIST}/attestations" ]]; then
  #   components="$(jq --arg k "_repo" --argjson v "$(build_component_obj "_repo")" '. + {($k):$v}' <<<"$components")"
  # fi

  # moving to component based releases for now
  # while IFS= read -r comp; do
  #   [[ -n "$comp" ]] || continue
  #   components="$(jq --arg k "$comp" --argjson v "$(build_component_obj "$comp")" '. + {($k):$v}' <<<"$components")"
  # done < <( ctx_list_components )

  # 1/29/26 - not currently used commenting to save cpu time
  # build files[] inventory
  # local files='[]'
  # while IFS= read -r abs; do
  #   local rel
  #   rel="${abs#"${DIST}/${component}/"}"
  #   # dont embed the manifests we are generating (or sigs) inside themselves
  #   [[ "$rel" == "release.json" ]] && continue
  #   [[ "$rel" == "release.json.sig" ]] && continue
  #   [[ "$rel" == "inventory.json" ]] && continue
  #   [[ "$rel" == "inventory.json.sig" ]] && continue

  #   local obj kind
  #   obj="$(file_obj "$rel")"
  #   kind="$(classify_kind "$rel")"

  #   # if binary annotate os/arch
  #   local osarch os="" arch=""
  #   osarch="$(parse_os_arch_from_bin_rel "$rel")"
  #   if [[ -n "$osarch" ]]; then
  #     os="$(awk '{print $1}' <<<"$osarch")"
  #     arch="$(awk '{print $2}' <<<"$osarch")"
  #   fi

  #    # attach evidence attestation info to evidence files by matching predicate.path == rel
  #   local ev_json=""
  #   ev_json="$(jq -c --arg p "$rel" '.[$p] // empty' <<<"$evidence_by_path" 2>/dev/null || true)"

  #   # if binary attach OCI subject (resolved refs) from buildctx.
  #   local subject_json=""
  #   if [ "${kind}" == "binary" ]; then
  #     local component
  #     component="$( discover_component_from_rel_path "$rel" )"

  #     if [[ -z "$os" || -z "$arch" ]]; then
  #       die "binary missing parsed os/arch (file=${rel})"
  #     fi

  #     local label="${os}/${arch}"
  #     log "==> (inventory) attaching buildctx subject for ${component} ${label} (file=${rel})"
  #     subject_json="$(ctx_get_subject_for_component_platform "$component" "$label" 2>/dev/null || true)"
  #     if [[ -z "${subject_json}" ]]; then
  #       die "could not find buildctx subject for component=${component} label=${label} (file=${rel})"
  #     fi
  #     if [[ -z "$(jq -r '.resolved.digest_ref // empty' <<<"$subject_json")" ]]; then
  #       die "subject missing resolved.digest_ref component=${component} label=${label}"
  #     fi

  #   fi

  #   obj="$(jq -n \
  #     --argjson base "$obj" \
  #     --arg kind "$kind" \
  #     --arg os "$os" \
  #     --arg arch "$arch" \
  #     --argjson subject "${subject_json:-null}" \
  #     --argjson evidence_referrer "${ev_json:-null}" \
  #     '
  #       $base
  #       +
  #       {kind:$kind}
  #       +
  #       (if $os != ""
  #         then {os:$os, arch:$arch}
  #         else {}
  #       end)
  #       +
  #       (if $subject != null then {oci_subject:$subject} else {} end)
  #       +
  #       (if $evidence_referrer != null then {oci_referrer:$evidence_referrer} else {} end)
  #      '
  #   )"
  #   files="$(add_to_array "$files" "$obj")"
  # done < <(find "$DIST/${component}" -type f | LC_ALL=C sort)

  # oras tooling
  local oras_ver
  oras_ver="$( oras version  | grep ^Version | awk '{ print $NF }' )"

  # gather metadata
  #local app release_id created_at
  #app="${APP:-}"
  #release_id="${RELEASE_ID:-}"
  #created_at="${BUILD_DATE:-}"

  ## git best-effort
  #local repo commit branch tag
  #repo="$(git config --get remote.origin.url 2>/dev/null || true)"
  #commit="$(git rev-parse HEAD 2>/dev/null || true)"
  #branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  #tag="$(git describe --tags --exact-match 2>/dev/null || true)"

  ## normalize dirty -> JSON boolean
  #local dirty_raw="${DIRTY:-false}"
  #local dirty_json="false"
  #[[ "$dirty_raw" == "true" ]] && dirty_json="true"

  source="$( ctx_get .source )"
  go_ver="$( go version | awk '{print $3}' || true)"
  cosign_ver="$( cosign version --json=true | jq -r .gitVersion || true )"
  grype_ver="$( grype version -o json | jq -r .version )"
  grype_db_source="$( grype db status -o json | jq -r .from )"
  grype_db_upstream_modified_at="$( grype db status -o json | jq .from | awk -F '_' '{ print $3 }' )"
  grype_db_checked_at="$( grype db status -o json | jq -r .built )"
  trivy_ver="$( trivy version -f json | jq -r .Version )"
  trivy_db_source="mirror.gcr.io/aquasec/trivy-db:2"
  trivy_db_upstream_modified_at_raw="$( trivy version -f json | jq -r .VulnerabilityDB.UpdatedAt )"
  trivy_db_upstream_modified_at="$( date -d "${trivy_db_upstream_modified_at_raw}" -u +"%Y-%m-%dT%H:%M:%SZ" )"
  trivy_db_checked_at="$( trivy version -f json | jq -r .VulnerabilityDB.DownloadedAt )"
  trivy_db_checked_at_raw="$( trivy version -f json | jq -r .VulnerabilityDB.DownloadedAt )"
  trivy_db_checked_at="$( date -d "${trivy_db_checked_at_raw}" -u +"%Y-%m-%dT%H:%M:%SZ" )"
  govuln_ver="$( govulncheck -format json | jq -r .config.scanner_version )"
  govuln_db_source="$( govulncheck -format json | jq -r .config.db )"
  govuln_db_upstream_modified_at="$( govulncheck -format json | jq -r .config.db_last_modified )"
  govuln_db_checked_at="$( date -u +"%Y-%m-%dT%H:%M:%SZ" )"
  cyclonedx_gomod_ver="$( cyclonedx-gomod version | grep ^Version | awk '{ print $NF }' || true )"
  cyclonedx_gomod_modsum="$( cyclonedx-gomod version | grep ^ModuleSum | awk '{ print $NF }' || true )"
  syft_ver="$( syft version -o json | jq -r .version )"
  syft_commit="$( syft version -o json | jq -r .gitCommit )"

  # distribution info (set in build pipeline)
  local bucket="${RELEASE_BUCKET:-${S3_BUCKET:-}}"
  local prefix="${RELEASE_PREFIX:-${S3_PREFIX:-}}"

  # write inventory.json
  jq -n -S \
    --arg schema "phxi.inventory.v1" \
    --arg app "$APP" \
    --arg release_id "$RELEASE_ID" \
    --arg created_at "$BUILD_DATE" \
    --arg version "$RELEASE_VERSION" \
    --arg build_id "$BUILD_ID" \
    --arg go_ver "$go_ver" \
    --arg cosign_ver "$cosign_ver" \
    --arg oras_ver "$oras_ver" \
    --arg grype_ver "$grype_ver" \
    --arg grype_db_source "$grype_db_source" \
    --arg grype_db_upstream_modified_at "$grype_db_upstream_modified_at" \
    --arg grype_db_checked_at "$grype_db_checked_at" \
    --arg trivy_ver "$trivy_ver" \
    --arg trivy_db_source "$trivy_db_source" \
    --arg trivy_db_upstream_modified_at "$trivy_db_upstream_modified_at" \
    --arg trivy_db_checked_at "$trivy_db_checked_at" \
    --arg govulncheck_ver "$govuln_ver" \
    --arg govulncheck_db_source "$govuln_db_source" \
    --arg govulncheck_db_upstream_modified_at "$govuln_db_upstream_modified_at" \
    --arg govulncheck_db_checked_at "$govuln_db_checked_at" \
    --arg cyclonedx_gomod_ver "$cyclonedx_gomod_ver" \
    --arg cyclonedx_gomod_modsum "$cyclonedx_gomod_modsum" \
    --arg bucket "$bucket" \
    --arg syft_ver "$syft_ver" \
    --arg syft_commit "$syft_commit" \
    --arg prefix "$prefix" \
    --arg component "$component" \
    --argjson generated_by "$generated_by" \
    --argjson build_info "$build_info" \
    --argjson oci_summary "$oci_summary" \
    --argjson source "$source" \
    '{
      schema:$schema,
      app:$app,
      release_id:$release_id,
      version:(if $version != "" then $version else null end),
      build_id:(if $build_id != "" then $build_id else null end),
      created_at:$created_at,
      generated_by:$generated_by | with_entries(select(.value != null)),
      source:$source,
      build: $build_info,
      distribution:(if ($bucket != "" or $prefix != "") then {provider:"s3", bucket:$bucket, prefix:$prefix} else null end),
      oci: (if ($oci_summary|type=="object" and ($oci_summary|keys|length)>0) then $oci_summary else null end),
      tooling:{
        go:{
          version:$go_ver,
          category: "toolchain",
        },
        cosign:{
          version:$cosign_ver,
          category: "signing-tool",
        },
        oras:{
          version:$oras_ver,
          category: "artifact-uploader"
        },
        grype:{
          version:$grype_ver,
          category: "vuln-scanner",
          db:{
            source:$grype_db_source,
            upstream_modified_at:$grype_db_upstream_modified_at,
            checked_at:$grype_db_checked_at
          }
        },
        trivy:{
          version:$trivy_ver,
          category: "vuln-scanner",
          db:{
            source:$trivy_db_source,
            upstream_modified_at:$trivy_db_upstream_modified_at,
            checked_at:$trivy_db_checked_at
          }
        },
        govulncheck:{
          version:$govulncheck_ver,
          category: "vuln-scanner",
          db:{
            source:$govulncheck_db_source,
            upstream_modified_at:$govulncheck_db_upstream_modified_at,
            checked_at:$govulncheck_db_checked_at
          }
        },
        syft:{
          version:$syft_ver,
          commit:$syft_commit,
          category: "sbom-generator"
        },
        cyclonedx_gomod:{
          version:$cyclonedx_gomod_ver,
          modsum:$cyclonedx_gomod_modsum,
          category: "sbom-generator"
        },
      },
      component:     $component
    }
    | with_entries(select(.value != null))
    | (if (.subjects? | type=="array" and length==0) then del(.subjects) else . end)
    | (if (.signing?  | type=="object" and (.signing|keys|length)==0) then del(.signing) else . end)
    | (.tooling |= with_entries(select(.value != "")))
    | (.source  |= with_entries(select(.value != "")))
    ' > "$OUT"

  # validate
  jq -e . "$OUT" >/dev/null 2>&1 || { die "ERROR: wrote invalid JSON to $OUT"; return 1; }
  log "==> (build) wrote ${OUT}"
}

args_json() {
  jq -cn --args '$ARGS.positional' -- "$@"
}

# Disabling shellcheck warning since the variables are used in jq expression
# shellcheck disable=SC2016
ctx_evidence_by_path_json() {
  ctx_get_json '
    def ev_stream:
      (.components // {} | to_entries[]? as $ce
        | (
            # artifact evidence: components.<c>.artifacts.<p>.evidence.<slot>[]?
            ($ce.value.artifacts // {} | to_entries[]? as $ae
              | ($ae.value.evidence // {} | to_entries[]? | .value[]? )
            ),
            # index evidence: components.<c>.index.evidence.<slot>[]?
            ($ce.value.index.evidence // {} | to_entries[]? | .value[]? )
          )
      );

    [ ev_stream
      | select(type=="object")
      | select(.predicate? and (.predicate|type=="object"))
      | select(.predicate.path? and (.predicate.path|type=="string") and (.predicate.path|length>0))
    ]
    | reduce .[] as $e ({}; .[$e.predicate.path] = $e)
  ' 2>/dev/null || echo '{}'
}

# Build a compact OCI summary for inventory.json from buildctx
# disabling shellcheck warning since the variables are used in jq expression
# shellcheck disable=SC2016
ctx_inventory_oci_summary_json() {
  ctx_get_json '
    (.components // {}) as $C
    | ($C | to_entries)
    | reduce .[] as $ce ({}; .[$ce.key] = (
        {
          oci: {
            registry: ($ce.value.oci.registry // null),
            repository: ($ce.value.oci.repository // null)
          } | with_entries(select(.value != null)),
          index: ($ce.value.index // null),
          artifacts: ($ce.value.artifacts // {})
        }
        | .index = (
            if .index == null then null else
              (.index | {
                kind, artifactType,
                oci: (.oci // {} | with_entries(select(.value != null))),
                resolved: (.resolved // {} | with_entries(select(.value != null))),
                evidence: (.evidence // {} | with_entries(select(.value != null)))
              } | with_entries(select(.value != null)))
            end
          )
        | .artifacts = (
            (.artifacts | to_entries)
            | map(
                .value as $a
                | {
                    platform_key: .key,
                    platform_label: ($a.platform.label // null),
                    kind: ($a.kind // null),
                    artifactType: ($a.artifactType // null),
                    oci: ($a.oci // {} | with_entries(select(.value != null))),
                    resolved: ($a.resolved // {} | with_entries(select(.value != null))),
                    evidence: ($a.evidence // {} | with_entries(select(.value != null)))
                  }
                  | with_entries(select(.value != null))
              )
            | sort_by(.platform_key)
          )
        | with_entries(select(.value != null))
      ))
  ' 2>/dev/null || echo '{}'
}

attest_inventory_json_to_index() {
  local component="$1"
  [[ -n "${DIST:-}" ]] || die "attest_release_json_to_indexes: DIST not set"
  [[ -f "${DIST}/${component}/inventory.json" ]] || die "attest_release_json_to_indexes: missing ${DIST}/${component}/inventory.json"

  local inv_abs="${DIST}/${component}/inventory.json"
  # local pred_abs="${DIST}/${component}/inventory.json"

  local pred_type="${PRED_INVENTORY_DESCRIPTOR:-https://phxi.net/attestations/inventory/v1}"
  #local out_dir="${DIST}/_repo/attestations/release/inventory"
  local out_dir="${DIST}/${component}/"
  mkdir -p "$out_dir"

  jq -r '.components | keys[]' "$inv_abs" | while IFS= read -r component; do
    local subject
    subject="$(jq -r --arg c "$component" '.components[$c].oci_index.digest_ref // empty' "$inv_abs")"
    [[ -n "$subject" ]] || die "release attest: missing oci_index.digest_ref for component=$component"

    log "==> (release) attesting inventory.json -> ${component} index ${subject}"

    local out=()
    if ! mapfile -t out < <(cosign_attest_predicate "$subject" "$inv_abs" "$pred_type"); then
      die "release attest: cosign_attest_predicate failed for component=$component subject=$subject"
    fi
    [[ ${#out[@]} -eq 4 ]] || die "release attest: unexpected cosign_attest_predicate output for component=$component"

    local att_digest_ref="${out[0]}"

    local dsse_abs="${out_dir}/inventory.json.intoto.v1.dsse.json"
    local manifest_abs="${out_dir}/inventory.json.oci.manifest.json"

    # save dsse_abs and manifest_abs (manifest content only)
    oci_fetch_attestation_dsse "$att_digest_ref" "$dsse_abs" "$manifest_abs" >/dev/null
  done
}