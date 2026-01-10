generate_inventory_json() {
  local OUT="${DIST}/inventory.json"
  # cache avoids re-hashing the same file over and over
  declare -A _SHA _SZ

  # ---------- build components{} ----------
  local components='{}'

  # get builder information
  build_info="$( ctx_get_json '.builder' )"

  generated_epoch="$( date +%s )"
  generated_date="$( date -d @${generated_epoch} -u +%Y-%m-%dT%H:%M:%SZ )"
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

  # include a pseudo "_repo" component if root-level evidence exists
  # this gets moved to root level source_manifest and source_evidence in final jq, keeps parsing simpler for now
  if [[ -f "${DIST}/build.json" || -d "${DIST}/sbom" || -d "${DIST}/scan" || -d "${DIST}/attestations" ]]; then
    components="$(jq --arg k "_repo" --argjson v "$(build_component_obj "_repo")" '. + {($k):$v}' <<<"$components")"
  fi

  while IFS= read -r comp; do
    [[ -n "$comp" ]] || continue
    components="$(jq --arg k "$comp" --argjson v "$(build_component_obj "$comp")" '. + {($k):$v}' <<<"$components")"
  done < <(discover_components)

  # ---------- build files[] inventory ----------
  local files='[]'
  while IFS= read -r abs; do
    local rel="${abs#${DIST}/}"
    # dont embed the manifest we are generating (or its .sig file) inside itself
    [[ "$rel" == "release.json" ]] && continue
    [[ "$rel" == "release.json.sig" ]] && continue

    local obj kind
    obj="$(file_obj "$rel")"
    kind="$(classify_kind "$rel")"

    # if it's a binary, annotate os/arch
    local osarch os="" arch=""
    osarch="$(parse_os_arch_from_bin_rel "$rel")"
    if [[ -n "$osarch" ]]; then
      os="$(awk '{print $1}' <<<"$osarch")"
      arch="$(awk '{print $2}' <<<"$osarch")"
    fi

    if [ "${kind}" == "binary" ]; then
      local component="$( discover_component_from_rel_path "$rel" )"

      log "==> (evidence) locating build context oci subject for component:${component} os:${os} arch:${arch} (file:${rel})"
      # find it in the oci subjects buildctx if present
      local subject_json
      subject_json="$( ctx_get_json ".oci.subjects[] | select(.component==\"${component}\") | select(.platform_label==\"${os}/${arch}\")" || true )"
      log "subject_json=${subject_json}"

      if [ "${subject_json}x" == "x" ]; then
        die "could not find subject entry in buildctx for component:${component} os:${os} arch:${arch} (file:${rel})"
      fi
    fi

    obj="$(jq -n \
      --argjson base "$obj" \
      --arg kind "$kind" \
      --arg os "$os" \
      --arg arch "$arch" \
      --argjson oci "${subject_json:-null}" \
      '
        $base
        +
        {kind:$kind}
        +
        (if $os != ""
          then {os:$os, arch:$arch}
          else {}
        end)
        +
        (if $oci != null then {oci:$oci} else {} end)
      '
    )"
    files="$(add_to_array "$files" "$obj")"
  done < <(find "$DIST" -type f | LC_ALL=C sort)

  # ---------- policies ----------
  policy_enforcement="${policy_enforcement:-warn}"
  policy_overrides="${policy_overrides:-}"
  evidence_policy="$( jq -n '
  {
    required: {
      sbom: { formats: ["spdx-json","cyclonedx-json"], attestation_required: true },
      vuln: { scanners: ["grype","trivy","govulncheck"], attestation_required: true },
    },
    optional: {
      provenance: { enabled: false, attestation_required: true }
    }
  }
  ')"

  vulnerability_policy="$( jq -n '
  {
    severity_system: "scanner-native",
    normalization: {
      strategy: "worst"
    },
    gating: {
      default: {
        block_on: ["critical","high"],
        allow_if_vex: true
      }
    }
  }
  ')"

  signing_policy="$( jq -n '
  {
    required: {
      subject: true,
      inventory: true
    }
  }
  ')"

  freshness_policy="$( jq -n '
  {
    max_age_hours: {
      trivy_db_observed: 72,
      grype_db_built: 72,
      govulndb_upstream_modified: 168
    }
  }
  ')"

  # ---------- oras tooling ----------
  local oras_ver="$( oras version  | grep ^Version | awk '{ print $NF }' )"

  # ---------- gather metadata ----------
  local app="${APP:-}"
  local release_id="${RELEASE_ID:-}"
  local created_at="${BUILD_DATE:-}"

  # git best-effort
  local repo commit branch tag
  repo="$(git config --get remote.origin.url 2>/dev/null || true)"
  commit="$(git rev-parse HEAD 2>/dev/null || true)"
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  tag="$(git describe --tags --exact-match 2>/dev/null || true)"

  # normalize dirty -> JSON boolean
  local dirty_raw="${DIRTY:-false}"
  local dirty_json="false"
  [[ "$dirty_raw" == "true" ]] && dirty_json="true"

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

  ## TODO signing hints (set in build pipeline)
  # local cosign_key_ref="${COSIGN_KEY_REF:-${COSIGN_KEY:-${COSIGN_KMS_KEY:-${COSIGN_AWSKMS_KEY:-}}}}"
  # local cosign_pubkey_path="${COSIGN_PUBKEY_PATH:-}"
  # local cosign_pubkey_sha256=""
  # if [[ -n "$cosign_pubkey_path" && -f "$cosign_pubkey_path" ]]; then
  #   cosign_pubkey_sha256="$(sha256sum "$cosign_pubkey_path" | awk '{print $1}')"
  # fi

  # distribution info (set in build pipeline)
  local bucket="${RELEASE_BUCKET:-${S3_BUCKET:-}}"
  local prefix="${RELEASE_PREFIX:-${S3_PREFIX:-}}"

  # ---------- write inventory.json ----------
  jq -n -S \
    --arg schema "phxi.inventory.v1" \
    --arg app "$APP" \
    --arg release_id "$RELEASE_ID" \
    --arg created_at "$BUILD_DATE" \
    --arg version "$RELEASE_VERSION" \
    --arg build_id "$BUILD_ID" \
    --arg cosign_key_ref "$cosign_key_ref" \
    --arg cosign_pubkey_path "$cosign_pubkey_path" \
    --arg cosign_pubkey_sha256 "$cosign_pubkey_sha256" \
    --arg repo "$repo" \
    --arg commit "$commit" \
    --arg branch "$branch" \
    --arg tag "$tag" \
    --argjson dirty "$dirty_json" \
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
    --arg policy_enforcement "$policy_enforcement" \
    --argjson policy_overrides "${policy_overrides:-null}" \
    --argjson evidence_policy "${evidence_policy:-null}" \
    --argjson vulnerability_policy "${vulnerability_policy:-null}" \
    --argjson signing_policy "${signing_policy:-null}" \
    --argjson freshness_policy "${freshness_policy:-null}" \
    --argjson files "$files" \
    --argjson components "$components" \
    --argjson generated_by "$generated_by" \
    --argjson build_info "$build_info" \
    '{
      schema:$schema,
      app:$app,
      release_id:$release_id,
      version:(if $version != "" then $version else null end),
      build_id:(if $build_id != "" then $build_id else null end),
      created_at:$created_at,
      generated_by:$generated_by | with_entries(select(.value != null)),
      source:{
        repo:$repo,
        commit:$commit,
        branch:$branch,
        tag:$tag,
        dirty:$dirty
      },
      build: $build_info,
      distribution:(if ($bucket != "" or $prefix != "") then {provider:"s3", bucket:$bucket, prefix:$prefix} else null end),
      policy: (
        { enforcement: $policy_enforcement }
	    + (if $policy_overrides     != null then {overrides:     $policy_overrides}     else {} end)
        + (if $evidence_policy      != null then {evidence:      $evidence_policy}      else {} end)
        + (if $vulnerability_policy != null then {vulnerability: $vulnerability_policy} else {} end)
        + (if $signing_policy       != null then {signing:       $signing_policy}       else {} end)
        + (if $freshness_policy     != null then {freshness:     $freshness_policy}     else {} end)
       | if length==0 then null else . end
      ),
      signing: (
        if ($cosign_key_ref != "" or $cosign_pubkey_path != "" or $cosign_pubkey_sha256 != "")
        then {
          cosign: {
            key_ref: (if $cosign_key_ref != "" then $cosign_key_ref else null end),
            pubkey: {
              path: (if $cosign_pubkey_path != "" then $cosign_pubkey_path else null end),
              sha256: (if $cosign_pubkey_sha256 != "" then $cosign_pubkey_sha256 else null end)
            } | with_entries(select(.value != null))
          } | with_entries(select(.value != null))
        }
        else null end
      ),
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
      source_manifest:   ($components._repo.build? // null),
      source_evidence:($components._repo.source_evidence? // null),
      components:     ($components | del(._repo))
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