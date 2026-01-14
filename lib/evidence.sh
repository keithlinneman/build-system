# shellcheck shell=bash

file_obj() {
  local rel="$1"
  local abs="${DIST}/${rel}"
  [[ -f "$abs" ]] || { jq -n 'null'; return 0; }

  if [[ -z "${_SHA[$rel]+x}" ]]; then _SHA["$rel"]="$(sha256_of "$abs")"; fi
  if [[ -z "${_SZ[$rel]+x}"  ]]; then _SZ["$rel"]="$(size_of "$abs")";  fi

  jq -n \
    --arg path "$rel" \
    --arg sha256 "${_SHA[$rel]}" \
    --argjson size "${_SZ[$rel]}" \
    '{path:$path, hashes: {sha256:$sha256}, size:$size}'
}

file_obj_or_null() {
  local rel="$1"
  ( [[ -f "${DIST}/${rel}" ]] && file_obj "$rel" ) || jq -n 'null'
}

dist_relpath() {
  local p="$1"
  [[ -n "${DIST:-}" ]] || die "DIST not set"
  if [[ "$p" == "${DIST}/"* ]]; then
    printf '%s\n' "${p#"${DIST}/"}"
  else
    printf '%s\n' "$p"
  fi
}

dist_abspath() {
  local p="$1"
  [[ -n "${DIST:-}" ]] || die "DIST not set"
  if [[ "$p" == /* ]]; then
    printf '%s\n' "$p"
  elif [[ "$p" == "${DIST}/"* ]]; then
    printf '%s\n' "$p"
  else
    printf '%s\n' "${DIST}/${p}"
  fi
}

evidence_content_type_for_sbom_path() {
  local rel="$1"
  case "$rel" in
    *.spdx.json) echo "${PRED_SBOM_SPDX:?PRED_SBOM_SPDX required}" ;;
    *.cdx.json)  echo "${PRED_SBOM_CDX:?PRED_SBOM_CDX required}" ;;
    *)           echo "" ;;
  esac
}

# returns content type not the cosign envelope type
evidence_content_type_for_source_scan() {
  # args: scanner kind format
  local scanner="$1" kind="$2" format="$3"
  case "$scanner" in
    govulncheck) echo "${PRED_VULN_GOVULNCHECK:?}" ;;
    grype)       echo "${PRED_VULN_GRYPE:?}" ;;
    trivy)       echo "${PRED_VULN_TRIVY:?}" ;;
    *)           echo "https://phxi.net/attestations/${scanner}/source/v1" ;;
  esac
}

# ---------- classify for files[] ----------
classify_kind() {
  local rel="$1"
  if [[ "$rel" == *"/attestations/"* ]] || [[ "$rel" == *.sigstore.json ]]; then
    echo "attestation"
  elif [[ "$rel" == *.sig ]]; then
    echo "signature"
  elif [[ "$rel" == *.sha256 ]]; then
    echo "checksum"
  elif [[ "$rel" == *sbom/* ]] && [[ "$rel" == *.json ]]; then
    echo "sbom"
  elif [[ "$rel" == *scan/* ]] && [[ "$rel" == *.json ]]; then
    echo "scan"
  elif [[ "$rel" == "build.json" ]] || [[ "$rel" == */build.json ]] || [[ "$rel" == "release.json" ]] || [[ "$rel" == "inventory.json" ]]; then
    echo "manifest"
  elif [[ "$rel" == */bin/* ]]; then
    echo "binary"
  else
    echo "file"
  fi
}

parse_os_arch_from_bin_rel() {
  # expects <comp>/bin/<os>/<arch>/<name>
  local rel="$1"
  IFS='/' read -r comp bin os arch rest <<<"$rel" || true
  if [[ "$bin" == "bin" && -n "$os" && -n "$arch" ]]; then
    echo "$os $arch"
  else
    echo "null null"
  fi
}

discover_component_from_rel_path() {
  # expects <comp>/bin/<os>/<arch>/<name>
  local rel="$1"
  IFS='/' read -r comp bin os arch rest <<<"$rel" || true
  if [[ -n "$comp" ]]; then
    echo "$comp"
  else
    echo "unknown"
  fi
}

evidence_init_oci_maps() {
  # These are jq variables not shell variables so disabling shellcheck single quote warning
  # shellcheck disable=SC2016
  OCI_SUBJECTS_BY_KEY="$(
    ctx_get_json '
      def mk_tag_ref(reg; repo; tag):
        if (reg|length)>0 and (repo|length)>0 and (tag|length)>0
        then (reg + "/" + repo + ":" + tag) else null end;

      def mk_digest_ref(reg; repo; digest):
        if (reg|length)>0 and (repo|length)>0 and (digest|length)>0
        then (reg + "/" + repo + "@" + digest) else null end;

      (.components // {})
      | to_entries
      | map(
          .key as $c
          | (.value.oci.registry // "") as $reg
          | (.value.oci.repository // "") as $repo
          | ((.value.artifacts // {}) | to_entries
             | map(
                 .key as $p
                 | .value as $a
                 | ($a.platform.os // "") as $os
                 | ($a.platform.arch // "") as $arch
                 | {
                     key: ($c + "|" + $os + "|" + $arch),
                     value: ({
                       component: $c,
                       platform: {
                         os: $os,
                         architecture: $arch,
                         label: ($a.platform.label // null),
                         key: $p
                       },
                       tag: ($a.oci.tag // null),
                       tag_ref: ($a.resolved.tag_ref // mk_tag_ref($reg; $repo; ($a.oci.tag // ""))),
                       digest: ($a.oci.digest // null),
                       digest_ref: ($a.resolved.digest_ref // mk_digest_ref($reg; $repo; ($a.oci.digest // ""))),
                       size: ($a.oci.size // null),
                       repository: (if ($reg|length)>0 and ($repo|length)>0 then ($reg + "/" + $repo) else null end),
                       artifactType: ($a.artifactType // null),
                       mediaType: ($a.oci.mediaType // null),
                       pushed_at: ($a.oci.pushed_at // null)
                     } | with_entries(select(.value != null)))
                   }
               )
           )
        )
      | add
      | from_entries
    '
  )"

  # These are jq variables not shell variables so disabling shellcheck single quote warning
  # shellcheck disable=SC2016
  OCI_INDEX_BY_COMP="$(
    ctx_get_json '
      def mk_tag_ref(reg; repo; tag):
        if (reg|length)>0 and (repo|length)>0 and (tag|length)>0
        then (reg + "/" + repo + ":" + tag) else null end;

      def mk_digest_ref(reg; repo; digest):
        if (reg|length)>0 and (repo|length)>0 and (digest|length)>0
        then (reg + "/" + repo + "@" + digest) else null end;

      (.components // {})
      | to_entries
      | map(
          .key as $c
          | (.value.oci.registry // "") as $reg
          | (.value.oci.repository // "") as $repo
          | (.value.index // {}) as $idx
          | {
              key: $c,
              value: ({
                component: $c,
                tag: ($idx.oci.tag // null),
                tag_ref: ($idx.resolved.tag_ref // mk_tag_ref($reg; $repo; ($idx.oci.tag // ""))),
                digest: ($idx.oci.digest // null),
                digest_ref: ($idx.resolved.digest_ref // mk_digest_ref($reg; $repo; ($idx.oci.digest // ""))),
                repository: (if ($reg|length)>0 and ($repo|length)>0 then ($reg + "/" + $repo) else null end),
                artifactType: ($idx.artifactType // null),
                mediaType: ($idx.oci.mediaType // null),
                size: ($idx.oci.size // null),
                pushed_at: ($idx.oci.pushed_at // null),
                manifests: ($idx.oci.manifests // [])
              } | with_entries(select(.value != null)))
            }
        )
      | from_entries
    '
  )"
}



oci_subject_trim_for() {
  local comp="$1" os="$2" arch="$3"
  local key="${comp}|${os}|${arch}"

  jq -c --arg key "$key" '
    .[$key] // null
    | if . == null then null else
        {
          tag_ref,
          tag,
          digest,
          digest_ref,
          size,
          repository,
          artifactType,
          mediaType,
          pushed_at
        }
      end
  ' <<<"$OCI_SUBJECTS_BY_KEY"
}

oci_index_trim_for() {
  local comp="$1"

  jq -c --arg comp "$comp" '
    .[$comp] // null
    | if . == null then null else
        {
          tag,
          tag_ref,
          digest,
          digest_ref,
          repository,
          artifactType,
          mediaType,
          pushed_at,
          manifests
        }
      end
  ' <<<"$OCI_INDEX_BY_COMP"
}

# ---------- SBOM blocks ----------
build_sbom_block() {
  # args: base_prefix ("" or "web"), scope ("source"|"artifacts"), name ("source" or "web.linux-amd64")
  local base="$1"
  local scope="$2"
  local name="$3"

  local pfx=""
  [[ -n "$base" ]] && pfx="${base}/"

  local sbom_dir="${pfx}sbom/${scope}"
  local att_dir="${pfx}attestations/sbom/${scope}"

  # ext -> format
  local -a exts=("spdx" "cdx")
  local -A fmt=(
    ["spdx"]="spdx-json"
    ["cdx"]="cyclonedx-json"
  )

  local items='[]'
  local ext report_rel att_rel report_obj att_obj item

  for ext in "${exts[@]}"; do
    report_rel="${sbom_dir}/${name}.${ext}.json"
    att_rel="${att_dir}/${name}.${ext}.json.intoto.v1.sigstore.json"

    report_obj="$(file_obj_or_null "$report_rel")"
    [[ "$report_obj" == "null" ]] && continue

    att_obj="$(file_obj_or_null "$att_rel")"

    item="$(jq -n \
      --arg format "${fmt[$ext]}" \
      --argjson report "$report_obj" \
      --argjson att "$att_obj" \
      '{
        format: $format,
        report: $report,
      }
      | if ($att != null) then . + {attestations: [$att]} else . end'
    )"

    items="$(add_to_array "$items" "$item")"
  done

  # if no SBOMs exist, return {} so merge logic stays happy
  #jq -n --argjson items "$items" '
  #  if ($items|length)==0 then {} else { $items } end
  #'

  jq -n --argjson items "$items" '
    if ($items|length)==0 then null else { sbom: $items } end
  '
}

# ---------- scans (source-level) ----------
build_scans_for_dir() {
  # args: scan_dir_rel, att_dir_rel
  local scan_dir="$1"
  local att_dir="$2"

  [[ -d "${DIST}/${scan_dir}" ]] || { echo "[]"; return 0; }

  local items='[]'
  while IFS= read -r abs; do
    local rel base
    rel="${abs#"${DIST}/"}"
    base="$(basename "$rel")"

    # scanner is the first token before '.'
    local scanner="${base%%.*}"
    local rest="${base#"${scanner}".}"

    local kind="other"
    local format="json"
    case "$rest" in
      vuln.json)       kind="vuln"; format="json" ;;
      vuln.sarif.json) kind="vuln"; format="sarif" ;;
      *.sarif.json)    kind="other"; format="sarif" ;;
      *)               kind="other"; format="json" ;;
    esac

    local att_rel="${att_dir}/${base}.intoto.v1.sigstore.json"

    local item
    item="$(jq -n \
      --arg scanner "$scanner" \
      --arg kind "$kind" \
      --arg format "$format" \
      --argjson report "$(file_obj "$rel")" \
      --argjson attestation "$(file_obj_or_null "$att_rel")" \
      '{scanner:$scanner, kind:$kind, format:$format, report:$report, attestations:[$attestation]}')"
    items="$(add_to_array "$items" "$item")"
  done < <(find "${DIST}/${scan_dir}" -maxdepth 1 -type f \( -name '*.json' -o -name '*.sarif.json' \) | LC_ALL=C sort)

  jq -n --argjson items "$items" '
    ($items
      | sort_by(.scanner)
      | group_by(.scanner)
      | map(
          (.[0].scanner) as $scanner
          | {scanner:$scanner, reports: (map({kind, format, report, attestations} | with_entries(select(.value!=null))))}
          | if (.reports? | type=="array" and length==0) then del(.reports) else . end
        )
    )
  '

}

  # ---------- scans (artifact-level per os/arch) ----------
build_artifact_scans() {
  # args: comp, os, arch
  local comp="$1" os="$2" arch="$3"
  local scan_dir="${comp}/scan/artifacts"
  local att_dir="${comp}/attestations/scan/artifacts"
  [[ -d "${DIST}/${scan_dir}" ]] || { echo "[]"; return 0; }
  local prefix="${comp}.${os}-${arch}."
  local items='[]'

  while IFS= read -r abs; do
  local rel base
    rel="${abs#"${DIST}/"}"
    base="$(basename "$rel")"
    [[ "$base" == ${prefix}* ]] || continue

    local after="${base#"${prefix}"}"
    local scanner="${after%%.*}"
    local rest="${after#"${scanner}."}"

    local kind="other"
    local format="json"
    case "$rest" in
      vuln.json)       kind="vuln"; format="json" ;;
      vuln.sarif.json) kind="vuln"; format="sarif" ;;
      *.sarif.json)    kind="other"; format="sarif" ;;
      *)               kind="other"; format="json" ;;
    esac

    local att_rel="${att_dir}/${base}.intoto.v1.sigstore.json"

    local item
    item="$(jq -n \
      --arg scanner "$scanner" \
      --arg kind "$kind" \
      --arg format "$format" \
      --argjson report "$(file_obj "$rel")" \
      --argjson att "$(file_obj_or_null "$att_rel")" \
      '{scanner:$scanner, kind:$kind, format:$format, report:$report, attestations:([$att] | map(select(.!=null)))}')"

    items="$(add_to_array "$items" "$item")"
  done < <(find "${DIST}/${scan_dir}" -maxdepth 1 -type f \( -name '*.json' -o -name '*.sarif.json' \) | LC_ALL=C sort)

  jq -n --argjson items "$items" '
    ($items
      | sort_by(.scanner)
      | group_by(.scanner)
      | map(
          (.[0].scanner) as $scanner
          | {
              scanner: $scanner,
              reports: (
                map(
                  {kind, format, report, attestations}
                  | (if (.attestations|type=="array" and length==0) then del(.attestations) else . end)
                )
              )
            }
          | if (.reports? | type=="array" and length==0) then del(.reports) else . end
        )
    )
  '
}

# ---------- build one component object ----------
build_component_obj() {
  local comp="$1"
  local pfx=""
  [[ "$comp" != "_repo" ]] && pfx="${comp}/"

  # build block
  local build_block
  build_block="$(jq -n \
    --argjson manifest   "$(file_obj_or_null "${pfx}build.json")" \
    --argjson signature  "$(file_obj_or_null "${pfx}build.json.sig")" \
    '{
       manifest:$manifest,
       signature:$signature
     }
     | with_entries(select(.value != null))
  ')"

  # source evidence
  local sbom_source
  sbom_source="$(build_sbom_block "${pfx%/}" "source" "source")"

  local scans_source
  scans_source="$(build_scans_for_dir "${pfx}scan/source" "${pfx}attestations/scan/source")"

  local source_evidence
  source_evidence="$(jq -n \
    --argjson sbom "$sbom_source" \
    --argjson scans "$scans_source" \
    '{
       sbom:$sbom.sbom,
       scans:$scans
     }
     | with_entries(select(.value != null))
      | (if (type=="object") and (.scans? | type=="array") and ((.scans|length)==0) then del(.scans) else . end)
     | (if (type=="object") and (.sbom? | type=="array") and ((.sbom|length)==0) then del(.sbom) else . end)
  ')"

  # oci index
  local oci_index
  oci_index="$(oci_index_trim_for "$comp")"

  # artifacts
  local artifacts='[]'
  if [[ "$comp" != "_repo" && -d "${DIST}/${comp}/bin" ]]; then

    while IFS= read -r bin_abs; do
      local bin_rel="${bin_abs#"${DIST}/"}"
      case "$bin_rel" in
        *.sig|*.sha256|*.sigstore.json) continue ;;
      esac

      local os_arch os arch platform name
      os_arch="$(parse_os_arch_from_bin_rel "$bin_rel")"
      [[ -n "$os_arch" ]] || continue
      os="$(awk '{print $1}' <<<"$os_arch")"
      arch="$(awk '{print $2}' <<<"$os_arch")"
      platform="${os}/${arch}"
      name="${comp}.${os}-${arch}"

      # subject & sidecars
      local subject_obj sig_obj sha_obj
      subject_obj="$(file_obj "$bin_rel")"

      # add oci info (trimmed) to subject obj if present
      local oci_subject
      oci_subject="$(oci_subject_trim_for "$comp" "$os" "$arch")"

      if [ "${oci_subject}x" != "x" ]; then
        log "==> (evidence) got oci_subject for ${comp} ${os}/${arch}: ${oci_subject}"
        #subject_obj="$(jq -c \
        #  --argjson oci_subject "$oci_subject" \
        #  '
        #    . + (if $oci_subject != null then {oci_subject:$oci_subject} else {} end)
        #  ' <<<"$subject_obj"
        #)"
      fi

	    #subject_obj="$(jq -c \
	    #  --arg oci_ref "${oci_ref:-}" \
	    #  --arg oci_digest "${oci_digest:-}" \
	    #  --arg oci_repo "${oci_repo:-}" \
	    #  --arg oci_tag "${oci_tag:-}" \
	    #  '
	    #  . + {
	    #    oci: (
	    #      { ref: $oci_ref, digest: $oci_digest, repository: $oci_repo, tag: $oci_tag }
	    #      | with_entries(select(.value | length > 0))
	    #      | if length == 0 then null else . end
	    #    )
	    #  }
	    #  | if .oci == null then del(.oci) else . end
	    #  ' <<<"$subject_obj"
	    #)"

      sig_obj="$(file_obj_or_null "${bin_rel}.sig")"
      sha_obj="$(file_obj_or_null "${bin_rel}.sha256")"

      # sbom artifacts block
      local sbom_art
      sbom_art="$(build_sbom_block "$comp" "artifacts" "$name")"

      # scans for this artifact
      local scans
      scans="$(build_artifact_scans "$comp" "$os" "$arch")"

      # provenance placeholder (future)
      local prov='[]'
      if [[ -d "${DIST}/${comp}/attestations/provenance/artifacts" ]]; then
        while IFS= read -r prov_abs; do
          local prov_rel="${prov_abs#"${DIST}/"}"
          [[ "$(basename "$prov_rel")" == "${name}"* ]] || continue
          prov="$(add_to_array "$prov" "$(file_obj "$prov_rel")")"
        done < <(find "${DIST}/${comp}/attestations/provenance/artifacts" -maxdepth 1 -type f -name '*.sigstore.json' | LC_ALL=C sort)
      fi

      local artifact
      artifact="$(jq -n \
        --arg os "$os" --arg arch "$arch" --arg platform "$platform" \
        --argjson subject "$subject_obj" \
        --argjson sig "$sig_obj" \
        --argjson sha "$sha_obj" \
        --argjson sbom "$sbom_art" \
        --argjson scans "$scans" \
        --argjson provenance "$prov" \
        --argjson oci_subject "${oci_subject:-}" \
        '{
          os:$os, arch:$arch, platform:$platform,
          subject:$subject,
          oci_subject:$oci_subject,
          signatures: ([ $sig ] | map(select(.!=null))),
	        sbom: (if ($sbom|type)=="object" then ($sbom.sbom // null)
	          elif ($sbom|type)=="array" then $sbom else null end),
          scans:$scans,
          provenance: (if ($provenance|length)>0 then $provenance else null end)
        }
        | (if (.oci_subject? | type=="array" and length==0) then del(.oci_subject) else . end)
        | (if (.signatures? | type=="array" and length==0) then del(.signatures) else . end)
        | (if (.scans?      | type=="array" and length==0) then del(.scans)      else . end)
        | (if (.sbom?       | type=="array" and length==0) then del(.sbom) else . end)
        | (if (.provenance? == null) then del(.provenance) else . end)
        ')"

      artifacts="$(add_to_array "$artifacts" "$artifact")"
    done < <(find "${DIST}/${comp}/bin" -type f | LC_ALL=C sort)
  fi

  jq -n \
    --argjson build "$build_block" \
    --argjson source_evidence "$source_evidence" \
    --argjson artifacts "$artifacts" \
    --argjson oci_index "$oci_index" \
    '{
       build:$build,
       source_evidence:$source_evidence,
       targets:$artifacts,
       oci_index:$oci_index
    }
    | with_entries(select(.value != null))
    | (if (type=="object") and (.targets? | type=="array") and ((.targets|length)==0) then del(.targets) else . end)
    | (if (type=="object") and (.source_evidence? | type=="array") and ((.source_evidence|length)==0) then del(.source_evidence) else . end)
    | (if (type=="object") and (.build? | type=="array") and ((.build|length)==0) then del(.build) else . end)
    '
}

# attach_binary_sbom() {
#   # args: component platform_key sbom_path sbom_predicate_type
#   local component="$1"
#   local pkey="$2"
#   local sbom_path="$3"
#   local predicate_type="$4"   # e.g. "cyclonedx" or a URI you standardize on

#   local subject
#   subject="$(ctx_get_artifact_field "$component" "$pkey" '.resolved.digest_ref')"
#   [[ -n "$subject" ]] || die "missing subject digest_ref for $component/$pkey"

#   mapfile -t out < <(cosign_attest_predicate "$subject" "$sbom_path" "$predicate_type")
#   local tag_ref="${out[0]}"
#   local digest_ref="${out[1]}"
#   local mediaType="${out[2]}"
#   local size="${out[3]}"
#   local pushed_at="${out[4]}"

#   local ev
#   ev="$(jq -n \
#     --arg kind "cosign-attestation" \
#     --arg predicate_type "$predicate_type" \
#     --arg predicate_path "$sbom_path" \
#     --arg subject "$subject" \
#     --arg tag_ref "$tag_ref" \
#     --arg digest_ref "$digest_ref" \
#     --arg mediaType "$mediaType" \
#     --arg size "$size" \
#     --arg pushed_at "$pushed_at" \
#     --arg signer "$SIGNER_URI" \
#     --arg signed_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
#     '{
#       kind: $kind,
#       predicate_type: $predicate_type,
#       predicate_path: $predicate_path,
#       ref: $subject,
#       oci: {
#         tag_ref: $tag_ref,
#         digest_ref: $digest_ref,
#         mediaType: $mediaType,
#         size: ($size|tonumber),
#         pushed_at: $pushed_at
#       },
#       signer: $signer,
#       signed_at: $signed_at
#     }'
#   )"

#   ctx_artifact_evidence_append "$component" "$pkey" "sbom" "$ev"
# }

# ctx_artifact_evidence_append() {
#   # args: component platform_key category evidence_json
#   local component="$1"
#   local pkey="$2"
#   local category="$3"
#   local evidence_json="$4"
#   local tmp; tmp="$(mktemp)"
#   jq \
#     --arg c "$component" \
#     --arg p "$pkey" \
#     --arg cat "$category" \
#     --argjson ev "$evidence_json" \
#     '
#       .components[$c].artifacts[$p].evidence[$cat] = (
#         (.components[$c].artifacts[$p].evidence[$cat] // [])
#         | map(select((.key // "") != ($ev.key // "")))
#         + [ $ev ]
#       )
#     ' "${BUILDCTX_PATH}" >"$tmp" && mv -f "$tmp" "${BUILDCTX_PATH}"
# }

# ctx_index_evidence_append() {
#   # args: component category evidence_json
#   local component="$1"
#   local category="$2"
#   local evidence_json="$3"
#   local tmp;tmp="$(mktemp)"
#   jq \
#     --arg c "$component" \
#     --arg cat "$category" \
#     --argjson ev "$evidence_json" \
#     '
#       .components[$c].index.evidence[$cat] = (
#         (.components[$c].index.evidence[$cat] // [])
#         | map(select((.ref // "") != ($ev.ref // "")))
#         + [ $ev ]
#       )
#    ' "${BUILDCTX_PATH}" >"$tmp" && mv -f "$tmp" "${BUILDCTX_PATH}"
# }

evidence_init() {
  mkdir -p "${DIST}/_repo/sbom/source"
}

scanner_init() {
  # doing component source scans not repo source scans for now
  mkdir -p "${DIST}/_repo/scan/source"
  # Update grype vuln check databases
  log "==> (evidence) updating grype vuln database"
  grype db update

  # Update trivy vuln check databases
  log "==> (evidence) updating trivy vuln database"
  trivy filesystem --download-db-only
}

evidence_component_init() {
  local c="$1"
  mkdir -p \
    "${DIST}/${c}/sbom/source" \
    "${DIST}/${c}/sbom/artifacts" \
    "${DIST}/${c}/scan/source" \
    "${DIST}/${c}/scan/artifacts" \
    "${DIST}/${c}/attestations/sbom/source" \
    "${DIST}/${c}/attestations/sbom/artifacts" \
    "${DIST}/${c}/attestations/scan/source" \
    "${DIST}/${c}/attestations/scan/artifacts" \
    "${DIST}/${c}/attestations/provenance/artifacts"
}

evidence_generate_repo_source_sboms() {
  # generate cyclonedx-gomod cdx repo-wide source sboms
  cyclonedx-gomod mod -json=true -licenses=true -output "${DIST}/_repo/sbom/source/source.gomod.cdx.json" || die "Failed to generate cyclonedx-gomod repo source sbom!"

  # generate syft cdx/spdx repo-wide source sboms
  syft scan dir:. --exclude "./dist" --exclude "./.git" --exclude "./tools" --exclude "./webassets" --source-name "${APP}" --source-version "${RELEASE_VERSION}" --output spdx-json="${DIST}/_repo/sbom/source/source.syft.spdx.json" --output cyclonedx-json="${DIST}/_repo/sbom/source/source.syft.cdx.json" || die "Failed to generate syft repo source sbom!"
}

# evidence_attach_repo_source_sboms() {
#   # sign/attest syft repo source sbom with cosign (spdx)
#   log "==> (attest) adding cosign in-toto attestation for syft repo source sbom (spdx)"
#   attest_file_dsse_v1 "./dist/build.json" "dist/sbom/source/source.spdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"

#   # sign/attest syft repo source sbom with cosign (cdx)
#   log "==> (attest) adding cosign in-toto attestation for syft repo source sbom (cdx)"
#   attest_file_dsse_v1 "./dist/build.json" "dist/sbom/source/source.cdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
# }

evidence_generate_component_source_sboms() {
  local component="$1"
  # generate cyclonedx-gomod cdx component source sboms
  cyclonedx-gomod app -json=true -licenses=true -main "./cmd/${component}/" -output "${DIST}/${component}/sbom/source/source.gomod.cdx.json" || die "Failed to generate cyclonedx-gomod sbom!"

  # build component sbom from source
  log "==> (evidence) generating source sboms for component ${component}"
  syft scan dir:. --exclude "./dist" --exclude "./.git" --exclude "./tools" --exclude "./webassets" --source-name "${APP}-${component}" --source-version "${RELEASE_VERSION}" --output spdx-json="${DIST}/${component}/sbom/source/source.syft.spdx.json" --output cyclonedx-json="${DIST}/${component}/sbom/source/source.syft.cdx.json" || die "Failed to generate sbom!"
}

# evidence_attach_component_source_sbom() {
#   local component="$1"
#   # sign/attest cyclonedx-gomod component source sbom with cosign (cdx)
#   log "==> (evidence) adding cosign in-toto attestation for cyclonedx-gomod component source sbom (cdx)"
#   attest_file_dsse_v1 "dist/sbom/${component}/source.app.cdx.json" "dist/sbom/${component}/source.app.cdx.json" "https://phxi.net/attestations/cyclonedx-gomod/source/v1"

#   # sign/attest syft component source sbom with cosign (spdx)
#   log "==> (evidence) adding cosign in-toto attestation for syft component source sbom (spdx)"
#   attest_file_dsse_v1 "./dist/${component}/build.json" "dist/${component}/sbom/source/source.spdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
#   # sign/attest syft component source sbom with cosign (cdx)
#   log "==> (evidence) adding cosign in-toto attestation for syft component source sbom (cdx)"
#   attest_file_dsse_v1 "./dist/${component}/build.json" "dist/${component}/sbom/source/source.cdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
# }

# evidence_generate_component_artifact_sboms() {
#   local component="$1"
#   local os="$2"
#   local arch="$3"
#   # generate cyclonedx-gomod cdx component binary sboms
#   cyclonedx-gomod bin -json=true -licenses=true -output "${DIST}/${component}/sbom/artifacts/${component}.${os}-${arch}.gomod.cdx.json" || die "Failed to generate cyclonedx-gomod sbom!"

#   # generate syft cdx/spdx component binary sboms
#   #log "==> (evidence) generating sboms for binary"
#   syft scan file:"${DIST}/${component}/bin/${os}/${arch}/${component}" --source-name "${component}" --source-version "${RELEASE_VERSION}" --output spdx-json="${DIST}/${component}/sbom/artifacts/${component}.${os}-${arch}.syft.spdx.json" --output cyclonedx-json="${DIST}/${component}/sbom/artifacts/${component}.${os}-${arch}.syft.cdx.json" || die "Failed to generate sbom!"
# }

evidence_generate_component_artifact_sboms() {
  local component="${1:?component required}"
  local pkey="${2:?platform_key required}"

  local bin_path bin_path_in prefix os arch out_prefix
  bin_path_in="$(ctx_get_artifact_field "$component" "$pkey" '.local.path')"
  bin_path="$( dist_abspath "${bin_path_in}" )"
  os="$(ctx_get_artifact_field "$component" "$pkey" '.platform.os')"
  arch="$(ctx_get_artifact_field "$component" "$pkey" '.platform.arch')"

  [[ -n "$bin_path" && -f "$bin_path" ]] || die "missing binary for ${component}/${pkey}: $bin_path"
  [[ -n "$os" && -n "$arch" ]] || die "missing platform for ${component}/${pkey}: os=$os arch=$arch"

  mkdir -p "${DIST}/${component}/sbom/artifacts"
  out_prefix="${DIST}/${component}/sbom/artifacts/${component}.${os}-${arch}"

  # generate cyclonedx-gomod cdx component binary sboms
  cyclonedx-gomod bin -json=true -licenses=true -output "${out_prefix}.gomod.cdx.json" "${bin_path}" || die "Failed to generate cyclonedx-gomod sbom!"

   # generate syft cdx/spdx component binary sboms
   #log "==> (evidence) generating sboms for binary"
   syft scan file:"${bin_path}" --source-name "${component}" --source-version "${RELEASE_VERSION}" --output spdx-json="${out_prefix}.syft.spdx.json" --output cyclonedx-json="${out_prefix}.syft.cdx.json" || die "Failed to generate sbom!"
}

# evidence_attach_component_artifact_sboms() {
#   # sign/attest syft sbom with cosign (spdx)
#   log "==> (evidence) adding cosign in-toto attestation for syft binary sbom (spdx)"
#   attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/sbom/artifacts/${COMPONENT}.${OS}-${ARCH}.spdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
#   # sign/attest syft sbom with cosign (cdx)
#   log "==> (evidence) adding cosign in-toto attestation for syft binary sbom (cdx)"
#   attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/sbom/artifacts/${COMPONENT}.${OS}-${ARCH}.cdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
# }

# evidence_generate_component_artifact_scan_reports() {
#   component="$1"
#   # scan binary with trivy for vulns (generate json report)
#   log "==> (evidence) scanning binary with trivy for vulns (generate json)"
#   trivy rootfs --scanners vuln --format json -o "${DIST}/${component}/scan/artifact/${component}.${OS}-${ARCH}.trivy.vuln.json" "${fname}"
#   # convert trivy vuln report (generate sarif report)
#   log "==> (evidence) convert trivy json vuln report (generate sarif)"
#   trivy convert --format sarif -o "${DIST}/_repo/scan/source/${component}.${OS}-${ARCH}.trivy.vuln.sarif.json" "${DIST}/_repo/scan/source/${component}.${OS}-${ARCH}.trivy.vuln.json"

#   # scan binary with grype for vulns (generate json report)
#   log "==> (evidence) scanning binary with grype for vulns (generate json)"
#   grype "./${fname}" --name "${APP}-${component}" -o json --file "${DIST}/_repo/scan/source/${component}.${OS}-${ARCH}.grype.vuln.json"
#   # scan binary with grype for vulns (generate sarif report)
#   log "==> (evidence) scanning binary with grype for vulns (generate sarif)"
#   grype "./${fname}" --name "${APP}-${component}" -o sarif --file "${DIST}/_repo/scan/source/${component}.${OS}-${ARCH}.grype.vuln.sarif.json"

#   # scan binary with govulncheck for vulns (generate json report)
#   log "==> (evidence) scanning binary with govulncheck for vulns (generate json)"
#   govulncheck -mode=binary -json "./${fname}" > "${DIST}/_repo/scan/source/${component}.${OS}-${ARCH}.govulncheck.vuln.json"
#   # scan binary with govulncheck for vulns (generate sarif report)
#   log "==> (evidence) scanning binary with govulncheck for vulns (generate sarif)"
#   govulncheck -mode=binary -format sarif "./${fname}" > "${DIST}/_repo/scan/source/${component}.${OS}-${ARCH}.govulncheck.vuln.sarif.json"
# }

evidence_generate_component_artifact_scan_reports() {
  local component="${1:?component required}"
  local pkey="${2:?platform_key required}"

  local bin_path_in bin_path os arch out_prefix
  bin_path_in="$(ctx_get_artifact_field "$component" "$pkey" '.local.path')"
  bin_path="$( dist_abspath "${bin_path_in}" )"
  os="$(ctx_get_artifact_field "$component" "$pkey" '.platform.os')"
  arch="$(ctx_get_artifact_field "$component" "$pkey" '.platform.arch')"

  [[ -n "$bin_path" && -f "$bin_path" ]] || die "missing binary for ${component}/${pkey}: $bin_path"
  [[ -n "$os" && -n "$arch" ]] || die "missing platform for ${component}/${pkey}: os=$os arch=$arch"

  mkdir -p "${DIST}/${component}/scan/artifacts"
  out_prefix="${DIST}/${component}/scan/artifacts/${component}.${os}-${arch}"

  # Trivy (binary file)
  log "==> (evidence) ${component}/${pkey} trivy vuln json"
  trivy rootfs --scanners vuln --format json \
    -o "${out_prefix}.trivy.vuln.json" "$bin_path"

  log "==> (evidence) ${component}/${pkey} trivy vuln sarif"
  trivy convert --format sarif \
    -o "${out_prefix}.trivy.vuln.sarif.json" "${out_prefix}.trivy.vuln.json"

  # Grype (binary file)
  log "==> (evidence) ${component}/${pkey} grype vuln json"
  grype "file:${bin_path}" --name "${APP}-${component}" -o json \
    --file "${out_prefix}.grype.vuln.json"

  log "==> (evidence) ${component}/${pkey} grype vuln sarif"
  grype "file:${bin_path}" --name "${APP}-${component}" -o sarif \
    --file "${out_prefix}.grype.vuln.sarif.json"

  # Govulncheck (binary)
  log "==> (evidence) ${component}/${pkey} govulncheck vuln json"
  govulncheck -mode=binary -json "$bin_path" > "${out_prefix}.govulncheck.vuln.json"
  
  log "==> (evidence) ${component}/${pkey} govulncheck vuln sarif"
  govulncheck -mode=binary -format sarif "$bin_path" > "${out_prefix}.govulncheck.vuln.sarif.json"
}

# evidence_attach_component_artifact_scan_reports() {
#   # sign/attest trivy report with cosign (json)
#   log "==> (evidence) adding cosign in-toto attestation for trivy vuln report (json)"
#   attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.trivy.vuln.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

#   # sign/attest trivy report with cosign (sarif)
#   log "==> (evidence) adding cosign in-toto attestation for trivy vuln report (sarif)"
#   attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.trivy.vuln.sarif.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

#   # sign/attest grype report with cosign (json)
#   log "==> (evidence) adding cosign in-toto attestation for grype vuln report (json)"
#   attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.grype.vuln.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

#   # sign/attest grype report with cosign (sarif)
#   log "==> (evidence) adding cosign in-toto attestation for grype vuln report (sarif)"
#   attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.grype.vuln.sarif.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

#   # sign/attest govulncheck report with cosign (json)
#   log "==> (evidence) adding cosign in-toto attestation for govulncheck binary vuln report (json)"
#   attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.govulncheck.vuln.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

#   # sign/attest govulncheck report with cosign (sarif)
#   log "==> (evidence) adding cosign in-toto attestation for govulncheck binary vuln report (sarif)"
#   attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.govulncheck.vuln.sarif.json" "https://cosign.sigstore.dev/attestation/vuln/v1"
# }

evidence_generate_repo_source_scan_reports() {
  # generate govulncheck repo source report (json)
  log "==> (evidence) generating govulncheck repo-wide source report (json)"
  govulncheck -json ./... > "${DIST}/_repo/scan/source/govulncheck.vuln.json"
  # generate govulncheck repo source report (sarif)
  log "==> (evidence) generating govulncheck report (sarif)"
  govulncheck -format sarif ./... > "${DIST}/_repo/scan/source/govulncheck.vuln.sarif.json"

  # generate grype repo source report (json)
  log "==> (evidence) generating grype repo source report (json)"
  grype "${DIST}/_repo/sbom/source/source.syft.cdx.json" --name "${APP}" -o json --file "${DIST}/_repo/scan/source/grype.vuln.json"
  # generate grype repo source report (sarif)
  log "==> (evidence) generating grype repo source report (sarif)"
  grype "${DIST}/_repo/sbom/source/source.syft.cdx.json" --name "${APP}" -o sarif --file "${DIST}/_repo/scan/source/grype.vuln.sarif.json"
}

# evidence_attach_repo_source_scan_reports() {
#   # sign/attest govulncheck source report with cosign (json)
#   log "==> (evidence) adding cosign in-toto attestation for govulncheck repo source vuln report (json)"
#   attest_file_dsse_v1 "dist/sbom/source/source.cdx.json" "${DIST}/scan/source/govulncheck.vuln.json" "https://phxi.net/attestations/govulncheck/source/v1"
#   # sign/attest govulncheck source report with cosign (sarif)
#   log "==> (evidence) adding cosign in-toto attestation for govulncheck repo source vuln report (sarif)"
#   attest_file_dsse_v1 "dist/sbom/source/source.cdx.json" "${DIST}/scan/source/govulncheck.vuln.sarif.json" "https://phxi.net/attestations/govulncheck/source/v1"


#   # sign/attest grype repo source report with cosign (json)
#   log "==> (evidence) adding cosign in-toto attestation for grype repo source vuln report (json)"
#   attest_file_dsse_v1 "dist/sbom/source/source.cdx.json" "${DIST}/scan/source/grype.vuln.json" "https://phxi.net/attestations/grype/source/v1"
#   # sign/attest grype repo source report with cosign (sarif)
#   log "==> (evidence) adding cosign in-toto attestation for grype repo source vuln report (sarif)"
#   attest_file_dsse_v1 "dist/sbom/source/source.cdx.json" "${DIST}/scan/source/grype.vuln.sarif.json" "https://phxi.net/attestations/grype/source/v1"
# }

evidence_generate_component_source_scan_reports() {
  local component="$1"
  # generate component source govulnscan report (json)
  log "==> (evidence) generating govulncheck component=${component} source report (json)"
  govulncheck -json "./cmd/${component}/..." > "${DIST}/${component}/scan/source/govulncheck.vuln.json"
  # generate component source govulnscan report (sarif)
  log "==> (evidence) generating govulncheck component=${component} source report (json)"
  govulncheck -format sarif "./cmd/${component}/..." > "${DIST}/${component}/scan/source/govulncheck.vuln.sarif.json"

  # generate component source grype report (json)
  log "==> (evidence) generating grype component=${component} source report (json)"
  grype "${DIST}/${component}/sbom/source/source.syft.cdx.json" --name "${APP}-${component}" -o json --file "${DIST}/${component}/scan/source/grype.vuln.json"
  # generate component source grype report (json)
  log "==> (evidence) generating grype component=${component} source report (sarif)"
  grype "${DIST}/${component}/sbom/source/source.syft.cdx.json" --name "${APP}-${component}" -o sarif --file "${DIST}/${component}/scan/source/grype.vuln.sarif.json"
}

# evidence_attach_component_source_scan_reports() {
#   # sign/attest govulncheck source report with cosign (json)
#   log "==> (evidence) adding cosign in-toto attestation for govulncheck component source vuln report (json)"
#   attest_file_dsse_v1 "dist/${COMPONENT}/sbom/source/source.cdx.json" "dist/${COMPONENT}/scan/source/govulncheck.vuln.json" "https://phxi.net/attestations/govulncheck/source/v1"
#   # generate component source govulnscan report (sarif)
#   log "==> (evidence) generating govulncheck component source report (sarif)"
#   govulncheck -format sarif "./cmd/${COMPONENT}/..." > "dist/${COMPONENT}/scan/source/govulncheck.vuln.sarif.json"
#   # sign/attest govulncheck source report with cosign (sarif)
#   log "==> (evidence) adding cosign in-toto attestation for govulncheck component source vuln report (sarif)"
#   attest_file_dsse_v1 "dist/${COMPONENT}/sbom/source/source.cdx.json" "dist/${COMPONENT}/scan/source/govulncheck.vuln.sarif.json" "https://phxi.net/attestations/govulncheck/source/v1"

#   # sign/attest grype source report with cosign (json)
#   log "==> (evidence) adding cosign in-toto attestation for grype component source vuln report (json)"
#   attest_file_dsse_v1 "dist/${COMPONENT}/sbom/source/source.cdx.json" "./dist/${COMPONENT}/scan/source/grype.vuln.json" "https://phxi.net/attestations/grype/source/v1"
#   # generate component source grype report (sarif)
#   log "==> (evidence) generating grype component source report (sarif)"
#   grype "./dist/${COMPONENT}/sbom/source/source.cdx.json" --name "${APP}-${COMPONENT}" -o sarif --file "./dist/${COMPONENT}/scan/source/grype.vuln.sarif.json"
#   # sign/attest grype source report with cosign (sarif)
#   log "==> (evidence) adding cosign in-toto attestation for grype component source vuln report (sarif)"
#   attest_file_dsse_v1 "dist/${COMPONENT}/sbom/source/source.cdx.json" "./dist/${COMPONENT}/scan/source/grype.vuln.sarif.json" "https://phxi.net/attestations/grype/source/v1"
# }

# cosign_attest_predicate - args: subject_digest_ref predicate_path predicate_type

# args:
#   1 scope            "artifact"|"index"|"repo" (string)
#   2 component        component name ("" allowed)
#   3 platform_key     platform key ("" allowed)
#   4 category         "sbom"|"scan"|... (string)
#   5 subject_digest_ref     registry/repo@sha256:...   (string)
#   6 predicate_path         local path (usually dist/...) (string)
#   7 predicate_type         URI/type string (string)
#   8 predicate_content_type content type of predicate (string)
#   9 att_digest_ref         registry/repo@sha256:... (string)
#  10 att_mediaType          descriptor mediaType (string, may be empty)
#  11 att_size               descriptor size (number/string)
#  12 att_pushed_at          timestamp (string, may be empty)
evidence_make_oci_attestation_record() {
  local scope="$1" component="$2" pkey="$3" category="$4"
  local subject_digest_ref="$5" predicate_path_in="$6" predicate_type="$7"
  local predicate_content_type="${8:-}"
  local att_digest_ref="$9" att_mediaType="${10}" att_size="${11}"
  local att_pushed_at="${12}"

  [[ -n "$subject_digest_ref" ]] || die "evidence_make_oci_attestation_record: missing subject_digest_ref"
  [[ -n "$predicate_path_in" ]]  || die "evidence_make_oci_attestation_record: missing predicate_path"

  local predicate_rel predicate_abs
  predicate_rel="$(dist_relpath "$predicate_path_in")"
  predicate_abs="$(dist_abspath "$predicate_rel")"

  [[ -f "$predicate_abs" ]] || die "evidence_make_oci_attestation_record: predicate file not found: $predicate_abs"
  [[ -n "$predicate_type" ]] || die "evidence_make_oci_attestation_record: missing predicate_type"
  [[ -n "$att_digest_ref" ]] || die "evidence_make_oci_attestation_record: missing att_digest_ref"

  local pred_sha pred_size now key
  pred_sha="$(sha256sum "$predicate_abs" | awk '{print $1}')"
  pred_size="$(wc -c <"$predicate_abs" | tr -d '[:space:]')"
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  key="oci-attest|${subject_digest_ref}|${predicate_type}|sha256:${pred_sha}"

  jq -c -n \
    --arg key "$key" \
    --arg kind "cosign-attestation" \
    --arg scope "$scope" \
    --arg category "$category" \
    --arg component "$component" \
    --arg platform_key "$pkey" \
    --arg subject "$subject_digest_ref" \
    --arg predicate_type "$predicate_type" \
    --arg predicate_content_type "$predicate_content_type" \
    --arg predicate_path "$predicate_rel" \
    --arg predicate_sha256 "$pred_sha" \
    --argjson predicate_size "$pred_size" \
    --arg signer "${SIGNER_URI:-}" \
    --arg signed_at "$now" \
    --arg att_digest_ref "$att_digest_ref" \
    --arg att_mediaType "$att_mediaType" \
    --argjson att_size "${att_size:-0}" \
    --arg att_pushed_at "$att_pushed_at" \
    '{
      key: $key,
      kind: $kind,
      scope: $scope,
      category: $category,

      component: (if ($component|length)>0 then $component else null end),
      platform_key: (if ($platform_key|length)>0 then $platform_key else null end),

      subject: { digest_ref: $subject },

      predicate: (
        {
          type: $predicate_type,
          path: $predicate_path,
          hashes: { sha256: $predicate_sha256 },
          size: $predicate_size
        }
        + (if ($predicate_content_type|length)>0 then { content_type: $predicate_content_type } else {} end)
      ),

      signer: (if ($signer|length)>0 then $signer else null end),
      signed_at: $signed_at,

      oci: {
        digest_ref: $att_digest_ref,
        mediaType: (if ($att_mediaType|length)>0 then $att_mediaType else null end),
        size: $att_size,
        pushed_at: (if ($att_pushed_at|length)>0 then $att_pushed_at else null end)
      }
    } | with_entries(select(.value != null))'
}

# attest a predicate to an *artifact* subject (per platform).

# evidence_attest_artifact_predicate() {
#   # args: component platform_key category predicate_path predicate_type
#   local component="$1" pkey="$2" category="$3" predicate_path="$4" predicate_type="$5"

#   local subject
#   subject="$(ctx_get_artifact_field "$component" "$pkey" '.resolved.digest_ref')"
#   [[ -n "$subject" ]] || die "evidence_attest_artifact_predicate: missing subject digest_ref for ${component}/${pkey}"

#   local out=()
#   if ! mapfile -t out < <(cosign_attest_predicate "$subject" "$predicate_path" "$predicate_type");then
#     die "evidence_attest_artifact_predicate: cosign_attest_predicate failed for ${component}/${pkey}"
#   fi
#   if [ ${#out[@]} -ne 4 ]; then
#     die "evidence_attest_artifact_predicate: cosign_attest_predicate returned unexpected output for ${component}/${pkey}"
#   fi
#   #local tag_ref="${out[0]}" digest_ref="${out[1]}" mediaType="${out[2]}" size="${out[3]}" pushed_at="${out[4]}"
#   local digest_ref="${out[0]}" mediaType="${out[1]}" size="${out[2]}" pushed_at="${out[3]}"

#   local ev
#   ev="$(evidence_make_oci_attestation_record \
#         "artifact" "$component" "$pkey" "$category" \
#         "$subject" "$predicate_path" "$predicate_type" \
#         "$digest_ref" "$mediaType" "$size" "$pushed_at")"

#   ctx_artifact_evidence_upsert "$component" "$pkey" "$category" "$ev"
# }

# # Generic: attest a predicate to a *component index* subject.
# # args: component category predicate_path predicate_type
# evidence_attest_index_predicate() {
#   local component="$1" category="$2" predicate_path="$3" predicate_type="$4"

#   local subject
#   subject="$(ctx_get_component_field "$component" '.index.resolved.digest_ref')"
#   [[ -n "$subject" ]] || die "evidence_attest_index_predicate: missing index subject digest_ref for ${component}"

#   mapfile -t out < <(cosign_attest_predicate "$subject" "$predicate_path" "$predicate_type")
#   if [ ${#out[@]} -ne 4 ]; then
#     die "evidence_attest_index_predicate: cosign_attest_predicate failed for ${component} index"
#   fi
#   # local tag_ref="${out[0]}" digest_ref="${out[1]}" mediaType="${out[2]}" size="${out[3]}" pushed_at="${out[4]}"
#   local digest_ref="${out[0]}" mediaType="${out[1]}" size="${out[2]}" pushed_at="${out[3]}"

#   local ev
#   ev="$(evidence_make_oci_attestation_record \
#         "index" "$component" "" "$category" \
#         "$subject" "$predicate_path" "$predicate_type" \
#         "$digest_ref" "$mediaType" "$size" "$pushed_at")"

#   ctx_index_evidence_upsert "$component" "$category" "$ev"
# }

evidence_attest_artifact_predicate() {
  # args: component platform_key category predicate_path predicate_type [predicate_content_type]
  local component="$1" pkey="$2" category="$3" predicate_path_in="$4" predicate_type="$5"
  local predicate_content_type="${6:-}"

  local subject
  subject="$(ctx_get_artifact_field "$component" "$pkey" '.resolved.digest_ref')"
  [[ -n "$subject" ]] || die "evidence_attest_artifact_predicate: missing subject digest_ref for ${component}/${pkey}"

  local predicate_rel predicate_abs
  predicate_rel="$(dist_relpath "$predicate_path_in")"
  predicate_abs="$(dist_abspath "$predicate_rel")"

  local out=()
  if ! mapfile -t out < <(cosign_attest_predicate "$subject" "$predicate_abs" "$predicate_type"); then
    die "evidence_attest_artifact_predicate: cosign_attest_predicate failed for ${component}/${pkey}"
  fi
  [[ ${#out[@]} -eq 4 ]] || die "evidence_attest_artifact_predicate: unexpected cosign_attest_predicate output for ${component}/${pkey}"

  local digest_ref="${out[0]}" mediaType="${out[1]}" size="${out[2]}" pushed_at="${out[3]}"

  local ev
  ev="$(evidence_make_oci_attestation_record \
        "artifact" "$component" "$pkey" "$category" \
        "$subject" "$predicate_rel" "$predicate_type" "$predicate_content_type" \
        "$digest_ref" "$mediaType" "$size" "$pushed_at")"

  ctx_artifact_evidence_upsert "$component" "$pkey" "$category" "$ev"
}

evidence_attest_index_predicate() {
  # args: component category predicate_path predicate_type [predicate_content_type]
  local component="$1" category="$2" predicate_path_in="$3" predicate_type="$4"
  local predicate_content_type="${5:-}"

  local subject
  subject="$(ctx_get_component_field "$component" '.index.resolved.digest_ref')"
  [[ -n "$subject" ]] || die "evidence_attest_index_predicate: missing index subject digest_ref for ${component}"

  local predicate_rel predicate_abs
  predicate_rel="$(dist_relpath "$predicate_path_in")"
  predicate_abs="$(dist_abspath "$predicate_rel")"

  local out=()
  if ! mapfile -t out < <(cosign_attest_predicate "$subject" "$predicate_abs" "$predicate_type"); then
    die "evidence_attest_index_predicate: cosign_attest_predicate failed for ${component} index"
  fi
  [[ ${#out[@]} -eq 4 ]] || die "evidence_attest_index_predicate: unexpected cosign_attest_predicate output for ${component} index"

  local digest_ref="${out[0]}" mediaType="${out[1]}" size="${out[2]}" pushed_at="${out[3]}"

  local ev
  ev="$(evidence_make_oci_attestation_record \
        "index" "$component" "" "$category" \
        "$subject" "$predicate_rel" "$predicate_type" "$predicate_content_type" \
        "$digest_ref" "$mediaType" "$size" "$pushed_at")"

  ctx_index_evidence_upsert "$component" "$category" "$ev"
}


# args: component platform_key sbom_path [predicate_type]
evidence_attest_artifact_sbom() {
  local component="$1" pkey="$2" sbom_path="$3"
  local predicate_type="${4:-https://cosign.sigstore.dev/attestation/sbom/v1}"
  evidence_attest_artifact_predicate "$component" "$pkey" "sbom" "$sbom_path" "$predicate_type"
}

# args: component platform_key scan_path [predicate_type]
evidence_attest_artifact_scan() {
  local component="$1" pkey="$2" scan_path="$3"
  local predicate_type="${4:-https://cosign.sigstore.dev/attestation/vuln/v1}"
  evidence_attest_artifact_predicate "$component" "$pkey" "scan" "$scan_path" "$predicate_type"
}

# args: component sbom_path [predicate_type]
evidence_attest_index_sbom() {
  local component="$1" sbom_path="$2"
  local predicate_type="${3:-https://cosign.sigstore.dev/attestation/sbom/v1}"
  evidence_attest_index_predicate "$component" "sbom" "$sbom_path" "$predicate_type"
}

# args: component scan_path [predicate_type]
evidence_attest_index_scan() {
  local component="$1" scan_path="$2"
  local predicate_type="${3:-https://cosign.sigstore.dev/attestation/vuln/v1}"
  evidence_attest_index_predicate "$component" "scan" "$scan_path" "$predicate_type"
}

evidence_list_component_source_scans() {
  # args: component
  local component="$1"
  local dir="${DIST}/${component}/scan/source"
  [[ -d "$dir" ]] || { jq -nc '[]'; return 0; }

  # only attesting sarif reports for now, keeping json on disk for extra audit data
  # find "$dir" -maxdepth 1 -type f \( -name '*.json' -o -name '*.sarif.json' \) \
  find "$dir" -maxdepth 1 -type f -name '*.sarif.json' \
    | LC_ALL=C sort \
    | awk -v dist="$DIST/" '
        { sub("^" dist, "", $0); print $0 }
      ' \
    | jq -Rs '
        split("\n")[:-1]
        | map(select(length>0))
        | map({
            path: .,
            base: (split("/")[-1])
          })
        | map(. + {
            scanner: (.base | split(".")[0]),
            format: (if (.base|endswith(".sarif.json")) then "sarif" else "json" end),
            kind: (if (.base|contains(".vuln.")) then "vuln" else "other" end)
          })
        | map(del(.base))
      '
}

evidence_list_component_artifact_scans() {
  # args: component platform_key
  local component="$1" pkey="$2"

  local os arch dir prefix
  os="$(ctx_get_artifact_field "$component" "$pkey" '.platform.os')"
  arch="$(ctx_get_artifact_field "$component" "$pkey" '.platform.arch')"
  [[ -n "$os" && -n "$arch" ]] || { jq -nc '[]'; return 0; }

  dir="${DIST}/${component}/scan/artifacts"
  [[ -d "$dir" ]] || { jq -nc '[]'; return 0; }

  prefix="${component}.${os}-${arch}."

  # only attesting sarif reports for now, keeping json on disk for extra audit data
  find "$dir" -maxdepth 1 -type f -name "${prefix}*.sarif.json" \
    | LC_ALL=C sort \
    | awk -v dist="$DIST/" '{ sub("^" dist, "", $0); print $0 }' \
    | jq -Rs --arg prefix "$prefix" '
        split("\n")[:-1]
        | map(select(length>0))
        | map({
            path: .,
            base: (split("/")[-1]),
            after: ((split("/")[-1]) | sub("^" + $prefix; ""))
          })
        | map(. + {
            scanner: (.after | split(".")[0]),
            format: (if (.base|endswith(".sarif.json")) then "sarif" else "json" end),
            kind: (if (.base|contains(".vuln.")) then "vuln" else "other" end)
          })
        | map(del(.base, .after))
      '
}

evidence_attest_component_index_scans() {
  # args: component
  local component="$1"
  local items
  items="$(evidence_list_component_source_scans "$component")"

  jq -c '.[]?' <<<"$items" | while IFS= read -r it; do
    local rel scanner kind format ct
    rel="$(jq -r '.path'   <<<"$it")"
    scanner="$(jq -r '.scanner' <<<"$it")"
    kind="$(jq -r '.kind' <<<"$it")"
    format="$(jq -r '.format' <<<"$it")"

    ct="$(evidence_content_type_for_source_scan "$scanner" "$kind" "$format")"
    # abs="${DIST}/${rel}"

    log "==> (attest) component=${component} index <- ${rel} (scanner=${scanner} format=${format})"
    evidence_attest_index_predicate "$component" "scan" "$rel" "https://cosign.sigstore.dev/attestation/vuln/v1" "$ct"
  done
}

evidence_attest_component_artifact_scan_reports() {
  # args: component platform_key
  local component="$1" pkey="$2"
  local items; items="$(evidence_list_component_artifact_scans "$component" "$pkey")"

  jq -c '.[]?' <<<"$items" | while IFS= read -r it; do
    local rel scanner kind format pred_type
    rel="$(jq -r '.path' <<<"$it")"
    scanner="$(jq -r '.scanner' <<<"$it")"
    kind="$(jq -r '.kind' <<<"$it")"
    format="$(jq -r '.format' <<<"$it")"

    pred_type="$(evidence_content_type_for_source_scan "$scanner" "$kind" "$format")"

    log "==> (attest) component=${component} artifact=${pkey} <- ${rel} (scanner=${scanner} format=${format})"
    evidence_attest_artifact_predicate \
      "$component" "$pkey" "scan" "$rel" \
      "$pred_type"
  done
}

evidence_list_component_source_sboms() {
  local component="$1"
  local dir="${DIST}/${component}/sbom/source"
  [[ -d "$dir" ]] || { jq -nc '[]'; return 0; }

  find "$dir" -maxdepth 1 -type f -name '*.json' \
    | LC_ALL=C sort \
    | awk -v dist="$DIST/" '{ sub("^" dist, "", $0); print $0 }' \
    | jq -Rs '
        split("\n")[:-1]
        | map(select(length>0))
        | map({
            path: .,
            format: (if endswith(".spdx.json") then "spdx-json"
                     elif endswith(".cdx.json") then "cyclonedx-json"
                     else "json" end)
          })
      '
}

evidence_list_component_artifact_sboms() {
  # args: component platform_key
  local component="$1" pkey="$2"

  local os arch dir prefix
  os="$(ctx_get_artifact_field "$component" "$pkey" '.platform.os')"
  arch="$(ctx_get_artifact_field "$component" "$pkey" '.platform.arch')"
  [[ -n "$os" && -n "$arch" ]] || { jq -nc '[]'; return 0; }

  dir="${DIST}/${component}/sbom/artifacts"
  [[ -d "$dir" ]] || { jq -nc '[]'; return 0; }

  prefix="${component}.${os}-${arch}."

  find "$dir" -maxdepth 1 -type f -name "${prefix}*.json" \
    | LC_ALL=C sort \
    | awk -v dist="$DIST/" '{ sub("^" dist, "", $0); print $0 }' \
    | jq -Rs --arg prefix "$prefix" '
        split("\n")[:-1]
        | map(select(length>0))
        | map({
            path: .,
            base: (split("/")[-1])
          })
        | map(. + {
            producer: (.base | sub("^" + $prefix; "") | split(".")[0]),
            format: (if (.base|endswith(".spdx.json")) then "spdx-json"
                     elif (.base|endswith(".cdx.json")) then "cyclonedx-json"
                     else "json" end)
          })
        | map(del(.base))
      '
}


# evidence_attest_component_index_sboms() {
#   local component="$1"
#   local items; items="$(evidence_list_component_source_sboms "$component")"

#   jq -c '.[]?' <<<"$items" | while IFS= read -r it; do
#     local rel abs
#     rel="$(jq -r '.path' <<<"$it")"
#     # abs="${DIST}/${rel}"
#     log "==> (attest) component=${component} index <- ${rel} (sbom)"
#     evidence_attest_index_predicate "$component" "sbom" "$rel" "https://cosign.sigstore.dev/attestation/sbom/v1"
#   done
# }

evidence_attest_component_index_sboms() {
  local component="$1"
  local items; items="$(evidence_list_component_source_sboms "$component")"

  jq -c '.[]?' <<<"$items" | while IFS= read -r it; do
    local rel format ct
    rel="$(jq -r '.path' <<<"$it")"
    format="$(jq -r '.format' <<<"$it")"

    ct="$(evidence_content_type_for_sbom_path "$rel")"

    log "==> (attest) component=${component} index <- ${rel} (sbom)"
    evidence_attest_index_predicate \
      "$component" "sbom" "$rel" \
      "https://cosign.sigstore.dev/attestation/sbom/v1" \
      "$ct"
  done
}

evidence_attest_component_artifact_sboms() {
  # args: component platform_key
  local component="$1" pkey="$2"
  local items; items="$(evidence_list_component_artifact_sboms "$component" "$pkey")"

  jq -c '.[]?' <<<"$items" | while IFS= read -r it; do
    local rel format ct
    rel="$(jq -r '.path' <<<"$it")"
    format="$(jq -r '.format' <<<"$it")"

    ct="$(evidence_content_type_for_sbom_path "$rel")"   # your PRED_SBOM_* mapping

    log "==> (attest) component=${component} artifact=${pkey} <- ${rel} (sbom format=${format})"
    evidence_attest_artifact_predicate \
      "$component" "$pkey" "sbom" "$rel" \
      "https://cosign.sigstore.dev/attestation/sbom/v1" \
      "$ct"
  done
}
