# shellcheck shell=bash

file_obj() {
  local rel="$1"
  local abs="${DIST}/${rel}"
  [[ -f "$abs" ]] || { jq -n 'null'; return 0; }

  #if [[ -z "${_SHA[$rel]+x}" ]]; then _SHA["$rel"]="$(sha256_of "$abs")"; fi
  #if [[ -z "${_SZ[$rel]+x}"  ]]; then _SZ["$rel"]="$(size_of "$abs")";  fi
  # jq -n \
  #   --arg path "$rel" \
  #   --arg sha256 "${_SHA[$rel]}" \
  #   --argjson size "${_SZ[$rel]}" \
  #   '{path:$path, hashes: {sha256:$sha256}, size:$size}'

  local sha256 size
  sha256="$( sha256_of "$abs" )"
  size="$( size_of "$abs" )"

  jq -n \
    --arg path "$rel" \
    --arg sha256 "$sha256" \
    --argjson size "$size" \
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

evidence_predicate_type_for_scan() {
  # args: scanner kind
  local scanner="$1" kind="${2:-vuln}"
  case "$scanner" in
    govulncheck) echo "${PRED_VULN_GOVULNCHECK:?}" ;;
    grype)       echo "${PRED_VULN_GRYPE:?}" ;;
    trivy)       echo "${PRED_VULN_TRIVY:?}" ;;
    *)           echo "https://phxi.net/attestations/${scanner}/${kind}/v1" ;;
  esac
}

evidence_report_media_type_for_format() {
  # args: format ("sarif"|"json"|...)
  local format="$1"
  case "$format" in
    sarif) echo "application/sarif+json" ;;
    json)  echo "application/json" ;;
    *)     echo "" ;;
  esac
}

# classify for files[]
classify_kind() {
  local rel="$1"
  if [[ "$rel" == *"/attestations/"* ]] || [[ "$rel" == *.sigstore.json ]]; then
    echo "attestation"
  elif [[ "$rel" == *.sig ]] || [[ "$rel" == *.bundle.sigstore.json ]]; then
    echo "signature"
  elif [[ "$rel" == *.sha256 ]]; then
    echo "checksum"
  elif [[ "$rel" == *sbom/* ]] && [[ "$rel" == *.json ]]; then
    echo "sbom"
  elif [[ "$rel" == *"/license/"* ]] && [[ "$rel" == *.json ]]; then
    echo "license"
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
          size,
          repository,
          artifactType,
          mediaType,
          pushed_at,
          manifests
        }
      end
  ' <<<"$OCI_INDEX_BY_COMP"
}

# sbom blocks for evidence
build_sbom_block() {
  # args: base_prefix ("" or "web"), scope ("source"|"artifacts"), name ("source" or "web.linux-amd64")
  local base="$1"
  local scope="$2"
  local name="$3"

  local pfx=""
  [[ -n "$base" ]] && pfx="${base}/"

  local sbom_dir="${pfx}sbom/${scope}"
  local att_dir="${pfx}attestations/sbom/${scope}"

  [[ -d "${DIST}/${sbom_dir}" ]] || { jq -n 'null'; return 0; }

  local items='[]'
  while IFS= read -r abs; do
    local rel basefile rest producer format att_rel report_obj item
    rel="${abs#"${DIST}/"}"
    basefile="$(basename "$rel")"

    # match: <name>.<producer>.(cdx|spdx).json
    [[ "$basefile" == "${name}."*".json" ]] || continue
    rest="${basefile#"${name}".}"
    producer="${rest%%.*}"

    if [[ "$basefile" == *.spdx.json ]]; then
      format="spdx-json"
    elif [[ "$basefile" == *.cdx.json ]]; then
      format="cyclonedx-json"
    else
      format="json"
    fi

    sbom_features="$(sbom_features_from_file "$abs")"

    report_obj="$(file_obj_or_null "$rel")"
    [[ "$report_obj" == "null" ]] && continue

    local atts
    atts="$(collect_attestations_for_evidence "$att_dir" "$basefile")"

    item="$( jq -n \
      --arg producer "$producer" \
      --arg format "$format" \
      --argjson report "$report_obj" \
      --argjson atts "$atts" \
      --argjson sbom_features "$sbom_features" \
      '{
         producer: $producer,
         format: $format,
         features: $sbom_features,
         report: $report
       }
       | if ($atts | length) > 0 then . + {attestations: $atts} else . end
      '
    )"

    items="$(add_to_array "$items" "$item")"
  done < <(find "${DIST}/${sbom_dir}" -maxdepth 1 -type f -name "${name}*.json" | LC_ALL=C sort)

  jq -n --argjson items "$items" '
    if ($items|length)==0 then null else { sbom: $items } end
  '
}

build_license_block() {
  # args: base_prefix ("" or "web"), scope ("source"|"artifacts"), name ("source" or "web.linux-amd64")
  local base="$1"
  local scope="$2"
  local name="$3"

  local pfx=""
  [[ -n "$base" ]] && pfx="${base}/"

  local lic_dir="${pfx}license/${scope}"
  local att_dir="${pfx}attestations/license/${scope}"

  [[ -d "${DIST}/${lic_dir}" ]] || { jq -n 'null'; return 0; }

  # convention:
  #   source   -> <lic_dir>/source.licenses.json
  #   artifacts-> <lic_dir>/<name>.licenses.json   (name = comp.os-arch)
  local file="${name}.licenses.json"
  local report_rel="${lic_dir}/${file}"
  local report_obj
  report_obj="$(file_obj_or_null "$report_rel")"
  [[ "$report_obj" != "null" ]] || { jq -n 'null'; return 0; }

  local atts
  atts="$(collect_attestations_for_evidence "$att_dir" "$file")"

  jq -n \
    --arg format "summary-json" \
    --argjson report "$report_obj" \
    --argjson atts "$atts" \
    '{
        format: $format,
        report: $report
      }
      | if ($atts | length) > 0 then . + {attestations: $atts} else . end
      | { license: [.] }
    '
}

# source level scans generated by seraching for files in scan dir on disk
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

    local atts
    atts="$(collect_attestations_for_evidence "$att_dir" "$base")"

    local item
    item="$( jq -n \
      --arg scanner "$scanner" \
      --arg kind "$kind" \
      --arg format "$format" \
      --argjson report "$(file_obj "$rel")" \
      --argjson atts "$atts" \
      '{
          scanner:$scanner,
          kind:$kind,
          format:$format,
          report:$report
        }
        | if ($atts | length) > 0 then . + {attestations: $atts} else . end
      '
    )"

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

  # artifact-level scans per os/arch
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

    local att_rel="${att_dir}/${base}.intoto.v1.dsse.json"
    [[ -f "${DIST}/${att_rel}" ]] || att_rel="${att_dir}/${base}.intoto.v1.sigstore.json"

    local atts
    atts="$(collect_attestations_for_evidence "$att_dir" "$base")"

    local item
    item="$( jq -n \
      --arg scanner "$scanner" \
      --arg kind "$kind" \
      --arg format "$format" \
      --argjson report "$(file_obj "$rel")" \
      --argjson atts "$atts" \
      '{scanner:$scanner, kind:$kind, format:$format, report:$report}
       | if ($atts | length) > 0 then . + {attestations: $atts} else . end
      '
    )"

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

# build one component object
build_component_obj() {
  local comp="$1"
  local pfx=""
  [[ "$comp" != "_repo" ]] && pfx="${comp}/"

  # build block
  local build_manifest
  build_manifest="$(jq -n \
    --argjson manifest   "$(file_obj_or_null "${pfx}build.json")" \
    --argjson signature  "$(file_obj_or_null "${pfx}build.json.bundle.sigstore.json")" \
    '{
       manifest:$manifest,
       signature:$signature
     }
     | with_entries(select(.value != null))
     | if (length==0) then null else . end
  ')"

  # source evidence
  local sbom_source
  sbom_source="$(build_sbom_block "${pfx%/}" "source" "source")"

  local license_source
  license_source="$(build_license_block "${pfx%/}" "source" "source")"

  local scans_source
  scans_source="$(build_scans_for_dir "${pfx}scan/source" "${pfx}attestations/scan/source")"

  local source_evidence
  source_evidence="$(jq -n \
    --argjson sbom "$sbom_source" \
    --argjson license "$license_source" \
    --argjson scans "$scans_source" \
    '{
       sbom:$sbom.sbom,
       license:$license.license,
       scans:$scans
     }
     | with_entries(select(.value != null))
     | (if (type=="object") and (.scans? | type=="array") and ((.scans|length)==0) then del(.scans) else . end)
     | (if (type=="object") and (.sbom? | type=="array") and ((.sbom|length)==0) then del(.sbom) else . end)
     | (if (type=="object") and (.license? | type=="array") and ((.license|length)==0) then del(.license) else . end)
    '
  )"

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

      sig_obj="$(file_obj_or_null "${bin_rel}.bundle.sigstore.json")"
      sha_obj="$(file_obj_or_null "${bin_rel}.sha256")"

      # sbom artifacts block
      local sbom_art
      sbom_art="$(build_sbom_block "$comp" "artifacts" "$name")"

      # license artifacts block
      local lic_art
      lic_art="$(build_license_block "$comp" "artifacts" "$name")"

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
        --argjson license "$lic_art" \
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
          license: (if ($license|type)=="object" then ($license.license // null)
            elif ($license|type)=="array" then $license else null end),
          scans:$scans,
          provenance: (if ($provenance|length)>0 then $provenance else null end)
        }
        | (if (.oci_subject? | type=="array" and length==0) then del(.oci_subject) else . end)
        | (if (.signatures? | type=="array" and length==0) then del(.signatures) else . end)
        | (if (.scans?      | type=="array" and length==0) then del(.scans)      else . end)
        | (if (.sbom?       | type=="array" and length==0) then del(.sbom) else . end)
        | (if (.license?    | type=="array" and length==0) then del(.license) else . end)
        | (if (.provenance? == null) then del(.provenance) else . end)
        ')"

      artifacts="$(add_to_array "$artifacts" "$artifact")"
    done < <(find "${DIST}/${comp}/bin" -type f | LC_ALL=C sort)
  fi

  jq -n \
    --argjson build_manifest "$build_manifest" \
    --argjson source_evidence "$source_evidence" \
    --argjson artifacts "$artifacts" \
    --argjson oci_index "$oci_index" \
    '{
       build_manifest:$build_manifest,
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
    "${DIST}/${c}/license/source" \
    "${DIST}/${c}/license/artifacts" \
    "${DIST}/${c}/scan/source" \
    "${DIST}/${c}/scan/artifacts" \
    "${DIST}/${c}/attestations/sbom/source" \
    "${DIST}/${c}/attestations/sbom/artifacts" \
    "${DIST}/${c}/attestations/license/source" \
    "${DIST}/${c}/attestations/license/artifacts" \
    "${DIST}/${c}/attestations/scan/source" \
    "${DIST}/${c}/attestations/scan/artifacts" \
    "${DIST}/${c}/attestations/provenance/artifacts"
}

evidence_generate_repo_source_sboms() {
  # generate cyclonedx-gomod cdx repo-wide source sboms
  cyclonedx-gomod mod -json=true -licenses=true -output "${DIST}/_repo/sbom/source/source.gomod.cdx.json" || die "Failed to generate cyclonedx-gomod repo source sbom!"

  # generate syft cdx/spdx repo-wide source sboms
  syft scan dir:. --exclude "./dist" --exclude "./.git" --exclude "./tools" --exclude "./webassets" --enrich golang --source-name "${APP}" --source-version "${RELEASE_VERSION}" --output spdx-json="${DIST}/_repo/sbom/source/source.syft.spdx.json" --output cyclonedx-json="${DIST}/_repo/sbom/source/source.syft.cdx.json" || die "Failed to generate syft repo source sbom!"
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
  syft scan dir:. --exclude "./dist" --exclude "./.git" --exclude "./tools" --exclude "./webassets" --enrich golang --source-name "${APP}-${component}" --source-version "${RELEASE_VERSION}" --output spdx-json="${DIST}/${component}/sbom/source/source.syft.spdx.json" --output cyclonedx-json="${DIST}/${component}/sbom/source/source.syft.cdx.json" || die "Failed to generate sbom!"
}

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
  # wrapping with jq or else it emits multiple json objects which is invalid format for cosign and our evidence predicate types
  govulncheck -mode=binary -json "$bin_path" | jq -s '{ entries: . }' > "${out_prefix}.govulncheck.vuln.json"
  
  log "==> (evidence) ${component}/${pkey} govulncheck vuln sarif"
  govulncheck -mode=binary -format sarif "$bin_path" > "${out_prefix}.govulncheck.vuln.sarif.json"
}

# old attestation functions for local files - attesting in oci now
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
  # wrapping with jq or else it emits multiple json objects which is invalid format for cosign and our evidence predicate types
  govulncheck -json ./... | jq -s '{ entries: . }' > "${DIST}/_repo/scan/source/govulncheck.vuln.json"
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

# old attestation functions for local files - attesting in oci now
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
  # wrapping with jq or else it emits multiple json objects which is invalid format for cosign and our evidence predicate types
  govulncheck -json "./cmd/${component}/..." | jq -s '{ entries: . }' > "${DIST}/${component}/scan/source/govulncheck.vuln.json"
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

# old attestation functions for local files - attesting in oci now
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
#  13 dsse_envelope_path     relative path to dsse envelope file (string)
#  14 dsse_envelope_sha256   sha256 of dsse envelope file (string)
#  15 dsse_envelope_size     size of dsse envelope file (number)
#  16 dsse_envelope_mediaType mediaType of dsse envelope file (string)
evidence_make_oci_attestation_record() {
  local scope="$1" component="$2" pkey="$3" category="$4"
  local subject_digest_ref="$5" predicate_path_in="$6" predicate_type="$7"
  local predicate_content_type="${8:-}"
  local att_digest_ref="$9" att_mediaType="${10}" att_size="${11}"
  local att_pushed_at="${12}"
  local dsse_envelope_path="${13}" dsse_envelope_sha256="${14}"
  local dsse_envelope_size="${15}" dsse_envelope_mediaType="${16}"


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
    --arg dsse_envelope_path "$dsse_envelope_path" \
    --arg dsse_envelope_sha256 "$dsse_envelope_sha256" \
    --argjson dsse_envelope_size "${dsse_envelope_size:-0}" \
    --arg dsse_envelope_mediaType "$dsse_envelope_mediaType" \
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
      bundle: {
        path: $dsse_envelope_path,
        hashes: { sha256: $dsse_envelope_sha256 },
        size: $dsse_envelope_size,
        mediaType: (if ($dsse_envelope_mediaType|length)>0 then $dsse_envelope_mediaType else null end)
      },
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

# attest a predicate to an artifact subject (per platform)

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

  log "evidence_attest_artifact_predicate: attested predicate for ${component}/${pkey} subject=${subject} predicate=${predicate_rel} digest_ref=${digest_ref}"
  # save dsse envelope to local file for auditing and s3/oci deploy flexibility
  local dsse_rel dsse_abs dsse_mt dsse_manifest_rel dsse_manifest_abs dsse_sha256_sum dsse_size
  dsse_rel="$(awk -F/ '{print $1"/attestations/"$2"/"$3"/"$4".intoto.v1.dsse.json"}' <<<"$predicate_rel")"
  dsse_abs="$(dist_abspath "$dsse_rel")"

  # temporarily storing manifest next to it
  dsse_manifest_rel="${dsse_rel%.intoto.v1.dsse.json}.oci.manifest.json"
  dsse_manifest_abs="$(dist_abspath "$dsse_manifest_rel")"

  dsse_mt="$(oci_fetch_attestation_dsse "$digest_ref" "$dsse_abs" "$dsse_manifest_abs")"

  dsse_sha256_sum="$(sha256sum "$dsse_abs" | awk '{print $1}')"
  dsse_size="$( stat -c%s "$dsse_abs" )"

  local ev
  ev="$(evidence_make_oci_attestation_record \
        "artifact" "$component" "$pkey" "$category" \
        "$subject" "$predicate_rel" "$predicate_type" "$predicate_content_type" \
        "$digest_ref" "$mediaType" "$size" "$pushed_at" \
        "$dsse_rel" "$dsse_sha256_sum" "$dsse_size" "$dsse_mt"
  )"

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

  # save dsse envelope to local file for auditing and s3/oci deploy flexibility
  local dsse_rel dsse_abs dsse_mt dsse_manifest_rel dsse_manifest_abs dsse_sha256_sum dsse_size
  dsse_rel="$(awk -F/ '{print $1"/attestations/"$2"/"$3"/"$4".intoto.v1.dsse.json"}' <<<"$predicate_rel")"
  dsse_abs="$(dist_abspath "$dsse_rel")"

  # temporarily storing manifest next to it
  #dsse_manifest_rel="${dsse_rel%.dsse.json}.manifest.json"
  dsse_manifest_rel="${dsse_rel%.intoto.v1.dsse.json}.oci.manifest.json"

  dsse_manifest_abs="$(dist_abspath "$dsse_manifest_rel")"

  # write the dsse envelope and return the mediaType
  dsse_mt="$(oci_fetch_attestation_dsse "$digest_ref" "$dsse_abs" "$dsse_manifest_abs")"

  dsse_sha256_sum="$(sha256sum "$dsse_abs" | awk '{print $1}')"
  dsse_size="$( stat -c%s "$dsse_abs" )"

  local ev
  ev="$(evidence_make_oci_attestation_record \
        "index" "$component" "" "$category" \
        "$subject" "$predicate_rel" "$predicate_type" "$predicate_content_type" \
        "$digest_ref" "$mediaType" "$size" "$pushed_at" \
        "$dsse_rel" "$dsse_sha256_sum" "$dsse_size" "$dsse_mt"
  )"

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

  find "$dir" -maxdepth 1 -type f -name '*.json' \
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
  # nevermind if we are generating evidence it must be attested. renamed outputs to include full original filename to support this
  #find "$dir" -maxdepth 1 -type f -name "${prefix}*.sarif.json" \
  find "$dir" -maxdepth 1 -type f -name "${prefix}*.json" \
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

evidence_oci_attest_component_index_scans() {
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

    local pred_type
    pred_type="$(evidence_predicate_type_for_scan "$scanner" "$kind")"
    ct="$(evidence_report_media_type_for_format "$format")"
    # abs="${DIST}/${rel}"

    log "==> (attest) component=${component} index <- ${rel} (scanner=${scanner} format=${format})"
    evidence_attest_index_predicate "$component" "scan" "$rel" "$pred_type" "$ct"
  done
}

evidence_oci_attest_component_artifact_scan_reports() {
  # args: component platform_key
  local component="$1" pkey="$2"
  local items; items="$(evidence_list_component_artifact_scans "$component" "$pkey")"

  jq -c '.[]?' <<<"$items" | while IFS= read -r it; do
    local rel scanner kind format pred_type ct
    rel="$(jq -r '.path' <<<"$it")"
    scanner="$(jq -r '.scanner' <<<"$it")"
    kind="$(jq -r '.kind' <<<"$it")"
    format="$(jq -r '.format' <<<"$it")"

    pred_type="$(evidence_predicate_type_for_scan "$scanner" "$kind")"
    ct="$(evidence_report_media_type_for_format "$format")"

    log "==> (attest) component=${component} artifact=${pkey} <- ${rel} (scanner=${scanner} format=${format})"
    evidence_attest_artifact_predicate \
      "$component" "$pkey" "scan" "$rel" \
      "$pred_type" "$ct"
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

evidence_oci_attest_component_index_sboms() {
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

evidence_oci_attest_component_artifact_sboms() {
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

sbom_detect_format() {
  local f="$1"
  jq -r '
    if (.bomFormat? == "CycloneDX") then "cyclonedx"
    elif (.spdxVersion? or .SPDXID? or .packages?) then "spdx"
    else "unknown"
    end
  ' "$f"
}

# sbom_features_from_file() {
#   local f="$1"
#   local fmt
#   fmt="$(sbom_detect_format "$f")"

#   case "$fmt" in
#     cyclonedx)
#       jq -c '
#         {
#           licenses:        ( ( (.components? // []) | any(.licenses? and (.licenses|length>0)) )
#                           or ( (.metadata?.component?.licenses? // []) | length > 0 ) ),
#           license_expressions: ( (.components? // []) | any(.licenses?[]?.expression?) ),
#           purls:           ( (.components? // []) | any(.purl?) ),
#           cpes:            ( (.components? // []) | any(.cpe?) ),
#           dependency_graph:( (.dependencies? // []) | length > 0 ),
#           file_level:      ( (.components? // []) | any((.type? // "") == "file") ),
#           hashes:          ( (.components? // []) | any(.hashes? and (.hashes|length>0)) ),
#           external_refs:   ( (.components? // []) | any(.externalReferences? and (.externalReferences|length>0)) ),
#           properties:      ( (.components? // []) | any(.properties? and (.properties|length>0)) )
#         }
#       ' "$f"
#       ;;
#     spdx)
#       jq -c '
#         {
#           licenses: (
#             ( (.packages? // []) | any(.licenseDeclared? or .licenseConcluded?) )
#             or ( (.files? // []) | any(.licenseConcluded?) )
#           ),
#           license_expressions: (
#             ( (.packages? // []) | any((.licenseDeclared? // "" | type=="string") and (.licenseDeclared|test("[()ANDOR]"))) )
#             or ( (.packages? // []) | any((.licenseConcluded? // "" | type=="string") and (.licenseConcluded|test("[()ANDOR]"))) )
#           ),
#           purls:            ( (.packages? // []) | any(.externalRefs?[]?.referenceType? == "purl") ),
#           cpes:             ( (.packages? // []) | any(.externalRefs?[]?.referenceType? == "cpe23Type") ),
#           dependency_graph: ( (.relationships? // []) | length > 0 ),
#           file_level:       ( (.files? // []) | length > 0 ),
#           hashes:           ( (.packages? // []) | any(.checksums? and (.checksums|length>0)) )
#                             or ( (.files? // []) | any(.checksums? and (.checksums|length>0)) ),
#           external_refs:    ( (.packages? // []) | any(.externalRefs? and (.externalRefs|length>0)) )
#         }
#       ' "$f"
#       ;;
#     *)
#       echo "null"
#       ;;
#   esac
# }

sbom_features_from_file() {
  local f="$1"

  jq -c '
    # ---- CycloneDX helpers ----
    def cdx_license_present:
      ((.metadata?.component?.licenses? // [] | length) > 0)
      or ((.metadata?.component?.evidence?.licenses? // [] | length) > 0)
      or ((.components? // []) | any(
            ((.licenses? // [] | length) > 0) or
            ((.evidence?.licenses? // [] | length) > 0)
         ));

    def cdx_license_expression_present:
      ((.metadata?.component?.licenses? // []) | any(.expression?))
      or ((.metadata?.component?.evidence?.licenses? // []) | any(.expression?))
      or ((.components? // []) | any(
            ((.licenses? // []) | any(.expression?)) or
            ((.evidence?.licenses? // []) | any(.expression?))
         ));

    def cdx_has_purls:
      ((.metadata?.component?.purl? // "" | length) > 0)
      or ((.components? // []) | any((.purl? // "" | length) > 0));

    def cdx_has_cpes:
      ((.components? // []) | any((.cpe? // "" | length) > 0));

    def cdx_dep_graph: ((.dependencies? // []) | length) > 0;
    def cdx_file_level: ((.components? // []) | any((.type? // "") == "file"));
    def cdx_hashes: ((.components? // []) | any((.hashes? // []) | length > 0));
    def cdx_external_refs: ((.components? // []) | any((.externalReferences? // []) | length > 0));
    def cdx_properties: ((.components? // []) | any((.properties? // []) | length > 0));
    def cdx_scopes: ((.components? // []) | any((.scope? // "" | tostring | length) > 0));

    # ---- SPDX helpers ----
    def spdx_asserted: (type=="string") and . != "" and . != "NOASSERTION" and . != "NONE";

    def spdx_license_present:
      ((.packages? // []) | any((.licenseDeclared? | spdx_asserted) or (.licenseConcluded? | spdx_asserted)))
      or ((.files? // []) | any((.licenseConcluded? | spdx_asserted)))
      or ((.hasExtractedLicensingInfos? // []) | length > 0);

    def spdx_license_expression_present:
      ((.packages? // []) | any(
        ((.licenseDeclared? | spdx_asserted) and (.licenseDeclared | test(" AND | OR |\\(|\\)"))) or
        ((.licenseConcluded? | spdx_asserted) and (.licenseConcluded | test(" AND | OR |\\(|\\)")))
      ));

    def spdx_has_purls: ((.packages? // []) | any((.externalRefs? // []) | any(.referenceType? == "purl")));
    def spdx_has_cpes:  ((.packages? // []) | any((.externalRefs? // []) | any(.referenceType? == "cpe23Type")));
    def spdx_dep_graph: ((.relationships? // []) | length) > 0;
    def spdx_file_level: ((.files? // []) | length) > 0;
    def spdx_hashes:
      ((.packages? // []) | any((.checksums? // []) | length > 0))
      or ((.files? // []) | any((.checksums? // []) | length > 0));

    if (.bomFormat? == "CycloneDX") then
      {
        licenses: cdx_license_present,
        license_expressions: cdx_license_expression_present,
        purls: cdx_has_purls,
        cpes: cdx_has_cpes,
        dependency_graph: cdx_dep_graph,
        file_level: cdx_file_level,
        hashes: cdx_hashes,
        external_refs: cdx_external_refs,
        properties: cdx_properties,
        scopes: cdx_scopes
      }
    elif (.spdxVersion? or .SPDXID? or .packages?) then
      {
        licenses: spdx_license_present,
        license_expressions: spdx_license_expression_present,
        purls: spdx_has_purls,
        cpes: spdx_has_cpes,
        dependency_graph: spdx_dep_graph,
        file_level: spdx_file_level,
        hashes: spdx_hashes
      }
    else
      null
    end
  ' "$f"
}

license_rank_for_sbom_basename() {
  local base="$1" name="$2"
  # Lower is better
  if [[ "$base" == "${name}.gomod.cdx.json" ]]; then echo 10; return 0; fi
  if [[ "$base" == *.gomod.cdx.json ]]; then echo 20; return 0; fi
  if [[ "$base" == *.cdx.json ]]; then echo 30; return 0; fi
  if [[ "$base" == *.spdx.json ]]; then echo 40; return 0; fi
  echo 90
}

license_select_sbom_from_dir() {
  # args: dir_abs name_prefix
  local dir_abs="$1"
  local name="$2"

  [[ -d "$dir_abs" ]] || return 1

  local best_lic="" best_lic_rank=999
  local best_any="" best_any_rank=999

  while IFS= read -r abs; do
    local base rank rel features
    base="$(basename "$abs")"
    [[ "$base" == "${name}."*".json" ]] || continue

    rank="$(license_rank_for_sbom_basename "$base" "$name")"
    rel="${abs#"${DIST}/"}"

    if (( rank < best_any_rank )); then
      best_any_rank="$rank"
      best_any="$rel"
    fi

    features="$(sbom_features_from_file "$abs" 2>/dev/null || echo 'null')"
    if jq -e '.licenses == true' >/dev/null 2>&1 <<<"$features"; then
      if (( rank < best_lic_rank )); then
        best_lic_rank="$rank"
        best_lic="$rel"
      fi
    fi
  done < <(find "$dir_abs" -maxdepth 1 -type f -name "${name}*.json" | LC_ALL=C sort)

  if [[ -n "$best_lic" ]]; then printf '%s\n' "$best_lic"; return 0; fi
  if [[ -n "$best_any" ]]; then printf '%s\n' "$best_any"; return 0; fi
  return 1
}

license_report_out_rel_source() {
  local component="$1"
  printf '%s/license/source/source.licenses.json' "$component"
}

license_report_out_rel_artifact() {
  local component="$1" os="$2" arch="$3"
  printf '%s/license/artifacts/%s.%s-%s.licenses.json' "$component" "$component" "$os" "$arch"
}

license_report_generate_from_sbom() {
  # args: component scope platform_key sbom_rel out_rel
  set -euo pipefail
  local component="$1" scope="$2" platform_key="$3" sbom_rel="$4" out_rel="$5"

  local sbom_abs out_abs
  sbom_abs="$(dist_abspath "$sbom_rel")"
  out_abs="$(dist_abspath "$out_rel")"
  mkdir -p "$(dirname "$out_abs")"

  [[ -f "$sbom_abs" ]] || die "license_report_generate_from_sbom: missing sbom: $sbom_abs"

  local now sbom_sha sbom_size features
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sbom_sha="$(sha256sum "$sbom_abs" | awk '{print $1}')"
  sbom_size="$(stat -c%s "$sbom_abs")"
  features="$(sbom_features_from_file "$sbom_abs" 2>/dev/null || echo 'null')"

  # best-effort get producer and format from filename
  local base producer fmt
  base="$(basename "$sbom_rel")"
  if [[ "$base" == *.cdx.json ]]; then fmt="cyclonedx-json"
  elif [[ "$base" == *.spdx.json ]]; then fmt="spdx-json"
  else fmt="json"
  fi

  # producer is token after "<name>."
  # source.* is source.<producer>.*
  # artifact is <comp>.<os-arch>.<producer>.*
  local nameprefix
  if [[ "$scope" == "source" ]]; then
    nameprefix="source"
  else
    local os arch
    os="$(ctx_get_artifact_field "$component" "$platform_key" '.platform.os')"
    arch="$(ctx_get_artifact_field "$component" "$platform_key" '.platform.arch')"
    nameprefix="${component}.${os}-${arch}"
  fi
  producer="${base#"${nameprefix}."}"
  producer="${producer%%.*}"

  # load license policy from app config
  local license_policy
  license_policy="$( jq -c '.policy.license // {}' "${APP_CFG_PATH:?APP_CFG_PATH required}" )"

  # generate license report
  # testing an implementation of report generation and license gate evaluation in jq for efficiency
  jq -n \
    --slurpfile bom "$sbom_abs" \
    --argjson policy "$license_policy" \
    --arg schema "phxi.license_report.v1" \
    --arg predicate_type "${PRED_LICENSE_REPORT:-}" \
    --arg generated_at "$now" \
    --arg scope "$scope" \
    --arg component "$component" \
    --arg platform_key "$platform_key" \
    --arg sbom_path "$sbom_rel" \
    --arg sbom_sha256 "$sbom_sha" \
    --argjson sbom_size "$sbom_size" \
    --arg sbom_format "$fmt" \
    --arg sbom_producer "$producer" \
    --argjson sbom_features "$features" \
    '
    def spdx_asserted:
      (type=="string") and . != "" and . != "NOASSERTION" and . != "NONE";

    def spdx_purl(p):
      ((p.externalRefs // [])
        | map(select(.referenceType? == "purl"))
        | .[0].referenceLocator // null);

    def spdx_item(p):
      {
        name: (p.name // null),
        version: (p.versionInfo // null),
        spdxid: (p.SPDXID // null),
        purl: spdx_purl(p),
        licenses: ([p.licenseDeclared, p.licenseConcluded]
                  | map(select(spdx_asserted))
                  | unique)
      } | with_entries(select(.value != null));

    def cdx_lic_str(x):
      if x.expression? then x.expression
      else (x.license.id // x.license.name // empty) end;

    def cdx_licenses_for(c):
      (
        ([ (c.licenses // [])[]? | cdx_lic_str(.) ]
         + [ (c.evidence?.licenses // [])[]? | cdx_lic_str(.) ])
        | map(select(type=="string" and length>0))
        | unique
      );

    def cdx_item(c):
      ({
        bom_ref: (c["bom-ref"] // null),
        type: (c.type // null),
        name: (c.name // null),
        group: (c.group // null),
        version: (c.version // null),
        purl: (c.purl // null),
        licenses: cdx_licenses_for(c)
      } | with_entries(select(.value != null)));

    def gate_license($l):
      # check deny exact match
      if (($policy.deny // []) | any(. == $l)) then
        { result: "denied", reason: "deny_list" }
      # check deny regex
      elif (($policy.deny_regex // []) | any(. as $pat | $l | test($pat))) then
        { result: "denied", reason: "deny_regex" }
      # check allow exact match
      elif (($policy.allow // []) | any(. == $l)) then
        { result: "allowed", reason: "allow_list" }
      # unknown — depends on allow_unknown
      elif ($policy.allow_unknown // false) then
        { result: "allowed", reason: "allow_unknown" }
      else
        { result: "unknown", reason: "not_in_allow_list" }
      end;

    def gate_item(item):
      (item.licenses // []) as $lics |
      if ($lics | length) == 0 then
        # no licenses declared
        if (($policy.max_without_license // 0) == 0) then
          { result: "denied", reason: "no_license_declared", details: [] }
        else
          { result: "unknown", reason: "no_license_declared", details: [] }
        end
      else
        ($lics | map(. as $l | { license: $l } + gate_license($l))) as $details |
        if ($details | any(.result == "denied")) then
          { result: "denied", reason: "license_denied", details: $details }
        elif ($details | any(.result == "unknown")) then
          { result: "unknown", reason: "license_unknown", details: $details }
        else
          { result: "allowed", reason: "all_licenses_allowed", details: $details }
        end
      end;

    def summarize(items):
      {
        items_total: (items | length),
        with_licenses: (items | map(select((.licenses // []) | length > 0)) | length),
        without_licenses: (items | map(select((.licenses // []) | length == 0)) | length),
        unique_licenses: (items | map(.licenses[]?) | unique | length),
        by_license: (
          (items | map(.licenses[]?) | sort)
          | group_by(.)
          | map({license: .[0], count: length})
        ),
        gate: {
          allowed: (items | map(select(.gate.result == "allowed")) | length),
          denied: (items | map(select(.gate.result == "denied")) | length),
          unknown: (items | map(select(.gate.result == "unknown")) | length),
          denied_licenses: (
            [items[].gate.details[]? | select(.result == "denied") | .license]
            | unique
          ),
          unknown_licenses: (
            [items[].gate.details[]? | select(.result == "unknown") | .license]
            | unique
          )
        }
      };

    ($bom[0]) as $b |

    (
      if ($b.bomFormat? == "CycloneDX") then
        (
          ([ $b.metadata?.component? ] | map(select(.!=null)))
          + ($b.components // [])
          | map(cdx_item(.) | . + { gate: gate_item(.) })
        )
      elif ($b.spdxVersion? or $b.SPDXID? or $b.packages?) then
        (($b.packages // []) | map(spdx_item(.) | . + { gate: gate_item(.) }))
      else
        []
      end
    ) as $items |

    {
      schema: $schema,
      predicate_type: (if ($predicate_type|length)>0 then $predicate_type else null end),
      generated_at: $generated_at,
      scope: $scope,
      component: (if ($component|length)>0 then $component else null end),
      platform_key: (if ($platform_key|length)>0 then $platform_key else null end),
      input: ({
        sbom: {
          path: $sbom_path,
          hashes: { sha256: $sbom_sha256 },
          size: $sbom_size,
          format: (if ($sbom_format|length)>0 then $sbom_format else null end),
          producer: (if ($sbom_producer|length)>0 then $sbom_producer else null end),
          features: $sbom_features
        }
      } | with_entries(select(.value != null))),
      policy: $policy,
      summary: summarize($items),
      items: $items
    }
    | with_entries(select(.value != null))
    ' > "$out_abs"

}

evidence_generate_component_source_license_report() {
  # args: component
  local component="$1"

  local sbom_dir="${DIST}/${component}/sbom/source"
  local sbom_rel
  if ! sbom_rel="$(license_select_sbom_from_dir "$sbom_dir" "source")"; then
    die "license: could not find any source SBOMs for component=${component}"
  fi

  local out_rel
  out_rel="$(license_report_out_rel_source "$component")"

  log "==> (license) component=${component} scope=source sbom=${sbom_rel} -> ${out_rel}"
  license_report_generate_from_sbom "$component" "source" "" "$sbom_rel" "$out_rel"

  log "==> (attest) component=${component} index <- ${out_rel} (license)"
  evidence_attest_index_predicate \
    "$component" "license" "$out_rel" \
    "${PRED_LICENSE_REPORT:?PRED_LICENSE_REPORT required}" \
    "application/json"
}

evidence_generate_component_artifact_license_report() {
  # args: component platform_key
  local component="$1" pkey="$2"

  local os arch
  os="$(ctx_get_artifact_field "$component" "$pkey" '.platform.os')"
  arch="$(ctx_get_artifact_field "$component" "$pkey" '.platform.arch')"
  [[ -n "$os" && -n "$arch" ]] || die "license: missing os/arch for ${component}/${pkey}"

  local name="${component}.${os}-${arch}"
  local sbom_dir="${DIST}/${component}/sbom/artifacts"
  local sbom_rel
  if ! sbom_rel="$(license_select_sbom_from_dir "$sbom_dir" "$name")"; then
    die "license: could not find any artifact SBOMs for component=${component} pkey=${pkey}"
  fi

  local out_rel
  out_rel="$(license_report_out_rel_artifact "$component" "$os" "$arch")"

  log "==> (license) component=${component} scope=artifacts pkey=${pkey} sbom=${sbom_rel} -> ${out_rel}"
  license_report_generate_from_sbom "$component" "artifacts" "$pkey" "$sbom_rel" "$out_rel"

  log "==> (attest) component=${component} artifact=${pkey} <- ${out_rel} (license)"
  evidence_attest_artifact_predicate \
    "$component" "$pkey" "license" "$out_rel" \
    "${PRED_LICENSE_REPORT:?PRED_LICENSE_REPORT required}" \
    "application/json"
}

evidence_local_attest_component_platform() {
  local component="$1" pkey="$2"

  local bin_path_in bin_path os arch platform_suffix
  bin_path_in="$(ctx_get_artifact_field "$component" "$pkey" '.local.path')"
  bin_path="$(dist_abspath "$bin_path_in")"
  os="$(ctx_get_artifact_field "$component" "$pkey" '.platform.os')"
  arch="$(ctx_get_artifact_field "$component" "$pkey" '.platform.arch')"
  platform_suffix="${os}-${arch}"

  [[ -f "$bin_path" ]] || die "local attest: binary not found: $bin_path"

  # artifact-scope sboms
  local items
  items="$(evidence_list_component_artifact_sboms "$component" "$pkey")"
  while IFS= read -r it; do
    [[ -n "$it" ]] || continue
    local rel pred_abs
    rel="$(jq -r '.path' <<<"$it")"
    pred_abs="$(dist_abspath "$rel")"

    log "==> (local-attest) artifact sbom: ${rel} -> binary ${platform_suffix}"
    attest_file_dsse_v1 "$bin_path" "$pred_abs" \
      "https://cosign.sigstore.dev/attestation/sbom/v1"
  done < <(jq -c '.[]?' <<<"$items")

  # artifact-scope scans
  items="$(evidence_list_component_artifact_scans "$component" "$pkey")"
  while IFS= read -r it; do
    [[ -n "$it" ]] || continue
    local rel scanner kind pred_type pred_abs
    rel="$(jq -r '.path' <<<"$it")"
    scanner="$(jq -r '.scanner' <<<"$it")"
    kind="$(jq -r '.kind' <<<"$it")"
    pred_type="$(evidence_predicate_type_for_scan "$scanner" "$kind")"
    pred_abs="$(dist_abspath "$rel")"

    log "==> (local-attest) artifact scan: ${rel} -> binary ${platform_suffix}"
    attest_file_dsse_v1 "$bin_path" "$pred_abs" "$pred_type"
  done < <(jq -c '.[]?' <<<"$items")

  # artifact-scope license
  local lic_rel lic_abs
  lic_rel="$(license_report_out_rel_artifact "$component" "$os" "$arch")"
  lic_abs="$(dist_abspath "$lic_rel")"
  if [[ -f "$lic_abs" ]]; then
    log "==> (local-attest) artifact license: ${lic_rel} -> binary ${platform_suffix}"
    attest_file_dsse_v1 "$bin_path" "$lic_abs" \
      "${PRED_LICENSE_REPORT:?PRED_LICENSE_REPORT required}"
  fi

  # source-scope SBOMs (explicit bundle_out with platform to avoid collision)
  items="$(evidence_list_component_source_sboms "$component")"
  while IFS= read -r it; do
    [[ -n "$it" ]] || continue
    local rel pred_abs basename bundle_out
    rel="$(jq -r '.path' <<<"$it")"
    pred_abs="$(dist_abspath "$rel")"
    basename="$(basename "$rel")"
    bundle_out="${DIST}/${component}/attestations/sbom/source/${basename}.${platform_suffix}.intoto.v1.sigstore.json"
    mkdir -p "$(dirname "$bundle_out")"

    log "==> (local-attest) source sbom: ${rel} -> binary ${platform_suffix}"
    attest_file_dsse_v1 "$bin_path" "$pred_abs" \
      "https://cosign.sigstore.dev/attestation/sbom/v1" \
      "" "$bundle_out"
  done < <(jq -c '.[]?' <<<"$items")

  # source-scope scans
  items="$(evidence_list_component_source_scans "$component")"
  while IFS= read -r it; do
    [[ -n "$it" ]] || continue
    local rel scanner kind pred_type pred_abs basename bundle_out
    rel="$(jq -r '.path' <<<"$it")"
    scanner="$(jq -r '.scanner' <<<"$it")"
    kind="$(jq -r '.kind' <<<"$it")"
    pred_type="$(evidence_predicate_type_for_scan "$scanner" "$kind")"
    pred_abs="$(dist_abspath "$rel")"
    basename="$(basename "$rel")"
    bundle_out="${DIST}/${component}/attestations/scan/source/${basename}.${platform_suffix}.intoto.v1.sigstore.json"
    mkdir -p "$(dirname "$bundle_out")"

    log "==> (local-attest) source scan: ${rel} -> binary ${platform_suffix}"
    attest_file_dsse_v1 "$bin_path" "$pred_abs" "$pred_type" \
      "" "$bundle_out"
  done < <(jq -c '.[]?' <<<"$items")

  # source-scope license
  local src_lic_rel src_lic_abs
  src_lic_rel="$(license_report_out_rel_source "$component")"
  src_lic_abs="$(dist_abspath "$src_lic_rel")"
  if [[ -f "$src_lic_abs" ]]; then
    local basename bundle_out
    basename="$(basename "$src_lic_rel")"
    bundle_out="${DIST}/${component}/attestations/license/source/${basename}.${platform_suffix}.intoto.v1.sigstore.json"
    mkdir -p "$(dirname "$bundle_out")"

    log "==> (local-attest) source license: ${src_lic_rel} -> binary ${platform_suffix}"
    attest_file_dsse_v1 "$bin_path" "$src_lic_abs" \
      "${PRED_LICENSE_REPORT:?PRED_LICENSE_REPORT required}" \
      "" "$bundle_out"
  fi
}

collect_attestations_for_evidence() {
  local att_dir="$1" basefile="$2"
  local atts='[]'

  # oci-fetched envelope
  local oci_rel="${att_dir}/${basefile}.intoto.v1.dsse.json"
  if [[ -f "${DIST}/${oci_rel}" ]]; then
    local obj
    obj="$(file_obj "$oci_rel" | jq -c '. + {type: "oci"}')"
    atts="$(add_to_array "$atts" "$obj")"
  fi

  # local sigstore bundles (attested to specific binary)
  while IFS= read -r abs; do
    local rel fname obj platform_key platform_label
    rel="${abs#"${DIST}/"}"
    fname="$(basename "$rel")"

    # extract platform from filename if present (for artifact-scoped attestations)
    local after="${fname#"${basefile}".}"
    local before_intoto="${after%.intoto.v1.sigstore.json}"

    if [[ "$before_intoto" != "$after" && -n "$before_intoto" && "$before_intoto" != *"."* ]]; then
      # has platform suffix like "linux-amd64"
      platform_key="${before_intoto//-/_}"
      platform_label="${before_intoto//-//}"
      # fix: only first dash becomes slash
      local os="${before_intoto%%-*}"
      local arch="${before_intoto#*-}"
      platform_key="${os}_${arch}"
      platform_label="${os}/${arch}"

      obj="$(file_obj "$rel" | jq -c \
        --arg pk "$platform_key" \
        --arg pl "$platform_label" \
        '. + {type: "local", platform_key: $pk, platform_label: $pl}')"
    else
      obj="$(file_obj "$rel" | jq -c '. + {type: "local"}')"
    fi

    atts="$(add_to_array "$atts" "$obj")"
  done < <(find "${DIST}/${att_dir}" -maxdepth 1 -type f -name "${basefile}*.intoto.v1.sigstore.json" 2>/dev/null | LC_ALL=C sort)





  echo "$atts"
}