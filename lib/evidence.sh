  # ---------- component discovery ----------
  discover_components() {
    if [[ -n "${BUILD_COMPONENTS:-}" ]]; then
      # honor explicit list
      echo "${BUILD_COMPONENTS}" | tr ' ' '\n' | LC_ALL=C sort
      return 0
    fi
    ls cmd/
  }

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
    [[ -f "${DIST}/${rel}" ]] && file_obj "$rel" || jq -n 'null'
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
  OCI_SUBJECTS_BY_KEY="$(
    ctx_get_json '
      (.oci.subjects // [])
      | map({ key: (.component + "|" + .platform.os + "|" + .platform.architecture), value: . })
      | from_entries
    '
  )"

  OCI_INDEX_BY_COMP="$(
    ctx_get_json '
      (.oci.indexes // [])
      | map({ key: .component, value: . })
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
          descriptor_size,
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
    local rel="${abs#${DIST}/}"
    local base="$(basename "$rel")"

    # scanner is the first token before '.'
    local scanner="${base%%.*}"
    local rest="${base#${scanner}.}"

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
    local rel="${abs#${DIST}/}"
    local base="$(basename "$rel")"
    [[ "$base" == ${prefix}* ]] || continue

    local after="${base#${prefix}}"
    local scanner="${after%%.*}"
    local rest="${after#${scanner}.}"

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
      local bin_rel="${bin_abs#${DIST}/}"
      case "$bin_rel" in
        *.sig|*.sha256|*.sigstore.json) continue ;;
      esac

      local os_arch
      os_arch="$(parse_os_arch_from_bin_rel "$bin_rel")"
      [[ -n "$os_arch" ]] || continue
      local os arch
      local os="$(awk '{print $1}' <<<"$os_arch")"
      local arch="$(awk '{print $2}' <<<"$os_arch")"
      local platform="${os}/${arch}"

      local name="${comp}.${os}-${arch}"

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
          local prov_rel="${prov_abs#${DIST}/}"
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

attach_binary_sbom() {
  # args: component platform_key sbom_path sbom_predicate_type
  local component="$1"
  local pkey="$2"
  local sbom_path="$3"
  local predicate_type="$4"   # e.g. "cyclonedx" or a URI you standardize on

  local subject
  subject="$(ctx_get_artifact_field "$component" "$pkey" '.resolved.digest_ref')"
  [[ -n "$subject" ]] || die "missing subject digest_ref for $component/$pkey"

  mapfile -t out < <(cosign_attest_predicate "$subject" "$sbom_path" "$predicate_type")
  local tag_ref="${out[0]}"
  local digest_ref="${out[1]}"
  local mediaType="${out[2]}"
  local size="${out[3]}"
  local pushed_at="${out[4]}"

  local ev
  ev="$(jq -n \
    --arg kind "cosign-attestation" \
    --arg predicate_type "$predicate_type" \
    --arg predicate_path "$sbom_path" \
    --arg subject "$subject" \
    --arg tag_ref "$tag_ref" \
    --arg digest_ref "$digest_ref" \
    --arg mediaType "$mediaType" \
    --arg size "$size" \
    --arg pushed_at "$pushed_at" \
    '{
      kind: $kind,
      predicate_type: $predicate_type,
      predicate_path: $predicate_path,
      subject_digest_ref: $subject,
      oci: {
        tag_ref: $tag_ref,
        digest_ref: $digest_ref,
        mediaType: $mediaType,
        descriptor_size: ($size|tonumber),
        pushed_at: $pushed_at
      }
    }'
  )"

  ctx_artifact_evidence_append "$component" "$pkey" "sbom" "$ev"
}

evidence_init() {
  mkdir -p ${DIST}/sbom/source ${DIST}/scan/source
  
  # Update grype vuln check databases
  log "==> (evidence) updating grype vuln database"
  grype db update

  # Update trivy vuln check databases
  log "==> (evidence) updating trivy vuln database"
  trivy filesystem --download-db-only
}

evidence_generate_repo_source_sbom() {
  # generate syft cdx/spdx repo-wide source sboms
  syft scan dir:. --exclude "./dist" --exclude "./.git" --exclude "./tools" --exclude "./webassets" --source-name "${APP}" --source-version "${RELEASE_VERSION}" --output spdx-json="${DIST}/sbom/source/source.spdx.json" --output cyclonedx-json="${DIST}/sbom/source/source.cdx.json" || exit "Failed to generate sbom!"
}

evidence_attach_repo_source_sbom() {
  # sign/attest syft repo source sbom with cosign (spdx)
  log "==> (attest) adding cosign in-toto attestation for syft repo source sbom (spdx)"
  attest_file_dsse_v1 "./dist/build.json" "dist/sbom/source/source.spdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
  
  # sign/attest syft repo source sbom with cosign (cdx)
  log "==> (attest) adding cosign in-toto attestation for syft repo source sbom (cdx)"
  attest_file_dsse_v1 "./dist/build.json" "dist/sbom/source/source.cdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"

}

evidence_generate_component_source_sbom() {
  # generate cyclonedx-gomod cdx component source sboms
  cyclonedx-gomod app -main "./cmd/${1}/" -output "dist/sbom/${1}/source.app.cdx.json" -json=true -licenses=true

  # build component sbom from source
  log "==> (evidence) generating source sboms for component ${COMPONENT}"
  syft scan dir:. --exclude "./dist" --exclude "./.git" --exclude "./tools" --exclude "./webassets" --source-name "${APP}-${COMPONENT}" --source-version "${RELEASE_VERSION}" --output spdx-json="dist/${COMPONENT}/sbom/source/source.spdx.json" --output cyclonedx-json="dist/${COMPONENT}/sbom/source/source.cdx.json" || exit "Failed to generate sbom!"
}

evidence_attach_component_source_sbom() {
  # sign/attest cyclonedx-gomod component source sbom with cosign (cdx)
  log "==> (evidence) adding cosign in-toto attestation for cyclonedx-gomod component source sbom (cdx)"
  attest_file_dsse_v1 "dist/sbom/${1}/source.app.cdx.json" "dist/sbom/${1}/source.app.cdx.json" "https://phxi.net/attestations/cyclonedx-gomod/source/v1"

  # sign/attest syft component source sbom with cosign (spdx)
  log "==> (evidence) adding cosign in-toto attestation for syft component source sbom (spdx)"
  attest_file_dsse_v1 "./dist/${COMPONENT}/build.json" "dist/${COMPONENT}/sbom/source/source.spdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"

  # sign/attest syft component source sbom with cosign (cdx)
  log "==> (evidence) adding cosign in-toto attestation for syft component source sbom (cdx)"
  attest_file_dsse_v1 "./dist/${COMPONENT}/build.json" "dist/${COMPONENT}/sbom/source/source.cdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
}

evidence_generate_component_binary_sbom() {
  # generate syft cdx/spdx component binary sboms
  #syft scan file:"${DIST}/${1}/bin/${2}/${3}/${1}" --source-name "${1}" --source-version "${RELEASE_VERSION}" --output spdx-json="dist/${1}/sbom/artifacts/${1}.${2}-${3}.spdx.json" --output cyclonedx-json="dist/${1}/sbom/artifacts/${1}.${2}-${3}.cdx.json" || exit "Failed to generate sbom!"
  # generate sboms from binary
  log "==> (evidence) generating sboms for binary"
  syft scan file:"${fname}" --output spdx-json="dist/${COMPONENT}/sbom/artifacts/${COMPONENT}.${OS}-${ARCH}.spdx.json" --output cyclonedx-json="dist/${COMPONENT}/sbom/artifacts/${COMPONENT}.${OS}-${ARCH}.cdx.json"
}

evidence_attach_component_binary_sbom() {
  # sign/attest syft sbom with cosign (spdx)
  log "==> (evidence) adding cosign in-toto attestation for syft binary sbom (spdx)"
  attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/sbom/artifacts/${COMPONENT}.${OS}-${ARCH}.spdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
  # sign/attest syft sbom with cosign (cdx)
  log "==> (evidence) adding cosign in-toto attestation for syft binary sbom (cdx)"
  attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/sbom/artifacts/${COMPONENT}.${OS}-${ARCH}.cdx.json" "https://cosign.sigstore.dev/attestation/sbom/v1"
}

evidence_generate_component_binary_scan_reports() {
  # scan binary with trivy for vulns (generate json report)
  log "==> (evidence) scanning binary with trivy for vulns (generate json)"
  trivy rootfs --scanners vuln --format json -o "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.trivy.vuln.json" "${fname}"
  # convert trivy vuln report (generate sarif report)
  log "==> (evidence) convert trivy json vuln report (generate sarif)"
  trivy convert --format sarif -o "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.trivy.vuln.sarif.json" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.trivy.vuln.json"

  # scan binary with grype for vulns (generate json report)
  log "==> (evidence) scanning binary with grype for vulns (generate json)"
  grype "./${fname}" --name "${APP}-${COMPONENT}" -o json --file "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.grype.vuln.json"
  # scan binary with grype for vulns (generate sarif report)
  log "==> (evidence) scanning binary with grype for vulns (generate sarif)"
  grype "./${fname}" --name "${APP}-${COMPONENT}" -o sarif --file "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.grype.vuln.sarif.json"

  # scan binary with govulncheck for vulns (generate json report)
  log "==> (evidence) scanning binary with govulncheck for vulns (generate json)"
  govulncheck -mode=binary -json "./${fname}" > dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.govulncheck.vuln.json
  # scan binary with govulncheck for vulns (generate sarif report)
  log "==> (evidence) scanning binary with govulncheck for vulns (generate sarif)"
  govulncheck -mode=binary -format sarif "./${fname}" > dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.govulncheck.vuln.sarif.json
}

evidence_attach_component_binary_scan_reports() {
  # sign/attest trivy report with cosign (json)
  log "==> (evidence) adding cosign in-toto attestation for trivy vuln report (json)"
  attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.trivy.vuln.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

  # sign/attest trivy report with cosign (sarif)
  log "==> (evidence) adding cosign in-toto attestation for trivy vuln report (sarif)"
  attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.trivy.vuln.sarif.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

  # sign/attest grype report with cosign (json)
  log "==> (evidence) adding cosign in-toto attestation for grype vuln report (json)"
  attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.grype.vuln.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

  # sign/attest grype report with cosign (sarif)
  log "==> (evidence) adding cosign in-toto attestation for grype vuln report (sarif)"
  attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.grype.vuln.sarif.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

  # sign/attest govulncheck report with cosign (json)
  log "==> (evidence) adding cosign in-toto attestation for govulncheck binary vuln report (json)"
  attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.govulncheck.vuln.json" "https://cosign.sigstore.dev/attestation/vuln/v1"

  # sign/attest govulncheck report with cosign (sarif)
  log "==> (evidence) adding cosign in-toto attestation for govulncheck binary vuln report (sarif)"
  attest_file_dsse_v1 "$fname" "dist/${COMPONENT}/scan/artifacts/${COMPONENT}.${OS}-${ARCH}.govulncheck.vuln.sarif.json" "https://cosign.sigstore.dev/attestation/vuln/v1"
}

evidence_generate_repo_source_scan_reports() {
  # generate govulncheck repo source report (json)
  log "==> (evidence) generating govulncheck repo-wide source report (json)"
  govulncheck -json ./... > "${DIST}/scan/source/govulncheck.vuln.json"
  # generate govulncheck repo source report (sarif)
  log "==> (evidence) generating govulncheck report (sarif)"
  govulncheck -format sarif ./... > "${DIST}/scan/source/govulncheck.vuln.sarif.json"

  # generate grype repo source report (json)
  log "==> (evidence) generating grype repo source report (json)"
  grype "${DIST}/sbom/source/source.cdx.json" --name "${APP}" -o json --file "${DIST}/scan/source/grype.vuln.json"
  # generate grype repo source report (sarif)
  log "==> (evidence) generating grype repo source report (sarif)"
  grype "${DIST}/sbom/source/source.cdx.json" --name "${APP}" -o sarif --file "${DIST}/scan/source/grype.vuln.sarif.json"
}

evidence_attach_repo_source_scan_reports() {
  # sign/attest govulncheck source report with cosign (json)
  log "==> (evidence) adding cosign in-toto attestation for govulncheck repo source vuln report (json)"
  attest_file_dsse_v1 "dist/sbom/source/source.cdx.json" "${DIST}/scan/source/govulncheck.vuln.json" "https://phxi.net/attestations/govulncheck/source/v1"
  # sign/attest govulncheck source report with cosign (sarif)
  log "==> (evidence) adding cosign in-toto attestation for govulncheck repo source vuln report (sarif)"
  attest_file_dsse_v1 "dist/sbom/source/source.cdx.json" "${DIST}/scan/source/govulncheck.vuln.sarif.json" "https://phxi.net/attestations/govulncheck/source/v1"


  # sign/attest grype repo source report with cosign (json)
  log "==> (evidence) adding cosign in-toto attestation for grype repo source vuln report (json)"
  attest_file_dsse_v1 "dist/sbom/source/source.cdx.json" "${DIST}/scan/source/grype.vuln.json" "https://phxi.net/attestations/grype/source/v1"
  # sign/attest grype repo source report with cosign (sarif)
  log "==> (evidence) adding cosign in-toto attestation for grype repo source vuln report (sarif)"
  attest_file_dsse_v1 "dist/sbom/source/source.cdx.json" "${DIST}/scan/source/grype.vuln.sarif.json" "https://phxi.net/attestations/grype/source/v1"
}

evidence_generate_component_source_scan_reports() {
  # generate component source govulnscan report (json)
  log "==> (evidence) generating govulncheck component source report (json)"
  govulncheck -json "./cmd/${COMPONENT}/..." > "dist/${COMPONENT}/scan/source/govulncheck.vuln.json"

  # generate component source grype report (json)
  log "==> (evidence) generating grype component source report (json)"
  grype "./dist/${COMPONENT}/sbom/source/source.cdx.json" --name "${APP}-${COMPONENT}" -o json --file "./dist/${COMPONENT}/scan/source/grype.vuln.json"
}

evidence_attach_component_source_scan_reports() {
  # sign/attest govulncheck source report with cosign (json)
  log "==> (evidence) adding cosign in-toto attestation for govulncheck component source vuln report (json)"
  attest_file_dsse_v1 "dist/${COMPONENT}/sbom/source/source.cdx.json" "dist/${COMPONENT}/scan/source/govulncheck.vuln.json" "https://phxi.net/attestations/govulncheck/source/v1"
  # generate component source govulnscan report (sarif)
  log "==> (evidence) generating govulncheck component source report (sarif)"
  govulncheck -format sarif "./cmd/${COMPONENT}/..." > "dist/${COMPONENT}/scan/source/govulncheck.vuln.sarif.json"
  # sign/attest govulncheck source report with cosign (sarif)
  log "==> (evidence) adding cosign in-toto attestation for govulncheck component source vuln report (sarif)"
  attest_file_dsse_v1 "dist/${COMPONENT}/sbom/source/source.cdx.json" "dist/${COMPONENT}/scan/source/govulncheck.vuln.sarif.json" "https://phxi.net/attestations/govulncheck/source/v1"

  # sign/attest grype source report with cosign (json)
  log "==> (evidence) adding cosign in-toto attestation for grype component source vuln report (json)"
  attest_file_dsse_v1 "dist/${COMPONENT}/sbom/source/source.cdx.json" "./dist/${COMPONENT}/scan/source/grype.vuln.json" "https://phxi.net/attestations/grype/source/v1"
  # generate component source grype report (sarif)
  log "==> (evidence) generating grype component source report (sarif)"
  grype "./dist/${COMPONENT}/sbom/source/source.cdx.json" --name "${APP}-${COMPONENT}" -o sarif --file "./dist/${COMPONENT}/scan/source/grype.vuln.sarif.json"
  # sign/attest grype source report with cosign (sarif)
  log "==> (evidence) adding cosign in-toto attestation for grype component source vuln report (sarif)"
  attest_file_dsse_v1 "dist/${COMPONENT}/sbom/source/source.cdx.json" "./dist/${COMPONENT}/scan/source/grype.vuln.sarif.json" "https://phxi.net/attestations/grype/source/v1"
}

# cosign_attest_predicate - args: subject_digest_ref predicate_path predicate_type
