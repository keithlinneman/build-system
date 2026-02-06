# shellcheck shell=bash

# canonical severity ordering (lower = worse) - used by jq expressions for worst-case normalization
SUMMARY_SEV_RANK_JQ='
  def sev_rank:
    if   . == "critical"   then 0
    elif . == "high"       then 1
    elif . == "medium"     then 2
    elif . == "low"        then 3
    elif . == "negligible" then 4
    elif . == "unknown"    then 5
    else 6 end;

  def sev_from_rank:
    if   . == 0 then "critical"
    elif . == 1 then "high"
    elif . == 2 then "medium"
    elif . == 3 then "low"
    elif . == 4 then "negligible"
    elif . == 5 then "unknown"
    else "unknown" end;
'

# output lines of {"id":"CVE-...", "severity":"high"} for each vuln from each scanner with normalizations applied
# trivy json: .Results[].Vulnerabilities[]
summary_extract_trivy_vulns() {
  local report="$1"
  [[ -f "$report" ]] || { return 0; }
  jq -c "${SUMMARY_SEV_RANK_JQ}"'
    [.Results[]?.Vulnerabilities[]?
     | {id: .VulnerabilityID, severity: (.Severity | ascii_downcase)}
     | select(.id != null and (.id|length) > 0)
    ]
    | group_by(.id)
    | map(min_by(.severity | sev_rank))
    | .[]
  ' "$report" 2>/dev/null || true
}

# grype json: .matches[].vulnerability
summary_extract_grype_vulns() {
  local report="$1"
  [[ -f "$report" ]] || { return 0; }
  jq -c "${SUMMARY_SEV_RANK_JQ}"'
    [.matches[]?
     | {id: .vulnerability.id, severity: (.vulnerability.severity | ascii_downcase)}
     | select(.id != null and (.id|length) > 0)
    ]
    | group_by(.id)
    | map(min_by(.severity | sev_rank))
    | .[]
  ' "$report" 2>/dev/null || true
}

# govulncheck - count unique .finding.osv entries
# returns JSON object since govulncheck doesnt use severity levels
summary_extract_govulncheck() {
  local report="$1"
  [[ -f "$report" ]] || { echo '{"findings":0,"vuln_ids":[]}'; return 0; }

  # govulncheck -json emits NDJSON (one object per line)
  jq -s '
    [.[] | select(.finding?) | .finding.osv]
    | unique
    | { findings: length, vuln_ids: . }
  ' "$report" 2>/dev/null || echo '{"findings":0,"vuln_ids":[]}'
}

# per-scanner severity counts with deduplication within each

summary_count_severities() {
  local input="$1"
  [[ -s "$input" ]] || { echo '{"critical":0,"high":0,"medium":0,"low":0,"negligible":0,"unknown":0}'; return 0; }

  jq -s '
    group_by(.severity)
    | map({key: .[0].severity, value: length})
    | from_entries
    | {
        critical:   (.critical // 0),
        high:       (.high // 0),
        medium:     (.medium // 0),
        low:        (.low // 0),
        negligible: (.negligible // 0),
        unknown:    (.unknown // 0)
      }
  ' "$input"
}

# deduplications across scanners for same cve - keep worst severity, count severity totals after deduplication
summary_merge_and_count() {
  local input="$1"
  [[ -s "$input" ]] || { echo '{"critical":0,"high":0,"medium":0,"low":0,"negligible":0,"unknown":0,"total":0}'; return 0; }

  jq -s "${SUMMARY_SEV_RANK_JQ}"'
    group_by(.id)
    | map(min_by(.severity | sev_rank))
    | group_by(.severity)
    | map({key: .[0].severity, value: length})
    | from_entries
    | . + {
        critical:   (.critical // 0),
        high:       (.high // 0),
        medium:     (.medium // 0),
        low:        (.low // 0),
        negligible: (.negligible // 0),
        unknown:    (.unknown // 0)
      }
    | . + { total: (.critical + .high + .medium + .low + .negligible + .unknown) }
  ' "$input"
}

# determine worst severity present in merged counts
summary_worst_severity() {
  local counts_json="$1"
  jq -r '
    if .critical > 0 then "critical"
    elif .high > 0 then "high"
    elif .medium > 0 then "medium"
    elif .low > 0 then "low"
    elif .negligible > 0 then "negligible"
    elif .unknown > 0 then "unknown"
    else "none"
    end
  ' <<<"$counts_json"
}

# generate scan reports

# collect all scan reports for a component (source + artifacts), extract per-scanner results
summary_collect_component_vulns() {
  local component="$1"
  local tmpdir
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/summary.XXXXXX")"

  local trivy_vulns="${tmpdir}/trivy.ndjson"
  local grype_vulns="${tmpdir}/grype.ndjson"
  local all_vulns="${tmpdir}/all.ndjson"

  # i cant go back to 'touch' or 'truncate' after llms introduced me to smiley face truncation
  :> "$trivy_vulns"
  :> "$grype_vulns"
  :> "$all_vulns"

  # source-level scans (grype + govulncheck only, no trivy on source)
  local src_scan_dir="${DIST}/${component}/scan/source"

  if [[ -d "$src_scan_dir" ]]; then
    if [[ -f "${src_scan_dir}/grype.vuln.json" ]]; then
      summary_extract_grype_vulns "${src_scan_dir}/grype.vuln.json" >> "$grype_vulns"
    fi
  fi

  # artifact-level scans (all three scanners, per platform)
  local art_scan_dir="${DIST}/${component}/scan/artifacts"
  if [[ -d "$art_scan_dir" ]]; then
    while IFS= read -r f; do
      local base
      base="$(basename "$f")"
      case "$base" in
        *.trivy.vuln.json)
          summary_extract_trivy_vulns "$f" >> "$trivy_vulns"
          ;;
        *.grype.vuln.json)
          summary_extract_grype_vulns "$f" >> "$grype_vulns"
          ;;
      esac
    done < <(find "$art_scan_dir" -maxdepth 1 -type f -name '*.vuln.json' ! -name '*.sarif.*' | LC_ALL=C sort)
  fi

  # combine trivy + grype for cross-scanner dedup
  cat "$trivy_vulns" "$grype_vulns" > "$all_vulns"

  # per-scanner counts (within-scanner deduped)
  local trivy_counts grype_counts
  trivy_counts="$(summary_count_severities "$trivy_vulns")"
  grype_counts="$(summary_count_severities "$grype_vulns")"

  # govulncheck (source + artifact, merged)
  local govulncheck_combined="${tmpdir}/govulncheck.ndjson"
  : > "$govulncheck_combined"

  # source govulncheck
  if [[ -f "${src_scan_dir}/govulncheck.vuln.json" ]]; then
    summary_extract_govulncheck "${src_scan_dir}/govulncheck.vuln.json" > "${tmpdir}/govulncheck_src.json"
  else
    echo '{"findings":0,"vuln_ids":[]}' > "${tmpdir}/govulncheck_src.json"
  fi

  # artifact govulncheck (merge across platforms)
  local govulncheck_art_ids='[]'
  if [[ -d "$art_scan_dir" ]]; then
    while IFS= read -r f; do
      local this_ids
      this_ids="$(summary_extract_govulncheck "$f" | jq -c '.vuln_ids')"
      govulncheck_art_ids="$(jq -s '.[0] + .[1] | unique' <<<"$govulncheck_art_ids"$'\n'"$this_ids")"
    done < <(find "$art_scan_dir" -maxdepth 1 -type f -name '*.govulncheck.vuln.json' | LC_ALL=C sort)
  fi

  # merge govulncheck source + artifact IDs
  local govulncheck_src_ids govulncheck_all_ids govulncheck_summary
  govulncheck_src_ids="$(jq -c '.vuln_ids' "${tmpdir}/govulncheck_src.json")"
  govulncheck_all_ids="$(jq -s '.[0] + .[1] | unique' <<<"$govulncheck_src_ids"$'\n'"$govulncheck_art_ids")"
  govulncheck_summary="$(jq -n --argjson ids "$govulncheck_all_ids" '{findings: ($ids|length), vuln_ids: $ids}')"
  
  # cross-scanner dedup (trivy + grype only, govulncheck doesnt use CVE IDs)
  local merged_counts worst_sev
  merged_counts="$(summary_merge_and_count "$all_vulns")"
  worst_sev="$(summary_worst_severity "$merged_counts")"

  # gate evaluation
  local gate_threshold gate_result
  gate_threshold="high"
  gate_result="pass"

  local crit high
  crit="$(jq -r '.critical' <<<"$merged_counts")"
  high="$(jq -r '.high' <<<"$merged_counts")"
  govulncheck_findings="$(jq -r '.findings' <<<"$govulncheck_summary")"

  if (( crit > 0 || high > 0 || govulncheck_findings > 0 )); then
    gate_result="fail"
  fi

  # build scanners_used array
  local scanners_used='[]'
  if [[ -s "$trivy_vulns" ]] || [[ -n "$(find "${art_scan_dir}" -maxdepth 1 -name "${component}.*.trivy.vuln.json" -print -quit 2>/dev/null)" ]]; then
    scanners_used="$( jq '. + ["trivy"]' <<<"$scanners_used" )"
  fi

  [[ -s "$grype_vulns" ]] && scanners_used="$(jq '. + ["grype"]' <<<"$scanners_used")"
  [[ "$(jq -r '.findings' <<<"$govulncheck_summary")" != "0" || -f "${src_scan_dir}/govulncheck.vuln.json" ]] && scanners_used="$(jq '. + ["govulncheck"]' <<<"$scanners_used")"

  # determine scan timestamp from newest scan report mtime
  local scanned_at
  scanned_at="$(find "${DIST}/${component}/scan" -type f -name '*.vuln.json' -printf '%T@\n' 2>/dev/null \
    | sort -rn | head -1 | xargs -I{} date -d @{} -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

  # assemble vulnerability summary
  _VULN_SUMMARY="$(jq -n \
    --argjson scanners_used "$scanners_used" \
    --arg scanned_at "$scanned_at" \
    --arg scope "source+artifacts" \
    --argjson counts "$merged_counts" \
    --argjson by_trivy "$trivy_counts" \
    --argjson by_grype "$grype_counts" \
    --argjson govulncheck "$govulncheck_summary" \
    --arg worst_severity "$worst_sev" \
    --arg gate_threshold "$gate_threshold" \
    --arg gate_result "$gate_result" \
    --arg dedup_method "vuln_id_worst_severity" \
    '{
      scanners_used: $scanners_used,
      scanned_at: $scanned_at,
      scope: $scope,
      deduplication: $dedup_method,
      counts: ($counts | del(.total)),
      total: $counts.total,
      by_scanner: {
        trivy: $by_trivy,
        grype: $by_grype,
        govulncheck: $govulncheck
      },
      worst_severity: $worst_severity,
      gate_threshold: $gate_threshold,
      gate_result: $gate_result
    }'
  )"

  rm -rf "$tmpdir"
}

# sbom summary
summary_collect_sbom_info() {
  local component="$1"

  local generators='[]'
  local formats='[]'
  local source_pkg_count=0
  local artifact_pkg_count=0

  # check which generators produced sboms
  local sbom_src_dir="${DIST}/${component}/sbom/source"
  local sbom_art_dir="${DIST}/${component}/sbom/artifacts"

  if [[ -d "$sbom_src_dir" ]]; then
    [[ -n "$(find "$sbom_src_dir" -name '*.gomod.*' -print -quit 2>/dev/null)" ]] && \
      generators="$(jq '. + ["cyclonedx-gomod"] | unique' <<<"$generators")"
    [[ -n "$(find "$sbom_src_dir" -name '*.syft.*' -print -quit 2>/dev/null)" ]] && \
      generators="$(jq '. + ["syft"] | unique' <<<"$generators")"

    [[ -n "$(find "$sbom_src_dir" -name '*.spdx.json' -print -quit 2>/dev/null)" ]] && \
      formats="$(jq '. + ["spdx-json"] | unique' <<<"$formats")"
    [[ -n "$(find "$sbom_src_dir" -name '*.cdx.json' -print -quit 2>/dev/null)" ]] && \
      formats="$(jq '. + ["cyclonedx-json"] | unique' <<<"$formats")"
  fi

  if [[ -d "$sbom_art_dir" ]]; then
    [[ -n "$(find "$sbom_art_dir" -name '*.gomod.*' -print -quit 2>/dev/null)" ]] && \
      generators="$(jq '. + ["cyclonedx-gomod"] | unique' <<<"$generators")"
    [[ -n "$(find "$sbom_art_dir" -name '*.syft.*' -print -quit 2>/dev/null)" ]] && \
      generators="$(jq '. + ["syft"] | unique' <<<"$generators")"
  fi

  # get package counts from license reports
  local src_lic="${DIST}/${component}/license/source/source.licenses.json"
  if [[ -f "$src_lic" ]]; then
    source_pkg_count="$(jq -r '.summary.items_total // 0' "$src_lic")"
  fi

  # artifact package count: take max across platforms (should be similar)
  local art_lic_dir="${DIST}/${component}/license/artifacts"
  if [[ -d "$art_lic_dir" ]]; then
    artifact_pkg_count="$(find "$art_lic_dir" -name '*.licenses.json' -exec jq -r '.summary.items_total // 0' {} \; 2>/dev/null \
      | sort -rn | head -1 || echo 0)"
  fi

  local generated_at
  generated_at="$(find "${DIST}/${component}/sbom" -type f -name '*.json' -printf '%T@\n' 2>/dev/null \
    | sort -rn | head -1 | xargs -I{} date -d @{} -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

  _SBOM_SUMMARY="$(jq -n \
    --argjson generators "$generators" \
    --argjson formats "$formats" \
    --argjson source_package_count "$source_pkg_count" \
    --argjson artifact_package_count "${artifact_pkg_count:-0}" \
    --arg generated_at "$generated_at" \
    '{
      generators: $generators,
      formats_produced: $formats,
      source_package_count: $source_package_count,
      artifact_package_count: $artifact_package_count,
      generated_at: $generated_at
    }'
  )"
}

# license summary
summary_collect_license_info() {
  local component="$1"

  local compliant=true
  local unique_licenses='[]'
  local denied_found='[]'
  local without_license_count=0

  # read from source license report
  local src_lic="${DIST}/${component}/license/source/source.licenses.json"
  if [[ -f "$src_lic" ]]; then
    unique_licenses="$(jq -c '[.summary.by_license[]?.license] | unique | sort' "$src_lic" 2>/dev/null || echo '[]')"
    without_license_count="$(jq -r '.summary.without_licenses // 0' "$src_lic")"

    # check against deny list from policy
    # shellcheck disable=SC2016
    denied_found="$(jq -c '
      ["GPL-2.0-only","GPL-2.0-or-later","GPL-3.0-only","GPL-3.0-or-later",
       "AGPL-3.0-only","AGPL-3.0-or-later","LGPL-2.1-only","LGPL-2.1-or-later",
       "LGPL-3.0-only","LGPL-3.0-or-later","SSPL-1.0","BUSL-1.1"] as $deny |
      [.items[]?.licenses[]? | select(. as $l | $deny | any(. == $l))]
      | unique
    ' "$src_lic" 2>/dev/null || echo '[]')"

    local denied_count
    denied_count="$(jq 'length' <<<"$denied_found")"
    if (( denied_count > 0 )); then
      compliant=false
    fi
  fi

  _LICENSE_SUMMARY="$(jq -n \
    --argjson compliant "$compliant" \
    --argjson unique_licenses "$unique_licenses" \
    --argjson denied_found "$denied_found" \
    --argjson without_license_count "$without_license_count" \
    '{
      compliant: $compliant,
      unique_licenses: $unique_licenses,
      denied_found: $denied_found,
      without_license_count: $without_license_count
    }'
  )"
}

# signing summary
summary_collect_signing_info() {
  local component="$1"

  local method="aws-kms"
  local key_ref="${SIGNER_URI:-unknown}"
  local artifacts_attested=false
  local index_attested=false
  local inventory_signed=false
  local release_signed=false

  # check if artifact attestations exist
  local att_dir="${DIST}/${component}/attestations"
  if [[ -d "${att_dir}/sbom/artifacts" ]] && [[ -n "$(find "${att_dir}/sbom/artifacts" -name '*.dsse.json' -print -quit 2>/dev/null)" ]]; then
    artifacts_attested=true
  fi

  # check if index attestations exist
  if [[ -d "${att_dir}/sbom/source" ]] && [[ -n "$(find "${att_dir}/sbom/source" -name '*.dsse.json' -print -quit 2>/dev/null)" ]]; then
    index_attested=true
  fi

  # check for inventory attestation
  if [[ -f "${DIST}/${component}/inventory.json.intoto.v1.dsse.json" ]]; then
    inventory_signed=true
  fi

  # check for release.json signature
  if [[ -f "${DIST}/${component}/release.json.sig" ]]; then
    release_signed=true
  fi

  _SIGNING_SUMMARY="$(jq -n \
    --arg method "$method" \
    --arg key_ref "$key_ref" \
    --argjson artifacts_attested "$artifacts_attested" \
    --argjson index_attested "$index_attested" \
    --argjson inventory_signed "$inventory_signed" \
    --argjson release_signed "$release_signed" \
    '{
      method: $method,
      key_ref: $key_ref,
      artifacts_attested: $artifacts_attested,
      index_attested: $index_attested,
      inventory_signed: $inventory_signed,
      release_signed: $release_signed
    }'
  )"
}

# evidence completeness summary - which types of evidence are present for the component
summary_collect_evidence_completeness() {
  local component="$1"
  local d="${DIST}/${component}"

  local sbom_source=false sbom_artifacts=false
  local scan_source=false scan_artifacts=false
  local license_source=false license_artifacts=false
  local attestations_attached=false

  [[ -n "$(find "${d}/sbom/source" -name '*.json' -print -quit 2>/dev/null)" ]] && sbom_source=true
  [[ -n "$(find "${d}/sbom/artifacts" -name '*.json' -print -quit 2>/dev/null)" ]] && sbom_artifacts=true
  [[ -n "$(find "${d}/scan/source" -name '*.json' -print -quit 2>/dev/null)" ]] && scan_source=true
  [[ -n "$(find "${d}/scan/artifacts" -name '*.json' -print -quit 2>/dev/null)" ]] && scan_artifacts=true
  [[ -n "$(find "${d}/license/source" -name '*.json' -print -quit 2>/dev/null)" ]] && license_source=true
  [[ -n "$(find "${d}/license/artifacts" -name '*.json' -print -quit 2>/dev/null)" ]] && license_artifacts=true
  [[ -n "$(find "${d}/attestations" -name '*.dsse.json' -print -quit 2>/dev/null)" ]] && attestations_attached=true

  _EVIDENCE_COMPLETENESS="$(jq -n \
    --argjson sbom_source "$sbom_source" \
    --argjson sbom_artifacts "$sbom_artifacts" \
    --argjson scan_source "$scan_source" \
    --argjson scan_artifacts "$scan_artifacts" \
    --argjson license_source "$license_source" \
    --argjson license_artifacts "$license_artifacts" \
    --argjson attestations_attached "$attestations_attached" \
    '{
      sbom_source: $sbom_source,
      sbom_artifacts: $sbom_artifacts,
      scan_source: $scan_source,
      scan_artifacts: $scan_artifacts,
      license_source: $license_source,
      license_artifacts: $license_artifacts,
      attestations_attached: $attestations_attached
    }'
  )"
}

# main summary generator - collects all the above info and assembles into a single summary json blob per-component

generate_component_release_summary() {
  local component="${1:?component required}"

  log "==> (summary) collecting vulnerability data for component=${component}"
  summary_collect_component_vulns "$component"

  log "==> (summary) collecting SBOM info for component=${component}"
  summary_collect_sbom_info "$component"

  log "==> (summary) collecting license info for component=${component}"
  summary_collect_license_info "$component"

  log "==> (summary) collecting signing info for component=${component}"
  summary_collect_signing_info "$component"

  log "==> (summary) collecting evidence completeness for component=${component}"
  summary_collect_evidence_completeness "$component"

  local generated_at
  generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # assemble final summary for release.json inclusion
  jq -n \
    --arg schema "phxi.release.summary.v1" \
    --arg generated_at "$generated_at" \
    --argjson vulnerabilities "$_VULN_SUMMARY" \
    --argjson sbom "$_SBOM_SUMMARY" \
    --argjson licenses "$_LICENSE_SUMMARY" \
    --argjson signing "$_SIGNING_SUMMARY" \
    --argjson evidence "$_EVIDENCE_COMPLETENESS" \
    '{
      schema: $schema,
      generated_at: $generated_at,
      vulnerabilities: $vulnerabilities,
      sbom: $sbom,
      licenses: $licenses,
      signing: $signing,
      evidence_completeness: $evidence
    }'
}