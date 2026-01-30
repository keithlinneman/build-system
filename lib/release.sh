# shellcheck shell=bash

# generate_release_json() {
#   local schema now inventory_json
#   schema="phxi.release.v1"
#   now="$( date --utc +%Y-%m-%dT%H:%M:%SZ )"
#   inventory_json="$( file_obj "${DIST}/inventory.json" )"
#   distribution_json="$( jq -n \
#     --arg provider "s3" \
#     --arg bucket "${DEPLOYMENT_BUCKET:-}" \
#     --arg bucket_prefix "/apps/${APP}/releases/${RELEASE_VERSION}/${BUILD_ID}/" \
#     '{
#       provider: $provider,
#       bucket: $bucket,
#       prefix: $bucket_prefix
#     }'
#   )"

#   jq -n \
#     --arg schema "$schema" \
#     --arg created_at "$now" \
#     --arg app "$APP" \
#     --arg release_id "$RELEASE_ID" \
#     --argjson inventory_json "$inventory_json" \
#     --argjson distribution "$distribution_json" \
#     '{
#       schema: $schema,
#       app: $app,
#       created_at: $created_at,
#       release_id: $release_id,
#       oci: {},
#       inventory: $inventory_json,
#       distribution: $distribution_json

#     }' \
#   > "${DIST}/release.json"

# }

# shellcheck shell=bash
# lib/release.sh

release_distribution_json() {
  local app="${1:?app required}"
  local version="${2:?version required}"
  local build_id="${3:?build_id required}"

  local bucket="${DEPLOYMENT_BUCKET:-}"
  local prefix="${DEPLOYMENT_BUCKET_PREFIX:-apps/${app}/releases/${release_id}/}"

  prefix="${prefix#/}"
  [[ "$prefix" == */ ]] || prefix="${prefix}/"

  jq -n \
    --arg provider "s3" \
    --arg bucket "$bucket" \
    --arg prefix "$prefix" \
    --arg region "${AWS_REGION:-}" \
    --arg uri "s3://${bucket}/${prefix}" \
    '{
      provider: $provider,
      bucket: (if ($bucket|length)>0 then $bucket else null end),
      region: (if ($region|length)>0 then $region else null end),
      uri: $uri,
      prefix: $prefix,
      objects: {
        release: "release.json",
        inventory: "inventory.json"
      }
    } | with_entries(select(.value != null))'
}

release_component_from_inventory() {
  local inv_abs="${1:?inventory.json abs path required}"

  jq '{
    oci: {
      repository: .oci_index.repository,
      tag: .oci_index.tag,
      tag_ref: .oci_index.tag_ref,
      digest: .oci_index.digest,
      digest_ref: .oci_index.digest_ref,
      mediaType: .oci_index.mediaType,
      artifactType: .oci_index.artifactType,
      size: .oci_index.size,
      pushed_at: .oci_index.pushed_at
    },
    artifacts: [.targets[] | {
      os: .os,
      arch: .arch,
      binary: {
        path: .subject.path,
        sha256: .subject.hashes.sha256,
        size: .subject.size
      }
    }]
  }' "$inv_abs"
}

release_min_source_json() {
  local ctx_abs="${1:?buildctx abs required}"
  jq -c '.source | {repo, resolved_branch, ref, detached, commit, commit_short, commit_date, base_tag, commits_since_tag, dirty}' "$ctx_abs"
}

release_min_builder_json() {
  local ctx_abs="${1:?buildctx abs required}"
  jq -c '.builder | {repo, branch, commit, commit_short, commit_date, dirty}' "$ctx_abs"
}

generate_component_release_json() {
  local component="${1:?component name required}"
  local OUT="${DIST}/${component}/release.json"
  [[ -n "${DIST:-}" ]] || die "generate_release_json: DIST not set"
  [[ -n "${BUILDCTX_PATH:-}" && -f "${BUILDCTX_PATH}" ]] || die "generate_release_json: BUILDCTX_PATH missing/not a file"

  local inv_abs inv_rel
  inv_abs="${DIST}/${component}/inventory.json"
  inv_rel="$( dist_relpath "${inv_abs}" )"
  [[ -f "${inv_abs}" ]] || die "generate_release_json: missing ${inv_abs}"

  local schema="phxi.release.v1"
  local app version build_id release_id created_at created_epoch track

  app="$( ctx_get '.app' )"
  track="$( ctx_get '.release.track' )"
  version="$( ctx_get '.release.version' )"
  build_id="$( ctx_get '.release.build_id' )"
  release_id="$( ctx_get '.release.release_id' )"
  created_at="$( date --utc +%Y-%m-%dT%H:%M:%SZ )"
  created_epoch="$( date +%s )"

  local inv_obj dist_obj release_data source builder release_policy
  inv_obj="$( file_obj "$inv_rel")"
  # ctx_obj="$(release_file_obj "$BUILDCTX_PATH")"
  dist_obj="$( release_distribution_json "$app" "$version" "$build_id" )"
  release_data="$( release_component_from_inventory "$inv_abs" )"
  source="$( release_min_source_json "$BUILDCTX_PATH" )"
  builder="$( release_min_builder_json "$BUILDCTX_PATH" )"
  release_policy="$( generate_release_policy )"
  jq -n \
    --arg schema "$schema" \
    --arg app "$app" \
    --arg version "$version" \
    --arg build_id "$build_id" \
    --arg release_id "$release_id" \
    --arg created_at "$created_at" \
    --argjson created_epoch "$created_epoch" \
    --arg track "$track" \
    --argjson inventory "$inv_obj" \
    --argjson distribution "$dist_obj" \
    --argjson component "$component" \
    --argjson release_data "$release_data" \
    --argjson source "$source" \
    --argjson builder "$builder" \
    --argjson release_policy "$release_policy" \
    '{
      schema: $schema,
      app: $app,
      version: $version,
      build_id: $build_id,
      release_id: $release_id,
      track: (if ($track|length)>0 then $track else null end),
      created_at: $created_at,
      epoch: $created_epoch,
      source: $source,
      builder: $builder,
      components: $components,
      policy: $release_policy,
      files: { inventory: $inventory },
      distribution: $distribution
    } + $release_data | with_entries(select(.value != null))' \
    > "${OUT}"

  log "==> (release) wrote ${OUT}"
}

# attest_release_json_to_indexes() {
#   set -euo pipefail
#   [[ -n "${DIST:-}" ]] || die "attest_release_json_to_indexes: DIST not set"
#   [[ -f "${DIST}/inventory.json" ]] || die "attest_release_json_to_indexes: missing ${DIST}/inventory.json"
#   [[ -f "${DIST}/release.json" ]] || die "attest_release_json_to_indexes: missing ${DIST}/release.json"

#   local inv_abs="${DIST}/inventory.json"
#   local pred_abs="${DIST}/release.json"

#   local pred_type="${PRED_RELEASE_DESCRIPTOR:-https://phxi.net/attestations/release/v1}"
#   # local out_dir="${DIST}/_repo/attestations/release/index"
#   local out_dir="${DIST}"
#   mkdir -p "$out_dir"

#   jq -r '.components | keys[]' "$inv_abs" | while IFS= read -r component; do
#     local subject
#     subject="$(jq -r --arg c "$component" '.components[$c].oci_index.digest_ref // empty' "$inv_abs")"
#     [[ -n "$subject" ]] || die "release attest: missing oci_index.digest_ref for component=$component"

#     log "==> (release) attesting release.json -> ${component} index ${subject}"

#     local out=()
#     if ! mapfile -t out < <(cosign_attest_predicate "$subject" "$pred_abs" "$pred_type"); then
#       die "release attest: cosign_attest_predicate failed for component=$component subject=$subject"
#     fi
#     [[ ${#out[@]} -eq 4 ]] || die "release attest: unexpected cosign_attest_predicate output for component=$component"

#     local att_digest_ref="${out[0]}"

#     local dsse_abs="${out_dir}/release.json.intoto.v1.dsse.json"
#     local manifest_abs="${out_dir}/release.json.oci.manifest.json"

#     # save dsse_abs and manifest_abs (manifest content only)
#     oci_fetch_attestation_dsse "$att_digest_ref" "$dsse_abs" "$manifest_abs" >/dev/null
#   done
# }

attest_release_json_to_component_index() {
  local component="$1"
  [[ -n "${DIST:-}" ]] || die "attest_release_json_to_component_indexes: DIST not set"

  local inv_abs="${DIST}/${component}/inventory.json"
  [[ -f "$inv_abs" ]] || die "attest_release_json_to_component_indexes: missing ${inv_abs}"

  local pred_abs="${DIST}/${component}/release.json"
  [[ -f "$pred_abs" ]] || die "attest_release_json_to_component_indexes: missing ${pred_abs}"

  local pred_type="${PRED_RELEASE_DESCRIPTOR:-https://phxi.net/attestations/release/v1}"
  # local out_dir="${DIST}/_repo/attestations/release/index"
  local out_dir="${DIST}/${component}"
  mkdir -p "$out_dir"

  local subject
  subject="$(jq -r '.oci_index.digest_ref // empty' "$inv_abs")"

  [[ -n "$subject" ]] || die "release attest: missing oci_index.digest_ref for component=$component"

  log "==> (release) attesting release.json -> ${component} index ${subject}"

  local out=()
  if ! mapfile -t out < <(cosign_attest_predicate "$subject" "$pred_abs" "$pred_type"); then
    die "release attest: cosign_attest_predicate failed for component=$component subject=$subject"
  fi
  [[ ${#out[@]} -eq 4 ]] || die "release attest: unexpected cosign_attest_predicate output for component=$component"

  local att_digest_ref="${out[0]}"
  local dsse_abs="${out_dir}/release.json.intoto.v1.dsse.json"
  local manifest_abs="${out_dir}/release.json.oci.manifest.json"

  # save dsse_abs and manifest_abs (manifest content only)
  oci_fetch_attestation_dsse "$att_digest_ref" "$dsse_abs" "$manifest_abs" >/dev/null
}

generate_release_policy() {
  # policies
  local policy_schema_version policy_enforcement policy_defaults policy_overrides
  policy_schema_version="phxi.policy.v1"
  policy_enforcement="${policy_enforcement:-warn}"

  policy_defaults="$(
    jq --arg enforcement "$policy_enforcement" --arg license_predicate_type "${PRED_LICENSE_REPORT:-https://phxi.net/attestations/licenses/v1}" -n '
    {
      enforcement: $enforcement,
      signing: {
        require_inventory_signature: true,
        require_subject_signatures: true
      },
      evidence: {
        sbom: {
          required: true,
          attestation_required: true,
          formats: ["spdx-json","cyclonedx-json"],
          attestation_required: true
        },
        scan: {
          required: true,
          attestation_required: true,
          scanners: ["grype","trivy","govulncheck"],
          attestation_required: true
        },
        license: {
          required: false,
          attestation_required: true,
          formats: ["summary-json"]
        },
        provenance: {
          required: false,
          attestation_required: true
        }
      },
      license: {
        input: {
          predicate_type: $license_predicate_type,
          preferred_scope_order: ["artifacts","source"]
        },
        missing: {
          max_without_licenses: 0
        },
        deny: {
          spdx_ids: [
            "GPL-2.0-only","GPL-2.0-or-later",
            "GPL-3.0-only","GPL-3.0-or-later",
            "AGPL-3.0-only","AGPL-3.0-or-later",
            "LGPL-2.1-only","LGPL-2.1-or-later",
            "LGPL-3.0-only","LGPL-3.0-or-later",
            "SSPL-1.0","BUSL-1.1"
          ],
          regex: ["(?i)\\bGPL\\b","(?i)\\bAGPL\\b","(?i)\\bLGPL\\b"]
        },
        allow: {
          mode: "optional",
          spdx_ids: ["MIT","Apache-2.0","BSD-2-Clause","BSD-3-Clause","ISC"],
          allow_unknown: false
        },
        expressions: {
          enabled: true,
          parse: "spdx-lite",
          or_semantics: "any-allowed",
          and_semantics: "all-allowed",
          unknown_semantics: "deny"
        },
        normalization: {
          casefold: true,
          trim: true,
          aliases: {
            "Apache 2.0": "Apache-2.0",
            "Apache License 2.0": "Apache-2.0",
            "BSD-3": "BSD-3-Clause",
            "BSD-2": "BSD-2-Clause"
          }
        }
      },
      vulnerability: {
        normalization: {
          strategy: "worst"
        },
        gating: {
          default: {
            block_on: ["critical","high"],
            allow_if_vex: true
          }
        }
      },
      freshness: {
        max_age_hours: {
          trivy_db_observed: 72,
          grype_db_built: 72,
          govulndb_upstream_modified: 168
        }
      }
    }'
  )"
  policy_overrides="$( 
    jq -n '
    [
      {
        selector: {
          component: "web",
          scope: "index"
        },
        set: {
          enforcement: "block"
        }
      },
      {
        selector: {
          component: "web",
          scope: "artifact",
          platform: "linux/amd64"
        },
        set: {
          vulnerability: {
            gating: {
              block_on: ["critical","high","medium"],
              allow_if_vex: false
            }
          }
        }
      }
    ]'
  )"

  policy_defaults="${policy_defaults:-}"
  policy_overrides="${policy_overrides:-}"
  # evidence_policy="$( jq -n '
  # {
  #   required: {
  #     sbom: { formats: ["spdx-json","cyclonedx-json"], attestation_required: true },
  #     scan: { scanners: ["grype","trivy","govulncheck"], attestation_required: true },
  #   },
  #   optional: {
  #     provenance: { enabled: false, attestation_required: true }
  #   }
  # }
  # ')"

  # scan_policy="$( jq -n '
  # {
  #   severity_system: "scanner-native",
  #   normalization: {
  #     strategy: "worst"
  #   },
  #   gating: {
  #     default: {
  #       block_on: ["critical","high"],
  #       allow_if_vex: true
  #     }
  #   }
  # }
  # ')"

  # signing_policy="$( jq -n '
  # {
  #   required: {
  #     subject: true,
  #     inventory: true
  #   }
  # }
  # ')"

  # freshness_policy="$( jq -n '
  # {
  #   max_age_hours: {
  #     trivy_db_observed: 72,
  #     grype_db_built: 72,
  #     govulndb_upstream_modified: 168
  #   }
  # }
  # ')"
  jq -n \
    --arg policy_schema_version "$policy_schema_version" \
    --argjson policy_defaults "${policy_defaults:-null}" \
    --argjson policy_overrides "${policy_overrides:-null}" \
    '{
      schema_version: $policy_schema_version,
      defaults: ($policy_defaults // []),
      overrides: ($policy_overrides // [])
    }'
}