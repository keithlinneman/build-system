# shellcheck shell=bash

sign_file()
{
  # Generate cosign files
  export AWS_SDK_LOAD_CONFIG=1
  export COSIGN_REKOR_URL=""

  #log "==> (sign) getting env name from aws ssm param"
  #ENV="$(aws --profile "${AWS_BASE_PROFILE}" ssm get-parameter --name "/platform/env/name" --query Parameter.Value --output text)"

  #log "==> (sign) getting cosign kms url from aws ssm param"
  #SIGNER_URI="$(aws --profile "${AWS_BASE_PROFILE}" ssm get-parameter --name "/platform/signing/${ENV}/cosign/signer" --query Parameter.Value --output text)"
  #log "==> using kms signer url $SIGNER_URI"

  local file sig
  file="$1"
  sig="${file}.sig"

  # using subshell to separate env vars/creds that cosign relies on cleanly
  (
    # intentionally doing this in a subshell, suppress shellcheck subshell warnings
    # shellcheck disable=SC2030
    AWS_REGION=us-east-2 AWS_DEFAULT_REGION=us-east-2

    log "==> (sign) signing file ${file} with cosign"
    # not using rekor/sigstore at all for now - offline signing using kms key
    log "==> (sign) cosign sign-blob --yes --use-signing-config=false --new-bundle-format=false --key \"$SIGNER_URI\" --output-signature \"${sig}\" \"$file\""
    #cosign sign-blob --yes --use-signing-config=false --new-bundle-format=false --key "$SIGNER_URI" --output-signature "${sig}" "$file" 1>/dev/null 2>&1
    if ! err="$( cosign_with_signer_aws sign-blob --yes --use-signing-config=false --new-bundle-format=false --key "$SIGNER_URI" --output-signature "${sig}" "$file" 2>&1 >/dev/null )"; then
      die "ERROR: cosign sign-blob failed: $err"
    fi
  )
}

sign_release_json_for_component() {
  local component="${1:?component required}"
  [[ -f "${DIST}/${component}/release.json" ]] || die "sign_release_json_for_component: release.json not found for component=${component}"
  sign_file "${DIST}/${component}/release.json"
}
  
attest_file_dsse_v1() {
  set -euo pipefail

  local subject_path="${1:?subject_path required}"
  local predicate_path="${2:?predicate_path required}"
  local predicate_type="${3:?predicate_type required}"

  # Optional overrides:
  local subject_name="${4:-}"
  local bundle_out="${5:-}"

  [[ -f "$subject_path" ]]   || { die "attest: subject not found: $subject_path"; return 2; }
  [[ -f "$predicate_path" ]] || { die "attest: predicate not found: $predicate_path"; return 2; }

  # get stable portable subject name (use path relative to dist/ if available)
  if [[ -z "$subject_name" ]]; then
    if command -v realpath >/dev/null 2>&1; then
      # If DIST_DIR is set, use it; else try "dist"
      local dist_root="${DIST_DIR:-dist}"
      subject_name="$(realpath --relative-to="$dist_root" "$subject_path" 2>/dev/null || basename "$subject_path")"
    else
      subject_name="$(basename "$subject_path")"
    fi
  fi

  # derive bundle output path under attestations/ that mirrors the predicate path
  if [[ -z "$bundle_out" ]]; then
    local dist_root rel first base rel_under
    dist_root="${DIST_DIR:-dist}"

    if command -v realpath >/dev/null 2>&1; then
      rel="$(realpath --relative-to="$dist_root" "$predicate_path" 2>/dev/null || basename "$predicate_path")"
    else
      rel="${predicate_path#"${dist_root}"/}"
    fi

    first="${rel%%/*}"
    case "$first" in
      scan|sbom|attestations|release.json|release.json.sig)
        base="$dist_root"
        rel_under="$rel"
        ;;
      *)
        base="$dist_root/$first"
        rel_under="${rel#"${first}"/}"
        ;;
    esac

    bundle_out="${base}/attestations/${rel_under}.intoto.v1.sigstore.json"
    mkdir -p "$(dirname "$bundle_out")"
  fi


  local sha tmp_statement
  sha="$(sha256sum "$subject_path" | awk '{print $1}')"
  tmp_statement="$(mktemp "${TMPDIR:-/tmp}/intoto.statement.v1.XXXXXX.json")"

  log "==> (attest) subject=${subject_name} sha256=${sha}"
  log "==> (attest) predicateType=${predicate_type}"
  log "==> (attest) bundle_out=${bundle_out}"

  # if predicate is valid json embed it, otherwise embed as base64 in a small json wrapper
  if jq -e . "$predicate_path" >/dev/null 2>&1; then
    jq -n \
      --arg subj_sha "$sha" \
      --arg subj_name "$subject_name" \
      --arg ptype "$predicate_type" \
      --slurpfile pred "$predicate_path" \
      '{
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: $subj_name, digest: { sha256: $subj_sha } }],
        predicateType: $ptype,
        predicate: $pred[0]
      }' > "$tmp_statement"
  else
    local pred_b64 pred_name
    pred_b64="$(base64 -w0 "$predicate_path")"
    pred_name="$(basename "$predicate_path")"
    jq -n \
      --arg subj_sha "$sha" \
      --arg subj_name "$subject_name" \
      --arg ptype "$predicate_type" \
      --arg pname "$pred_name" \
      --arg b64 "$pred_b64" \
      '{
        _type: "https://in-toto.io/Statement/v1",
        subject: [{ name: $subj_name, digest: { sha256: $subj_sha } }],
        predicateType: $ptype,
        predicate: { file: $pname, content_b64: $b64 }
      }' > "$tmp_statement"
  fi

  (
    # acquire signer creds in subshell
    #eval "$(aws --profile "$aws_profile" configure export-credentials --format env)"
    #export AWS_REGION="$aws_region" AWS_DEFAULT_REGION="$aws_region"

    # intentionally doing this in a subshell, suppress shellcheck subshell warnings
    # shellcheck disable=SC2031 disable=SC2030
    export AWS_REGION=us-east-2 AWS_DEFAULT_REGION=us-east-2

    log "==> (attest) cosign attest-blob (DSSE bundle)"
    if ! err="$( cosign_with_signer_aws attest-blob --no-tlog-upload --yes --key "$SIGNER_URI" --statement "$tmp_statement" --bundle "$bundle_out" --output-file /dev/null 2>&1 >/dev/null )"; then
      die "ERROR: cosign attest-blob failed: $err"
      return 1
    fi

  )
  rm -f "$tmp_statement"

}

cosign_attest_predicate() {
  # args: subject_digest_ref predicate_path predicate_type
  # returns: tag_ref digest_ref mediaType size pushed_at
  local subject="$1"           # repo@sha256:...
  local predicate_path="$2"
  local predicate_type="$3"

  [[ -n "$subject" ]] || die "cosign_attest_predicate: missing subject"
  [[ -f "$predicate_path" ]] || die "cosign_attest_predicate: predicate file not found: $predicate_path"
  [[ -n "$predicate_type" ]] || die "cosign_attest_predicate: missing predicate_type"

  local base_repo="${subject%@*}"  # repo

  # we cant get the exact referrer created returned, so we save the list before and diff it to the list after
  # seems like there must be a better way to do this
  local before after_json after_digests new_digest digest_ref
  before="$(oras discover --format json "$subject" \
    | jq -r '.referrers[]?.digest // empty' \
    | LC_ALL=C sort -u)"

  # Attest (referrers model)
  cosign_with_signer_aws attest --yes \
    --key "${SIGNER_URI}" \
    --predicate "${predicate_path}" \
    --type "${predicate_type}" \
    "${subject}" >/dev/null

  # Get list of referrers after
  after_json="$(oras discover --format json "$subject")"
  after_digests="$(
    jq -r '((.referrers // .manifests // [])[]? | .digest // empty)' <<<"$after_json" \
      | sed '/^$/d' | LC_ALL=C sort -u
  )"

  # Referrers after (retry for eventual consistency / ACTIVE lag)
  local after_json after_digests new_digest=""
  local sleep_s=0.2

  for _ in {1..10}; do
    after_json="$(oras discover --format json "$subject" 2>/dev/null || true)"

    after_digests="$(
      jq -r '((.referrers // .manifests // [])[]? | .digest // empty)' <<<"$after_json" \
        | sed '/^$/d' | LC_ALL=C sort -u
    )"

    new_digest="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after_digests") | tail -n 1)"

    if [[ -n "$new_digest" ]]; then
      break
    fi

    sleep "$sleep_s"
    # simple backoff: 0.2, 0.4, 0.8, 1.6, ...
    sleep_s="$(awk -v s="$sleep_s" 'BEGIN{printf "%.3f", (s<2.0 ? s*2 : 2.0)}')"
  done

  if [[ -z "$new_digest" ]]; then
    echo "ERROR: couldn't determine new referrer digest (referrers didn't change after attest)" >&2
    echo "DEBUG(before):" >&2; printf '%s\n' "$before" >&2
    echo "DEBUG(after):" >&2;  printf '%s\n' "$after_digests" >&2
    return 1
  fi
  digest_ref="${base_repo}@${new_digest}"

  # call oci_fetch_attestation_dsse() to store local file
  # oci_fetch_attestation_dsse "$digest_ref" ""

  local desc size mediaType signed_at
  desc="$(
    jq -c --arg d "$new_digest" '
      ((.referrers // .manifests // []) | map(select(.digest == $d)) | .[0]) // {}
    ' <<<"$after_json"
  )"
  mediaType="$(jq -r '.mediaType // empty' <<<"$desc")"
  size="$(jq -r '.size // empty' <<<"$desc")"
  signed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  printf '%s\n%s\n%s\n%s\n' \
    "$digest_ref" "${mediaType:-}" "${size:-0}" "$signed_at"
}

cosign_with_signer_aws() {
  # shellcheck disable=SC2030 disable=SC2031
  local region="${AWS_REGION:-us-east-2}"

  log "==> (signing) running cosign with AWS_REGION=${region}"
  # intentionally calling this from a subshell, suppress shellcheck subshell warnings
  # shellcheck disable=SC2030 disable=SC2031
  AWS_REGION="$region" AWS_DEFAULT_REGION="$region" cosign "$@"
}

oci_fetch_attestation_dsse() {
  # args: att_digest_ref out_path [out_manifest_path]
  local att_ref="${1:?att_digest_ref required}"
  local out="${2:?out_path required}"
  local out_manifest="${3:-}"

  local repo="${att_ref%@*}"

  mkdir -p "$(dirname "$out")"

  local manifest layer_digest layer_mt

  # simple retry (ecr referrers/manifest sometimes lag)
  local sleep_s=0.2
  for _ in {1..10}; do
    if manifest="$(oras manifest fetch --format json "$att_ref" 2>/dev/null)"; then
      # Prefer DSSE/in-toto-ish layers, fall back to first layer if needed
      layer_digest="$(
        jq -r '
          (.content.layers // .layers // [])
          | (map(select(.mediaType? | test("dsse|in-toto|json"; "i"))) + .)
          | .[0].digest // empty
        ' <<<"$manifest"
      )"
      layer_mt="$(
        jq -r --arg d "$layer_digest" '
          (.content.layers // .layers // [])
          | map(select(.digest == $d))
          | .[0].mediaType // empty
        ' <<<"$manifest"
      )"

      if [[ -n "$layer_digest" ]]; then
        break
      fi
    fi

    sleep "$sleep_s"
    sleep_s="$(awk -v s="$sleep_s" 'BEGIN{printf "%.3f", (s<2.0 ? s*2 : 2.0)}')"
  done

  [[ -n "${layer_digest:-}" ]] || die "oci_fetch_attestation_dsse: could not find layer digest in manifest for $att_ref"

  # keep the full manifest (for audits/debug) if set
  if [[ -n "$out_manifest" ]]; then
    mkdir -p "$(dirname "$out_manifest")"
    # saving the oci manifest content only
    #printf '%s\n' "$manifest" > "$out_manifest"
    jq -c '.content // .' <<<"$manifest" > "$out_manifest"
  fi

  # fetch the layer blob by digest from the same repo
  if ! err="$(oras blob fetch --output "$out" "${repo}@${layer_digest}" 2>&1 >/dev/null)"; then
    die "oci_fetch_attestation_dsse: oras blob fetch failed: $err"
  fi

  # return mediaType for inventory enrichment
  printf '%s\n' "${layer_mt:-}"
}
