# shellcheck shell=bash

signbinary()
{
  # Generate cosign files
  export AWS_SDK_LOAD_CONFIG=1
  export COSIGN_REKOR_URL=""

  #log "==> (sign) getting env name from aws ssm param"
  #ENV="$(aws --profile "${AWS_BASE_PROFILE}" ssm get-parameter --name "/platform/env/name" --query Parameter.Value --output text)"

  #log "==> (sign) getting cosign kms url from aws ssm param"
  #SIGNER_URI="$(aws --profile "${AWS_BASE_PROFILE}" ssm get-parameter --name "/platform/signing/${ENV}/cosign/signer" --query Parameter.Value --output text)"
  #log "==> using kms signer url $SIGNER_URI"

  BIN="$1"
  SIG="${BIN}.sig"

  # using subshell to separate env vars/creds that cosign relies on cleanly
  (
    # intentionally doing this in a subshell, suppress shellcheck subshell warnings
    # shellcheck disable=SC2030
    AWS_REGION=us-east-2 AWS_DEFAULT_REGION=us-east-2 AWS_PROFILE="$AWS_KMS_SIGNER_PROFILE"

    log "==> (sign) signing binary ${BIN} with cosign using aws_profile ${AWS_PROFILE}"
    # not using rekor/sigstore at all for now - offline signing using kms key
    log "==> (sign) cosign sign-blob --yes --tlog-upload=false --use-signing-config=false --new-bundle-format=false --key \"$SIGNER_URI\" --output-signature \"${SIG}\" \"$BIN\""
    #cosign sign-blob --yes --tlog-upload=false --use-signing-config=false --new-bundle-format=false --key "$SIGNER_URI" --output-signature "${SIG}" "$BIN" 1>/dev/null 2>&1
    if ! err="$( cosign sign-blob --yes --tlog-upload=false --use-signing-config=false --new-bundle-format=false --key "$SIGNER_URI" --output-signature "${SIG}" "$BIN" 2>&1 >/dev/null )"; then
      die "ERROR: cosign sign-blob failed: $err"
    fi
  )
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
    export AWS_REGION=us-east-2 AWS_DEFAULT_REGION=us-east-2 AWS_PROFILE="$AWS_KMS_SIGNER_PROFILE"

    log "==> (attest) cosign attest-blob (DSSE bundle)"
    if ! err="$( cosign attest-blob --yes --tlog-upload=false --key "$SIGNER_URI" --statement "$tmp_statement" --bundle "$bundle_out" --output-file /dev/null 2>&1 >/dev/null )"; then
      die "ERROR: cosign attest-blob failed: $err"
      return 1
    fi

  )
  rm -f "$tmp_statement"

}

# cosign_attest_predicate() {
#   # args: subject_digest_ref predicate_path predicate_type
#   local subject="$1"
#   local predicate_path="$2"
#   local predicate_type="$3"

#   [[ -n "$subject" ]] || die "cosign_attest_predicate: missing subject"
#   [[ -f "$predicate_path" ]] || die "cosign_attest_predicate: predicate file not found: $predicate_path"
#   [[ -n "$predicate_type" ]] || die "cosign_attest_predicate: missing predicate_type"

#   # Common flags (adjust to your model)
#   cosign_with_signer_aws attest --yes \
#     --key "${SIGNER_URI}" \
#     --predicate "${predicate_path}" \
#     --type "${predicate_type}" \
#     --tlog-upload=false \
#     "${subject}"

#   local tag_ref digest_ref desc size mediaType now
#   # old tag style, we are using new referrer model now
#   # Where cosign stored the attestation artifact
#   #tag_ref="$( cosign triangulate --type attestation "${subject}" )"
#     # Resolve to digest ref for stable identity
#   # digest_ref="$(oras resolve "${tag_ref}")"

#   # Descriptor info
#   desc="$(oras manifest fetch --descriptor "${digest_ref}" --output json)"
#   size="$(jq -r '.size' <<<"$desc")"
#   mediaType="$(jq -r '.mediaType' <<<"$desc")"
#   now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
#   printf '%s\n%s\n%s\n%s\n%s\n' \
#     "$tag_ref" "$digest_ref" "$mediaType" "$size" "$now"
# }

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
    --tlog-upload=false \
    "${subject}" >/dev/null

  # Get list of referrers after
  after_json="$(oras discover --format json "$subject")"
  after_digests="$(
    jq -r '((.referrers // .manifests // [])[]? | .digest // empty)' <<<"$after_json" \
      | sed '/^$/d' | LC_ALL=C sort -u
  )"

  # # Find new digest(s)
  # new_digest="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after_digests") | tail -n 1)"
  # if [[ -z "$new_digest" ]]; then
  #   echo "ERROR: couldn't determine new referrer digest" >&2
  #   return 1
  # fi
  # digest_ref="${base_repo}@${new_digest}"

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


# oci_attest_predicate_ev_json() {
#   local category="${1:?category}"
#   local subject="${2:?subject_digest_ref}"
#   local predicate_path="${3:?predicate_path}"
#   local predicate_type="${4:?predicate_type}"

#   local pred_sha
#   pred_sha="$(sha256sum "$predicate_path" | awk '{print $1}')"

#   mapfile -t out < <(cosign_attest_predicate "$subject" "$predicate_path" "$predicate_type")
#   local tag_ref="${out[0]}"
#   local digest_ref="${out[1]}"
#   local mediaType="${out[2]}"
#   local size="${out[3]}"
#   local pushed_at="${out[4]}"

#   local key="${category}|${predicate_type}|${pred_sha}"
#   local signed_at
#   signed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

#   jq -n \
#     --arg key "$key" \
#     --arg category "$category" \
#     --arg predicateType "$predicate_type" \
#     --arg predicate_path "$predicate_path" \
#     --arg predicate_sha256 "$pred_sha" \
#     --arg subject "$subject" \
#     --arg tag_ref "$tag_ref" \
#     --arg digest_ref "$digest_ref" \
#     --arg mediaType "$mediaType" \
#     --arg size "$size" \
#     --arg pushed_at "$pushed_at" \
#     --arg signer "$SIGNER_URI" \
#     --arg signed_at "$signed_at" \
#     '{
#       key: $key,
#       kind: "cosign-attestation",
#       category: $category,
#       predicateType: $predicateType,
#       predicate: { path: $predicate_path, sha256: $predicate_sha256 },
#       subject: { digest_ref: $subject },
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
# }

# cosign_with_signer_aws() {
#   AWS_PROFILE="${AWS_KMS_SIGNER_PROFILE:?}"
#   AWS_SDK_LOAD_CONFIG=1
#   # intentionally calling this from a subshell, suppress shellcheck subshell warnings
#   # shellcheck disable=SC2030 disable=SC2031
#   AWS_REGION="${AWS_REGION:-us-east-2}"
#   log "==> (signing) running cosign with AWS_PROFILE=${AWS_PROFILE} AWS_REGION=${AWS_REGION}"
#   log "==> (debug) current env: $( env )"
#   cosign "$@"
# }

cosign_with_signer_aws() {
  local profile="${AWS_KMS_SIGNER_PROFILE:?AWS_KMS_SIGNER_PROFILE required}"
  # shellcheck disable=SC2030 disable=SC2031
  local region="${AWS_REGION:-us-east-2}"

  log "==> (signing) running cosign with AWS_PROFILE=${profile} AWS_REGION=${region}"
  # intentionally calling this from a subshell, suppress shellcheck subshell warnings
  # shellcheck disable=SC2030 disable=SC2031
  AWS_PROFILE="$profile" AWS_SDK_LOAD_CONFIG=1 AWS_REGION="$region" AWS_DEFAULT_REGION="$region" AWS_EC2_METADATA_DISABLED=true cosign "$@"
}
