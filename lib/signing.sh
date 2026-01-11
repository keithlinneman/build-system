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
    export AWS_REGION=us-east-2 AWS_DEFAULT_REGION=us-east-2
    export AWS_PROFILE="$AWS_KMS_SIGNER_PROFILE"

    log "==> (sign) signing binary ${BIN} with cosign using aws_profile ${AWS_PROFILE}"
    # not using rekor/sigstore at all for now - offline signing using kms key
    log "==> (sign) cosign sign-blob --yes --tlog-upload=false --use-signing-config=false --new-bundle-format=false --key \"$SIGNER_URI\" --output-signature \"${SIG}\" \"$BIN\""
    #cosign sign-blob --yes --tlog-upload=false --use-signing-config=false --new-bundle-format=false --key "$SIGNER_URI" --output-signature "${SIG}" "$BIN" 1>/dev/null 2>&1
    if ! err="$( cosign sign-blob --yes --tlog-upload=false --use-signing-config=false --new-bundle-format=false --key "$SIGNER_URI" --output-signature "${SIG}" "$BIN" 2>&1 >/dev/null )"; then
      die "ERROR: cosign sign-blob failed: $err"
      return 1
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
    local dist_root rel first base rel_under stem
    dist_root="${DIST_DIR:-dist}"

    if command -v realpath >/dev/null 2>&1; then
      rel="$(realpath --relative-to="$dist_root" "$predicate_path" 2>/dev/null || basename "$predicate_path")"
    else
      rel="${predicate_path#${dist_root}/}"
    fi

    first="${rel%%/*}"
    case "$first" in
      scan|sbom|attestations|release.json|release.json.sig)
        base="$dist_root"
        rel_under="$rel"
        ;;
      *)
        base="$dist_root/$first"
        rel_under="${rel#${first}/}"
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

    export AWS_REGION=us-east-2 AWS_DEFAULT_REGION=us-east-2
    export AWS_PROFILE="$AWS_KMS_SIGNER_PROFILE"

    log "==> (attest) cosign attest-blob (DSSE bundle)"
    if ! err="$( cosign attest-blob --yes --tlog-upload=false --key "$SIGNER_URI" --statement "$tmp_statement" --bundle "$bundle_out" --output-file /dev/null 2>&1 >/dev/null )"; then
      die "ERROR: cosign attest-blob failed: $err"
      return 1
    fi

  )
  rm -f "$tmp_statement"

}

cosign_attest_predicate() {
  # args: subject_digest_ref predicate_path predicate_type
  local subject="$1"
  local predicate_path="$2"
  local predicate_type="$3"

  [[ -n "$subject" ]] || die "cosign_attest_predicate: missing subject"
  [[ -f "$predicate_path" ]] || die "cosign_attest_predicate: predicate file not found: $predicate_path"
  [[ -n "$predicate_type" ]] || die "cosign_attest_predicate: missing predicate_type"

  # Common flags (adjust to your model)
  cosign attest --yes \
    --key "${SIGNER_URI}" \
    --predicate "${predicate_path}" \
    --type "${predicate_type}" \
    --tlog-upload=false \
    "${subject}" >/dev/null

  # Where cosign stored the attestation artifact
  local tag_ref="$( cosign triangulate --type attestation "${subject}" )"
  
  # Resolve to digest ref for stable identity
  local digest_ref="$(oras resolve "${tag_ref}")"

  # Descriptor info
  local desc="$(oras manifest fetch --descriptor "${digest_ref}" --output json)"
  local size="$(jq -r '.size' <<<"$desc")"
  local mediaType="$(jq -r '.mediaType' <<<"$desc")"
  local now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '%s\n%s\n%s\n%s\n%s\n' \
    "$tag_ref" "$digest_ref" "$mediaType" "$size" "$now"
}


oci_attest_predicate_ev_json() {
  local category="${1:?category}"
  local subject="${2:?subject_digest_ref}"
  local predicate_path="${3:?predicate_path}"
  local predicate_type="${4:?predicate_type}"

  local pred_sha
  pred_sha="$(sha256sum "$predicate_path" | awk '{print $1}')"

  mapfile -t out < <(cosign_attest_predicate "$subject" "$predicate_path" "$predicate_type")
  local tag_ref="${out[0]}"
  local digest_ref="${out[1]}"
  local mediaType="${out[2]}"
  local size="${out[3]}"
  local pushed_at="${out[4]}"

  local key="${category}|${predicate_type}|${pred_sha}"
  local signed_at
  signed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  jq -n \
    --arg key "$key" \
    --arg category "$category" \
    --arg predicateType "$predicate_type" \
    --arg predicate_path "$predicate_path" \
    --arg predicate_sha256 "$pred_sha" \
    --arg subject "$subject" \
    --arg tag_ref "$tag_ref" \
    --arg digest_ref "$digest_ref" \
    --arg mediaType "$mediaType" \
    --arg size "$size" \
    --arg pushed_at "$pushed_at" \
    --arg signer "$SIGNER_URI" \
    --arg signed_at "$signed_at" \
    '{
      key: $key,
      kind: "cosign-attestation",
      category: $category,
      predicateType: $predicateType,
      predicate: { path: $predicate_path, sha256: $predicate_sha256 },
      subject: { digest_ref: $subject },
      oci: {
        tag_ref: $tag_ref,
        digest_ref: $digest_ref,
        mediaType: $mediaType,
        size: ($size|tonumber),
        pushed_at: $pushed_at
      },
      signer: $signer,
      signed_at: $signed_at
    }'
}
