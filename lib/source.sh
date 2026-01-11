#!/bin/bash
set -Eeuo pipefail

# usage: source_checkout_repo <repo_url> <ref> <dest_dir>
# - ref can be tag, sha, branch, or origin/HEAD
source_checkout_repo() {
  local repo="$1"
  local ref="$2"
  local dest="$3"

  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"

  # clone + fetch tags/branches
  git clone --no-checkout --filter=blob:none "$repo" "$dest" >/dev/null
  git -C "$dest" fetch --tags --prune origin '+refs/heads/*:refs/remotes/origin/*' >/dev/null

  # resolve origin/HEAD if requested
  if [[ "$ref" == "origin/HEAD" || "$ref" == "HEAD" || -z "$ref" ]]; then
    ref="$(git -C "$dest" symbolic-ref -q --short refs/remotes/origin/HEAD | sed 's#^origin/##')"
    [[ -n "$ref" ]] || die "unable to resolve origin/HEAD for repo=$repo"
  fi

  # resolve to commit sha
  local sha=""
  if sha="$(git -C "$dest" rev-parse -q --verify "${ref}^{commit}" 2>/dev/null)"; then
    :
  elif sha="$(git -C "$dest" rev-parse -q --verify "origin/${ref}^{commit}" 2>/dev/null)"; then
    :
  else
    die "unable to resolve ref=$ref in repo=$repo"
  fi

  git -C "$dest" checkout --detach "$sha" >/dev/null

  log "==> (source) checked out repo=$repo ref=$ref sha=$sha dir=$dest"
}
