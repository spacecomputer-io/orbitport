#!/usr/bin/env bash
# Signed download links: the backend signs a URL with an expiry, the edge checks it with the public key.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
require_openssl3
init_demo signed-download-links

title "Signed download links"

BASE="https://downloads.example.com"

# backend: sign "<path>\n<expires>" and build the link
sign_link() {
  local path="$1" expires="$2" res
  printf '%s\n%s' "$path" "$expires" >link-input
  res=$(rpc kms.Sign "$(jq -nc --arg k "$KEY_SIGN_ED25519" --arg m "$(b64 <link-input)" \
    '{KeyId:$k, Message:$m, SigningAlgorithm:"ED25519", MessageType:"RAW"}')")
  echo "$BASE$path?expires=$expires&sig=$(sig_bytes "$(echo "$res" | jq -r '.Signature')" | b64url)"
}

# edge: only the public key, checks expiry then signature
edge_check() {
  local url="$1" path query expires sig
  path="${url#"$BASE"}" path="${path%%\?*}"
  query="${url#*\?}"
  expires=$(echo "$query" | tr '&' '\n' | sed -n 's/^expires=//p')
  sig=$(echo "$query" | tr '&' '\n' | sed -n 's/^sig=//p')
  info "GET $path (expires $(fmt_epoch "$expires"))"
  if (( expires < $(date +%s) )); then
    bad "edge: 403, link expired"
    return
  fi
  printf '%s\n%s' "$path" "$expires" >edge-input
  printf '%s' "$sig" | b64url_d >edge-sig
  if openssl pkeyutl -verify -pubin -inkey edge-public-key.pem -rawin -in edge-input -sigfile edge-sig >/dev/null 2>&1; then
    ok "edge: 200, serving the file"
  else
    bad "edge: 403, signature does not match"
  fi
}

step "The edge loads the backend's public key once"
rpc kms.GetPublicKey "$(jq -nc --arg k "$KEY_SIGN_ED25519" '{KeyId:$k}')" | jq -j '.PublicKey' | ed25519_pem >edge-public-key.pem
ok "edge-public-key.pem cached, no secret on the edge"

step "The backend creates a link valid for 5 minutes"
expires=$(( $(date +%s) + 300 ))
link=$(sign_link /files/q3-report.pdf "$expires")
echo "$link" >link.txt
echo "$link" | show

step "A user opens the link"
edge_check "$link"

step "The user changes the path to another file"
edge_check "${link/q3-report/payroll}"

step "The user extends the expiry by a day"
edge_check "${link/expires=$expires/expires=$((expires + 86400))}"

step "A link that expired an hour ago"
old=$(sign_link /files/q3-report.pdf "$(( $(date +%s) - 3600 ))")
edge_check "$old"

done_banner
