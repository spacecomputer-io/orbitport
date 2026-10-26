#!/usr/bin/env bash
# JWTs signed by the KMS: an ES256 token with no key file on disk.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo kms-jwt

title "JWTs signed by the KMS (ES256)"

# DER ECDSA signature to the 64-byte r||s form JWS uses
der_to_jose() {
  local ints r s
  ints=$(openssl asn1parse -inform DER -in "$1" | awk -F: '/INTEGER/ {print $NF}')
  r=$(echo "$ints" | sed -n 1p) s=$(echo "$ints" | sed -n 2p)
  printf '%064s%064s' "$r" "$s" | tr ' ' '0' | unhex
}

# 64-byte r||s back to DER, for openssl verification
jose_to_der() {
  local h
  h=$(hex <"$1")
  printf 'asn1=SEQUENCE:sig\n[sig]\nr=INTEGER:0x%s\ns=INTEGER:0x%s\n' "${h:0:64}" "${h:64:64}" >sig.cnf
  openssl asn1parse -genconf sig.cnf -out "$2" >/dev/null
}

verify_jwt() {
  local jwt="$1" h p s
  IFS=. read -r h p s <<<"$jwt"
  printf '%s.%s' "$h" "$p" >jwt-input
  printf '%s' "$s" | b64url_d >jwt-sig.raw
  jose_to_der jwt-sig.raw jwt-sig.der
  verify_ecdsa jwt-pub.pem jwt-sig.der jwt-input
}

step "Build the header and claims"
version=$(rpc kms.GetKeyMetadata "$(jq -nc --arg k "$KEY_SIGN" '{KeyId:$k}')" | jq -r '.KeyMetadata.PrimaryVersion')
now=$(date +%s)
header=$(jq -nc --arg kid "$KEY_SIGN:v$version" '{alg:"ES256", typ:"JWT", kid:$kid}')
claims=$(jq -nc --argjson now "$now" '{sub:"user_42", scope:"orders:read", iat:$now, exp:($now + 900)}')
echo "$header" | jq . | show
echo "$claims" | jq . | show

step "Sign '<header>.<claims>' with the KMS"
signing_input="$(printf '%s' "$header" | b64url).$(printf '%s' "$claims" | b64url)"
printf '%s' "$signing_input" >signing-input
res=$(sign_raw "$KEY_SIGN" ECDSA_SHA_256 signing-input)
sig_bytes "$(echo "$res" | jq -r '.Signature')" >sig.der
jwt="$signing_input.$(der_to_jose sig.der | b64url)"
echo "$jwt" >token.jwt
ok "token minted, no private key on this machine"
echo "$jwt" | fold -w 100 | show

step "Any service verifies it with the public key"
public_key_pem "$KEY_SIGN" "$version" >jwt-pub.pem
if verify_jwt "$jwt"; then ok "verifier: signature valid"; else bad "verifier: signature invalid"; fi
info "Paste token.jwt and jwt-pub.pem into any JWT library or debugger to check it there too."

step "A user edits the scope to orders:write"
IFS=. read -r h _ s <<<"$jwt"
forged="$h.$(jq -c '.scope = "orders:write"' <<<"$claims" | tr -d '\n' | b64url).$s"
if verify_jwt "$forged"; then ok "verifier: forged token accepted"; else bad "verifier: forged token rejected"; fi

done_banner
