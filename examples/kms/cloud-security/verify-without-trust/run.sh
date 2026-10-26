#!/usr/bin/env bash
# Verify without trusting us: standard signatures, checked with plain openssl.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo verify-without-trust

title "Verify without trusting us"

step "Sign a statement with the KMS"
printf 'Invoice 2026-118: 4,800.00 EUR, due 2026-11-30\n' >invoice.txt
show <invoice.txt
res=$(sign_raw "$KEY_SIGN" ECDSA_SHA_256 invoice.txt)
sig_bytes "$(echo "$res" | jq -r '.Signature')" >invoice.sig

step "Publish the public key and its fingerprint"
public_key_pem "$KEY_SIGN" "$(echo "$res" | jq -r '.KeyVersion')" >public-key.pem
show <public-key.pem
info "fingerprint sha256:$(openssl pkey -pubin -in public-key.pem -outform DER | sha256_hex)"

step "From here on, no calls to Orbitport. Plain openssl:"
cmd="openssl dgst -sha256 -verify public-key.pem -signature invoice.sig invoice.txt"
info "\$ $cmd"
if $cmd 2>/dev/null | show; then ok "invoice verified"; else bad "invoice not verified"; fi

step "Change the amount"
sed 's/4,800.00/48,000.00/' invoice.txt >invoice-edited.txt
info "\$ openssl dgst -sha256 -verify public-key.pem -signature invoice.sig invoice-edited.txt"
if openssl dgst -sha256 -verify public-key.pem -signature invoice.sig invoice-edited.txt 2>/dev/null | show; then
  ok "edited invoice accepted"
else
  bad "edited invoice rejected"
fi
note "Standard ECDSA P-256 with SHA-256, DER encoded: no SDK, no account, no trust in the provider."

done_banner
