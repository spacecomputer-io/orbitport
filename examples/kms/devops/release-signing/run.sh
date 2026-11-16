#!/usr/bin/env bash
# Release signing in CI: the runner gets signatures, never the key.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo release-signing

title "Release signing in CI"

customer_verify() {
  if openssl dgst -sha256 -verify release-public-key.pem -signature "$2" "$1" >/dev/null 2>&1; then
    ok "customer: $1 is the signed release"
  else
    bad "customer: $1 does not match the signature, do not install"
  fi
}

step "CI builds the release"
mkdir -p build/myapp
printf '#!/bin/sh\necho "myapp 1.4.0"\n' >build/myapp/myapp
printf 'version: 1.4.0\n' >build/myapp/VERSION
tar -czf myapp-1.4.0.tar.gz -C build myapp
info "myapp-1.4.0.tar.gz  sha256 $(sha256_hex <myapp-1.4.0.tar.gz | cut -c1-16)..."

step "CI signs the SHA-256 of the artifact with the KMS"
res=$(rpc kms.Sign "$(jq -nc --arg k "$KEY_SIGN" --arg m "$(sha256_b64 <myapp-1.4.0.tar.gz)" \
  '{KeyId:$k, Message:$m, SigningAlgorithm:"ECDSA_SHA_256", MessageType:"DIGEST"}')")
sig_bytes "$(echo "$res" | jq -r '.Signature')" >myapp-1.4.0.tar.gz.sig
ok "myapp-1.4.0.tar.gz.sig (key version $(echo "$res" | jq -r '.KeyVersion'))"
info "Only the 32-byte hash was sent. The runner holds a token, not a signing key."

step "The project publishes its public key once"
rpc kms.GetPublicKey "$(jq -nc --arg k "$KEY_SIGN" '{KeyId:$k}')" | jq -j '.PublicKey' >release-public-key.pem
show <release-public-key.pem

step "A customer downloads and verifies with plain openssl"
info "openssl dgst -sha256 -verify release-public-key.pem -signature myapp-1.4.0.tar.gz.sig myapp-1.4.0.tar.gz"
customer_verify myapp-1.4.0.tar.gz myapp-1.4.0.tar.gz.sig

step "A mirror serves a modified tarball"
cp myapp-1.4.0.tar.gz mirror-myapp-1.4.0.tar.gz
printf 'x' >>mirror-myapp-1.4.0.tar.gz
customer_verify mirror-myapp-1.4.0.tar.gz myapp-1.4.0.tar.gz.sig
note "A compromised runner could ask for signatures while the attacker has access, but cannot take the key with it."

done_banner
