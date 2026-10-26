#!/usr/bin/env bash
# Image and SBOM signing: sign the image digest and its SBOM, check both before deploy.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
require_openssl3
init_demo image-sbom-signing

title "Container image and SBOM signing"

# deploy gate: the image digest and the SBOM must both verify
deploy_gate() {
  local digest_hex="$1" sbom="$2" good=1
  printf '%s' "$digest_hex" | unhex >gate-digest.bin
  if verify_ecdsa_prehashed pipeline-public-key.pem image.sig gate-digest.bin; then
    ok "image sha256:${digest_hex:0:12}... signed by the pipeline"
  else
    bad "image sha256:${digest_hex:0:12}... not signed by the pipeline"; good=0
  fi
  if verify_ecdsa pipeline-public-key.pem sbom.sig "$sbom"; then
    ok "SBOM signed by the pipeline"
  else
    bad "SBOM does not match its signature"; good=0
  fi
  if (( good )); then ok "deploy allowed"; else bad "deploy blocked"; fi
}

step "The pipeline builds the image and its SBOM"
cat >manifest.json <<'JSON'
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:4b825dc642cb6eb9a060e54bf8d69288fbee4904"},"layers":[{"digest":"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"}]}
JSON
digest=$(sha256_hex <manifest.json)
info "image  registry.example.com/shop/api@sha256:${digest:0:16}..."
cat >sbom.cdx.json <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
  {"name":"openssl","version":"3.5.1","purl":"pkg:deb/debian/openssl@3.5.1"},
  {"name":"express","version":"4.21.2","purl":"pkg:npm/express@4.21.2"}
]}
JSON
info "sbom   sbom.cdx.json (2 components)"

step "The pipeline signs the image digest and the SBOM digest with the KMS"
res=$(rpc kms.Sign "$(jq -nc --arg k "$KEY_SIGN" --arg m "$(printf '%s' "$digest" | unhex | b64)" \
  '{KeyId:$k, Message:$m, SigningAlgorithm:"ECDSA_SHA_256", MessageType:"DIGEST"}')")
sig_bytes "$(echo "$res" | jq -r '.Signature')" >image.sig
res=$(sign_digest "$KEY_SIGN" sbom.cdx.json)
sig_bytes "$(echo "$res" | jq -r '.Signature')" >sbom.sig
ok "image.sig and sbom.sig pushed next to the image"

step "The cluster's deploy gate checks both with the public key"
public_key_pem "$KEY_SIGN" >pipeline-public-key.pem
deploy_gate "$digest" sbom.cdx.json

step "Someone pushes a different image under the same tag"
deploy_gate "$(printf 'other image' | sha256_hex)" sbom.cdx.json

step "Someone removes a vulnerable component from the SBOM"
jq -c '.components |= map(select(.name != "openssl"))' sbom.cdx.json >sbom-edited.json
deploy_gate "$digest" sbom-edited.json

done_banner
