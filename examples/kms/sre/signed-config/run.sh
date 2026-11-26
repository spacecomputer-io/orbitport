#!/usr/bin/env bash
# Signed config and feature flags: a service loads only config that verifies.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo signed-config

title "Signed config and feature flags"

# the service: verifies before loading, keeps the last good config otherwise
service_reload() {
  if openssl dgst -sha256 -verify service-public-key.pem -signature "$1.sig" "$1" >/dev/null 2>&1; then
    cp "$1" active-flags.json
    ok "service: loaded $(jq -c . "$1")"
  else
    bad "service: signature check failed, keeping $(jq -c . active-flags.json)"
  fi
}

step "The service ships with the release pipeline's public key"
rpc kms.GetPublicKey "$(jq -nc --arg k "$KEY_SIGN" '{KeyId:$k}')" | jq -j '.PublicKey' >service-public-key.pem
echo '{}' >active-flags.json
ok "service-public-key.pem baked into the image"

step "The pipeline publishes flags and signs them"
echo '{"new_checkout":false,"rate_limit_rps":200,"maintenance":false}' >flags.json
res=$(rpc kms.Sign "$(jq -nc --arg k "$KEY_SIGN" --arg m "$(b64 <flags.json)" \
  '{KeyId:$k, Message:$m, SigningAlgorithm:"ECDSA_SHA_256", MessageType:"RAW"}')")
sig_bytes "$(echo "$res" | jq -r '.Signature')" >flags.json.sig
ok "flags.json and flags.json.sig written to the ConfigMap"

step "The service reloads"
service_reload flags.json

step "Someone edits the ConfigMap directly: maintenance on, rate limit 1"
jq -c '.maintenance = true | .rate_limit_rps = 1' flags.json >flags-edited.json
cp flags.json.sig flags-edited.json.sig
service_reload flags-edited.json
note "Only changes that went through the pipeline, which can sign, take effect."

done_banner
