#!/usr/bin/env bash
# Software license keys: sign once with the KMS, verify offline in the app.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
require_openssl3
init_demo license-keys

title "Software license keys (Ed25519)"

# the shipped app: only the embedded public key, no network
app_check_license() {
  local lic payload sig
  lic=$(cat "$1")
  payload="${lic%%.*}" sig="${lic##*.}"
  printf '%s' "$payload" | b64url_d >lic-payload
  printf '%s' "$sig" | b64url_d >lic-sig
  if verify_ed25519 app-public-key.pem lic-sig lic-payload; then
    ok "app: license valid for $(jq -r '"\(.customer), \(.seats) seats, plan \(.plan)"' lic-payload)"
  else
    bad "app: license invalid, running in trial mode"
  fi
}

step "The vendor embeds the public key in the app at build time"
public_key_pem "$KEY_SIGN_ED25519" >app-public-key.pem
show <app-public-key.pem

step "The vendor issues a license and signs it with the KMS"
cat >license.json <<'JSON'
{"customer":"Acme Corp","plan":"team","seats":10,"expires":"2027-12-31"}
JSON
show <license.json
res=$(sign_raw "$KEY_SIGN_ED25519" ED25519 license.json)
echo "$(b64url <license.json).$(sig_bytes "$(echo "$res" | jq -r '.Signature')" | b64url)" >license.key
ok "license.key sent to the customer"
show <license.key

step "The app checks the license offline"
app_check_license license.key

step "The customer edits the license to 500 seats"
lic=$(cat license.key)
echo "$(jq -c '.seats = 500' license.json | tr -d '\n' | b64url).${lic##*.}" >license-edited.key
app_check_license license-edited.key
note "The private key never left the KMS, so nobody can mint a valid license without the vendor."

done_banner
