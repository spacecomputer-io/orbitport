#!/usr/bin/env bash
# Incident response: revoke the runner's token, rotate, keep going.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo incident-response

title "Incident response: compromised CI runner"

sign_release() {
  printf '%s' "$1" >"$1.txt"
  local res
  res=$(rpc kms.Sign "$(jq -nc --arg k "$KEY_ROTATION_SIGN" --arg m "$(b64 <"$1.txt")" \
    '{KeyId:$k, Message:$m, SigningAlgorithm:"ECDSA_SHA_256", MessageType:"RAW"}')")
  echo "$(date -u +%H:%M:%S)  $1  key v$(echo "$res" | jq -r '.KeyVersion')" >>signing.log
}

step "Normal day: the runner signs releases"
sign_release release-2.3.0
sign_release release-2.3.1
show <signing.log

step "Alert: the runner is compromised"
note "What the attacker has: the runner's token. What the attacker does not have: the signing key."
info "1) Revoke the runner's token in the dashboard: $ORBITPORT_DASHBOARD_URL"
info "   From that moment every call with it returns 401, so access ends there."
pause

step "Rotate the signing key so post-incident signatures are easy to tell apart"
v=$(rpc kms.RotateKey "$(jq -nc --arg k "$KEY_ROTATION_SIGN" '{KeyId:$k}')" | jq -r '.KeyMetadata.PrimaryVersion')
ok "signing key now v$v"

step "A new runner, with a new token, signs the next release"
sign_release release-2.3.2
show <signing.log
note "No key to replace on laptops or servers, no re-signing of old releases: the key never left the KMS."

done_banner
