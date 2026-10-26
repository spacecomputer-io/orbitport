#!/usr/bin/env bash
# Signed webhooks: the sender signs each payload, the receiver checks it with the public key.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo signed-webhooks

title "Signed webhooks"

# receiver side: rebuild "<timestamp>.<body>" and verify with only the public key
receive() {
  local body_file="$1" ts="$2" sig_file="$3"
  { printf '%s.' "$ts"; cat "$body_file"; } >signed-input
  if verify_ecdsa receiver-pub.pem "$sig_file" signed-input; then
    ok "receiver: signature valid, event accepted"
  else
    bad "receiver: signature invalid, event rejected"
  fi
}

step "The receiver fetches the sender's public key once and caches it"
public_key_pem "$KEY_SIGN" >receiver-pub.pem
show <receiver-pub.pem

step "The sender signs '<timestamp>.<body>' and sends the signature as a header"
cat >event.json <<'JSON'
{"type":"payment.succeeded","id":"evt_1042","amount":4999,"currency":"EUR"}
JSON
ts=$(date +%s)
{ printf '%s.' "$ts"; cat event.json; } >to-sign
res=$(sign_raw "$KEY_SIGN" ECDSA_SHA_256 to-sign)
sig_bytes "$(echo "$res" | jq -r '.Signature')" >signature.der
info "POST /webhooks"
info "X-Timestamp: $ts"
info "X-Key-Version: $(echo "$res" | jq -r '.KeyVersion')"
info "X-Signature: $(b64 <signature.der | cut -c1-48)..."
show <event.json

step "The receiver verifies the event"
receive event.json "$ts" signature.der

step "An attacker changes the amount in transit"
sed 's/4999/1/' event.json >tampered.json
show <tampered.json
receive tampered.json "$ts" signature.der

step "An attacker replays the event with a new timestamp"
receive event.json "$((ts + 3600))" signature.der
note "The timestamp is signed too, so the receiver can also reject old events."

done_banner
