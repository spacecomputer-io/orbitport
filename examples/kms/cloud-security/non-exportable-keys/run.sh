#!/usr/bin/env bash
# Non-exportable keys vs. stored secrets.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo non-exportable-keys

title "Non-exportable keys vs. stored secrets"

step "Option A: keep a private key as a secret in the key-store"
openssl genpkey -algorithm ed25519 -out stored-key.pem 2>/dev/null
rpc kms_keystore.Put "$(jq -nc --rawfile pem stored-key.pem '{Name:"examples/security/signing-key", Secret:{pem:$pem}}')" >/dev/null
ok "stored"
info "Anyone holding the token reads it back in full:"
rpc kms_keystore.Get '{"Name":"examples/security/signing-key"}' | jq -j '.Secret.pem' | show
note "Once copied, it works anywhere, forever. Revoking the token does not get it back."

step "Option B: a KMS key"
rpc kms.GetKeyMetadata "$(jq -nc --arg k "$KEY_SIGN_ED25519" '{KeyId:$k}')" | jq '.KeyMetadata | {KeyId, KeySpec, KeyUsage, PrimaryVersion, PublicKey}' | show
info "Metadata and the public key, nothing else. No API call returns the private key."
printf 'release 2.3.2' >msg.txt
res=$(sign_raw "$KEY_SIGN_ED25519" ED25519 msg.txt)
ok "but it signs: $(echo "$res" | jq -r '.Signature' | cut -c1-40)..."
note "A leaked token lets an attacker sign only until the token is revoked. The key itself never leaves."

step "Clean up the stored copy"
rpc kms_keystore.Delete '{"Name":"examples/security/signing-key"}' >/dev/null
ok "deleted"

done_banner
