#!/usr/bin/env bash
# Rotation drill: rotate live keys, nothing breaks.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo rotation-drill

title "Rotation drill"

step "Before rotation: encrypt a record and sign a message"
ct=$(encrypt_value "$KEY_ROTATION_ENCRYPT" "order 1042: card ending 4242")
printf 'deploy approved by alice' >approval.txt
res=$(sign_raw "$KEY_ROTATION_SIGN" ECDSA_SHA_256 approval.txt)
old_version=$(echo "$res" | jq -r '.KeyVersion')
sig_bytes "$(echo "$res" | jq -r '.Signature')" >approval.sig
ok "ciphertext and signature made with key version $old_version"

step "Rotate both keys"
enc_v=$(rpc kms.RotateKey "$(jq -nc --arg k "$KEY_ROTATION_ENCRYPT" '{KeyId:$k}')" | jq -r '.KeyMetadata.PrimaryVersion')
sign_v=$(rpc kms.RotateKey "$(jq -nc --arg k "$KEY_ROTATION_SIGN" '{KeyId:$k}')" | jq -r '.KeyMetadata.PrimaryVersion')
ok "encryption key now v$enc_v, signing key now v$sign_v"

step "Old ciphertext still decrypts"
ok "$(decrypt_value "$KEY_ROTATION_ENCRYPT" "$ct")"

step "Old signature still verifies with the old public key version"
public_key_pem "$KEY_ROTATION_SIGN" "$old_version" >"pub-v$old_version.pem"
if verify_ecdsa "pub-v$old_version.pem" approval.sig approval.txt; then
  ok "v$old_version signature valid"
else
  bad "v$old_version signature invalid"
fi

step "New signatures use the new version"
res=$(sign_raw "$KEY_ROTATION_SIGN" ECDSA_SHA_256 approval.txt)
sig_bytes "$(echo "$res" | jq -r '.Signature')" >approval-new.sig
new_version=$(echo "$res" | jq -r '.KeyVersion')
public_key_pem "$KEY_ROTATION_SIGN" "$new_version" >"pub-v$new_version.pem"
if verify_ecdsa "pub-v$new_version.pem" approval-new.sig approval.txt; then
  ok "signed with v$new_version, verifies with GetPublicKey(Version=$new_version)"
fi
note "Store (signature, key id, key version) together and verification survives any number of rotations."

done_banner
