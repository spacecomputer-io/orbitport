#!/usr/bin/env bash
# Rotation drill: rotate live keys, nothing breaks.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo rotation-drill

title "Rotation drill"

step "Before rotation: encrypt a record and sign a message"
ct=$(rpc kms.Encrypt "$(jq -nc --arg k "$KEY_ROTATION_ENCRYPT" --arg p "$(printf 'order 1042: card ending 4242' | b64)" \
  '{KeyId:$k, Plaintext:$p, EncryptionAlgorithm:"AES_256_GCM96"}')" | jq -r '.CiphertextBlob')
printf 'deploy approved by alice' >approval.txt
res=$(rpc kms.Sign "$(jq -nc --arg k "$KEY_ROTATION_SIGN" --arg m "$(b64 <approval.txt)" \
  '{KeyId:$k, Message:$m, SigningAlgorithm:"ECDSA_SHA_256", MessageType:"RAW"}')")
old_version=$(echo "$res" | jq -r '.KeyVersion')
sig_bytes "$(echo "$res" | jq -r '.Signature')" >approval.sig
ok "ciphertext and signature made with key version $old_version"

step "Rotate both keys"
enc_v=$(rpc kms.RotateKey "$(jq -nc --arg k "$KEY_ROTATION_ENCRYPT" '{KeyId:$k}')" | jq -r '.KeyMetadata.PrimaryVersion')
sign_v=$(rpc kms.RotateKey "$(jq -nc --arg k "$KEY_ROTATION_SIGN" '{KeyId:$k}')" | jq -r '.KeyMetadata.PrimaryVersion')
ok "encryption key now v$enc_v, signing key now v$sign_v"

step "Old ciphertext still decrypts"
pt=$(rpc kms.Decrypt "$(jq -nc --arg k "$KEY_ROTATION_ENCRYPT" --arg c "$ct" \
  '{KeyId:$k, CiphertextBlob:$c, EncryptionAlgorithm:"AES_256_GCM96"}')" | jq -r '.Plaintext' | b64d)
ok "$pt"

step "Old signature still verifies with the old public key version"
rpc kms.GetPublicKey "$(jq -nc --arg k "$KEY_ROTATION_SIGN" --argjson v "$old_version" '{KeyId:$k, Version:$v}')" | jq -j '.PublicKey' >"pub-v$old_version.pem"
if openssl dgst -sha256 -verify "pub-v$old_version.pem" -signature approval.sig approval.txt >/dev/null 2>&1; then
  ok "v$old_version signature valid"
else
  bad "v$old_version signature invalid"
fi

step "New signatures use the new version"
res=$(rpc kms.Sign "$(jq -nc --arg k "$KEY_ROTATION_SIGN" --arg m "$(b64 <approval.txt)" \
  '{KeyId:$k, Message:$m, SigningAlgorithm:"ECDSA_SHA_256", MessageType:"RAW"}')")
sig_bytes "$(echo "$res" | jq -r '.Signature')" >approval-new.sig
new_version=$(echo "$res" | jq -r '.KeyVersion')
rpc kms.GetPublicKey "$(jq -nc --arg k "$KEY_ROTATION_SIGN" --argjson v "$new_version" '{KeyId:$k, Version:$v}')" | jq -j '.PublicKey' >"pub-v$new_version.pem"
if openssl dgst -sha256 -verify "pub-v$new_version.pem" -signature approval-new.sig approval.txt >/dev/null 2>&1; then
  ok "signed with v$new_version, verifies with GetPublicKey(Version=$new_version)"
fi
note "Store (signature, key id, key version) together and verification survives any number of rotations."

done_banner
