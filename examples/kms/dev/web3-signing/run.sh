#!/usr/bin/env bash
# Web3 backend signing: an Ethereum key that never leaves the KMS.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo web3-signing

title "Web3 backend signing (EIP-191)"

step "The backend's Ethereum key lives in the KMS"
meta=$(rpc kms.GetKeyMetadata "$(jq -nc --arg k "$KEY_ETH" '{KeyId:$k}')")
address=$(echo "$meta" | jq -r '.KeyMetadata.Address')
ok "address $address"

step "Sign a login challenge with EIP-191 (personal_sign)"
message="Sign in to example.app
Nonce: $(openssl rand -hex 8)
Issued at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s' "$message" >message.txt
show <message.txt
sig=$(rpc kms.Sign "$(jq -nc --arg k "$KEY_ETH" --arg m "$message" \
  '{KeyId:$k, Message:$m, SigningAlgorithm:"ETHEREUM_SECP256K1", MessageType:"EIP191"}')" | jq -r '.Signature')
echo "$sig" >signature.txt
ok "signature ${sig:0:20}...${sig: -8}"

step "Anyone recovers the signer's address off-chain"
if command -v cast >/dev/null 2>&1; then
  if cast wallet verify --address "$address" "$message" "$sig" >/dev/null 2>&1; then
    ok "cast: signature is from $address"
  else
    bad "cast: signature does not recover to $address"
  fi
  step "Someone changes the nonce"
  if cast wallet verify --address "$address" "${message/Nonce: /Nonce: 00}" "$sig" >/dev/null 2>&1; then
    ok "cast: edited message accepted"
  else
    bad "cast: edited message does not recover to $address"
  fi
else
  note "Install Foundry (cast) to check it here, or use any EIP-191 verifier:"
  info "cast wallet verify --address $address \"\$(cat message.txt)\" $sig"
fi

done_banner
