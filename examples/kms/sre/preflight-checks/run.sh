#!/usr/bin/env bash
# Preflight checks: the pipeline confirms the KMS supports what the release needs.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo preflight-checks

title "Preflight checks before deploy"

# experimental schemes are left out of the examples
caps=$(rpc kms.GetCapabilities '{}' | jq -c '.Schemes |= map(select((.Tags // []) | index("experimental") | not))')
echo "$caps" >capabilities.json

# check <scheme> <key spec> [signing algorithm]
check() {
  local scheme="$1" spec="$2" alg="${3:-}" found
  found=$(echo "$caps" | jq --arg s "$scheme" --arg k "$spec" --arg a "$alg" '
    [.Schemes[] | select(.Scheme == $s and ((.KeySpecs // []) | index($k)) != null)
      | select($a == "" or ([(.SigningCapabilities // [])[].SigningAlgorithm] | index($a)) != null)] | length > 0')
  if [[ "$found" == "true" ]]; then
    ok "$scheme $spec${alg:+ $alg}"
    return 0
  fi
  bad "$scheme $spec${alg:+ $alg} not supported"
  return 1
}

preflight() {
  local failed=0 req
  for req in "$@"; do
    # shellcheck disable=SC2086
    check $req || failed=1
  done
  if (( failed )); then bad "preflight failed, deploy stopped"; else ok "preflight passed, deploying"; fi
}

step "Supported schemes"
echo "$caps" | jq -r '.Schemes[] | "\(.Scheme): \((.KeySpecs // []) | join(", "))"' | show

step "Release 2.4 needs: AES-256 encryption, P-256 signing, Ethereum signing"
preflight "TRANSIT AES_256_GCM96" "TRANSIT ECDSA_P256 ECDSA_SHA_256" "ETHEREUM ECC_SECG_P256K1 ETHEREUM_SECP256K1"

step "Release 3.0 also asks for RSA 8192, which is not offered"
preflight "TRANSIT AES_256_GCM96" "TRANSIT RSA_8192 RSASSA_PSS_SHA_256"

done_banner
