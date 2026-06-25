#!/usr/bin/env bash
# Drives ghz against the KMS for every (operation, algorithm) across a
# concurrency sweep. Writes one ghz JSON report per (slug, concurrency) under
# $RESULTS. All knobs are env vars so the same script runs locally and in-cluster.
set -euo pipefail

KMS_ADDR="${KMS_ADDR:-plugin-kms:50004}"
PROTO="${PROTO:-proto/plugins/kms.proto}"
IMPORT="${IMPORT:-proto}"
DATA="${DATA:-bench/kms/data}"
RESULTS="${RESULTS:-bench/kms/results}"
CONCURRENCY="${CONCURRENCY:-1 2 5 10 20 50 100 200}"
DURATION="${DURATION:-10s}" # each cell runs for this long (ghz -z); bounds total wall-clock
TENANTS="${TENANTS:-50}"
SETTLE="${SETTLE:-10}" # drain pause between ops; a saturated OpenBao (heavy keygen) else poisons the next op's cells. ponytail: fixed pause, raise if a heavy op still bleeds into the next

mkdir -p "$RESULTS"

# CreateKey is stateful (aliases are consumed), so it's driven by an inline ghz
# template that mints a unique alias per request instead of a static data file.
createkey_data() {
  local spec usage scheme=""
  case "$1" in
    aes)        spec=AES_256_GCM96; usage=ENCRYPT_DECRYPT ;;
    ed25519)    spec=ED25519;       usage=SIGN_VERIFY ;;
    ecdsa_p256) spec=ECDSA_P256;    usage=SIGN_VERIFY ;;
    ecdsa_p384) spec=ECDSA_P384;    usage=SIGN_VERIFY ;;
    rsa_4096)   spec=RSA_4096;      usage=SIGN_VERIFY ;;
    secp256k1)  spec=ECC_SECG_P256K1; usage=SIGN_VERIFY; scheme=ETHEREUM ;;
  esac
  local s=""
  [ -n "$scheme" ] && s=",\"scheme\":\"$scheme\""
  printf '{"description":"kmsbench","keySpec":"%s","keyUsage":"%s","clientId":"bench-tenant-{{mod .RequestNumber %d}}","alias":"cb-{{.RequestNumber}}-{{.UUID}}"%s}' \
    "$spec" "$usage" "$TENANTS" "$s"
}

# Skip algos the target doesn't support (bootstrap records them in available.txt).
is_avail() { grep -qxF "$1" "$DATA/available.txt" 2>/dev/null; }

# "method  slug  source  algo"  — source is file:<name> (static data) or tmpl:<algo> (CreateKey).
ops=(
  "Encrypt          encrypt-aes        file:encrypt-aes        aes"
  "Decrypt          decrypt-aes        file:decrypt-aes        aes"
  "Sign             sign-ed25519       file:sign-ed25519       ed25519"
  "Sign             sign-ecdsa_p256    file:sign-ecdsa_p256    ecdsa_p256"
  "Sign             sign-ecdsa_p384    file:sign-ecdsa_p384    ecdsa_p384"
  "Sign             sign-rsa_4096      file:sign-rsa_4096      rsa_4096"
  "Sign             sign-secp256k1     file:sign-secp256k1     secp256k1"
  "GenerateDataKey  gendatakey-aes     file:gendatakey-aes     aes"
  "RotateKey        rotate             file:rotate             aes"
  "CreateKey        createkey-aes        tmpl:aes        aes"
  "CreateKey        createkey-ed25519    tmpl:ed25519    ed25519"
  "CreateKey        createkey-ecdsa_p256 tmpl:ecdsa_p256 ecdsa_p256"
  "CreateKey        createkey-ecdsa_p384 tmpl:ecdsa_p384 ecdsa_p384"
  "CreateKey        createkey-secp256k1  tmpl:secp256k1  secp256k1"
  # RSA-4096 keygen (~2s each) saturates OpenBao the hardest — run it LAST so its
  # backlog can't poison a following op's cells.
  "CreateKey        createkey-rsa_4096   tmpl:rsa_4096   rsa_4096"
)

for entry in "${ops[@]}"; do
  read -r method slug src algo <<<"$entry"
  if ! is_avail "$algo"; then
    echo "skip: $slug (algo $algo unavailable on target)"
    continue
  fi
  for c in $CONCURRENCY; do
    out="$RESULTS/${slug}-c${c}.json"
    base=(ghz --insecure --proto "$PROTO" --import-paths "$IMPORT"
          --call "kmsapi.KmsPlugin.${method}" -c "$c" -z "$DURATION" -O json -o "$out")
    if [[ "$src" == file:* ]]; then
      "${base[@]}" --data-file "$DATA/${src#file:}.json" "$KMS_ADDR"
    else
      "${base[@]}" --data "$(createkey_data "${src#tmpl:}")" "$KMS_ADDR"
    fi
    echo "done: $method $slug c=$c -> $out"
  done
  sleep "$SETTLE" # let OpenBao drain before the next op measures
done
