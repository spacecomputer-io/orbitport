#!/usr/bin/env bash
# Shared helpers for the KMS examples. Every run.sh sources this file.
#
# Configuration comes only from examples/.env (shared by all examples), never from the shell:
#   ORBITPORT_PAT            personal access token from the dashboard (required)
#   ORBITPORT_URL            gateway base URL (default https://op.spacecomputer.io)
#   ORBITPORT_DASHBOARD_URL  dashboard URL shown by some demos
#   DEMO_PAUSE=1             wait for Enter between steps

set -euo pipefail

KMS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="$(dirname "$KMS_DIR")"

# ignore copies in the shell, so a stale token there cannot shadow .env
unset ORBITPORT_PAT ORBITPORT_URL ORBITPORT_DASHBOARD_URL DEMO_PAUSE
if [[ -f "$EXAMPLES_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$EXAMPLES_DIR/.env"
  set +a
fi

ORBITPORT_URL="${ORBITPORT_URL:-https://op.spacecomputer.io}"
ORBITPORT_DASHBOARD_URL="${ORBITPORT_DASHBOARD_URL:-https://accounts.spacecomputer.io}"
RPC_URL="${ORBITPORT_URL%/}/api/v1/rpc"

# demo keys, created once by setup.sh (aliases are scoped to your account)
# shellcheck disable=SC2034
{
  KEY_ENCRYPT="examples-encrypt"
  KEY_SIGN="examples-sign-p256"
  KEY_SIGN_ED25519="examples-sign-ed25519"
  KEY_ETH="examples-eth"
  KEY_ROTATION_SIGN="examples-rotation-sign"
  KEY_ROTATION_ENCRYPT="examples-rotation-encrypt"
}

############################################
# Output
############################################

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_BOLD=$'\033[1m' C_DIM=$'\033[2m' C_RED=$'\033[31m' C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m' C_BLUE=$'\033[34m' C_CYAN=$'\033[36m' C_RESET=$'\033[0m'
else
  C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN="" C_RESET=""
fi

STEP_NO=0

title() {
  echo
  echo "${C_BOLD}${C_BLUE}== $* ==${C_RESET}"
}

step() {
  STEP_NO=$((STEP_NO + 1))
  pause
  echo
  echo "${C_BOLD}${STEP_NO}. $*${C_RESET}"
}

info() { echo "   $*"; }
ok()   { echo "   ${C_GREEN}✔ $*${C_RESET}"; }
bad()  { echo "   ${C_RED}✘ $*${C_RESET}"; }
note() { echo "   ${C_YELLOW}$*${C_RESET}"; }
die()  { echo "${C_RED}error: $*${C_RESET}" >&2; exit 1; }

# show a file or value in a dimmed block, long lines cut; awk also ends a last line with no newline
show() {
  awk -v d="$C_DIM" -v r="$C_RESET" '{ if (length($0) > 105) $0 = substr($0, 1, 105) "…"; print "     " d $0 r }'
}

pause() {
  if [[ "${DEMO_PAUSE:-0}" == "1" && -t 0 ]]; then
    read -r -p "   ${C_DIM}(Enter to continue)${C_RESET}" _
  fi
}

done_banner() {
  echo
  echo "${C_BOLD}${C_GREEN}Done.${C_RESET} Files are in ${WORK_DIR#"$KMS_DIR"/}"
}

############################################
# Setup checks
############################################

require_tools() {
  local bin
  for bin in "$@"; do
    command -v "$bin" >/dev/null 2>&1 || die "'$bin' is required but not installed"
  done
}

# Ed25519 verification and prehashed verification need OpenSSL 3 (LibreSSL lacks them)
require_openssl3() {
  openssl version | grep -q '^OpenSSL 3' ||
    die "OpenSSL 3 is required (found: $(openssl version)). On macOS: brew install openssl@3"
}

require_pat() {
  [[ -n "${ORBITPORT_PAT:-}" ]] ||
    die "ORBITPORT_PAT is not set. Create a token in the dashboard and put it in examples/.env"
}

# work dir per demo, kept after the run so the files can be inspected
init_demo() {
  local slug="$1"
  require_tools curl jq openssl
  require_pat
  WORK_DIR="$KMS_DIR/.work/$slug"
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
  cd "$WORK_DIR"
}

############################################
# JSON-RPC
############################################

# rpc_try <method> <params-json>: prints the result JSON, or the error message with status 1.
# The token goes through a header file, so it never shows up in the process list.
rpc_try() {
  local method="$1" params="$2" body resp code err
  body=$(jq -nc --arg m "$method" --argjson p "$params" '{jsonrpc:"2.0", id:1, method:$m, params:$p}')
  echo "   ${C_CYAN}→ $method${C_RESET} ${C_DIM}$(echo "$params" | jq -c 'walk(if type == "string" and length > 40 then .[0:37] + "..." else . end)')${C_RESET}" >&2
  resp=$(curl -sS -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -H @<(printf 'Authorization: Bearer %s\n' "$ORBITPORT_PAT") \
    --data-binary @- -w $'\n%{http_code}' <<<"$body") || { echo "cannot reach $RPC_URL"; return 1; }
  code="${resp##*$'\n'}"
  resp="${resp%$'\n'*}"
  case "$code" in
    401) echo "401 Unauthorized: check ORBITPORT_PAT (expired or revoked?)"; return 1 ;;
    402) echo "402 out of credits: add credits in the dashboard ($ORBITPORT_DASHBOARD_URL)"; return 1 ;;
    429) echo "429 rate limited: wait a few seconds and run again"; return 1 ;;
  esac
  if echo "$resp" | jq -e '.result' >/dev/null 2>&1; then
    echo "$resp" | jq -c '.result'
    return 0
  fi
  err=$(echo "$resp" | jq -r '.error.message // empty' 2>/dev/null || true)
  echo "${err:-HTTP $code: $resp}"
  return 1
}

# rpc <method> <params-json>: like rpc_try, but stops the demo on error
rpc() {
  local out
  if out=$(rpc_try "$@"); then
    echo "$out"
    return 0
  fi
  if [[ "$out" == *"does not belong"* || "$out" == *"not found"* ]]; then
    die "$1 failed: $out (did you run ./setup.sh?)"
  fi
  die "$1 failed: $out"
}

############################################
# Encoding
############################################

b64()  { openssl base64 -A; }
b64d() { openssl base64 -d -A; }
b64url()  { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64url_d() {
  local s
  s=$(tr -- '-_' '+/')
  case $(( ${#s} % 4 )) in
    2) s="$s==" ;;
    3) s="$s=" ;;
  esac
  printf '%s' "$s" | openssl base64 -d -A
}
hex()  { od -An -v -tx1 | tr -d ' \n'; }
unhex() {
  local h i
  h=$(tr -d ' \n')
  # shellcheck disable=SC2059
  for ((i = 0; i < ${#h}; i += 2)); do printf "\\x${h:i:2}"; done
}
sha256_hex() { openssl dgst -sha256 -r | cut -d' ' -f1; }
sha256_b64() { openssl dgst -sha256 -binary | b64; }

# human date for an epoch, BSD and GNU date
fmt_epoch() { date -u -r "$1" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || date -u -d "@$1" '+%Y-%m-%d %H:%M:%S UTC'; }

############################################
# Signing
############################################

# sign_raw <key> <algorithm> <file>: prints the Sign result JSON (Signature, KeyVersion)
sign_raw() {
  local key="$1" alg="$2" file="$3"
  rpc kms.Sign "$(jq -nc --arg k "$key" --arg a "$alg" --arg m "$(b64 <"$file")" \
    '{KeyId:$k, Message:$m, SigningAlgorithm:$a, MessageType:"RAW"}')"
}

# sign_digest <key> <file>: ECDSA P-256 over the file's SHA-256, the file never leaves the machine
sign_digest() {
  local key="$1" file="$2"
  rpc kms.Sign "$(jq -nc --arg k "$key" --arg m "$(sha256_b64 <"$file")" \
    '{KeyId:$k, Message:$m, SigningAlgorithm:"ECDSA_SHA_256", MessageType:"DIGEST"}')"
}

# sig_bytes <Signature>: strips the vault:vN: prefix and decodes, writes DER or raw bytes to stdout
sig_bytes() { printf '%s' "${1#vault:v*:}" | b64d; }

# public_key_pem <key> [version]: writes a PEM public key to stdout.
# Ed25519 keys come back as 32 raw bytes, wrapped here in the standard SPKI header.
public_key_pem() {
  local key="$1" version="${2:-}" params pub
  if [[ -n "$version" ]]; then
    params=$(jq -nc --arg k "$key" --argjson v "$version" '{KeyId:$k, Version:$v}')
  else
    params=$(jq -nc --arg k "$key" '{KeyId:$k}')
  fi
  pub=$(rpc kms.GetPublicKey "$params" | jq -r '.PublicKey')
  if [[ "$pub" == -----BEGIN* ]]; then
    printf '%s\n' "$pub"
  else
    { printf '302a300506032b6570032100' | unhex; printf '%s' "$pub" | b64d; } |
      openssl pkey -pubin -inform DER -outform PEM
  fi
}

# verify_ecdsa <pub.pem> <sig.der> <file>
verify_ecdsa() { openssl dgst -sha256 -verify "$1" -signature "$2" "$3" >/dev/null 2>&1; }

# verify_ed25519 <pub.pem> <sig.bin> <file>
verify_ed25519() { openssl pkeyutl -verify -pubin -inkey "$1" -rawin -in "$3" -sigfile "$2" >/dev/null 2>&1; }

# verify_ecdsa_prehashed <pub.pem> <sig.der> <digest.bin>
verify_ecdsa_prehashed() {
  openssl pkeyutl -verify -pubin -inkey "$1" -in "$3" -sigfile "$2" -pkeyopt digest:sha256 >/dev/null 2>&1
}

############################################
# Envelope encryption: AES-256-CTR + HMAC-SHA256 under a 64-byte data key
############################################

# envelope_encrypt <key> <in> <out>: writes <out> (ciphertext) and <out>.json (wrapped key, iv, mac).
# Only the request for a data key goes to the KMS; the file is encrypted locally.
envelope_encrypt() {
  local key="$1" in="$2" out="$3" dk keyhex enc_key mac_key iv mac
  dk=$(rpc kms.GenerateDataKey "$(jq -nc --arg k "$key" '{KeyId:$k, NumberOfBytes:64}')")
  keyhex=$(echo "$dk" | jq -r '.Plaintext' | b64d | hex)
  enc_key="${keyhex:0:64}" mac_key="${keyhex:64:64}"
  iv=$(openssl rand -hex 16)
  openssl enc -aes-256-ctr -K "$enc_key" -iv "$iv" -in "$in" -out "$out"
  mac=$({ printf '%s' "$iv" | unhex; cat "$out"; } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac_key" -r | cut -d' ' -f1)
  jq -n --arg k "$key" --arg w "$(echo "$dk" | jq -r '.CiphertextBlob')" --arg iv "$iv" --arg mac "$mac" \
    '{key_id:$k, wrapped_key:$w, iv:$iv, mac:$mac, cipher:"aes-256-ctr+hmac-sha256"}' >"$out.json"
  unset keyhex enc_key mac_key
}

# envelope_decrypt <in> <out> [header]: unwraps the data key with the KMS, checks the MAC, decrypts locally.
# The header defaults to <in>.json.
envelope_decrypt() {
  local in="$1" out="$2" hdr keyhex enc_key mac_key iv mac
  hdr=$(cat "${3:-$in.json}")
  keyhex=$(rpc kms.Decrypt "$(jq -nc --arg k "$(echo "$hdr" | jq -r '.key_id')" --arg c "$(echo "$hdr" | jq -r '.wrapped_key')" \
    '{KeyId:$k, CiphertextBlob:$c, EncryptionAlgorithm:"AES_256_GCM96"}')" | jq -r '.Plaintext' | b64d | hex)
  enc_key="${keyhex:0:64}" mac_key="${keyhex:64:64}"
  iv=$(echo "$hdr" | jq -r '.iv')
  mac=$({ printf '%s' "$iv" | unhex; cat "$in"; } | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac_key" -r | cut -d' ' -f1)
  if [[ "$mac" != "$(echo "$hdr" | jq -r '.mac')" ]]; then
    unset keyhex enc_key mac_key
    return 1
  fi
  openssl enc -d -aes-256-ctr -K "$enc_key" -iv "$iv" -in "$in" -out "$out"
  unset keyhex enc_key mac_key
}

############################################
# Field encryption (small values through Encrypt / Decrypt)
############################################

encrypt_value() {
  rpc kms.Encrypt "$(jq -nc --arg k "$1" --arg p "$(printf '%s' "$2" | b64)" \
    '{KeyId:$k, Plaintext:$p, EncryptionAlgorithm:"AES_256_GCM96"}')" | jq -r '.CiphertextBlob'
}

decrypt_value() {
  rpc kms.Decrypt "$(jq -nc --arg k "$1" --arg c "$2" \
    '{KeyId:$k, CiphertextBlob:$c, EncryptionAlgorithm:"AES_256_GCM96"}')" | jq -r '.Plaintext' | b64d
}
