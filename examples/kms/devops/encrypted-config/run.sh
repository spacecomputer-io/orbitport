#!/usr/bin/env bash
# Encrypted config files: commit the ciphertext, decrypt at deploy time.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo encrypted-config

title "Encrypted config files"

step "A values file with secrets"
cat >values.secret.yaml <<'YAML'
database:
  password: "pg-9f3c1a"
smtp:
  password: "mail-77b2e0"
oauth:
  clientSecret: "oa-c41d93"
YAML
show <values.secret.yaml

step "Encrypt it with a data key from the KMS and commit only the ciphertext"
dk=$(rpc kms.GenerateDataKey "$(jq -nc --arg k "$KEY_ENCRYPT" '{KeyId:$k, NumberOfBytes:64}')")
envelope_encrypt "$dk" values.secret.yaml values.secret.yaml.enc
# drop the plaintext data key, only the wrapped copy is kept
unset dk
mkdir -p repo
mv values.secret.yaml.enc values.secret.yaml.enc.json repo/
rm values.secret.yaml
ls -1 repo | show
if grep -rq 'pg-9f3c1a' repo; then bad "plaintext found in repo"; else ok "no plaintext in the repo"; fi

step "At deploy time, the pipeline decrypts it with the KMS"
dk=$(rpc kms.Decrypt "$(jq -c '{KeyId:.key_id, CiphertextBlob:.wrapped_key, EncryptionAlgorithm:"AES_256_GCM96"}' repo/values.secret.yaml.enc.json)" | jq -r '.Plaintext')
envelope_decrypt "$dk" repo/values.secret.yaml.enc values.secret.yaml || die "integrity check failed"
ok "values.secret.yaml restored for helm, never committed"
show <values.secret.yaml

done_banner
