#!/usr/bin/env bash
# Field-level PII encryption: encrypt sensitive columns before they reach the database.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo pii-encryption

title "Field-level PII encryption"

step "The app receives two sign-ups"
cat >users.csv <<'CSV'
id,name,email,national_id
1,Ada Lovelace,ada@example.com,AB123456
2,Alan Turing,alan@example.com,CD789012
CSV
show <users.csv

step "Before writing to the DB, the app encrypts email and national_id with the KMS"
encrypt_field() {
  rpc kms.Encrypt "$(jq -nc --arg k "$KEY_ENCRYPT" --arg p "$(printf '%s' "$1" | b64)" \
    '{KeyId:$k, Plaintext:$p, EncryptionAlgorithm:"AES_256_GCM96"}')" | jq -r '.CiphertextBlob'
}
echo "id,name,email,national_id" >db.csv
tail -n +2 users.csv | while IFS=, read -r id name email nid; do
  email_ct=$(encrypt_field "$email")
  nid_ct=$(encrypt_field "$nid")
  echo "$id,$name,$email_ct,$nid_ct" >>db.csv
done
ok "rows stored with encrypted columns"

step "The DB dump leaks. This is what the attacker sees"
# each blob is base64 JSON around the ciphertext; decoding it reveals nothing more
inner() { printf '%s' "$1" | b64d | jq -r '.ciphertext' | cut -c1-30; }
{
  head -1 db.csv
  tail -n +2 db.csv | while IFS=, read -r id name email nid; do
    echo "$id,$name,$(inner "$email")…,$(inner "$nid")…"
  done
} | show
note "Names stay searchable, the sensitive columns are ciphertext. No key is in the dump or in the app."

step "The app reads a row back and decrypts only what it needs"
row=$(sed -n 2p db.csv)
email_ct=$(echo "$row" | cut -d, -f3)
email=$(rpc kms.Decrypt "$(jq -nc --arg k "$KEY_ENCRYPT" --arg c "$email_ct" \
  '{KeyId:$k, CiphertextBlob:$c, EncryptionAlgorithm:"AES_256_GCM96"}')" | jq -r '.Plaintext' | b64d)
ok "row 1 email: $email"

done_banner
