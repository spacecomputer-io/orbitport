#!/usr/bin/env bash
# Crypto-shredding: one data key per user, delete it to erase the user's data.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo crypto-shredding

title "Crypto-shredding for GDPR erasure"

read_record() {
  if [[ ! -f "keys/$1.json" ]]; then
    bad "$1: no data key, record cannot be decrypted"
    return
  fi
  if envelope_decrypt "records/$1.enc" "$1.out" "keys/$1.json"; then
    ok "$1: $(cat "$1.out")"
  else
    bad "$1: integrity check failed"
  fi
}

step "Each user's data is encrypted under their own data key"
mkdir -p records keys
for user in alice bob; do
  [[ $user == alice ]] && orders="[1042,1077]" || orders="[1103]"
  echo "{\"user\":\"$user\",\"email\":\"$user@example.com\",\"orders\":$orders}" >"$user.json"
  envelope_encrypt "$KEY_ENCRYPT" "$user.json" "records/$user.enc"
  mv "records/$user.enc.json" "keys/$user.json"
  rm "$user.json"
done
info "records/ holds ciphertext (also copied to logs, replicas, backups)"
info "keys/ holds one small wrapped data key per user"
{ echo "records/  $(cd records && echo *)"; echo "keys/     $(cd keys && echo *)"; } | show

step "The app reads both users"
read_record alice
read_record bob

step "Alice asks to be forgotten: delete her wrapped data key"
rm keys/alice.json
ok "keys/alice.json deleted"

step "Her records are still on disk, but unreadable"
read_record alice
read_record bob
note "Every copy of the wrapped key must go, including backups of the key table. Her data in old backups then stays ciphertext."

done_banner
