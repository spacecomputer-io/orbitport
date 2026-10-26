#!/usr/bin/env bash
# Encrypted backups: encrypt a database dump before it leaves the machine.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo encrypted-backups

title "Encrypted backups"

step "Nightly job dumps the database"
{
  echo "-- dump of shop, $(date -u +%F)"
  echo "CREATE TABLE customers (id int, email text, card_last4 text);"
  for i in $(seq 1 2000); do echo "INSERT INTO customers VALUES ($i, 'user$i@example.com', '$((1000 + i % 9000))');"; done
} >shop.sql
info "shop.sql  $(du -h shop.sql | cut -f1)"

step "Compress, encrypt locally with a data key, upload"
gzip -kf shop.sql
envelope_encrypt "$KEY_ENCRYPT" shop.sql.gz shop.sql.gz.enc
mkdir -p bucket
mv shop.sql.gz.enc shop.sql.gz.enc.json bucket/
rm shop.sql shop.sql.gz
ok "uploaded to bucket/"
ls -1 bucket | show
note "Whoever reads the bucket gets ciphertext. Decrypting needs a call to the KMS with your token."

step "Restore drill"
envelope_decrypt bucket/shop.sql.gz.enc restored.sql.gz || die "integrity check failed"
gunzip -f restored.sql.gz
ok "restored.sql: $(grep -c '^INSERT' restored.sql) rows"

done_banner
