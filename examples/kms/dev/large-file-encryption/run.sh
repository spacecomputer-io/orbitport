#!/usr/bin/env bash
# Large file encryption with envelope keys: the file never travels to the KMS.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo large-file-encryption

title "Large file encryption (envelope encryption)"

SIZE_MB="${SIZE_MB:-100}"

step "Create a ${SIZE_MB} MB file"
dd if=/dev/urandom of=dataset.bin bs=1048576 count="$SIZE_MB" 2>/dev/null
orig=$(sha256_hex <dataset.bin)
info "dataset.bin  $(du -h dataset.bin | cut -f1)  sha256 ${orig:0:16}..."

step "Ask the KMS for a data key, encrypt the file locally"
start=$(date +%s)
envelope_encrypt "$KEY_ENCRYPT" dataset.bin dataset.bin.enc
ok "encrypted in $(( $(date +%s) - start ))s"
info "Only the data key request went to the KMS, not the ${SIZE_MB} MB."
info "Stored next to the file: the wrapped data key, unusable without the KMS"
jq '.wrapped_key |= .[0:48] + "..."' dataset.bin.enc.json | show
rm dataset.bin

step "Later: unwrap the data key with the KMS and decrypt locally"
envelope_decrypt dataset.bin.enc dataset.bin || die "integrity check failed"
if [[ "$(sha256_hex <dataset.bin)" == "$orig" ]]; then
  ok "decrypted file matches the original"
else
  bad "decrypted file differs"
fi

step "Someone flips one byte of the encrypted file"
printf '\xff' | dd of=dataset.bin.enc bs=1 seek=1000 conv=notrunc 2>/dev/null
if envelope_decrypt dataset.bin.enc tampered.bin 2>/dev/null; then
  ok "tampered file decrypted"
else
  bad "integrity check failed, nothing decrypted"
fi

done_banner
