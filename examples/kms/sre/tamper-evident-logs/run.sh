#!/usr/bin/env bash
# Tamper-evident logs: sign a daily digest, prove later that nothing changed.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo tamper-evident-logs

title "Tamper-evident logs"

audit() {
  local meta
  meta=$(cat audit-2026-10-22.log.sig.json)
  public_key_pem "$(echo "$meta" | jq -r '.key_id')" "$(echo "$meta" | jq -r '.key_version')" >audit-pub.pem
  echo "$meta" | jq -r '.signature' | b64d >audit.sig
  if verify_ecdsa audit-pub.pem audit.sig "$1"; then
    ok "auditor: $1 matches the signed digest"
  else
    bad "auditor: $1 was modified after signing"
  fi
}

step "A day of audit logs"
cat >audit-2026-10-22.log <<'LOG'
2026-10-22T08:58:12Z user=alice action=login ip=10.0.0.12
2026-10-22T09:03:40Z user=bob action=login ip=10.0.0.31
2026-10-22T09:05:02Z user=bob action=role.grant target=bob role=admin
2026-10-22T09:06:55Z user=bob action=export table=customers rows=48210
2026-10-22T09:30:17Z user=carol action=login ip=10.0.0.7
2026-10-22T10:12:44Z user=alice action=deploy service=api version=2.3.1
LOG
show <audit-2026-10-22.log

step "At midnight, sign the SHA-256 of the file"
res=$(sign_digest "$KEY_SIGN" audit-2026-10-22.log)
jq -n --arg k "$KEY_SIGN" --argjson v "$(echo "$res" | jq '.KeyVersion')" \
  --arg s "$(sig_bytes "$(echo "$res" | jq -r '.Signature')" | b64)" \
  '{key_id:$k, key_version:$v, signature:$s}' >audit-2026-10-22.log.sig.json
ok "audit-2026-10-22.log.sig.json stored next to the log"

step "Months later, an auditor checks the log"
audit audit-2026-10-22.log

step "Someone with disk access removes the role.grant by bob"
grep -v 'user=bob action=role.grant' audit-2026-10-22.log >audit-edited.log || true
info "$(( $(wc -l <audit-2026-10-22.log) - $(wc -l <audit-edited.log) )) line(s) removed"
audit audit-edited.log
note "The signature records the key version, so this check works after any number of rotations."

done_banner
