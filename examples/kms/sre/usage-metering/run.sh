#!/usr/bin/env bash
# Usage and metering: every call is counted per operation in the dashboard.

source "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"
init_demo usage-metering

title "Usage and metering"

step "Run a small burst of operations"
for i in 1 2 3; do encrypt_value "$KEY_ENCRYPT" "record $i" >/dev/null; done
printf 'usage demo' >msg.txt
for i in 1 2; do sign_raw "$KEY_SIGN" ECDSA_SHA_256 msg.txt >/dev/null; done
rpc kms.GetCapabilities '{}' >/dev/null
ok "3 x kms.Encrypt, 2 x kms.Sign, 1 x kms.GetCapabilities"

step "Open the dashboard"
info "$ORBITPORT_DASHBOARD_URL"
info "Requests are counted per operation (kms.Encrypt, kms.Sign, ...) with the credits each one used."
note "One place to see who called what and what it cost for the account."

done_banner
