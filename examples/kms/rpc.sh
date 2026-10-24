#!/usr/bin/env bash
# One-off JSON-RPC call with the examples configuration. Safe from any shell.
#
#   ./rpc.sh <method> [params-json]
#   ./rpc.sh kms.GetKeyMetadata '{"KeyId":"examples-sign-p256"}'
#   ./rpc.sh kms.GetCapabilities

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[[ $# -ge 1 ]] || { sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
require_tools curl jq
require_pat
params="${2:-}"
[[ -n "$params" ]] || params='{}'
echo "$params" | jq -e . >/dev/null 2>&1 || die "params must be valid JSON: $params"

rpc "$1" "$params" | jq .
