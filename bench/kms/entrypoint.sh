#!/usr/bin/env bash
# Container entrypoint: provision fixtures, run the sweep, print the table.
set -euo pipefail
: "${KMS_ADDR:?set KMS_ADDR (e.g. plugin-kms:50004)}"
mkdir -p "$DATA" "$RESULTS"

# Load-generator specs. ponytail: this is the BENCH CLIENT (a GKE pod), NOT the
# OpenBao VM — syscalls here can't see the remote server. Logged only to confirm
# the client isn't the bottleneck behind max-RPS.
echo ">> load generator (bench client, NOT the OpenBao VM):" >&2
echo "   nproc=$(nproc 2>/dev/null) memTotal=$(awk '/MemTotal/{print $2,$3}' /proc/meminfo 2>/dev/null)" >&2
[ -r /sys/fs/cgroup/cpu.max ] && echo "   cgroup: cpu.max=$(cat /sys/fs/cgroup/cpu.max) memory.max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)" >&2 || true

echo ">> bootstrap fixtures against $KMS_ADDR" >&2
kmsbench-bootstrap -addr "$KMS_ADDR" -tenants "${TENANTS:-50}" -out "$DATA" >&2

echo ">> run sweep" >&2
./run.sh >&2

echo ">> results" >&2
./summarize.sh
