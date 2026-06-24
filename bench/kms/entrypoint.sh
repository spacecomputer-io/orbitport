#!/usr/bin/env bash
# Container entrypoint: provision fixtures, run the sweep, print the table.
set -euo pipefail
: "${KMS_ADDR:?set KMS_ADDR (e.g. plugin-kms:50004)}"
mkdir -p "$DATA" "$RESULTS"

echo ">> bootstrap fixtures against $KMS_ADDR" >&2
kmsbench-bootstrap -addr "$KMS_ADDR" -tenants "${TENANTS:-50}" -out "$DATA" >&2

echo ">> run sweep" >&2
./run.sh >&2

echo ">> results" >&2
./summarize.sh
