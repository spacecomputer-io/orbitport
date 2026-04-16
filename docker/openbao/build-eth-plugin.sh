#!/bin/sh

set -eu

SRC_DIR="${1:-/src}"
OUT_DIR="${2:-/out}"
PLUGIN_NAME="${PLUGIN_NAME:-ethereum-secrets-plugin}"

if [ ! -f "${SRC_DIR}/go.mod" ]; then
    echo "skipping ethereum plugin build: missing go.mod in ${SRC_DIR}"
    exit 0
fi

mkdir -p "${OUT_DIR}"

cd "${SRC_DIR}"
tmp_path="${OUT_DIR}/${PLUGIN_NAME}.tmp"
final_path="${OUT_DIR}/${PLUGIN_NAME}"

rm -f "${tmp_path}" "${final_path}" "${final_path}.sha256"

CGO_ENABLED=1 go build -o "${tmp_path}" ./cmd/plugin
mv "${tmp_path}" "${final_path}"
