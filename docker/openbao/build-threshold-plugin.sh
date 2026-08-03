#!/bin/sh

set -eu

SRC_DIR="${1:-/src}"
OUT_DIR="${2:-/out}"
PLUGIN_NAME="${PLUGIN_NAME:-openbao-threshold-plugin}"
WORK_DIR="${WORK_DIR:-/work/openbao-threshold-plugin}"

if [ ! -f "${SRC_DIR}/go.mod" ]; then
    echo "skipping threshold plugin build: missing go.mod in ${SRC_DIR}"
    exit 0
fi

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}" "${OUT_DIR}"
cp -R "${SRC_DIR}/." "${WORK_DIR}/"

cd "${WORK_DIR}"
rm -rf .cache/boringssl

tmp_path="${OUT_DIR}/${PLUGIN_NAME}.tmp"
final_path="${OUT_DIR}/${PLUGIN_NAME}"

rm -f "${tmp_path}" "${final_path}" "${final_path}.sha256"

make build-boringssl

CGO_ENABLED=1 \
CGO_CFLAGS="-I${WORK_DIR}/.cache/boringssl/include" \
CGO_LDFLAGS="-L${WORK_DIR}/.cache/boringssl/build -lcrypto" \
    go build -o "${tmp_path}" ./cmd/plugin

mv "${tmp_path}" "${final_path}"
