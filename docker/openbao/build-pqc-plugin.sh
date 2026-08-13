#!/bin/sh

set -eu

SRC_DIR="${1:-/src}"
OUT_DIR="${2:-/out}"
CACHE_DIR="${CACHE_DIR:-/cache}"
PLUGIN_NAME="${PLUGIN_NAME:-openbao-pqc-plugin}"
PQC_BACKEND="${PQC_BACKEND:-openssl}"

if [ ! -f "${SRC_DIR}/go.mod" ]; then
    echo "skipping PQC plugin build: missing go.mod in ${SRC_DIR}"
    exit 0
fi

case "${PQC_BACKEND}" in
    openssl | wolfssl)
        ;;
    *)
        echo "unsupported PQC_BACKEND=${PQC_BACKEND}; expected openssl or wolfssl"
        exit 1
        ;;
esac

mkdir -p "${OUT_DIR}" "${CACHE_DIR}"

cd "${SRC_DIR}"

tmp_path="${OUT_DIR}/${PLUGIN_NAME}.tmp"
final_path="${OUT_DIR}/${PLUGIN_NAME}"

rm -f "${tmp_path}" "${final_path}" "${final_path}.sha256"

make \
    GOCACHE="/root/.cache/go-build" \
    PLUGIN_NAME="${tmp_path}" \
    OPENSSL_DIR="${CACHE_DIR}/openssl" \
    WOLFSSL_DIR="${CACHE_DIR}/wolfssl" \
    "plugin-${PQC_BACKEND}"

mv "${tmp_path}" "${final_path}"
