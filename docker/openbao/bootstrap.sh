#!/bin/sh

set -eu

OPENBAO_ADDR="${OPENBAO_ADDR:-http://openbao:8200}"
OPENBAO_TOKEN="${OPENBAO_TOKEN:-root}"
OPENBAO_PLUGIN_DIR="${OPENBAO_PLUGIN_DIR:-/openbao/plugins}"
OPENBAO_ETH_PLUGIN_NAME="${OPENBAO_ETH_PLUGIN_NAME:-ethereum-secrets-plugin}"
OPENBAO_ETH_MOUNT="${OPENBAO_ETH_MOUNT:-ethereum}"
OPENBAO_TRANSIT_MOUNT="${OPENBAO_TRANSIT_MOUNT:-transit}"
OPENBAO_KV_MOUNT="${OPENBAO_KV_MOUNT:-orbitport-kv}"

export BAO_ADDR="${OPENBAO_ADDR}"
export BAO_TOKEN="${OPENBAO_TOKEN}"

plugin_path="${OPENBAO_PLUGIN_DIR}/${OPENBAO_ETH_PLUGIN_NAME}"

echo "waiting for OpenBao at ${BAO_ADDR}"
until bao status >/dev/null 2>&1; do
    sleep 1
done

enable_mount_if_missing() {
    mount_path="$1"
    mount_type="$2"

    if ! bao secrets list | grep -q "^${mount_path}/"; then
        bao secrets enable -path="${mount_path}" "${mount_type}"
    fi
}

enable_mount_if_missing "${OPENBAO_TRANSIT_MOUNT}" transit
enable_mount_if_missing "${OPENBAO_KV_MOUNT}" kv-v2

# PAT signing key (issuer plugin transit mode). Idempotent: read-or-create.
OPENBAO_PAT_KEY="${OPENBAO_PAT_KEY:-pat-signing}"
if ! bao read "${OPENBAO_TRANSIT_MOUNT}/keys/${OPENBAO_PAT_KEY}" >/dev/null 2>&1; then
    bao write -f "${OPENBAO_TRANSIT_MOUNT}/keys/${OPENBAO_PAT_KEY}" type=ecdsa-p256
    echo "created transit key ${OPENBAO_PAT_KEY} (ecdsa-p256)"
fi

if [ -f "${plugin_path}" ]; then
    plugin_sha="$(sha256sum "${plugin_path}" | cut -d' ' -f1)"
    bao plugin register -sha256="${plugin_sha}" secret "${OPENBAO_ETH_PLUGIN_NAME}"
    enable_mount_if_missing "${OPENBAO_ETH_MOUNT}" "${OPENBAO_ETH_PLUGIN_NAME}"
else
    echo "ethereum plugin binary not found at ${plugin_path}; skipping ethereum mount"
fi

echo "OpenBao bootstrap complete"
