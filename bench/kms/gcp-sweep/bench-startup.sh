#!/usr/bin/env bash
# GCE metadata startup-script for a single-use KMS bench VM. Runs the ENTIRE KMS
# stack (openbao + proxy + plugin-kms) plus the kmsbench load generator on this
# one box — see bench/kms/gcp-sweep/README.md — and streams the result table to
# the serial console, which the driving CI workflow (bench-kms-sweep.yaml in
# spacecomputer-global-infra) scrapes. The VM has no SSH access and no service
# account; the serial console is the only channel out.
#
# Everything the bench needs is built from the orbitport checkout (op-plugin has
# a compose `build:` context; openbao is a public image), so the only secret
# this VM needs is a short-lived GitHub token to clone the private repo.
#
# ponytail: clone token rides in VM metadata — fine for a throwaway, no-inbound,
# minutes-lived VM. Harden to a signed-URL tarball or GH App token if these VMs
# ever live longer or the repo's clone surface widens.
set -uo pipefail

MARK_START="===KMSBENCH_RESULT_START==="
MARK_END="===KMSBENCH_RESULT_END==="
MARK_DONE="===KMSBENCH_DONE==="   # workflow polls for this; ALWAYS emitted, pass or fail
MARK_FAIL="===KMSBENCH_FAILED==="

meta() {
  curl -sf -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"
}

# Emit DONE on any exit so the workflow never waits the full timeout on a failure.
finish() { echo "$MARK_DONE"; }
trap finish EXIT
fail() { echo "$MARK_FAIL $*"; exit 0; }   # exit 0: don't boot-loop the startup script

CLONE_TOKEN="$(meta clone-token)"        || fail "no clone-token in metadata"
ORBITPORT_REF="$(meta orbitport-ref)"    || ORBITPORT_REF="main"
CONCURRENCY="$(meta concurrency)"        || CONCURRENCY="1 5 20 50"
TENANTS="$(meta tenants)"                || TENANTS="50"
MACHINE_TYPE="$(meta machine-type)"      || MACHINE_TYPE="unknown"

echo ">> kms bench starting: machine_type=$MACHINE_TYPE ref=$ORBITPORT_REF concurrency='$CONCURRENCY' tenants=$TENANTS"

# --- 1. docker (official apt repo) ------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y                                   || fail "apt update"
  apt-get install -y ca-certificates curl gnupg git   || fail "apt install prereqs"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc || fail "docker gpg"
  chmod a+r /etc/apt/keyrings/docker.asc
  # shellcheck disable=SC1091  # /etc/os-release is a runtime file on the VM
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y                                   || fail "apt update (docker repo)"
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin || fail "apt install docker"
  systemctl enable --now docker                       || fail "start docker"
fi

# --- 2. clone orbitport (shallow) -------------------------------------------
rm -rf /root/orbitport
git clone --depth 1 --branch "$ORBITPORT_REF" \
  "https://x-access-token:${CLONE_TOKEN}@github.com/spacecomputer-io/orbitport.git" /root/orbitport \
  || fail "git clone orbitport@$ORBITPORT_REF"
cd /root/orbitport || fail "cd orbitport"

# --- 3. bring up the KMS stack ----------------------------------------------
# `up plugin-kms` pulls the whole chain via depends_on: eth-plugin-builder ->
# openbao -> openbao-bootstrap -> plugin-kms. The ethereum plugin is skipped
# gracefully (empty source dir => build-eth-plugin.sh and bootstrap.sh both
# no-op it), so secp256k1/ethereum bench rows self-skip — everything else runs.
mkdir -p /tmp/empty-eth-plugin
export ORBITPORT_OPENBAO_ETH_PLUGIN_DIR=/tmp/empty-eth-plugin
docker compose up -d --wait --build plugin-kms || fail "docker compose up plugin-kms"

# --- 4. build + run kmsbench (existing image, unmodified) -------------------
docker build -f bench/kms/Dockerfile -t kmsbench:local . || fail "docker build kmsbench"
# compose project name = checkout dir name ("orbitport") => network orbitport_default
RESULTS="$(docker run --rm --network orbitport_default \
  -e KMS_ADDR=plugin-kms:50004 -e TENANTS="$TENANTS" -e CONCURRENCY="$CONCURRENCY" \
  kmsbench:local)" || fail "kmsbench run"

# --- 5. hand the table back over the serial console -------------------------
echo "$MARK_START"
echo "<!-- machine_type: $MACHINE_TYPE -->"
echo "$RESULTS"
echo "$MARK_END"
# trap emits MARK_DONE
