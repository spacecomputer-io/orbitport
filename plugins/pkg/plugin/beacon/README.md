# Orbitport Plugin / Beacon

The Randomness Beacon. Publishes a continuously-updated, IPFS-pinned record of
satellite-derived random numbers under a stable IPNS name.

## Overview

Unlike the other plugins, `beacon` exposes no RPC of its own — it is a
background service. At startup it waits (via `health.WaitForDependencies`) for
the IPFS, cTRNG (aptosorbital), and masterseed plugins to become reachable,
then starts two cooperating loops:

- **Scheduler** — ticks on `BEACON_UPDATE_INTERVAL` (default 60s) and maintains
  the registry of beacons to keep fresh.
- **Builder** — pulls fresh entropy, assembles a new beacon record, pins it to
  IPFS, and republishes it under the configured IPNS key alias
  (`BEACON_REGISTRY`, default `orbitport-registry`). Consumers follow the
  stable `/ipns/...` name and always get the latest entry.

The IPNS lookup path uses direct alias lookup via `Key().Sign()` rather than
assuming an IPNS record already exists, which avoids a startup race where the
registry key is created but hasn't been published yet.

## Configuration

| Env var                             | Default                     | Description                                    |
| ----------------------------------- | --------------------------- | ---------------------------------------------- |
| `ORBITPORT_IPFS_PLUGIN`             | `plugin-ipfs:50002`         | gRPC address of the IPFS plugin                |
| `ORBITPORT_CTRNG_PLUGIN`            | `plugin-aptos-orbital:50001`| gRPC address of the cTRNG (aptosorbital) plugin|
| `ORBITPORT_MASTERSEED_PLUGIN`       | `plugin-masterseed:50003`   | gRPC address of the masterseed plugin          |
| `ORBITPORT_BEACON_REGISTRY`         | `orbitport-registry`        | IPNS key alias used for publishing             |
| `ORBITPORT_DEFAULT_BEACON_NAME`     | `randomness-beacon1.0`      | Default beacon identifier                      |
| `ORBITPORT_BEACON_MSG`              | (preset)                    | Embedded message included in each beacon round |
| `ORBITPORT_BEACON_UPDATE_INTERVAL`  | `60`                        | Scheduler tick in seconds                      |
| `ORBITPORT_IPFS_ADDRESS`            | `http://ipfs-node:5001`     | Kubo HTTP API (for direct IPNS key operations) |
| `ORBITPORT_REGISTRY_RETRIEVAL_TIMEOUT` | `90`                     | Seconds to wait when loading the registry      |

## Testing

E2E coverage lives in `plugins/test/e2e_beacon_test.go`; run via
`make go-e2e` (happy) or `make go-e2e-offline` (fallback path).
