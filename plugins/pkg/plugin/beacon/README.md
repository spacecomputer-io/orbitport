# Orbitport Plugin / Beacon

The Randomness Beacon. Publishes a continuously-updated, IPFS-pinned record of
satellite-derived random numbers under a stable IPNS name.

## Overview

Unlike the other plugins, `beacon` exposes no RPC of its own — it is a
background service. At startup it waits (via `health.WaitForDependencies`) for
the IPFS, cTRNG (`crypto2`), and masterseed plugins to become reachable,
then starts two cooperating loops:

- **Scheduler** — ticks on `ORBITPORT_BEACON_UPDATE_INTERVAL` (default 60s)
  and maintains the registry of beacons to keep fresh.
- **Builder** — pulls fresh entropy, assembles a new beacon record, pins it to
  IPFS, and republishes it under the configured IPNS key alias
  (`ORBITPORT_BEACON_REGISTRY`, default `orbitport-registry`). Consumers
  follow the stable `/ipns/...` name and always get the latest entry.

The IPNS lookup path uses direct alias lookup via `Key().Sign()` rather than
assuming an IPNS record already exists, which avoids a startup race where the
registry key is created but hasn't been published yet.

Configuration: see [CONTEXT.md → Plugin: `beacon`](../../../../CONTEXT.md#plugin-beacon).

## Testing

E2E coverage lives in `plugins/test/e2e_beacon_test.go`; run via
`make go-e2e` (happy) or `make go-e2e-offline` (fallback path).
