# Orbitport Plugin / IPFS

Thin wrapper over a local Kubo (go-ipfs) node that gives the gateway a
bounded, cached object store and IPNS publishing surface.

## Overview

Implements `IpfsPlugin` (`proto/plugins/ipfs.proto`) with:

- `Add(data)` — pin a blob, returns its CID.
- `Get(key, namespace)` — fetch a blob by CID or resolve via IPNS.
- `Publish(cid, publish_name)` — publish a CID under an IPNS key alias so
  consumers can follow a stable name across updates (used by the beacon).
- `Delete(cid)` — unpin and remove.
- `KeyInfo(publish_name)` — look up the `/ipns/<pub-key>` address for an
  existing key alias (direct lookup via `Key().Sign()`).

The plugin talks to a Kubo node over its HTTP API (`ORBITPORT_IPFS_ADDRESS`)
and fronts it with an LRU cache sized by `ORBITPORT_PLUGIN_CACHE_SIZE`.
Oversized payloads bypass the cache to avoid OOM on Add/Get, and `Add`/`Get`
enforce per-request byte ceilings (`PLUGIN_MAX_ADD_BYTES`,
`PLUGIN_MAX_GET_BYTES`). Published IPNS records use
`ORBITPORT_IPNS_LEASE_DURATION` as the record lifetime.

## Configuration

| Env var                         | Default                 | Description                      |
| ------------------------------- | ----------------------- | -------------------------------- |
| `ORBITPORT_IPFS_ADDRESS`        | `http://localhost:5001` | Kubo HTTP API endpoint           |
| `ORBITPORT_PLUGIN_CACHE_SIZE`   | `100`                   | LRU cache entry count            |
| `ORBITPORT_IPNS_LEASE_DURATION` | `24h`                   | IPNS record lifetime             |
| `ORBITPORT_PLUGIN_MAX_ADD_BYTES`| `1048576`               | Max bytes accepted by `Add`      |
| `ORBITPORT_PLUGIN_MAX_GET_BYTES`| `1048576`               | Max bytes returned by `Get`      |
