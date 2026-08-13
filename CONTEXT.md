# Orbitport — Context

Deep-dive context for contributors and AI tooling. The user-facing entrypoint is [`README.md`](README.md); a flat repo map is [`llms.txt`](llms.txt). This document is the single source of truth for env-var reference and internal architecture detail.

## Architecture

The project is split across two languages. A **Rust gateway** terminates HTTP and JSON-RPC at the edge, handles JWT authentication and per-token rate limiting, and fans out to a set of **Go plugins** over gRPC. Plugins are stateless sidecars that either wrap an upstream provider (e.g. Aptos Orbital, IPFS) or run a background service (e.g. the randomness beacon).

The gateway is a [Warp](https://github.com/seanmonstar/warp) + [Tonic](https://github.com/hyperium/tonic) server. At startup it performs a gRPC health-check wait on the `auth` and `masterseed` plugins (60 s deadline) before it accepts traffic, so a half-started stack never serves requests. Once live it listens on two ports: HTTP on `8080` and Prometheus metrics on `9100`.

All plugins share a single `op-plugin` binary that dispatches to the right implementation based on the `ORBITPORT_PLUGIN` env var — which is how one Docker image ends up running six different services in the compose stack. Plugin-to-plugin discovery is env-var driven (`ORBITPORT_APTOS_PLUGIN`, `ORBITPORT_IPFS_PLUGIN`, etc.), and every plugin exports its own Prometheus metrics on port `9000`.

Protobuf definitions live at the top-level [`proto/`](proto/) directory, split into `proto/services/` (external contracts the gateway exposes to clients, e.g. `ctrng.proto`) and `proto/plugins/` (internal gRPC contracts between gateway and plugins). Rust bindings are generated at build time via `tonic-build`; Go bindings are checked in under `plugins/proto/plugins/`.

## Repository layout

```
gateway/                    Rust HTTP + JSON-RPC server (Warp + Tonic)
  src/services/             External service layer (ctrng, jrpc)
  src/plugins.rs            Plugin catalog / gRPC client wiring
  src/filters.rs            Auth middleware + per-JWT rate limiter
  src/metrics.rs            Prometheus metrics

plugins/                    Go gRPC plugin services
  cmd/plugin/               Plugin dispatcher binary (selects via ORBITPORT_PLUGIN)
  cmd/mocker/               Mock Aptos Orbital API for dev/e2e
  pkg/plugin/               Plugin implementations (see below)
  pkg/core/health/          gRPC health-check dependency waiter
  proto/plugins/            Generated Go code for internal plugin protos
  test/                     E2E tests (happy / offline profiles)

proto/                      Protobuf source of truth
  services/                 External gateway services (ctrng.proto)
  plugins/                  Internal plugin RPCs (ao, auth, ipfs, masterseed)

docker-compose.yaml         Stack against real upstreams (Aptos Orbital + Auth0)
dev.docker-compose.yaml     Dev stack (mocker + authnoop, no external credentials)
beacons.yaml                Public beacon registry
```

## Plugins

| Plugin | Role | Notes |
| --- | --- | --- |
| [`aptosorbital`](plugins/pkg/plugin/aptosorbital/README.md) | Fetches true random seeds from the Aptos Orbital satellite API | Wraps `api.aptosorbital.com` |
| [`auth`](plugins/pkg/plugin/auth/README.md) | Fail-closed Auth0 JWT validation | Refuses to start without `AUTH0_DOMAIN`/`AUTH0_AUDIENCE` |
| [`authnoop`](plugins/pkg/plugin/authnoop/README.md) | Dev-only noop auth — accepts every token | Used in `dev.docker-compose.yaml` |
| [`ipfs`](plugins/pkg/plugin/ipfs/README.md) | Kubo wrapper with LRU cache, size ceilings, and IPNS publishing | Backs the beacon |
| [`masterseed`](plugins/pkg/plugin/masterseed/README.md) | Rolling pool of satellite seeds with offset-reserved derivation | Serves cTRNG to the gateway |
| [`beacon`](plugins/pkg/plugin/beacon/README.md) | Background service that publishes the randomness beacon to IPFS/IPNS | No RPC; consumes the others |
| [`kms`](plugins/pkg/plugin/kms/README.md) | Multi-tenant Key Management Service (encrypt / decrypt / sign / rotate) backed by OpenBao | Wraps Transit + Ethereum secrets engines |
| [`account`](plugins/pkg/plugin/account/README.md) | Per-request credit gating against the dashboard backend account service | Holds credits before serving compute; settles on success, releases on failure |

## Configuration

All env vars are prefixed `ORBITPORT_`. They can be supplied via `.env` at repo root (the gateway also reads `.gateway.env` if present). [`.example.env`](.example.env) tracks the credentials needed to run the production compose stack; the tables below list every knob the binaries actually read, so this file is the place to look when changing a default or adding a new variable.

### Gateway

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_HTTP_PORT` | `8080` | HTTP server port |
| `ORBITPORT_METRICS_PORT` | `9100` | Prometheus metrics port |
| `ORBITPORT_AUTH_PLUGIN` | — | gRPC URL of the auth plugin (required) |
| `ORBITPORT_MASTERSEED_PLUGIN` | — | gRPC URL of the masterseed plugin (required) |
| `ORBITPORT_TRNG_PLUGIN` | — | gRPC URL of the cTRNG plugin (`aptosorbital`) |
| `ORBITPORT_KMS_PLUGIN` | — | gRPC URL of the KMS plugin |
| `ORBITPORT_ACCOUNT_PLUGIN` | — | gRPC URL of the account plugin. When set, JWT-authenticated routes hold credits before serving, settle on success, and release on downstream failure. |
| `ORBITPORT_RATE_LIMIT` | `40` | Max requests per token per window |
| `ORBITPORT_RATE_LIMIT_WINDOW` | `10` | Rate-limit window in seconds (default ≈ 4 req/s per token) |
| `ORBITPORT_BULK_MAX` | `10` | Max items per bulk TRNG request |

### Plugin dispatcher

Applies to every `op-plugin` container regardless of which plugin it dispatches to:

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_PLUGIN` | `aptosorbital` | Which plugin this binary runs |
| `ORBITPORT_GRPC_PORT` | `50001` | gRPC listen port |
| `ORBITPORT_METRICS_PORT` | `9000` | Prometheus metrics port |

### Plugin: `auth`

| Env var | Required | Purpose |
| --- | --- | --- |
| `ORBITPORT_AUTH0_DOMAIN` | yes | Auth0 tenant domain |
| `ORBITPORT_AUTH0_AUDIENCE` | yes | Expected `aud` claim value |

`authnoop` takes no configuration.

### Plugin: `aptosorbital`

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_APTOS_ORBITAL_CLIENT_ID` | — | OAuth client ID (required) |
| `ORBITPORT_APTOS_ORBITAL_CLIENT_SECRET` | — | OAuth client secret (required) |
| `ORBITPORT_APTOS_ORBITAL_API_URL` | `https://api.aptosorbital.com` | Aptos Orbital API base URL |
| `ORBITPORT_APTOS_ORBITAL_AUTH_URL` | `https://auth.aptosorbital.com/oauth2/token` | OAuth token endpoint |
| `ORBITPORT_APTOS_ORBITAL_RATE_LIMIT` | `0.1` | Outbound rate limit (req/s) |

### Plugin: `masterseed`

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_APTOS_PLUGIN` | — | gRPC address of the `aptosorbital` plugin (required) |
| `ORBITPORT_DEFAULT_MASTER_SEEDS` | — | Comma-separated hex seeds for bootstrap |
| `ORBITPORT_MASTERSEED_TRNG_SIZE` | `32` | Derived output size in bytes |
| `ORBITPORT_MASTERSEED_MAX_SEEDS` | `100` | Max master seeds kept in the pool |
| `ORBITPORT_MASTERSEED_PERIOD` | `3600` | Refresh interval in seconds |
| `ORBITPORT_MASTER_SEED_MAX_COUNT_PER_REQUEST` | `1000` | Max derived seeds per `GetSeeds` call |

### Plugin: `ipfs`

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_IPFS_ADDRESS` | `http://localhost:5001` | Kubo HTTP API endpoint |
| `ORBITPORT_PLUGIN_CACHE_SIZE` | `100` | LRU cache entry count |
| `ORBITPORT_IPNS_LEASE_DURATION` | `24h` | IPNS record lifetime |
| `ORBITPORT_PLUGIN_MAX_ADD_BYTES` | `1048576` | Max bytes accepted by `Add` |
| `ORBITPORT_PLUGIN_MAX_GET_BYTES` | `1048576` | Max bytes returned by `Get` |

### Plugin: `beacon`

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_IPFS_PLUGIN` | `plugin-ipfs:50002` | gRPC address of the IPFS plugin |
| `ORBITPORT_CTRNG_PLUGIN` | `plugin-aptos-orbital:50001` | gRPC address of the cTRNG plugin |
| `ORBITPORT_MASTERSEED_PLUGIN` | `plugin-masterseed:50003` | gRPC address of the masterseed plugin |
| `ORBITPORT_BEACON_REGISTRY` | `orbitport-registry` | IPNS key alias used for publishing |
| `ORBITPORT_DEFAULT_BEACON_NAME` | `randomness-beacon1.0` | Default beacon identifier |
| `ORBITPORT_BEACON_MSG` | (preset) | Embedded message included in each beacon round |
| `ORBITPORT_BEACON_UPDATE_INTERVAL` | `60` | Scheduler tick in seconds |
| `ORBITPORT_IPFS_ADDRESS` | `http://ipfs-node:5001` | Kubo HTTP API (for direct IPNS key operations) |
| `ORBITPORT_REGISTRY_RETRIEVAL_TIMEOUT` | `90` | Seconds to wait when loading the registry |

### Plugin: `kms`

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_KMS_OPENBAO_PROXY_URL` | — | HTTP base URL of the OpenBao proxy (required) |
| `ORBITPORT_KMS_TRANSIT_MOUNT` | `transit` | Mount path of OpenBao's Transit Secrets Engine |
| `ORBITPORT_KMS_ETHEREUM_MOUNT` | `ethereum` | Mount path of the Ethereum Secrets Engine |
| `ORBITPORT_KMS_PQC_MOUNT` | `pqc` | Mount path of the PQC Secrets Engine |
| `ORBITPORT_KMS_KV_MOUNT` | `secret` | KV v2 mount used to persist key metadata |
| `ORBITPORT_KMS_TIMEOUT_SECS` | `10` | HTTP timeout per OpenBao request |

### Plugin: `account`

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_ACCOUNT_DASHBOARD_URL` | — | HTTPS base URL of the dashboard backend (required). Plugin calls `/service/credits/hold`, `/service/credits/hold/:id/settle`, and `/service/credits/hold/:id/release`. |
| `ORBITPORT_ACCOUNT_AUTH0_DOMAIN` | — | Auth0 tenant domain used for the M2M client credentials grant (required). |
| `ORBITPORT_ACCOUNT_AUTH0_AUDIENCE` | — | Audience requested when minting the M2M token. Same audience the dashboard's `ServiceAuthGuard` accepts (required). |
| `ORBITPORT_ACCOUNT_AUTH0_CLIENT_ID` | — | M2M application client_id (required). Must be present in the dashboard's `ALLOWED_SERVICE_CLIENT_IDS`. |
| `ORBITPORT_ACCOUNT_AUTH0_CLIENT_SECRET` | — | M2M application client_secret (required). |
| `ORBITPORT_ACCOUNT_CREDITS_PER_UNIT` | `1` | Credits charged per compute unit. Gateway always sends `units=1` in MVP; future operations may vary. |
| `ORBITPORT_ACCOUNT_HTTP_TIMEOUT_SECS` | `5` | HTTP timeout per dashboard request. Settle and release use a hard 2 s timeout regardless. |
| `ORBITPORT_ACCOUNT_ALLOW_INSECURE` | `false` | When `true`, accepts a non-`https://` `ORBITPORT_ACCOUNT_DASHBOARD_URL`. Local dev only — the M2M bearer leaks in plaintext. Plugin refuses to start otherwise. |

The plugin is fail-closed: missing required env refuses startup; non-https dashboard URL refuses startup unless `ORBITPORT_ACCOUNT_ALLOW_INSECURE=true`; dashboard 5xx → gateway 503; insufficient credits → gateway 402.

Credit lifecycle: the gateway `Hold`s (deduct + gate) before serving, then reports the terminal outcome — `Settle` on success (commits the hold), `Release` on failure (refunds). Both settle and release are best-effort with a hard 2 s timeout; a dropped call leaves the hold unresolved, and the dashboard sweeper refunds unresolved orphans after its TTL. This errs toward revenue loss, never overcharge.

## Protobuf workflow

Proto sources live at top-level [`proto/`](proto/). After editing:

1. `make protoc` regenerates Go bindings into `plugins/proto/plugins/`.
2. Rust bindings are produced at build time by `gateway/build.rs` reading directly from `proto/`, so no manual step.
3. CI runs `make protoc-dry-run` to ensure the checked-in Go code is in sync.

## Testing

| Suite | Command | Notes |
| --- | --- | --- |
| Rust + Go unit tests | `make test` | |
| Lint (clippy + golangci-lint) | `make lint` | |
| Format check | `make fmt` | |
| Gateway happy-path e2e | `make e2e` | Stands up dev compose, hits real endpoints |
| Gateway offline e2e | `make E2E_PROFILE=offline e2e` | Aptos Orbital unreachable; exercises masterseed/beacon fallback |
| All gateway e2e suites | `make e2e-all` | |
| Go beacon e2e | `make go-e2e` / `make go-e2e-offline` | |

E2E profiles: `happy` (all upstreams available) and `offline` (Aptos Orbital unreachable, exercising the masterseed and beacon fallback paths).

## Docker

- `op-gateway:<tag>` — Rust gateway.
- `op-plugin:<tag>` — multi-purpose Go plugin binary (dispatched by `ORBITPORT_PLUGIN`).
- `op-mocker:<tag>` — Aptos Orbital API mock used by `dev.docker-compose.yaml`.

All images run as unprivileged users. Build locally with `make docker-build`. Images are published to `ghcr.io/spacecomputer-io/orbitport/` on semver tags via `.github/workflows/build_push.yml`.

## CI/CD

Workflows live in `.github/workflows/`:

- `plugins.yml` — Go build, test, race, lint, protoc check.
- `gateway.yml` — Rust fmt, clippy, build, test, protoc check.
- `e2e.yml` — happy + offline e2e.
- `build_push.yml` — Docker build & push on version tags.
- `go-vuln-scan.yml` / `rust-vuln-scan.yml` — vulnerability scanning.
