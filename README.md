# SpaceComputer | Orbitport

![spacecomputer logo](https://raw.githubusercontent.com/spacecomputer-io/media-kit/refs/heads/main/SpaceComputer/logo/SpaceComputer_banner.png)

![Plugins](https://github.com/spacecomputer-io/orbitport/actions/workflows/plugins.yml/badge.svg?branch=main)
![Gateway](https://github.com/spacecomputer-io/orbitport/actions/workflows/gateway.yml/badge.svg?branch=main)
![E2E](https://github.com/spacecomputer-io/orbitport/actions/workflows/e2e.yml/badge.svg?branch=main)
![Build & Push Image](https://github.com/spacecomputer-io/orbitport/actions/workflows/build_push.yml/badge.svg)

## What is Orbitport?

Orbitport is a unified gateway to space-based orbital services operated by SpaceComputer. It gives web2 and web3 applications a single, secure entry point to services served from multiple providers and satellites — today that means `cTRNG` (cosmic True Random Number Generation) backed by the Aptos Orbital satellites, with more services on the roadmap.

The project is split across two languages. A **Rust gateway** terminates HTTP and JSON-RPC at the edge, handles JWT authentication and per-token rate limiting, and fans out to a set of **Go plugins** over gRPC. Plugins are stateless sidecars that either wrap an upstream provider (e.g. Aptos Orbital, IPFS) or run a background service (e.g. the randomness beacon). The whole thing is packaged as Docker images and runs from a single `docker-compose` command.

## Services

- **cTRNG** — cosmic true random numbers. Exposed as `POST /api/v1/rpc` (`ctrng.Get`) and `GET /api/v1/services/trng`. Served by the `masterseed` plugin, which derives on-demand seeds from a rolling pool of satellite-harvested entropy fetched through the `aptosorbital` plugin.
- **Randomness Beacon** — a background service that pins a continuously updated beacon record to IPFS and republishes it under a stable IPNS name. Implemented by the `beacon` plugin; the public registry is declared in [`beacons.yaml`](beacons.yaml).
- **Threshold consumption** *(experimental)* — clients can request encrypted output by passing `key=threshold@<pubkey>` on TRNG requests, so random values are never seen in plaintext by any single party.
- **spaceTEE** — Space Trusted Execution Environment. Planned; the gateway surface is designed to accommodate additional services as they come online.

## Architecture

```
                  ┌──────────┐
    HTTP/JSON ──▶ │ gateway  │ ──▶ plugin-auth        (AuthPlugin)
    JSON-RPC      │  (Rust)  │ ──▶ plugin-masterseed  (MasterSeedPlugin)
                  └────┬─────┘          │
                       │                ▼
                       │           plugin-aptos-orbital (RandomnessPlugin)
                       │                │
                       │                ▼
                       │           api.aptosorbital.com (satellites)
                       ▼
                  :9100/metrics (Prometheus)

                  ┌──────────────┐
                  │ plugin-beacon│ ──▶ plugin-ipfs ──▶ IPFS / IPNS
                  │ (background) │ ──▶ plugin-aptos-orbital
                  └──────────────┘ ──▶ plugin-masterseed
```

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

docker-compose.yaml         Production stack (real Aptos Orbital + Auth0)
dev.docker-compose.yaml     Dev stack (mocker + authnoop, no external credentials)
beacons.yaml                Public beacon registry
```

Each plugin is documented in its own README:

| Plugin | Purpose |
| --- | --- |
| [`aptosorbital`](plugins/pkg/plugin/aptosorbital/README.md) | Fetches true random seeds from the Aptos Orbital satellite API |
| [`auth`](plugins/pkg/plugin/auth/README.md) | Fail-closed Auth0 JWT validation |
| [`authnoop`](plugins/pkg/plugin/authnoop/README.md) | Dev-only noop auth — accepts every token |
| [`ipfs`](plugins/pkg/plugin/ipfs/README.md) | Kubo wrapper with LRU cache, size ceilings, and IPNS publishing |
| [`masterseed`](plugins/pkg/plugin/masterseed/README.md) | Rolling pool of satellite seeds with offset-reserved derivation |
| [`beacon`](plugins/pkg/plugin/beacon/README.md) | Background service that publishes the randomness beacon to IPFS/IPNS |

## Running locally

The fast path uses the dev compose stack, which swaps in the `authnoop` plugin and the Aptos Orbital mocker so no external credentials are required.

```bash
git clone https://github.com/spacecomputer-io/orbitport.git
cd orbitport
cp .example.env .env    # defaults are fine for dev
make devenv-up          # builds images, starts dev compose stack
curl http://localhost:8080/healthz
```

Smoke-test a cTRNG request once the stack is up:

```bash
curl -X POST http://localhost:8080/api/v1/rpc \
  -H "Authorization: Bearer dev" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ctrng.Get","params":{"chunks":3}}'
```

Teardown:

```bash
make devenv-down
```

### Production mode

`docker-compose.yaml` runs the same stack against real Aptos Orbital and real Auth0. You will need:

- `ORBITPORT_APTOS_ORBITAL_CLIENT_ID` / `ORBITPORT_APTOS_ORBITAL_CLIENT_SECRET` — OAuth credentials for the Aptos Orbital API.
- `ORBITPORT_AUTH0_DOMAIN` / `ORBITPORT_AUTH0_AUDIENCE` — Auth0 tenant config. The `auth` plugin is fail-closed and refuses to start without these.

See [`.example.env`](.example.env) for the full list.

## Configuration

All env vars are prefixed `ORBITPORT_` and can be supplied via `.env` (gateway also reads `.gateway.env` if present). Gateway-specific vars:

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_HTTP_PORT` | `8080` | HTTP server port |
| `ORBITPORT_METRICS_PORT` | `9100` | Prometheus metrics port |
| `ORBITPORT_AUTH_PLUGIN` | — | gRPC URL of the auth plugin (required) |
| `ORBITPORT_MASTERSEED_PLUGIN` | — | gRPC URL of the masterseed plugin (required) |
| `ORBITPORT_RATE_LIMIT` | `40` | Max requests per token per window |
| `ORBITPORT_RATE_LIMIT_WINDOW` | `10` | Rate-limit window in seconds (default ≈ 4 req/s per token) |
| `ORBITPORT_BULK_MAX` | `10` | Max items per bulk TRNG request |

Plugin dispatcher vars (apply to every `op-plugin` container):

| Env var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_PLUGIN` | `aptosorbital` | Which plugin this binary runs |
| `ORBITPORT_GRPC_PORT` | `50001` | gRPC listen port |
| `ORBITPORT_METRICS_PORT` | `9000` | Prometheus metrics port |

Plugin-specific vars (Auth0, Aptos Orbital, IPFS, masterseed, beacon) are documented in the per-plugin READMEs linked above.

## HTTP & JSON-RPC API

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `GET /healthz` | no | Liveness probe |
| `GET /api/v1/services/{service}` | Bearer JWT | Query params: `src`, `bulk` *(experimental)*, `key` *(experimental)* |
| `POST /api/v1/services/{service}` | Bearer JWT | JSON body: `src`, `bulk`, `key`, `args`. 1 KB body limit |
| `POST /api/v1/rpc` | Bearer JWT | JSON-RPC 2.0. 1 KB body limit, 10 s per-request timeout |

All authenticated endpoints go through the same per-JWT rate limiter (SHA-256 hashed token). The current JSON-RPC surface exposes a single method:

- `ctrng.Get({ "version": 1, "chunks": N })` — returns `N` random values (max 10) as `{ items: [{ value, src }] }`.

### Sample: JSON-RPC

```bash
curl -X POST http://localhost:8080/api/v1/rpc \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ctrng.Get","params":{"chunks":2}}'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "items": [
      { "value": "a1b2c3...", "src": "mixed" },
      { "value": "d4e5f6...", "src": "mixed" }
    ]
  }
}
```

### Sample: REST

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/v1/services/trng?bulk=3'
```

Prometheus metrics are served separately on port `9100`; see [`gateway/src/metrics.rs`](gateway/src/metrics.rs) for the full surface.

## Testing

```bash
make test                       # unit tests (Rust + Go)
make lint                       # clippy + golangci-lint
make e2e                        # happy-path e2e against dev compose
make E2E_PROFILE=offline e2e    # fallback path (Aptos unreachable)
make e2e-all                    # all e2e suites
make go-e2e                     # Go beacon e2e
```

E2E tests stand up their own dev compose stack. Two profiles are supported: `happy` (all upstreams available) and `offline` (Aptos Orbital unreachable, exercising the masterseed and beacon fallback paths).

## Docker images

Images are published to [`ghcr.io/spacecomputer-io/orbitport/`](https://github.com/orgs/spacecomputer-io/packages) on semver tags via `.github/workflows/build_push.yml`:

- `op-gateway:<tag>` — the Rust gateway.
- `op-plugin:<tag>` — the multi-purpose Go plugin binary (dispatched by `ORBITPORT_PLUGIN`).

Both run as unprivileged users. Build locally with `make docker-build`.

## Links

* [SpaceComputer docs](https://docs.spacecomputer.io)
* [Orbitport user guide](https://docs.spacecomputer.io/using-orbitport/user-guide)
* [Orbitport dev/internal docs](docs/README.md)
* [Public beacons list](beacons.yaml)

## Contributing

We welcome contributions to Orbitport! Please see our [contributing guidelines](CONTRIBUTING.md) for more information on how to get involved.

## License

Orbitport is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for more information.
