# SpaceComputer | Orbitport

![spacecomputer logo](https://raw.githubusercontent.com/spacecomputer-io/media-kit/refs/heads/main/SpaceComputer/logo/SpaceComputer_banner.png)

![Plugins](https://github.com/spacecomputer-io/orbitport/actions/workflows/plugins.yml/badge.svg?branch=main)
![Gateway](https://github.com/spacecomputer-io/orbitport/actions/workflows/gateway.yml/badge.svg?branch=main)
![E2E](https://github.com/spacecomputer-io/orbitport/actions/workflows/e2e.yml/badge.svg?branch=main)
![Build & Push Image](https://github.com/spacecomputer-io/orbitport/actions/workflows/build_push.yml/badge.svg)

## What is Orbitport?

Orbitport is a unified gateway to space-based orbital services operated by SpaceComputer. It gives web2 and web3 applications a single, secure entry point to services served from multiple providers and satellites — today that means `cTRNG` (cosmic True Random Number Generation) backed by the Aptos Orbital satellites, with more services on the roadmap.

The project is a **Rust gateway** that terminates HTTP and JSON-RPC at the edge and fans out to a set of **Go plugins** over gRPC. The whole thing is packaged as Docker images and runs from a single `docker-compose` command.

## Services

- **cTRNG** — cosmic true random numbers, served by the `masterseed` plugin from a rolling pool of satellite-harvested entropy.
- **Randomness Beacon** — a background service that pins a continuously updated beacon record to IPFS and republishes it under a stable IPNS name. Public registry: [`beacons.yaml`](beacons.yaml).
- **KMS** — multi-tenant Key Management Service backed by OpenBao. Encrypt/decrypt with Transit (`AES_256_GCM96`), sign with Transit (ECDSA, Ed25519, RSA) or with the Ethereum engine (secp256k1, including EIP-191). See the [`kms`](plugins/pkg/plugin/kms/README.md) plugin.
- **Threshold consumption** *(experimental)* — clients can request encrypted output by passing `key=threshold@<pubkey>` on TRNG requests, so random values are never seen in plaintext by any single party.
- **spaceTEE** — Space Trusted Execution Environment. Planned.

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

For a deeper walk-through (gRPC wiring, plugin internals, env-var reference, protobuf workflow, test profiles), see [`CONTEXT.md`](CONTEXT.md). A flat repo map is in [`llms.txt`](llms.txt).

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

### Running against real upstreams

`docker-compose.yaml` runs the same stack against real Aptos Orbital and real Auth0. You will need OAuth credentials for the Aptos Orbital API and an Auth0 tenant — see [`.example.env`](.example.env) for the full list. Note that this compose file is intended for local/staging use against live upstreams; production deployments require the operator's own infrastructure (orchestration, secret management, observability, networking).

## HTTP & JSON-RPC API

| Endpoint | Auth | Notes |
| --- | --- | --- |
| `GET /healthz` | no | Liveness probe |
| `GET /api/v1/services/{service}` | Bearer JWT | Query params: `src`, `bulk` *(experimental)*, `key` *(experimental)* |
| `POST /api/v1/services/{service}` | Bearer JWT | JSON body: `src`, `bulk`, `key`, `args`. 1 KB body limit |
| `POST /api/v1/rpc` | Bearer JWT | JSON-RPC 2.0. 1 KB body limit, 10 s per-request timeout |

All authenticated endpoints go through the same per-JWT rate limiter (SHA-256 hashed token). The current JSON-RPC surface:

- `ctrng.Get({ "version": 1, "chunks": N })` — returns `N` random values (max 10) as `{ items: [{ value, src }] }`.
- `kms.GetCapabilities` / `kms.CreateKey` / `kms.Encrypt` / `kms.Decrypt` / `kms.Sign` / `kms.GenerateDataKey` / `kms.RotateKey` — multi-tenant key management; see [`plugins/pkg/plugin/kms/README.md`](plugins/pkg/plugin/kms/README.md) and `proto/services/kms.proto` for the request/response shapes.

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

REST shorthand:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'http://localhost:8080/api/v1/services/trng?bulk=3'
```

Prometheus metrics are served separately on port `9100`.

## Configuration

All env vars are prefixed `ORBITPORT_`. The full list, including defaults, is the source-controlled [`.example.env`](.example.env); per-knob descriptions live in [`CONTEXT.md`](CONTEXT.md#configuration). For local dev, the defaults in `.example.env` are sufficient.

## Testing

```bash
make test                       # unit tests (Rust + Go)
make lint                       # clippy + golangci-lint
make e2e                        # happy-path e2e against dev compose
make E2E_PROFILE=offline e2e    # fallback path (Aptos unreachable)
```

See [`CONTEXT.md`](CONTEXT.md#testing) for the full e2e matrix.

## Links

* [SpaceComputer docs](https://docs.spacecomputer.io)
* [Orbitport user guide](https://docs.spacecomputer.io/using-orbitport/user-guide)
* [Orbitport dev/internal docs](docs/README.md)
* [Public beacons list](beacons.yaml)

## Contributing

We welcome contributions to Orbitport! Please see our [contributing guidelines](CONTRIBUTING.md) for more information on how to get involved.

## License

Orbitport is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for more information.
