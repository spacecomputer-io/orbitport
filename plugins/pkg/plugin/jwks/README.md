# JWKS plugin

Publishes the issuer plugin's public key set at `GET /.well-known/jwks.json`.

It holds no key material. It calls `GetJwks` on the issuer over gRPC, caches the
response, and serves it verbatim. The gateway used to do this; the gateway
routes and meters the JSON-RPC API, and republishing another service's keys is
not that job.

This is the only plugin that answers requests from the internet, so it serves
one GET route, never reads a request body, mounts nothing else on that port, and
bounds every phase of a request with a timeout.

## Env

| Var | Default | Purpose |
| --- | --- | --- |
| `ORBITPORT_JWKS_ISSUER_PLUGIN` | *(required)* | Issuer plugin gRPC address. Startup fails without it |
| `ORBITPORT_JWKS_HTTP_PORT` | `8080` | Public listener |
| `ORBITPORT_JWKS_CACHE_TTL_SECS` | `60` | Bounds how often an anonymous request reaches the issuer |
| `ORBITPORT_JWKS_TIMEOUT_SECS` | `5` | Bounds a single `GetJwks` call |

`ORBITPORT_GRPC_PORT` and `ORBITPORT_METRICS_PORT` come from the shared plugin
config. Nothing is registered on the gRPC port; it exists so the health server
backs the same k8s probes every other plugin uses.

## Fail-closed behaviour

- No issuer address configured, the process refuses to start.
- Issuer unreachable or slow, `503 {"error":"issuer_plugin_unavailable"}`. A
  stale key set is never served, so a rotated-out key cannot keep verifying.
- Issuer returns an empty key set, also a 503, and nothing is cached. Publishing
  an empty set as a 200 reads as "this issuer has no keys" and would make every
  verifier reject every PAT.
- HTTP listener dies, the process exits rather than passing probes while serving
  nothing.

## What this does not fix

The issuer's gRPC service carries `IssueToken` alongside `GetJwks` and
authenticates no caller, so code execution in this pod still reaches the mint
RPC. The boundary is network reachability, not which client this process holds.
A NetworkPolicy restricting who can dial the issuer is the fix for that, and it
is not in this chart yet.
