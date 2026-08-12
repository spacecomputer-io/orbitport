# Orbitport TLS proxy

This service provides the first, transport-only slice of a standard TLS
endpoint in front of the existing Orbitport HTTP gateway:

```text
HTTPS client -> TLS proxy -> HTTP Orbitport gateway
```

The proxy terminates TLS 1.3 and forwards the original HTTP request to the
configured Orbitport URL. It does not implement attestation, call OpenBao, or
change any Orbitport application route.

On every process start, the proxy generates a fresh self-signed ECDSA P-256
certificate and keeps its private key in memory. This certificate enables the
transport-only milestone; it does not assert a trusted endpoint identity. A
later attestation/PSK layer must provide that authentication.

## Local use

Start the Orbitport development environment so the gateway listens on
`http://127.0.0.1:8080`, then run the proxy from `tlsproxy/`:

```sh
ORBITPORT_TLS_PROXY_TARGET_URL=http://127.0.0.1:8080 \
go run ./cmd/tlsproxy
```

Call the real Orbitport health endpoint through TLS:

```sh
curl --insecure https://localhost:8443/healthz
```

The expected response is `{"status":"ok"}`.

## Docker Compose end-to-end test

From the Orbitport repository root, build and start the complete development
stack, then run a real `ctrng.Get` request through the TLS proxy:

```sh
make docker-build
make devenv
make e2e-tlsproxy
make devenv-down
```

The development stack exposes the proxy at `https://localhost:9443`. The
request follows the complete path:

```text
HTTPS client -> tlsproxy container -> gateway container -> Orbitport plugins
```

The package-level tests below continue to use a controlled HTTP backend so
they can validate forwarding behavior without requiring the full stack.

## Tests

The default tests cover request forwarding, certificate generation, classical
TLS, and Go's hybrid `X25519MLKEM768` group:

```sh
make test
```
