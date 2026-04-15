# Orbitport | Dev Guide

**Prerequisites**

- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-docker/)
- [Golang](https://go.dev/doc/install) (1.24+)
- [Rust](https://www.rust-lang.org/tools/install) (1.85+)

### Build Docker Images

Build the docker images for the plugins and the gateway:

**NOTE:** use `DOCKER_TAG` to set the tag for the images. `latest` by default.

```bash
make docker-build
```

If you want to use other build tool, use `CONTAINER_TOOL`:

```bash
make CONTAINER_TOOL=nerdctl docker-build
```

### Running Dev Mode with Docker

Teardown, build and run with docker compose:
```bash
make devenv-up
```

Run with docker compose:
```bash
make devenv
```

Tear down with:
```bash
make devenv-down
```

This will start the gateway and all plugins in docker containers, as well as mocked services.

#### Local OpenBao for KMS

`dev.docker-compose.yaml` now includes a local KMS backend stack:

- `openbao` in dev mode on host port `18200`
- `openbao-proxy` on host port `8200`
- a one-shot bootstrap that enables:
  - `transit`
  - `orbitport-kv` (KV v2)
  - `ethereum-secrets-plugin` at `ethereum`

The dev stack expects a plugin repo to exist at `../openbao-eth-plugin-poc` by default. If your checkout lives elsewhere, set:

```bash
ORBITPORT_OPENBAO_ETH_PLUGIN_DIR=/absolute/path/to/openbao-eth-plugin
```

The raw OpenBao dev server uses the root token `root`. The proxy injects that token for Orbitport's KMS plugin, so the gateway still talks only to `openbao-proxy`.

#### Running E2E Tests on Dev Mode

Run e2e tests on that environment:
```bash
make e2e-lazy
make E2E_PROFILE=load e2e-lazy
make E2E_PROFILE=offline e2e-lazy
```


### Running with Docker

Fill the required vars in `.env`, follow `.example.env`.

Run with docker compose:
```bash
docker-compose --env-file .env up
```

This will start the gateway and all plugins in docker containers.

### Making calls to KMS
```bash
make devenv
```

Call the gateway:
```bash
curl -X POST http://localhost:8080/api/v1/rpc \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer test_access_token' \
  -d '{
    "jsonrpc": "2.0",
    "id": 41,
    "method": "kms.CreateKey",
    "params": {
      "Description": "ethereum dev key",
      "Scheme": "ETHEREUM",
      "KeySpec": "ECC_SECG_P256K1",
      "KeyUsage": "SIGN_VERIFY",
      "Tags": [{ "TagKey": "test", "TagValue": "e2e" }]
    }
  }'
```

Then sign with the returned KeyId:
```bash
curl -X POST http://localhost:8080/api/v1/rpc \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer test_access_token' \
  -d '{
    "jsonrpc": "2.0",
    "id": 42,
    "method": "kms.Sign",
    "params": {
      "KeyId": "kms:REPLACE_ME",
      "Message": "Hello Orbitport",
      "SigningAlgorithm": "ETHEREUM_SECP256K1",
      "MessageType": "EIP191"
    }
  }'
```