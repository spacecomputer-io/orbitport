# Orbitport Plugins

Plugins are grpc services that runs in their own processes and encapsulate the logic to interact with the underlying services, written in golang for easy integration and to work with standard libraries.

## Plugins

- [x] [Auth](./pkg/plugin/auth)
- [x] [KMS](./pkg/plugin/kms)
- [x] [Account](./pkg/plugin/account)
- [x] [PAT issuer](./pkg/plugin/patissuer)
- [x] [JWKS](./pkg/plugin/jwks)

## Usage

Available commands are listed in the `Makefile`:

```sh
make help
```

To run a plugin, create and fill the corresponding `.env` file (for example,
`.auth.env`), then
use the `ENV_FILE` arg to specify the file to use:

```sh
make ENV_FILE=.auth.env run
```
Or in docker:

```sh
make ENV_FILE=.auth.env docker-run
```

## Testing (e2e)
`dev.docker-compose.yaml` uses a dedicated noop auth plugin for local development.
It also bootstraps the local OpenBao-backed KMS environment automatically. Running
`make devenv` or `make devenv-up` triggers the one-shot Compose services that execute
[`docker/openbao/build-eth-plugin.sh`](../docker/openbao/build-eth-plugin.sh)
and
[`docker/openbao/bootstrap.sh`](../docker/openbao/bootstrap.sh)
to build the Ethereum plugin, register it with OpenBao, and enable the required local mounts.

For the KMS happy path:
```sh
make ENV_FILE=.dev.env.ci devenv-up
make e2e-all
make devenv-down
```
