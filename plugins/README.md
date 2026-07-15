# Orbitport Plugins

Plugins are grpc services that runs in their own processes and encapsulate the logic to interact with the underlying services, written in golang for easy integration and to work with standard libraries.

## Plugins

- [x] [Aptos Orbital](./pkg/plugin/aptosorbital)
- [x] [Auth](./pkg/plugin/auth)
- [x] [IPFS](./pkg/plugin/ipfs)
- [x] [Beacon](./pkg/plugin/beacon)
- [x] [Masterseed](./pkg/plugin/masterseed)
- [x] [KMS](./pkg/plugin/kms)

## Usage

Available commands are listed in the `Makefile`:

```sh
make help
```

To run an plugin, you need to create/fill the corresponding `.env` file (e.g. `.aptosorbital.env` or `.auth.env`), and then
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

for happy-path (testing aptos connectivity):
```sh
make ENV_FILE=.dev.env.ci E2E_PROFILE=happy devenv-up
make e2e-all
make go-e2e
make devenv-down
```

for offline (testing lack of aptos connectivity - fallback):
```sh
make ENV_FILE=.dev.env.ci E2E_PROFILE=offline devenv-up
make go-e2e-offline
make devenv-down
```
