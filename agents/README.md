# Orbitport Agents

Agents are grpc services that runs in their own processes and encapsulate the logic to interact with the underlying services, written in golang for easy integration and to work with standard libraries.

## Agents

- [x] [Aptos Orbital](./pkg/agent/aptosorbital)
- [x] [Auth](./pkg/agent/auth)
- [ ] [IPFS](./pkg/agent/ipfs)

## Usage

Available commands are listed in the `Makefile`:

```sh
make help
```

To run an agent, you need to create/fill the corresponding `.env` file (e.g. `.aptosorbital.env` or `.auth.env`), and then
use the `ENV_FILE` arg to specify the file to use:

```sh
make ENV_FILE=.auth.env run
```
Or in docker:

```sh
make ENV_FILE=.auth.env run-docker
```
