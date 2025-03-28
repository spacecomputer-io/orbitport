# OrbitPort (v0.1)

**NOTE:** this folder contains an older version of the OrbitPort project. For the latest version, see the [root folder](../README.md).

---

OrbitPort is a Gateway to space computing services.

## Getting Started

See the [docs](docs/README.md) for more information.

### Prerequisites

- [Go](https://golang.org/dl/)
- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-docker/)

### API Usage

Get an access token from auth0:

```bash
curl --request POST \
  --url https://op.spacecoin.xyz/oauth/token \
  --header 'content-type: application/json' \
  --data '{"client_id":"${OP_CLIENT_ID}","client_secret":"${OP_CLIENT_SECRET}","audience":"https://op.spacecoin.xyz/api","grant_type":"client_credentials"}'
```

Call rand_seed endpoint:

```bash
curl --request GET --url https://op.spacecoin.xyz/api/v1/rand_seed --header 'authorization: Bearer ${ACCESS_TOKEN}'
```

### Dev Usage

Create an `.env` similar to `.env.example`, and fill the required vars for client id and secret.

#### Run

```bash
GOLOG_LOG_LEVEL=debug make run
```
**NOTE:** `make run` will also run `make build`.

#### Run in Docker

```bash
make run-docker
```
**NOTE:** `make run-docker` will also run `make build-docker`.

#### Set Debug Level

Set debug level to `GOLOG_LOG_LEVEL=info` or `error` to reduce verbosity.

Use the following format to set different levels for different subsystems:

```
GOLOG_LOG_LEVEL=error,subsystem1=info,subsystem2=debug
```
