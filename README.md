# OrbitPort

OrbitPort is a Gateway to space computing services.

## Getting Started

See the [docs](docs/README.md) for more information.

### Prerequisites

- [Go](https://golang.org/dl/)
- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-docker/)

### Usage

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
