# Stargate

The Gateway to space computing services.

## Getting Started

### Prerequisites

- [Go](https://golang.org/dl/)
- (For dev) [golangci-lint](https://golangci-lint.run/welcome/install/)
    - `brew install golangci-lint` on macOS
- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-docker/)

### Usage

Build the gateway binary:

```bash
make build
```

Create an `.env` similar to `.env.example`, and fill the required vars for client id and secret.

Run the gateway:

```bash
GOLOG_LOG_LEVEL=debug make run
```

Set debug level to `info` or `error` to reduce verbosity.
Or use the following format to set different levels for different subsystems:

```
GOLOG_LOG_LEVEL=error,subsystem1=info,subsystem2=debug
```
