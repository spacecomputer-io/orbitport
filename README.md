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

Create an `.env` similar to `.env.example`, and fill the required vars for client id and secret.

#### Build and Run Binary

```bash
GOLOG_LOG_LEVEL=debug make run
```

#### Run in Docker

```bash
make CLIENT_ID=your_client_id CLIENT_SECRET=your_client_secret docker-run
```

#### Set Debug Level

Set debug level to `GOLOG_LOG_LEVEL=info` or `error` to reduce verbosity.

Use the following format to set different levels for different subsystems:

```
GOLOG_LOG_LEVEL=error,subsystem1=info,subsystem2=debug
```
