# OrbitPort

Orbitport is a gateway to orbital services such as `cTRNG` (cosmic True Random Number Generation) or `cTEE` (cosmic TEE).


## Getting Started

Orbitport is composed of several components:
- **Agents:** are grpc services that runs in their own processes and encapsulate the logic to interact with the underlying services, written in golang for easy integration with standard libraries. Existing agents can be found in `./agents/pkg/agent/*`.
- **Gateway:** is the leading process that orchestrates the agents. The gateway is written in Rust and can be found in `./orbitport/src/bin/gateway.rs`.
- 

See the [docs](docs/README.md) for more information.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (`1.85.0`)
- [Go](https://golang.org/dl/) (`1.24`)
- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-docker/)

## Running Dev Mode with Docker

Run with docker compose:
```bash
docker-compose -f dev.docker-compose.yaml up
```

This will start the gateway and all agents in docker containers, as well as mocked services.

## Running with Docker

Fill the required vars in `.env`, follow `.example.env`.

Run with docker compose:
```bash
docker-compose --env-file .env up
```

This will start the gateway and all agents in docker containers.

## API Usage

### cTRNG

To make a trng request, run the following command: 

**NOTE:** for real access token see next section ([Access Token](#access-token))

```bash
curl http://localhost:8080/api/v1/services/trng --header "authorization: Bearer ${ACCESS_TOKEN}"
```

### Access Token

Get credentials for auth0:

```bash
OP_AUTH_URL=<auth0-audience>
OP_CLIENT_ID=<your-client-id>
OP_CLIENT_SECRET=<your-client-secret>
```

Get access token from auth0:

```bash
curl --request POST --url "https://${OP_AUTH_URL}/oauth/token" \
  --header 'content-type: application/json' \
  --data '{"client_id":"'"${OP_CLIENT_ID}"'","client_secret":"'"${OP_CLIENT_SECRET}"'","audience":"https://op.spacecoin.xyz/api","grant_type":"client_credentials"}' \
 | jq -r '.access_token'
```

