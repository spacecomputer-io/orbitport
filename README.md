# OrbitPort

Orbitport is a gateway to orbital services such as `cTRNG` (cosmic True Random Number Generation) or `spaceTEE`.
See the [docs](docs/README.md) for more information.

## Usage (API)

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
  --data '{"client_id":"'"${OP_CLIENT_ID}"'","client_secret":"'"${OP_CLIENT_SECRET}"'","audience":"https://op.spacecomputer.io/api","grant_type":"client_credentials"}' \
 | jq -r '.access_token'
```

### cTRNG

To make a trng request, run the following command:

```bash
curl http://localhost:8080/api/v1/services/trng --header "authorization: Bearer ${ACCESS_TOKEN}"
```


## Usage (ops)

**Prerequisites**

- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-docker/)

### Build Docker Images

Build the docker images for the agents and the gateway:

**NOTE:** use `DOCKER_TAG` to set the tag for the images. `latest` by default.

```bash
make docker-build
```

If you want to use other build tool, use `CONTAINER_TOOL`:

```bash
make CONTAINER_TOOL=nerdctl docker-build
```

### Running Dev Mode with Docker

Run with docker compose:
```bash
make devenv-up
```

This will start the gateway and all agents in docker containers, as well as mocked services.

Run e2e tests on that environment:
```bash
make e2e-lazy
make E2E_PROFILE=load e2e-lazy
make E2E_PROFILE=offline e2e-lazy
```

Tear down with:
```bash
make devenv-down
```

### Running with Docker

Fill the required vars in `.env`, follow `.example.env`.

Run with docker compose:
```bash
docker-compose --env-file .env up
```

This will start the gateway and all agents in docker containers.
