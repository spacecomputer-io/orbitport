# Orbitport | Dev Guide

**Prerequisites**

- [Make](https://www.gnu.org/software/make/)
- [Docker](https://docs.docker.com/get-docker/)

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


