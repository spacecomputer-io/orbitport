ENV_FILE?=".dev.env"
E2E_PROFILE?=happy
CONTAINER_TOOL?=docker ## CONTAINER_TOOL=nerdctl
DOCKER_TAG?=latest ## DOCKER_TAG=v*.*.*

protoc:
	@cd agents && make protoc
	@cp agents/proto/*.proto orbitport/proto/

test:
	@cd agents && make test
	@cd gateway && make test

lint:
	@cd agents && make lint
	@cd gateway && make lint

fmt:
	@cd agents && make fmt
	@cd gateway && make fmt

build: protoc
	@cd agents && make build
	@cd gateway && make build

e2e:
	@cd gateway && RUST_LOG=info cargo test --test e2e_${E2E_PROFILE} --features localtest

e2e-lazy:
	@cd gateway && RUST_LOG=info cargo test --test e2e_${E2E_PROFILE}

devenv-up: devenv-down
	@OPMOCK_PROFILE=${E2E_PROFILE} docker-compose --env-file=${ENV_FILE} -f dev.docker-compose.yaml up --build -d

devenv-down:
	@docker-compose -f dev.docker-compose.yaml down

docker-build:
	@cd gateway && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} docker-build
	@cd gateway && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} docker-build

help:
	@echo ""
	@echo "Usage: make [vars] <cmd>"
	@echo ""
	@echo "Available commands:"
	@echo "  protoc          Generate protobuf files"
	@echo "  test            Run unit tests"
	@echo "  lint            Run linters"
	@echo "  fmt             Format code"
	@echo "  build           Build the project"
	@echo "  e2e             Run end-to-end tests including setup"
	@echo "  e2e-lazy        Run end-to-end tests without setup"
	@echo "  devenv-up       Start development environment"
	@echo "  devenv-down     Stop development environment"
	@echo "  docker-build    Build Docker images of the project"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  ENV_FILE        Path to the environment file (default: .dev.env)"
	@echo "  E2E_PROFILE     Profile for end-to-end tests (default: happy)"
	@echo "  DOCKER_TAG      Tag for the Docker image (default: latest)"
	@echo "  CONTAINER_TOOL  Tool for managing containers, e.g. nerdctl (default: docker)"
	@echo ""

default: help
