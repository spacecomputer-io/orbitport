ENV_FILE?=".dev.env"
CONTAINER_TOOL?=docker ## CONTAINER_TOOL=nerdctl
DOCKER_TAG?=latest ## DOCKER_TAG=v*.*.*

protoc:
	@cd plugins && make protoc

test:
	@cd plugins && make test
	@cd gateway && make test

lint:
	@cd plugins && make lint
	@cd gateway && make lint

fmt:
	@cd plugins && make fmt
	@cd gateway && make fmt

build: protoc
	@cd plugins && make build
	@cd gateway && make build

e2e:
	@cd gateway && RUST_LOG=info cargo test --test e2e_happy --features localtest

e2e-lazy:
	@cd gateway && RUST_LOG=info cargo test --test e2e_happy

e2e-all:
	@cd gateway && RUST_LOG=info cargo test --test e2e_*

devenv:
	@docker-compose --env-file=${ENV_FILE} -f dev.docker-compose.yaml up -d

devenv-up: devenv-down docker-build
	@docker-compose --env-file=${ENV_FILE} -f dev.docker-compose.yaml up -d

devenv-down:
	@docker-compose -f dev.docker-compose.yaml down

docker-build:
	@cd plugins && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} docker-build
	@cd gateway && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} docker-build

help:
	@echo ""
	@echo "Usage: make [vars] <cmd>"
	@echo ""
	@echo "Available commands:"
	@echo "  test            Run unit tests"
	@echo "  lint            Run linters"
	@echo "  fmt             Format code"
	@echo "  build           Build the project"
	@echo "  e2e             Run end-to-end tests including setup"
	@echo "  e2e-lazy        Run end-to-end tests without setup"
	@echo "  e2e-all         Run all end-to-end tests"
	@echo "  devenv          Start development environment"
	@echo "  devenv-up       Build & start development environment (forced)"
	@echo "  devenv-down     Stop development environment"
	@echo "  docker-build    Build Docker images of the project"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  ENV_FILE        Path to the environment file (default: .dev.env)"
	@echo "  DOCKER_TAG      Tag for the Docker image (default: latest)"
	@echo "  CONTAINER_TOOL  Tool for managing containers, e.g. nerdctl (default: docker)"
	@echo ""

default: help
