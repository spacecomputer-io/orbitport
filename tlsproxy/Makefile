DOCKER_IMAGE?=op-tlsproxy
DOCKER_TAG?=latest
CONTAINER_TOOL?=docker ## CONTAINER_TOOL=nerdctl
E2E_URL?=https://localhost:9443

.PHONY: deps test e2e fmt fmt-check lint build docker-build help default

deps:
	@go mod download

test: deps
	@go test ./...

e2e:
	@ORBITPORT_TLS_PROXY_E2E_URL=${E2E_URL} go test -count=1 -tags=e2e ./e2e -v

fmt:
	@files="$$(gofmt -l .)"; test -z "$$files" || gofmt -w $$files

fmt-check:
	@test -z "$$(gofmt -l .)"

lint: deps
	@go vet ./...

build: deps
	@go build ./...

docker-build:
	@${CONTAINER_TOOL} build -t ${DOCKER_IMAGE}:${DOCKER_TAG} .

help:
	@echo ""
	@echo "Usage: make [vars] <cmd>"
	@echo ""
	@echo "Available commands:"
	@echo "  deps            Download Go dependencies"
	@echo "  test            Run unit tests"
	@echo "  e2e             Test the proxy against the running Orbitport stack"
	@echo "  fmt             Format Go code"
	@echo "  fmt-check       Check Go code formatting"
	@echo "  lint            Run go vet"
	@echo "  build           Build the proxy"
	@echo "  docker-build    Build the proxy Docker image"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  DOCKER_IMAGE    Image name (default: op-tlsproxy)"
	@echo "  DOCKER_TAG      Image tag (default: latest)"
	@echo "  CONTAINER_TOOL  Container tool (default: docker)"
	@echo "  E2E_URL         Proxy URL used by the e2e test"
	@echo ""

default: help
