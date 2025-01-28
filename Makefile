GOPACKAGES=$(shell go list ./internal/... && go list ./cmd/...)
DOCKER_IMAGE?=stargate
DOCKER_CONTAINER_NAME?=stargate-gateway

dependencies:
	go mod download

test: dependencies
	@go test -v $(GOPACKAGES)

race: dependencies
	@go test -race $(GOPACKAGES)

fmt: dependencies
	@go fmt ./...

tidy: dependencies
	@go mod tidy

lint: dependencies
	@golangci-lint run ./...

build: dependencies
	@go build -o bin/ ./cmd/...

run: build
	@./bin/gateway

build-docker:
	@docker build -t ${DOCKER_IMAGE} -f docker/Dockerfile .

clean-docker:
	@docker rm -f ${DOCKER_CONTAINER_NAME} 2> /dev/null

run-docker: clean-docker build-docker
	@docker run -p 8080:8080 -e GOLOG_LOG_LEVEL=debug -v ./.env:/.env \
		--name ${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE}

default: build