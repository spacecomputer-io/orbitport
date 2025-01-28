GOPACKAGES = $(shell go list ./internal/... && go list ./cmd/...)

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

build: dependencies
	@go build -o bin/ ./cmd/...

lint: dependencies
	@golangci-lint run ./...

run: build
	@./bin/gateway

default: build