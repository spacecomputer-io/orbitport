
protoc:
	@cd agents && make protoc
	@cp agents/proto/*.proto orbitport/proto/

test:
	@cd agents && make test
	@cd gateway && make test

build: protoc
	@cd agents && make build
	@cd gateway && make build

default: build
