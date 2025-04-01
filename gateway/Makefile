# Makefile for the gateway service
DOCKER_IMAGE?=op-gateway
DOCKER_CONTAINER_NAME?=gateway
RUST_LOG?=debug

test:
	@cargo test -- --skip test_e2e

test-unit:
	@cargo test

fmt:
	@cargo fmt

fmt-check:
	@cargo fmt -- --check

clippy:
	@cargo clippy -- -D warnings

lint: clippy

build:
	@cargo build --release

run: build
	@./target/release/gateway

build-docker:
	@docker build -t ${DOCKER_IMAGE} .

clean-docker:
	@docker rm -f ${DOCKER_CONTAINER_NAME} 2> /dev/null

run-docker: clean-docker build-docker
	@docker run -p 8080:8080 -e RUST_LOG=${RUST_LOG} -v ./.env:/.env \
		--name ${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE}

default: build
