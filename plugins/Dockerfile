# syntax=docker/dockerfile:1

################################################################################

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

ARG BUILD_TARGET=plugin

WORKDIR /app

# Copy go mod and sum files for downloading deps
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o bin/ ./cmd/${BUILD_TARGET}/...

################################################################################

FROM alpine:${ALPINE_VERSION}

ARG BUILD_TARGET=plugin

RUN apk --no-cache add curl \
    && addgroup -S appgroup \
    && adduser -S -G appgroup appuser

COPY --from=builder --chown=appuser:appgroup /app/bin/${BUILD_TARGET} /app

USER appuser

ENTRYPOINT ["/app"]
