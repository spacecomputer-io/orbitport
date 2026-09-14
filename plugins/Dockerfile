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
    && mkdir -p /etc/orbitport/kms \
    && addgroup -S appgroup \
    && adduser -S -G appgroup appuser \
    && chown -R appuser:appgroup /etc/orbitport

COPY --from=builder --chown=appuser:appgroup /app/bin/${BUILD_TARGET} /app
COPY --from=builder --chown=appuser:appgroup /app/pkg/plugin/kms/cedar/kms_default.cedar /etc/orbitport/kms/kms_default.cedar

USER appuser

ENTRYPOINT ["/app"]
