# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.24
ARG SOURCE_DATE_EPOCH=0
ARG BUILD_TARGET=plugin

FROM golang:${GO_VERSION}-alpine@sha256:1a97fbadb2eb46ba8e4bce6b08f45bc24ef0180d1f3b3192886a080c8268ba71 AS builder
WORKDIR /app

ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    TZ=UTC \
    LC_ALL=C \
    LANG=C.UTF-8 \
    GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org

# deps first (better cache + stability)
COPY go.mod go.sum ./

# Cache modules to make repeated builds consistent/faster
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY . .

# Reproducible Go build flags
RUN --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-buildid=" \
      -o /app/bin/${BUILD_TARGET} \
      ./cmd/${BUILD_TARGET}

FROM alpine:3.20@sha256:008827ed2172a676b08121e21cf9db0ce08a90ee6c8a12fc374af8a56c0e496d
ARG BUILD_TARGET=plugin

# If you truly need curl at runtime, keep it; otherwise remove this line for better reproducibility + smaller image.
RUN apk --no-cache add curl

COPY --from=builder /app/bin/${BUILD_TARGET} /app

ENTRYPOINT ["/app"]
