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

RUN CGO_ENABLED=0 go build -o bin/ ./cmd/${BUILD_TARGET}/...

################################################################################

# Distroless: CA certs and a nonroot user, no shell or package manager
FROM dhi.io/static:20250419-debian13

ARG BUILD_TARGET=plugin

COPY --from=builder /app/bin/${BUILD_TARGET} /app

USER 65532:65532

ENTRYPOINT ["/app"]
