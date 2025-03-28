# syntax=docker/dockerfile:1

################################################################################

ARG GO_VERSION=1.24

FROM golang:${GO_VERSION}-alpine AS builder

ARG BUILD_TARGET=agent

WORKDIR /app

# Copy go mod and sum files for downloading deps
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o bin/ ./cmd/${BUILD_TARGET}/...

################################################################################

FROM alpine:latest

ARG BUILD_TARGET=agent

RUN apk --no-cache add curl

COPY --from=builder /app/bin/${BUILD_TARGET} /app

ENTRYPOINT ["/app"]