# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/tlsproxy ./cmd/tlsproxy

FROM alpine:${ALPINE_VERSION}

RUN apk --no-cache add ca-certificates curl \
    && addgroup -S appgroup \
    && adduser -S -G appgroup appuser

COPY --from=builder --chown=appuser:appgroup /out/tlsproxy /app/tlsproxy

USER appuser

ENTRYPOINT ["/app/tlsproxy"]
