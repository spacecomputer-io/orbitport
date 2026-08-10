# syntax=docker/dockerfile:1

################################################################################

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22

FROM dhi.io/golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

ARG BUILD_TARGET=plugin

WORKDIR /app

# Copy go mod and sum files for downloading deps
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o bin/ ./cmd/${BUILD_TARGET}/...

################################################################################

FROM dhi.io/alpine-base:${ALPINE_VERSION}-alpine${ALPINE_VERSION}-dev

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

ARG BUILD_TARGET=plugin

RUN apk --no-cache add curl \
    && addgroup -S appgroup \
    && adduser -S -G appgroup appuser

COPY --from=builder --chown=appuser:appgroup /app/bin/${BUILD_TARGET} /app
USER appuser

ENTRYPOINT ["/app"]