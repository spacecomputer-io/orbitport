# syntax=docker/dockerfile:1

################################################################################

ARG GO_VERSION=1.24
ARG APLINE_VERSION=3.22

FROM dhi.io/golang:${GO_VERSION}-alpine${APLINE_VERSION} AS builder

ARG BUILD_TARGET=plugin

WORKDIR /app

# Copy go mod and sum files for downloading deps
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o bin/ ./cmd/${BUILD_TARGET}/...

################################################################################

FROM dhi.io/alpine:${APLINE_VERSION}

ARG BUILD_TARGET=plugin

RUN apk --no-cache add curl

COPY --from=builder /app/bin/${BUILD_TARGET} /app

ENTRYPOINT ["/app"]