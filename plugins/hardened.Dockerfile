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

RUN CGO_ENABLED=0 go build -o bin/ ./cmd/${BUILD_TARGET}/...

################################################################################

# distroless: CA certs and a nonroot user, no shell or package manager
# pinned by digest because the TEE measures this image
FROM dhi.io/static:20250419-debian13@sha256:98ef7a853608577e8d66dad1d25ada75d745d782f28d84e9ecfb85dfeb1f9c98

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

ARG BUILD_TARGET=plugin

COPY --from=builder /app/bin/${BUILD_TARGET} /app

USER 65532:65532

ENTRYPOINT ["/app"]