# Build context must be the repo root: docker build -f bench/kms/Dockerfile .
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22
ARG GHZ_VERSION=v0.120.0

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder
ARG GHZ_VERSION
RUN apk add --no-cache git
WORKDIR /src
# Install ghz first so it stays cached across bootstrap source edits.
# go install builds ghz for the target arch — no per-arch download juggling.
RUN go install github.com/bojand/ghz/cmd/ghz@${GHZ_VERSION}
COPY plugins/go.mod plugins/go.sum ./plugins/
RUN cd plugins && go mod download
COPY plugins ./plugins
RUN cd plugins && go build -o /out/kmsbench-bootstrap ./cmd/kmsbench-bootstrap

FROM alpine:${ALPINE_VERSION}
RUN apk add --no-cache bash jq
COPY --from=builder /go/bin/ghz /usr/local/bin/ghz
COPY --from=builder /out/kmsbench-bootstrap /usr/local/bin/kmsbench-bootstrap
WORKDIR /bench
COPY proto ./proto
COPY bench/kms/run.sh bench/kms/summarize.sh bench/kms/entrypoint.sh ./
RUN chmod +x run.sh summarize.sh entrypoint.sh
ENV DATA=/bench/data RESULTS=/bench/results PROTO=proto/plugins/kms.proto IMPORT=proto
ENTRYPOINT ["./entrypoint.sh"]
