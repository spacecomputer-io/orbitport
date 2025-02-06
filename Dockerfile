### build stage

FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod and sum files for downloading deps
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o bin/ ./cmd/gateway/...

### runtime stage

FROM alpine:latest

COPY --from=builder /app/bin/gateway /gateway

ENTRYPOINT ["/gateway"]