# syntax=docker/dockerfile:1

################################################################################

ARG RUST_VERSION=1.92

FROM rust:${RUST_VERSION}-slim-trixie AS build

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \ 
    protobuf-compiler

WORKDIR /app

# Leverage a cache mount to /usr/local/cargo/registry/
# for downloaded dependencies and a cache mount to /app/target/ for 
# compiled dependencies which will speed up subsequent builds.
# Leverage a bind mount to the src directory to avoid having to copy the
# source code into the container. Once built, copy the executable to an
# output directory before the cache mounted /app/target is unmounted.
RUN --mount=type=bind,source=gateway/src,target=src \
    --mount=type=bind,source=proto,target=proto \
    --mount=type=bind,source=gateway/build.rs,target=build.rs \
    --mount=type=bind,source=gateway/Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=gateway/Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    <<EOF
set -e
cargo build --locked --release --bin gateway 
cp ./target/release/gateway /bin/gateway
EOF

################################################################################

FROM debian:trixie-slim AS final

RUN groupadd --system appgroup \
    && useradd --system --gid appgroup --no-create-home --home-dir /nonexistent appuser

COPY --from=build --chown=appuser:appgroup /bin/gateway /bin/gateway

USER appuser

ENTRYPOINT ["/bin/gateway"]