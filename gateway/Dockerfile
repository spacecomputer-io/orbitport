# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.85
ARG SOURCE_DATE_EPOCH=0

# Pin the builder base image by digest (linux/amd64 digest recommended if you build amd64)
FROM rust:${RUST_VERSION}-slim-bullseye@sha256:94205f90cc51967908954ffe6188bbdbf7dc0778488d00d813f4f1fa1892925f AS build

WORKDIR /app

# Make BuildKit / tooling + Rust build more deterministic
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    TZ=UTC \
    LC_ALL=C \
    LANG=C.UTF-8 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="-C debuginfo=0 -C remap-path-prefix=/app=. -C link-arg=-Wl,--build-id=none"

# NOTE: This is still time-dependent unless you pin apt repos (snapshot) or package versions.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Use bind mounts (no COPY) + caches for speed; add verbose logging for debugging
RUN --mount=type=bind,source=src,target=src,readonly \
    --mount=type=bind,source=proto,target=proto,readonly \
    --mount=type=bind,source=build.rs,target=build.rs,readonly \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml,readonly \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock,readonly \
    --mount=type=cache,target=/app/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    <<'EOF'
set -euxo pipefail
cargo build --locked --release --bin gateway -vv
ls -lah ./target/release || true
cp ./target/release/gateway /bin/gateway
strip /bin/gateway || true
EOF



# Pin runtime base image by digest
FROM debian:bullseye-slim@sha256:5a6b8b0a6f10112aaf804f9a722a825d348a9c969434c218e76bf252dd1bafb4 AS final

COPY --from=build /bin/gateway /bin/gateway

ENTRYPOINT ["/bin/gateway"]
