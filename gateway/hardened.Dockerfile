# syntax=docker/dockerfile:1

################################################################################

ARG RUST_VERSION=1.92

FROM dhi.io/rust:${RUST_VERSION}-debian13-dev AS build

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    protobuf-compiler

# Created here rather than in the final stage — dhi.io/debian-base's
# non-dev runtime image doesn't ship shadow-utils, so groupadd/useradd
# aren't available there. /etc/passwd and /etc/group are just text files,
# so copying them across stages is enough for USER to resolve appuser.
RUN groupadd --system appgroup \
    && useradd --system --gid appgroup --no-create-home --home-dir /nonexistent appuser

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

FROM dhi.io/debian-base:trixie AS final

ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build --chown=appuser:appgroup /bin/gateway /bin/gateway

USER appuser

ENTRYPOINT ["/bin/gateway"]