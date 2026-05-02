# syntax=docker/dockerfile:1.7
ARG RUST_VERSION=1
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev protobuf-compiler pkg-config libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32v1-none \
 && rustup component add rust-src
# Rewrite ssh://git@gitlab.com/ → https://gitlab.com/ so cargo can fetch
# public deps (e.g. quip.network/xq-rs) without needing an SSH key in the
# build context. Cargo's lock keeps the original ssh:// source identity, so
# rev pins still match. CARGO_NET_GIT_FETCH_WITH_CLI is required for git's
# url.insteadOf to take effect (cargo's libgit2 backend ignores it).
RUN git config --global url."https://gitlab.com/".insteadOf "ssh://git@gitlab.com/"
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
WORKDIR /build
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p quip-network-node \
 && cp target/release/quip-network-node /usr/local/bin/quip-network-node

FROM debian:${DEBIAN_VERSION}-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /data --uid 1000 --shell /bin/false quip
COPY --from=builder /usr/local/bin/quip-network-node /usr/local/bin/quip-network-node
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
WORKDIR /data
EXPOSE 30333 9944 9615
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
