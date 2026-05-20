# syntax=docker/dockerfile:1.7
#
# CI toolchain image: rust:1-bookworm + the system deps needed to build the
# quip runtime (clang/libclang for bindgen, protobuf-compiler, libssl, cmake)
# plus the wasm32v1-none target and rust-src component required by
# substrate-wasm-builder.
#
# Pushed by the `ci-toolchain-image` job in `.gitlab-ci.yml` to
# docker.io/carback1/rust-substrate-builder:latest. The check-stage jobs
# (fmt/clippy/test/build) pull this image instead of installing the same
# deps from scratch on every CI run.

ARG RUST_VERSION=1
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-${DEBIAN_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev protobuf-compiler pkg-config libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32v1-none \
 && rustup component add rust-src clippy rustfmt

# Cargo prefers the git CLI for fetching from GitLab; this matches the
# behavior of the production Dockerfile so cargo can resolve ssh:// deps
# without an in-image SSH key.
RUN git config --global url."https://gitlab.com/".insteadOf "ssh://git@gitlab.com/"
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true
