# syntax=docker/dockerfile:1.7
#
# CI toolchain image: rust:1.95.0-bookworm + the system deps needed to build the
# quip runtime (clang/libclang for bindgen, protobuf-compiler, libssl, cmake)
# plus the wasm32v1-none target and rust-src component required by
# substrate-wasm-builder.
#
# The check-stage jobs in `.gitlab-ci.yml` pull this image from
# docker.io/carback1/rust-substrate-builder:latest. Rebuild and push manually
# from a workstation when this Dockerfile changes — there is no CI job that
# builds the image:
#
#   docker buildx build \
#     --platform linux/amd64 \
#     --file .gitlab/ci-toolchain.Dockerfile \
#     --tag carback1/rust-substrate-builder:latest \
#     --push \
#     .gitlab/

# Pin Rust in lockstep with the production Dockerfile. Rust 1.96.0 regressed
# the wasm32v1-none runtime link ("undefined symbol: ext_*"); 1.95.0 is the
# last known-good. Bump both Dockerfiles together after verifying a build.
ARG RUST_VERSION=1.95.0
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
