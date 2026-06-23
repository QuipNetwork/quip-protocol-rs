# Pin Rust deliberately: the runtime↔host ABI (sp-io ext_* host functions) is
# toolchain-sensitive. Rust 1.96.0 regressed the wasm32v1-none runtime link
# ("undefined symbol: ext_*"). Keep this in lockstep with the CI toolchain
# image (.gitlab/ci-toolchain.Dockerfile); bump both together after verifying.
ARG RUST_VERSION=1.95.0
ARG DEBIAN_VERSION=bookworm

# Shared toolchain base for the planner and builder stages: system build deps,
# the wasm runtime target, and cargo-chef. kaniko caches this layer, so it is
# built once and reused until the toolchain changes.
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS chef
# Substrate build deps; pinning system lib versions across Debian point
# releases is brittle and this is a build-only stage.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev protobuf-compiler pkg-config libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32v1-none \
 && rustup component add rust-src
# Install cargo-chef and rewrite ssh://git@gitlab.com/ → https://gitlab.com/ so
# cargo can fetch public deps (e.g. quip.network/xq-rs) without an SSH key in
# the build context. Cargo's lock keeps the original ssh:// source identity, so
# rev pins still match. CARGO_NET_GIT_FETCH_WITH_CLI is required for git's
# url.insteadOf to take effect (cargo's libgit2 backend ignores it).
RUN cargo install cargo-chef --locked --version '^0.1' \
 && git config --global url."https://gitlab.com/".insteadOf "ssh://git@gitlab.com/"
# Harden crate downloads against the runner VM's flaky network. cargo's HTTP/2
# multiplexing stalls on crates.io from VMs/CI ("[28] Timeout was reached /
# failed to transfer more than 10 bytes in 30s"); force HTTP/1.1 and retry more.
# The runtime's wasm build (substrate-wasm-builder) resolves + downloads its
# full dependency graph at build time, so it's especially exposed.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true \
    CARGO_NET_RETRY=10 \
    CARGO_HTTP_MULTIPLEXING=false
WORKDIR /build

# Planner: distil the dependency graph into recipe.json. cargo-chef's `prepare`
# runs `cargo metadata`, which loads the whole workspace, so it needs the full
# tree (a manifest-only COPY fails to resolve workspace members). recipe.json
# is still derived purely from the Cargo.toml/Cargo.lock graph — identical for a
# given lockfile regardless of source — so the `cook` layer below stays cached
# across source-only edits because kaniko keys `COPY --from=planner recipe.json`
# on the file's content. CI normalizes context mtimes so the key is stable
# across the fresh checkout each run does (see .gitlab-ci.yml).
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Builder: compile just the dependencies from the recipe (the slow part, ~the
# whole polkadot-sdk tree) as one cached layer, then build the workspace.
# SKIP_WASM_BUILD=1 keeps the runtime build script (substrate-wasm-builder)
# from trying to compile the wasm runtime against cargo-chef's stub sources;
# the real wasm runtime is built in the final `cargo build` below.
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN SKIP_WASM_BUILD=1 cargo chef cook --release -p quip-network-node --recipe-path recipe.json

# `substrate-build-script-utils` embeds the commit hash into
# `SUBSTRATE_CLI_IMPL_VERSION` (what `--version` prints). It checks the
# `SUBSTRATE_CLI_GIT_COMMIT_HASH` env var first and only falls back to `git
# rev-parse` if empty. The build context excludes `.git/` (see `.dockerignore`),
# so without the build-arg the binary ends up tagged `0.2.x-unknown`. CI passes
# `$CI_COMMIT_SHORT_SHA`; local `docker build` users can pass
# `--build-arg SUBSTRATE_CLI_GIT_COMMIT_HASH=$(git rev-parse --short=11 HEAD)`.
ARG SUBSTRATE_CLI_GIT_COMMIT_HASH=""
ENV SUBSTRATE_CLI_GIT_COMMIT_HASH=${SUBSTRATE_CLI_GIT_COMMIT_HASH}

COPY . .
# cargo-chef built the workspace crates as stubs during `cook`; cargo decides
# whether to rebuild them from source mtime. CI normalizes context mtimes to a
# fixed value for a stable kaniko cache key (see .gitlab-ci.yml), which can
# leave the real sources looking older than the cooked stub artifacts — cargo
# would then skip the rebuild and ship the stubs. Touch the sources to "now" so
# they are unambiguously newer and the real crates (and wasm runtime) rebuild.
RUN find . -name '*.rs' -exec touch {} + \
 && cargo build --release -p quip-network-node \
 && cp target/release/quip-network-node /usr/local/bin/quip-network-node

FROM debian:${DEBIAN_VERSION}-slim AS runtime
# runtime deps tracked with the Debian base; pinning point versions here adds
# churn without a security benefit.
# hadolint ignore=DL3008
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
