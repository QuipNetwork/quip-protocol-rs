#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/run-benchmarks.sh
#
# Regenerates pallet weight files (pallets/<dir>/src/weights.rs) by running
# the FRAME benchmarks. Meant to run on the benchmark reference machine (the
# CI `benchmark-weights` job), but runs anywhere for a local pre-flight —
# just don't commit weights measured off-reference hardware.
#
# What it does:
#   1. Builds the node with `--features runtime-benchmarks`.
#   2. Derives the pallet list from `benchmark pallet --list` — the runtime's
#      define_benchmarks! registry — so a newly registered pallet is picked up
#      with no change here.
#   3. Regenerates weights for every listed pallet that has a matching in-repo
#      crate directory (pallet_foo_bar -> pallets/foo-bar). Pallets without
#      one (frame_system, pallet_balances, ...) use upstream SubstrateWeight
#      and are skipped until runtime/src/weights/ wiring exists for them.
#
# Environment overrides:
#   STEPS / REPEAT   benchmark resolution (default 50 / 20, the settings the
#                    existing generated weights were produced with)
#   SKIP_PALLETS     space-separated pallets to skip. Default skips
#                    pallet_quantum_pow: its WeightInfo carries the QIP-03
#                    parameterized submit_proof(nodes, edges, solutions)
#                    signature, but the benchmark declares no Linear<>
#                    components yet, so regeneration would emit the
#                    un-parameterized signature and break the build. Drop it
#                    from the skip list once the benchmark grows components.

STEPS="${STEPS:-50}"
REPEAT="${REPEAT:-20}"
SKIP_PALLETS="${SKIP_PALLETS:-pallet_quantum_pow}"

echo "== Building node with runtime-benchmarks (this is the slow part) =="
cargo build --release --features runtime-benchmarks -p quip-network-node

BIN="${CARGO_TARGET_DIR:-target}/release/quip-network-node"

# `benchmark pallet --list` prints CSV rows of "<pallet>, <benchmark>".
# First column, deduplicated, header dropped.
mapfile -t pallets < <(
  "$BIN" benchmark pallet --list \
    | awk -F', ' '/^[a-z0-9_]+, /{print $1}' \
    | grep -v '^pallet$' \
    | sort -u
)

if [ "${#pallets[@]}" -eq 0 ]; then
  echo "ERROR: derived no pallets from 'benchmark pallet --list' — output format change?" >&2
  exit 1
fi

echo "== Benchmarkable pallets: ${pallets[*]} =="

for pallet in "${pallets[@]}"; do
  case " $SKIP_PALLETS " in
    *" $pallet "*)
      echo "-- $pallet: SKIPPED (SKIP_PALLETS)"
      continue
      ;;
  esac

  dir="pallets/$(echo "${pallet#pallet_}" | tr '_' '-')"
  if [ ! -d "$dir" ]; then
    echo "-- $pallet: no in-repo crate at $dir, skipping (upstream weights)"
    continue
  fi

  echo "== Benchmarking $pallet -> $dir/src/weights.rs =="
  "$BIN" benchmark pallet \
    --pallet "$pallet" \
    --extrinsic '*' \
    --steps "$STEPS" \
    --repeat "$REPEAT" \
    --output "$dir/src/weights.rs"
done

echo "== Done. Regenerated files: =="
git diff --stat -- 'pallets/*/src/weights.rs' || true
