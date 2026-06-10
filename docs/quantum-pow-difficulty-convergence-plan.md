# Quantum PoW Difficulty Convergence Plan

## Problem

Current PoW difficulty adjustment can converge into energy ranges that are
effectively unsolvable for the current design. A fast win can push
`max_energy_milli` too hard, and recovery then depends on decay sweeps that can
take hours before the threshold becomes mineable again.

The main causes are:

- The runtime energy curve uses `c = 0.700 / 0.750 / 0.800`, making the hard end
  too negative.
- The hardening cutoff is effectively 100 blocks, or roughly 600 seconds at
  six-second blocks.
- The prior miner-type/QPU dominance easing behavior is no longer represented.
  We cannot reliably use miner type today, but we can detect repeated wins by
  the same account.

## Goals

- Keep difficulty in a theoretically solvable range.
- Restore a roughly 10-minute convergence target after wins.
- Reduce difficulty when the same miner account dominates consecutive wins.
- Avoid changing extrinsic arguments or signed transaction encoding.
- Keep decay interval and proof hardening cutoff separate.

## Proposed Changes

### 1. Recalibrate the Energy Curve

Change runtime PoW curve constants in `runtime/src/configs/mod.rs`:

```rust
pub const QuantumPowCurveCEasyMilli: u32 = 700;
pub const QuantumPowCurveCKneeMilli: u32 = 725;
pub const QuantumPowCurveCHardMilli: u32 = 750;
```

This replaces the current `0.700 / 0.750 / 0.800` curve with
`0.700 / 0.725 / 0.750`.

Expected effect:

- The knee moves back into the intended range.
- The hard edge is still difficult, but no longer pushed into the known
  impossible range.
- Future tuning can move the middle value slightly upward, for example
  `0.728` or `0.730`, if observed chain data supports it.

Update all mock/test curve construction from `EnergyCurve::new(..., 700, 750,
800)` to `EnergyCurve::new(..., 700, 725, 750)`.

### 2. Separate Hardening Cutoff from Decay Interval

Keep `QuantumPowEpochLength = 100` as the decay interval.

In `pallets/quantum-pow/src/difficulty.rs`, replace the current target proof
threshold behavior with explicit policy names:

```rust
const HARDEN_CUTOFF_BLOCKS: u64 = 60;
const SLOW_PROOF_BLOCKS: u64 = 200;
```

The current `TARGET_PROOF_BLOCKS = 100` should not continue to decide whether a
win hardens or eases difficulty. A win before 60 blocks hardens. A win at or
after 60 blocks eases.

Important implementation detail:

- Do not simply set the existing `TARGET_PROOF_BLOCKS` to 60 while leaving
  `FAST_PROOF_BLOCKS = 60`.
- That would collapse the interpolation range in `sample_adjustment_milli`.
- Rework the sampling function so the hardening and easing ranges are explicit
  and cannot divide by zero.

### 3. Add Dominant-Winner Easing

Add storage to track consecutive wins by the same miner account. A simple shape
is enough:

```rust
pub type WinnerStreak<T: Config> = StorageValue<
    _,
    types::WinnerStreak<T::AccountId>,
    OptionQuery,
>;
```

Add a type in `pallets/quantum-pow/src/types.rs`:

```rust
pub struct WinnerStreak<AccountId> {
    pub miner: AccountId,
    pub count: u32,
}
```

Add a runtime config constant:

```rust
type ConsecutiveWinnerEasingThreshold: Get<u32>;
```

Recommended runtime value:

```rust
pub const QuantumPowConsecutiveWinnerEasingThreshold: u32 = 3;
```

Policy:

- If the current winner is the same account as the stored streak miner,
  increment the streak count.
- If the current winner differs, reset the streak to `{ miner, count: 1 }`.
- If the resulting streak count is greater than or equal to the threshold,
  force the post-win adjustment direction to `Easier`.
- Otherwise, use normal time-based difficulty adjustment.

This restores the spirit of miner-type/QPU awareness without adding node
descriptors or changing miner registration.

### 4. Clamp Existing Impossible Difficulty on Runtime Upgrade

`pallet_quantum_pow` does not currently have a storage version. Add one and
wire an `on_runtime_upgrade`.

Migration behavior:

- Read `DefaultTopology`.
- Read the matching registered topology.
- Build the new curve from the recalibrated constants.
- If `Difficulty.max_energy_milli < curve.min_milli`, clamp it to
  `curve.knee_milli`.
- Preserve `min_solutions` and `min_diversity_milli`.
- If no default topology is registered, no-op.

Rationale:

- Changing constants fixes future adjustment, but existing chain state may
  already hold an impossible threshold.
- Clamping only out-of-range values avoids disturbing healthy deployments.

### 5. Runtime Versioning

Bump `spec_version` in `runtime/src/lib.rs`.

Do not bump `transaction_version` unless extrinsic arguments change. This plan
does not require any extrinsic encoding changes.

## Tests

Add or update tests for:

- New curve constants: `700 / 725 / 750`.
- Curve ordering remains `min_milli < knee_milli < max_milli`.
- Fast proof before 60 blocks hardens for a non-dominant winner.
- Proof at or after 60 blocks eases.
- Consecutive same-miner wins at the threshold ease instead of harden.
- Winner streak resets when a different miner wins.
- Migration clamps an out-of-range `Difficulty.max_energy_milli` to the new
  knee.
- Migration leaves in-range difficulty unchanged.
- Existing decay and mining snapshot tests use the recalibrated curve.

## Non-Goals

- Do not add miner type or node descriptor metadata in this changeset.
- Do not change proof submission extrinsic arguments.
- Do not change `QuantumPowEpochLength` unless separate chain data shows decay
  cadence itself needs tuning.
- Do not change `min_solutions` or `min_diversity_milli` as part of automatic
  adjustment.
