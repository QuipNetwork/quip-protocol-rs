# Quantum PoW Difficulty Convergence Plan

## Terminology

A **qblock** (also `qpow_block`) is a chain block won by a quantum PoW
proof — what we previously referred to as "solution #N" or "problem #N".
The timing thresholds in this document are measured in elapsed *chain
blocks* (6-second Substrate blocks) between consecutive qblocks: a "fast
qblock" is one mined fewer than 60 chain blocks after the previous qblock.

## Problem

Current PoW difficulty adjustment can converge into energy ranges that are
effectively unsolvable for the current design. A fast qblock can push
`max_energy_milli` too hard, and recovery then depends on decay sweeps that can
take hours before the threshold becomes mineable again.

The main causes are:

- The runtime energy curve uses `c = 0.700 / 0.750 / 0.800`, making the hard end
  too negative.
- The hardening cutoff is effectively 100 chain blocks, or roughly 600
  seconds at six-second blocks.
- The prior miner-type/QPU dominance easing behavior is no longer represented.
  We cannot reliably use miner type today, but we can detect repeated qblock
  wins by the same account.

## Goals

- Keep difficulty in a theoretically solvable range.
- Restore a roughly 10-minute convergence target after qblocks.
- Reduce difficulty when the same miner account dominates consecutive
  qblocks.
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

In `pallets/quantum-pow/src/difficulty.rs`, keep the v0.1 block-native
thresholds:

```rust
const FAST_PROOF_BLOCKS: u64 = 60;
const TARGET_PROOF_BLOCKS: u64 = 100;
const SLOW_PROOF_BLOCKS: u64 = 200;
```

Direction follows the v0.1 `compute_next_block_requirements` policy:

- A qblock mined before 60 chain blocks (360s) always hardens, even for a
  dominant winner.
- A qblock at or after 60 chain blocks hardens gently (graduated 35%→5%
  band) unless the winner is dominant (see Section 3), in which case it
  eases.

`TARGET_PROOF_BLOCKS = 100` no longer decides direction — only the rate
bands: hardening interpolates 35%±30% → 5%±4% across 60–100 chain blocks,
easing interpolates 2.5%±2% → 15%±14% across 100–200 chain blocks, exactly
as v0.1 did across 360–600s and 600–1200s. The decay interval
(`EpochLength = 100`) remains a separate concept.

The 100-block value of `TARGET_PROOF_BLOCKS` is deliberately co-located
with `QuantumPowEpochLength = 100`: the first decay step, the hardening
band's gentle plateau, and the easing rate ramp all begin at the same
100-chain-block (600s) boundary. This yields three clean qblock cases:

1. **Fast qblock (< 60 chain blocks):** always hardens at 35%±30%,
   dominant or not.
2. **Regular qblock (60–99 chain blocks):** sub-epoch, so no decay has
   occurred; the adjustment starts from the stored difficulty. Streaks
   decide direction — a dominant winner eases, anyone else hardens on the
   graduated 35%→5% band.
3. **Slow qblock (≥ 100 chain blocks):** decay has already eased the
   stored difficulty by `elapsed / EpochLength` steps; the adjustment
   starts from that decay-eased base. Streaks decide direction, and
   hardening sits on the gentle 5%±4% plateau — so a long round can end
   easier overall even though the qblock itself hardened.

`TARGET_PROOF_BLOCKS` and `QuantumPowEpochLength` stay separate constants
(rate-band anchor vs decay cadence). Retuning the epoch length does not
move the rate bands — change both together or the three-case model above
stops holding.

### 3. Add Dominant-Winner Easing

Add storage to track consecutive qblocks won by the same miner account. A
simple shape is enough:

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

- If the current qblock winner is the same account as the stored streak
  miner, increment the streak count.
- If the current winner differs, reset the streak to `{ miner, count: 1 }`.
- A winner with streak count at or above the threshold is *dominant*: its
  qblocks at or past 60 chain blocks ease difficulty instead of hardening.
- Fast qblocks (under 60 chain blocks) always harden, dominant or not —
  matching v0.1, where the under-360s harden rule took precedence over
  repeat-winner easing.
- Non-dominant slow qblocks harden gently. v0.1 eased any repeat winner (a
  streak of 2, keyed on miner type); we instead require the configured
  threshold (3) by account, so a winner must demonstrate sustained dominance
  before difficulty pressure reverses.
- A threshold of `0` disables dominant-winner easing.

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
- Fast qblock before 60 chain blocks hardens, including for a dominant
  winner.
- Slow qblock at or after 60 chain blocks hardens gently for a non-dominant
  winner (including a different winner — the restored v0.1 rule).
- Consecutive same-miner slow qblocks at the threshold ease instead of
  harden.
- Winner streak resets when a different miner wins a qblock.
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
