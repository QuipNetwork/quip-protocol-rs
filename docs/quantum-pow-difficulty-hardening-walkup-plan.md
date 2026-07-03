# Quantum PoW Difficulty: Walk Up the Curve, Don't Slam the Ceiling

## Summary

A single fast qblock can harden `max_energy_milli` by up to ~65% of the entire
energy-curve range in one step, overshooting and **clamping to the hard ceiling**
(`min_milli`). Because per-epoch decay only eases ~2.5% of the range per step, the
threshold then takes **thousands of chain blocks** to crawl back into a mineable
range. The result is a slam-and-stall sawtooth: difficulty jumps to the hardest
the curve allows, no miner can win, and the chain stalls until decay walks the
threshold back down.

Difficulty should **walk up** the curve in small steps that track real miner
capability, so the threshold hovers just inside what miners can reach instead of
pinning the ceiling.

This is a follow-up to `quantum-pow-difficulty-convergence-plan.md`. That plan
fixed the curve *bounds* (recalibrated `c` to `0.700/0.725/0.750`) but left the
per-win *step size* at the legacy `35%±30%` band — so even on the narrower curve,
one fast win still saturates it.

## Evidence (live testnet, default topology `0xe66d3dfa…`, h=0)

Energy curve for the topology (4577 nodes / 41515 edges, h=0, J binary):

| point | c | expected GSE |
|-------|------|--------------|
| easy  | 0.700 | −13,646.0 |
| knee  | 0.725 | −14,133.4 |
| hard  | 0.750 | −14,620.7 |

Observed chain state:

- Stored base difficulty = **−14,620.7** — i.e. pinned to the **exact hard
  ceiling** (`min_milli`).
- Last winning block (472194) cleared a decayed threshold of **−14,204.1** with a
  winning energy of **−14,307.0**, then the post-win adjustment jumped the base to
  the −14,620.7 ceiling.
- The active mining field tops out around **−14,143 … −14,307** (eight most recent
  winners). Nothing observed reaches −14,620.7 — wins happen only after decay has
  eased the threshold back into that band.
- Recent inter-win gaps (blocks): 29, 280, 27, 200, 100, 300, **1401**. The long
  gaps are decay-recovery stalls after a hard clamp.

Simulation of the current algorithm (ported from `difficulty.rs`):

```
Single FAST win from the −14,204 threshold the 472194 winner cleared:
  fast-harden roll  5%  -> new base −14,249.6
  fast-harden roll 20%  -> new base −14,385.9
  fast-harden roll 35%  -> new base −14,522.1
  fast-harden roll 50%  -> new base −14,620.7   <-- CLAMPED TO HARD CEILING
  fast-harden roll 65%  -> new base −14,620.7   <-- CLAMPED TO HARD CEILING

Decay recovery from the ceiling (2.5%/step, one step per 100-block epoch):
  back to −14,357 (a mid GPU miner)  : 24 steps = 2,400 blocks
  back to −14,307 (field best win)   : 27 steps = 2,700 blocks
  back to −14,204 (last win level)   : 32 steps = 3,200 blocks
```

The fast band is `35%±30%` (per-mille `350±300`), so a large fraction of fast-win
rolls land ≥50% and clamp; even a median 35% roll lands at −14,522, a hair from
the ceiling.

## Root cause

The step is taken as a fraction of the **whole curve span**, not of the distance
remaining to the bound it is moving toward. In `adjust_energy_along_curve`
(`difficulty.rs:195-260`):

```
raw_delta = total_range × rate × curve_factor      # total_range = max_milli − min_milli
```

So a `35%` fast-harden roll is 35% of the *entire* ≈975-unit range, scaled by a
knee `curve_factor` that is ~0.9–1.0 across the middle and only falls to 0.1 right
at the edges. From a mid-curve threshold (the −14,204 the last winner cleared,
`curve_factor ≈ 0.93`) one win moves 0.35–0.65 × 975 ≈ **320–630 units** — past
`min_milli` — and the in-range clamp (`difficulty.rs:255-256`) then **pins it to
the ceiling**. `curve_factor` does not prevent this: it keys off *position on the
curve*, not *distance remaining*, and bottoms out at 0.1 rather than 0.

This compounds an **asymmetry** with easing:

- **Harden** (per winning qblock): `sample_adjustment_milli` fast band `350±300`
  per-mille → up to 65% of the total range in one step (`difficulty.rs:143-179`).
- **Ease** (per decay epoch): `DECAY_RATE_MILLI = 25` per-mille → 2.5% of the
  range per step (`difficulty.rs:48`, `apply_decay` `difficulty.rs:265-277`), one
  step per `EpochLength = 100` blocks.

The pallet feeds the *decayed live threshold* the winner actually cleared into the
adjustment (`lib.rs:516,522`), which is correct — but the step applied to it is a
fraction of the full range, so a fast win slams `min_milli`. The convergence plan's
curve recalibration narrowed the range but kept this total-range step, so the slam
persists.

Net behavior: near-vertical rise to the ceiling on a fast win, followed by a long,
shallow decay the field cannot win through for ~2,400–3,200 blocks (~4–5 hours at
6s blocks).

## Goals

- A single qblock moves difficulty by a *small* step, so the curve is climbed over
  many wins (a walk), never saturated in one.
- Hardening and easing are of comparable magnitude, so the steady state is a
  shallow sawtooth that hovers just inside achievable energy, not a slam-and-stall.
- No change to extrinsic arguments or signed-transaction encoding (constants /
  internal algorithm only; ships as a runtime upgrade with a `spec_version` bump).

## Proposed changes

All in `pallets/quantum-pow/src/difficulty.rs` unless noted.

### 1. Step a fraction of the distance to the bound, not of the whole range

Replace `total_range × rate × curve_factor` with a step proportional to the
distance **remaining** to whichever bound we move toward:

```
harden:  delta = (current_milli − min_milli) × rate     # current − (−14620.7) ; closes the gap to the hard cap
easier:  delta = (max_milli − current_milli) × rate
new   :  harden -> current − delta ;  easier -> current + delta
floor :  delta = max(delta, MIN_DELTA)                  # 1 energy step, so progress never stalls
```

Equivalently, in magnitudes, a harden of `(14620 − |current|) × 0.35`.

Properties this gives for free:

- **Geometric walk-up.** Each win closes a fixed fraction of the *remaining* gap,
  so from the field level (≈−14,300) it takes ~14 wins at `rate = 0.35` to approach
  the cap — a walk, not a one-win slam.
- **Asymptotic, no overshoot.** `current` approaches `min_milli` but never crosses
  it, so the in-range clamp (`difficulty.rs:255-256`) and the knee `curve_factor`
  become unnecessary — both can be dropped.
- **1-energy-step tail.** At the cap, `(current − min_milli) → 0`, so `delta`
  floors to a single energy unit; difficulty already at max moves at most ±1.

`rate` keeps its existing fast/graduated/slow bands (`sample_adjustment_milli`,
`difficulty.rs:143-179`) — they now mean "fraction of the remaining gap," which is
self-limiting, so the band magnitudes are no longer the thing preventing a slam.

### 2. Apply the same model to decay easing

`apply_decay` should ease by `(max_milli − current) × DECAY_RATE` per step (toward
the easy cap), so decay is a geometric walk-down symmetric with the walk-up rather
than a fixed 2.5%-of-range slab.

### 3. Re-balance the min-delta floors

Under the geometric model the per-step delta shrinks to the floor near the bound, so
the floor sets the size of the 1-energy-step tail. `MIN_PROOF_ADJUSTMENT_DELTA_MILLI
= 5000` (harden) vs `MIN_DECAY_DELTA_MILLI = 3000` (ease) (`difficulty.rs:39,44`) is
asymmetric — harden beats ease 5:3 at the tail. Set both to the same small value
(the "1 energy step" floor) so approach to either bound is symmetric.

Recovery is no longer a separate concern: easing toward the easy cap by
`(max − current) × rate` (§2) takes its *largest* steps exactly at the hard
ceiling (where `max − current` is the full range), so a threshold near `min_milli`
recovers fastest — the inverse of the old `curve_factor`, which was slowest there.

## Tests

- **No overshoot (`difficulty.rs` tests):** from any in-range `current` and any
  rate roll in the band, a single harden must leave `current > min_milli` (strictly
  inside); assert `delta == round((current − min_milli) × rate)` above the floor.
- **Walk-up property:** from the field level, it takes ≥K consecutive fast wins to
  reach within ε of `min_milli` (K large; e.g. ≥10).
- **Symmetry:** max harden step and max decay step per equal wall-clock are within a
  small factor.
- **Convergence simulation:** replay the observed win series (intervals 29, 280, 27,
  200, 100, 300, 1401) and assert the threshold stays within `[field_best − margin,
  knee]` and never pins `min_milli`; assert no decay-recovery gap > target.
- **Migration safety:** existing on-chain base at `min_milli` must converge upward
  under the new rates within a bounded number of blocks (pairs with the convergence
  plan's upgrade clamp, §4 there).

## Non-goals

- Changing the curve `c` constants again (done in the convergence plan).
- Changing extrinsic arguments, encoding, or `tx_version`.
- Touching diversity / min-solutions difficulty fields.

## References

- `pallets/quantum-pow/src/difficulty.rs`
  - `sample_adjustment_milli` (rate bands): `143-179`
  - `adjust_energy_along_curve` (step + in-range clamp): `195-260`
  - `apply_decay` / `DECAY_RATE_MILLI`: `265-277`, `48`
  - constants (`FAST/TARGET/SLOW_PROOF_BLOCKS`, min-delta floors): `30-48`
  - `adjust_on_proof_with_dominance`: `305-332`
- `pallets/quantum-pow/src/lib.rs` on-finalize adjustment (feeds decayed live
  threshold in, writes new base): `505-536`
- Prior work: `docs/quantum-pow-difficulty-convergence-plan.md` (curve
  recalibration + decay/hardening separation + dominant-winner easing).
