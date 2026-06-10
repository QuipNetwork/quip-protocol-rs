use codec::Encode;

use crate::types::DifficultyConfig;

// Difficulty policy is block-based.
//
// The earlier timestamp-based approach created a unit mismatch in the pallet,
// because proof decay was evaluated during block execution while the stored
// "last proof" marker was expressed in wall-clock units. We now use elapsed
// blocks everywhere in the difficulty path so:
// - decay aligns directly with `EpochLength`
// - proof adjustment and decay reason over the same time unit
// - validation does not depend on timestamp availability or conversion
//
// These constants are the block-native thresholds the current policy uses,
// measuring elapsed chain blocks between consecutive qblocks (PoW-won
// blocks — formerly referred to as "solution #"/"problem #"). They
// correspond to the earlier 6-second-block translation:
// 360s -> 60 blocks, 600s -> 100 blocks, 1200s -> 200 blocks.
//
// `TARGET_PROOF_BLOCKS` is deliberately co-located with the runtime's
// `QuantumPowEpochLength` (= 100, the decay interval): the first decay
// step, the hardening band's gentle plateau, and the easing rate ramp all
// begin at the same 100-block boundary. A win round is therefore either
// "sub-epoch" (adjusts from the stored difficulty) or "decayed" (adjusts
// gently from the decay-eased base) — never a mix. The two remain separate
// constants on purpose: this one anchors the rate bands, the runtime one
// sets decay cadence. Retune them together.
const FAST_PROOF_BLOCKS: u64 = 60;
const TARGET_PROOF_BLOCKS: u64 = 100;
const SLOW_PROOF_BLOCKS: u64 = 200;

/// Proof adjustment enforces a 5000-milli floor on the energy delta so very
/// small curve outputs still move the threshold by a perceptible amount.
/// Mirrors v0.1 `apply_min_adjustment(min_adj=5.0)` for non-decay
/// adjustments: v0.1 operated on whole energy units, chain state stores
/// milli-energy, so 5.0 units -> 5000 milli.
const MIN_PROOF_ADJUSTMENT_DELTA_MILLI: i64 = 5000;

/// Decay enforces a 3000-milli floor — matches v0.1
/// `apply_min_adjustment(min_adj=3.0)` (whole energy units -> milli) for
/// decay easing.
const MIN_DECAY_DELTA_MILLI: i64 = 3000;

/// Decay rate per epoch step: 25 per-mille = 2.5%, half of the typical
/// hardening floor (50 per-mille). Mirrors v0.1 `energy_ease_rate = 0.025`.
const DECAY_RATE_MILLI: u32 = 25;

/// Direction the energy threshold moves under an adjustment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Make mining harder — push `max_energy_milli` toward `min_milli`
    /// (i.e. more negative).
    Harder,
    /// Make mining easier — push `max_energy_milli` toward `max_milli`
    /// (i.e. less negative).
    Easier,
}

/// Topology-derived bounds for the difficulty energy curve.
///
/// The curve is calibrated against a single topology's `(num_nodes,
/// num_edges)` evaluated at three empirical `c` values:
///
/// - `min_milli` = `expected_gse_with_c(.., c_hard)` — hardest, most negative.
/// - `knee_milli` = `expected_gse_with_c(.., c_knee)` — where the curve
///   compression peaks (motion most aggressive here).
/// - `max_milli` = `expected_gse_with_c(.., c_easy)` — easiest, least negative.
///
/// All three values are in milli precision. `min_milli < knee_milli <
/// max_milli` (all negative).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnergyCurve {
    pub min_milli: i64,
    pub knee_milli: i64,
    pub max_milli: i64,
}

impl EnergyCurve {
    /// Build a curve from topology size and three per-mille c values.
    ///
    /// The c values are SCALE-encoded `u32` because pallet constants must
    /// implement `Get<_>` and `f64` does not implement `Encode`. They are
    /// divided by 1000 internally before being fed to
    /// `expected_gse_with_c`.
    pub fn new(
        num_nodes: u32,
        num_edges: u32,
        c_easy_milli: u32,
        c_knee_milli: u32,
        c_hard_milli: u32,
    ) -> Self {
        let c_easy = f64::from(c_easy_milli) / 1000.0;
        let c_knee = f64::from(c_knee_milli) / 1000.0;
        let c_hard = f64::from(c_hard_milli) / 1000.0;
        Self {
            min_milli: quantum_validation::expected_gse_with_c(num_nodes, num_edges, c_hard),
            knee_milli: quantum_validation::expected_gse_with_c(num_nodes, num_edges, c_knee),
            max_milli: quantum_validation::expected_gse_with_c(num_nodes, num_edges, c_easy),
        }
    }
}

// Rate bands mirror v0.1 `calculate_adjustment_rate_with_randomness`:
//
// Hardening: <360s (60 blocks) -> 35% ± 30%; >600s (100 blocks) -> 5% ± 4%;
// linear interpolation in between. The graduated band matters because slow
// qblocks won by a non-dominant winner harden too — they need the gentle
// 5% rates, not the fast-qblock 35% ones.
//
// Easing: <600s (100 blocks) -> 2.5% ± 2%; >1200s (200 blocks) -> 15% ± 14%;
// linear interpolation in between.
fn sample_adjustment_milli(mining_time_blocks: u64, harder: bool, seed: &[u8]) -> u32 {
    let (base, variance) = if harder {
        if mining_time_blocks < FAST_PROOF_BLOCKS {
            (350_u32, 300_u32)
        } else if mining_time_blocks > TARGET_PROOF_BLOCKS {
            (50_u32, 40_u32)
        } else {
            let progress = ((mining_time_blocks - FAST_PROOF_BLOCKS) * 1000
                / (TARGET_PROOF_BLOCKS - FAST_PROOF_BLOCKS)) as u32;
            (
                350 - ((350 - 50) * progress / 1000),
                300 - ((300 - 40) * progress / 1000),
            )
        }
    } else if mining_time_blocks > SLOW_PROOF_BLOCKS {
        (150_u32, 140_u32)
    } else if mining_time_blocks < TARGET_PROOF_BLOCKS {
        (25_u32, 20_u32)
    } else {
        let progress = ((mining_time_blocks - TARGET_PROOF_BLOCKS) * 1000
            / (SLOW_PROOF_BLOCKS - TARGET_PROOF_BLOCKS)) as u32;
        (
            25 + ((150 - 25) * progress / 1000),
            20 + ((140 - 20) * progress / 1000),
        )
    };

    let min_rate = base.saturating_sub(variance).max(1);
    let max_rate = base.saturating_add(variance);
    let digest = blake3::hash(&(seed, mining_time_blocks, harder).encode());
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    let sample = u64::from_be_bytes(bytes);
    let span = u64::from(max_rate.saturating_sub(min_rate));

    min_rate + (sample % (span + 1)) as u32
}

/// Move `current_milli` along the energy curve by `rate_milli` per-mille of
/// the total range, with adjustments compressed near the boundaries and
/// peaking at the knee.
///
/// Port of v0.1 `shared.energy_utils.adjust_energy_along_curve` at git ref
/// `33a4837^`. When `current_milli` lies outside `[min_milli, max_milli]`,
/// the curve degrades to a linear `total_range * rate` adjustment — same
/// behaviour as v0.1.
///
/// Unlike v0.1, an in-range `current_milli` is clamped back into
/// `[min_milli, max_milli]` after the adjustment: a max-roll fast win from
/// the knee can otherwise overshoot past `min_milli`, recreating the
/// impossible-threshold state the v1 storage migration exists to repair.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn adjust_energy_along_curve(
    current_milli: i64,
    rate_milli: u32,
    direction: Direction,
    curve: EnergyCurve,
    min_delta_milli: i64,
) -> i64 {
    // Energy is signed and negative; min < max (both negative).
    let min_f = curve.min_milli as f64;
    let max_f = curve.max_milli as f64;
    let knee_f = curve.knee_milli as f64;
    let cur_f = current_milli as f64;
    let total_range = max_f - min_f;
    let rate = f64::from(rate_milli) / 1000.0;

    // Defensive: a degenerate curve (e.g. zero-node topology) has total_range
    // == 0. There is no meaningful adjustment to apply; leave `current` alone.
    if total_range <= 0.0 {
        return current_milli;
    }

    let raw_delta_f = if cur_f < min_f || cur_f > max_f {
        // Out-of-range: v0.1 falls back to linear adjustment.
        total_range * rate
    } else {
        let normalized = (cur_f - min_f) / total_range;
        let knee_pos = (knee_f - min_f) / total_range;
        let curve_factor = if knee_pos <= 0.0 || knee_pos >= 1.0 {
            // Degenerate knee position (curve collapses); treat as linear.
            1.0
        } else if normalized <= knee_pos {
            0.1 + 0.9 * libm::sqrt(normalized / knee_pos)
        } else {
            1.0 - 0.9 * libm::sqrt((normalized - knee_pos) / (1.0 - knee_pos))
        };
        total_range * rate * curve_factor
    };

    let mut delta = libm::round(raw_delta_f) as i64;
    // Gate the min-delta floor on the raw float, not the rounded int. A
    // raw_delta_f in (0, 0.5) rounds to 0, which would skip the floor and
    // stall difficulty progress — exactly the case `min_delta_milli` exists
    // to prevent. Once the floor is applied, subsequent rounds compound the
    // adjustment instead of getting stuck at no-op.
    if raw_delta_f > 0.0 && delta < min_delta_milli {
        delta = min_delta_milli;
    }
    if delta == 0 {
        return current_milli;
    }

    let adjusted = match direction {
        Direction::Harder => current_milli.saturating_sub(delta),
        Direction::Easier => current_milli.saturating_add(delta),
    };
    // In-range thresholds stay in range (see doc comment). Out-of-range
    // inputs keep the unclamped linear fallback so root-set sentinel values
    // converge gradually instead of snapping to a boundary. The early
    // `total_range <= 0` return above guarantees `min < max` here, so
    // `clamp` cannot panic.
    if current_milli >= curve.min_milli && current_milli <= curve.max_milli {
        adjusted.clamp(curve.min_milli, curve.max_milli)
    } else {
        adjusted
    }
}

/// Apply per-epoch decay easing to `current`, easing only the energy
/// threshold via the curve. Diversity, solutions, and quality fields
/// (when present) are chain-static and never touched here.
pub fn apply_decay(current: DifficultyConfig, steps: u32, curve: EnergyCurve) -> DifficultyConfig {
    let mut difficulty = current;
    for _ in 0..steps {
        difficulty.max_energy_milli = adjust_energy_along_curve(
            difficulty.max_energy_milli,
            DECAY_RATE_MILLI,
            Direction::Easier,
            curve,
            MIN_DECAY_DELTA_MILLI,
        );
    }
    difficulty
}

/// Adjust difficulty after a winning proof by a non-dominant winner.
/// Mutates only `max_energy_milli`; `min_solutions` and
/// `min_diversity_milli` are chain-static (only the `set_difficulty`
/// extrinsic — `ensure_root` — can change them).
pub fn adjust_on_proof(
    current: DifficultyConfig,
    mining_time_blocks: u64,
    curve: EnergyCurve,
    randomness_seed: &[u8],
) -> DifficultyConfig {
    adjust_on_proof_with_dominance(current, mining_time_blocks, curve, randomness_seed, false)
}

/// Adjust difficulty after a winning proof (a qblock), following the v0.1
/// `compute_next_block_requirements` policy:
///
/// - A fast qblock (under [`FAST_PROOF_BLOCKS`] elapsed chain blocks)
///   ALWAYS hardens — even for a dominant winner.
/// - A slow qblock eases only when the winner dominates (`dominant_winner`,
///   i.e. the same account won at least `ConsecutiveWinnerEasingThreshold`
///   consecutive qblocks); otherwise it hardens gently via the graduated
///   rate band.
///
/// v0.1 keyed dominance on the miner *type* repeating once (streak 2); we
/// key it on the account meeting the configured threshold instead — see
/// QUI-653 for the rationale.
pub fn adjust_on_proof_with_dominance(
    current: DifficultyConfig,
    mining_time_blocks: u64,
    curve: EnergyCurve,
    randomness_seed: &[u8],
    dominant_winner: bool,
) -> DifficultyConfig {
    let harder = mining_time_blocks < FAST_PROOF_BLOCKS || !dominant_winner;
    let rate_milli = sample_adjustment_milli(mining_time_blocks, harder, randomness_seed);
    let direction = if harder {
        Direction::Harder
    } else {
        Direction::Easier
    };
    let new_max_energy_milli = adjust_energy_along_curve(
        current.max_energy_milli,
        rate_milli,
        direction,
        curve,
        MIN_PROOF_ADJUSTMENT_DELTA_MILLI,
    );
    DifficultyConfig {
        max_energy_milli: new_max_energy_milli,
        // Chain-static — never touched here.
        min_solutions: current.min_solutions,
        min_diversity_milli: current.min_diversity_milli,
    }
}

/// Compute the active difficulty for `block_number`, applying decay since
/// the previous winning proof.
///
/// This is the per-block view of difficulty that miners must clear and
/// that `adjust_on_proof` consumes as its baseline. All inputs are
/// explicit — the function reads no storage and is unit-testable in
/// isolation. The pallet wraps this with a method that does the four
/// storage reads (`Difficulty<T>`, `LastProofBlock<T>`, `EpochLength`
/// const, and `DefaultTopology<T>` → `RegisteredTopologies<T>` → curve).
///
/// A `None` curve disables decay — used at genesis (no topology
/// registered) or as a defensive fallback. `last_proof_block == 0` is
/// the genesis sentinel for "no winning proof yet".
pub fn current_difficulty(
    block_number: u32,
    base_difficulty: DifficultyConfig,
    last_proof_block: u32,
    epoch_length: u32,
    curve: Option<EnergyCurve>,
) -> DifficultyConfig {
    if last_proof_block == 0 || epoch_length == 0 {
        return base_difficulty;
    }
    let elapsed = block_number.saturating_sub(last_proof_block);
    let steps = elapsed / epoch_length;
    if steps == 0 {
        return base_difficulty;
    }
    match curve {
        Some(curve) => apply_decay(base_difficulty, steps, curve),
        None => base_difficulty,
    }
}
