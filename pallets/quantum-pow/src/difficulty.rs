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
// These constants are the block-native thresholds the current policy uses.
// They correspond to the earlier 6-second-block translation:
// 360s -> 60 blocks, 600s -> 100 blocks, 1200s -> 200 blocks.
const FAST_PROOF_BLOCKS: u64 = 60;
const TARGET_PROOF_BLOCKS: u64 = 100;
const SLOW_PROOF_BLOCKS: u64 = 200;

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

pub fn apply_decay(current: DifficultyConfig, steps: u32) -> DifficultyConfig {
    let mut difficulty = current;
    for _ in 0..steps {
        difficulty.max_energy_milli = difficulty.max_energy_milli.saturating_add(3);
        difficulty.min_diversity_milli = difficulty.min_diversity_milli.saturating_sub(10);
        difficulty.min_solutions = difficulty
            .min_solutions
            .saturating_sub((difficulty.min_solutions / 20).max(1));
        difficulty.min_quality_milli = difficulty.min_quality_milli.saturating_sub(10);
    }
    difficulty
}

pub fn adjust_on_proof(
    current: DifficultyConfig,
    mining_time_blocks: u64,
    randomness_seed: &[u8],
) -> DifficultyConfig {
    let harder = mining_time_blocks < TARGET_PROOF_BLOCKS;
    let adjustment_milli = sample_adjustment_milli(mining_time_blocks, harder, randomness_seed);
    let energy_delta = i64::from((adjustment_milli / 10).max(5));
    let diversity_delta = (adjustment_milli / 5).max(5);
    let solutions_delta = (adjustment_milli / 100).max(1);
    let quality_delta = (adjustment_milli / 5).max(5);

    if harder {
        DifficultyConfig {
            min_solutions: current.min_solutions.saturating_add(solutions_delta),
            max_energy_milli: current.max_energy_milli.saturating_sub(energy_delta),
            min_diversity_milli: current.min_diversity_milli.saturating_add(diversity_delta),
            min_quality_milli: current.min_quality_milli.saturating_add(quality_delta),
        }
    } else {
        DifficultyConfig {
            min_solutions: current.min_solutions.saturating_sub(solutions_delta),
            max_energy_milli: current.max_energy_milli.saturating_add(energy_delta),
            min_diversity_milli: current.min_diversity_milli.saturating_sub(diversity_delta),
            min_quality_milli: current.min_quality_milli.saturating_sub(quality_delta),
        }
    }
}
