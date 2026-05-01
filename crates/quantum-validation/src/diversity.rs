//! Diversity and symmetric Hamming distance helpers for Ising solution sets.

use alloc::vec;
use alloc::vec::Vec;

use crate::errors::ValidationError;
use crate::fixed::{round_div_u64, MilliDiversity, MILLI_SCALE};
use crate::validation::{ensure_valid_spins, validate_solution_set};

/// Compute symmetric Hamming distance between two spin configurations.
///
/// The distance is symmetric under global spin flip, so `a` and `-a` have
/// distance `0`. This matches the Python reference behavior and the Ising
/// model's sign symmetry.
pub fn symmetric_hamming(a: &[i8], b: &[i8]) -> Result<u32, ValidationError> {
    if a.len() != b.len() {
        return Err(ValidationError::SolutionLengthMismatch {
            expected: a.len(),
            actual: b.len(),
        });
    }

    ensure_valid_spins(a)?;
    ensure_valid_spins(b)?;

    let mut direct = 0_u32;
    let mut inverted = 0_u32;

    for (&lhs, &rhs) in a.iter().zip(b.iter()) {
        if lhs != rhs {
            direct += 1;
        }
        if lhs != -rhs {
            inverted += 1;
        }
    }

    Ok(direct.min(inverted))
}

/// Compute average pairwise diversity in milli precision.
///
/// The result is the average normalized symmetric Hamming distance between all
/// pairs of solutions, scaled by [`MILLI_SCALE`].
///
/// Examples:
///
/// - `0` means no diversity
/// - `333` means `0.333`
/// - `1000` means maximal diversity
pub fn calculate_diversity<T: AsRef<[i8]>>(
    solutions: &[T],
) -> Result<MilliDiversity, ValidationError> {
    if solutions.len() < 2 {
        return Ok(0);
    }

    let expected_len = ensure_valid_solution_inputs(solutions)?;

    let mut total_distance = 0_u64;
    let mut pair_count = 0_u64;

    for i in 0..solutions.len() {
        for j in (i + 1)..solutions.len() {
            total_distance += u64::from(symmetric_hamming(
                solutions[i].as_ref(),
                solutions[j].as_ref(),
            )?);
            pair_count += 1;
        }
    }

    let numerator = total_distance
        .checked_mul(MILLI_SCALE as u64)
        .ok_or(ValidationError::ArithmeticOverflow)?;
    let denominator = pair_count
        .checked_mul(expected_len as u64)
        .ok_or(ValidationError::ArithmeticOverflow)?;

    Ok(round_div_u64(numerator, denominator) as MilliDiversity)
}

/// Select a subset of solutions that maximizes pairwise separation.
///
/// The current implementation uses a simple farthest-point strategy:
///
/// 1. start from the most distant pair
/// 2. repeatedly add the candidate whose minimum distance to the selected set
///    is maximal
///
/// The returned indices refer to positions in the input slice.
pub fn select_diverse<T: AsRef<[i8]>>(
    solutions: &[T],
    target_count: usize,
) -> Result<Vec<usize>, ValidationError> {
    if solutions.is_empty() || target_count == 0 {
        return Ok(Vec::new());
    }

    ensure_valid_solution_inputs(solutions)?;

    if solutions.len() <= target_count {
        return Ok((0..solutions.len()).collect());
    }

    let mut selected = most_distant_pair(solutions)?;

    while selected.len() < target_count {
        let mut best_index = None;
        let mut best_min_distance = 0_u32;

        for candidate in 0..solutions.len() {
            if selected.contains(&candidate) {
                continue;
            }

            let mut min_distance = u32::MAX;
            for &chosen in &selected {
                let distance =
                    symmetric_hamming(solutions[candidate].as_ref(), solutions[chosen].as_ref())?;
                min_distance = min_distance.min(distance);
            }

            if best_index.is_none() || min_distance > best_min_distance {
                best_index = Some(candidate);
                best_min_distance = min_distance;
            }
        }

        if let Some(index) = best_index {
            selected.push(index);
        } else {
            break;
        }
    }

    Ok(selected)
}

fn most_distant_pair<T: AsRef<[i8]>>(solutions: &[T]) -> Result<Vec<usize>, ValidationError> {
    let mut best = (0_usize, 1_usize);
    let mut best_distance = symmetric_hamming(solutions[0].as_ref(), solutions[1].as_ref())?;

    for i in 0..solutions.len() {
        for j in (i + 1)..solutions.len() {
            let distance = symmetric_hamming(solutions[i].as_ref(), solutions[j].as_ref())?;
            if distance > best_distance {
                best = (i, j);
                best_distance = distance;
            }
        }
    }

    Ok(vec![best.0, best.1])
}

fn ensure_valid_solution_inputs<T: AsRef<[i8]>>(solutions: &[T]) -> Result<usize, ValidationError> {
    let expected_len = solutions[0].as_ref().len();
    if !validate_solution_set(solutions, expected_len) {
        for solution in solutions {
            let spins = solution.as_ref();
            if spins.len() != expected_len {
                return Err(ValidationError::SolutionLengthMismatch {
                    expected: expected_len,
                    actual: spins.len(),
                });
            }
            ensure_valid_spins(spins)?;
        }
    }

    Ok(expected_len)
}

#[cfg(test)]
mod tests {
    use super::{calculate_diversity, select_diverse, symmetric_hamming};

    #[test]
    fn symmetric_hamming_respects_global_spin_flip() {
        let a = [1, -1, 1, -1];
        let b = [-1, 1, -1, 1];

        assert_eq!(symmetric_hamming(&a, &b).unwrap(), 0);
    }

    #[test]
    fn diversity_is_zero_for_identical_solutions() {
        let solutions = [[1, -1], [1, -1]];

        assert_eq!(calculate_diversity(&solutions).unwrap(), 0);
    }

    #[test]
    fn select_diverse_prefers_extremes_first() {
        let solutions = [[1, 1], [1, -1], [-1, 1], [-1, -1]];
        let selected = select_diverse(&solutions, 2).unwrap();

        assert_eq!(selected.len(), 2);
        assert_ne!(selected[0], selected[1]);
    }
}
