//! Exact Ising energy computation in fixed-point milli precision.

use crate::errors::ValidationError;
use crate::fixed::{MilliEnergy, MilliValue, MILLI_SCALE};
use crate::validation::{ensure_valid_spins, ensure_valid_topology};

const DEFAULT_GSE_C: f64 = 0.75;
const DEFAULT_H_NONZERO_FRACTION: f64 = 2.0 / 3.0;
const DEFAULT_H_ALPHA: f64 = 0.88;

/// Compute the Ising energy of a spin configuration.
///
/// The function expects:
///
/// - `solution.len() == nodes.len()`
/// - `h.len() == nodes.len()`
/// - `edges.len() == j.len()`
/// - all spin values are in `{-1, +1}`
/// - every edge endpoint is present in `nodes`
///
/// The `nodes` slice defines the variable ordering used to interpret the
/// `solution` slice.
///
/// All values are fixed-point milli precision. For example:
///
/// - `500` means `0.5`
/// - `-1250` means `-1.25`
///
/// Returns a [`ValidationError`] if the structural inputs are malformed or if
/// the fixed-point computation overflows.
pub fn energy_of_solution(
    solution: &[i8],
    h: &[MilliValue],
    edges: &[(u32, u32)],
    j: &[MilliValue],
    nodes: &[u32],
) -> Result<MilliEnergy, ValidationError> {
    validate_shape(solution, h, edges, j, nodes)?;
    ensure_valid_spins(solution)?;

    let mut energy = 0_i64;

    for (position, (&node, &field)) in nodes.iter().zip(h.iter()).enumerate() {
        let _ = node;
        energy = energy
            .checked_add(i64::from(field) * i64::from(solution[position]))
            .ok_or(ValidationError::ArithmeticOverflow)?;
    }

    for (&(u, v), &coupling) in edges.iter().zip(j.iter()) {
        let u_pos =
            position_of_node(nodes, u).ok_or(ValidationError::UnknownNodeInEdge { node: u })?;
        let v_pos =
            position_of_node(nodes, v).ok_or(ValidationError::UnknownNodeInEdge { node: v })?;
        energy = energy
            .checked_add(
                i64::from(coupling) * i64::from(solution[u_pos]) * i64::from(solution[v_pos]),
            )
            .ok_or(ValidationError::ArithmeticOverflow)?;
    }

    Ok(energy)
}

/// Estimate the expected ground-state energy for a random Ising problem.
///
/// This mirrors the current Python reference model in
/// `shared.energy_utils.expected_solution_energy()` using its default
/// parameters:
///
/// - `c = 0.75`
/// - ternary local fields `{-1, 0, +1}`
///
/// The result is returned in milli precision.
pub fn expected_gse(num_nodes: u32, num_edges: u32) -> MilliEnergy {
    if num_nodes == 0 || num_edges == 0 {
        return 0;
    }

    let n = f64::from(num_nodes);
    let m = f64::from(num_edges);
    let avg_degree = (2.0 * m) / n;

    let sqrt_avg_degree = libm::sqrt(avg_degree);
    let j_contribution = -DEFAULT_GSE_C * sqrt_avg_degree * n;
    let h_contribution =
        -DEFAULT_GSE_C * DEFAULT_H_ALPHA * DEFAULT_H_NONZERO_FRACTION * n / sqrt_avg_degree;

    libm::round((j_contribution + h_contribution) * (MILLI_SCALE as f64)) as MilliEnergy
}

fn validate_shape(
    solution: &[i8],
    h: &[MilliValue],
    edges: &[(u32, u32)],
    j: &[MilliValue],
    nodes: &[u32],
) -> Result<(), ValidationError> {
    if nodes.is_empty() {
        return Err(ValidationError::EmptyNodes);
    }

    if solution.len() != nodes.len() {
        return Err(ValidationError::SolutionLengthMismatch {
            expected: nodes.len(),
            actual: solution.len(),
        });
    }

    if h.len() != nodes.len() {
        return Err(ValidationError::FieldLengthMismatch {
            expected: nodes.len(),
            actual: h.len(),
        });
    }

    if edges.len() != j.len() {
        return Err(ValidationError::EdgeWeightLengthMismatch {
            edges: edges.len(),
            weights: j.len(),
        });
    }

    ensure_valid_topology(nodes, edges)?;

    Ok(())
}

fn position_of_node(nodes: &[u32], target: u32) -> Option<usize> {
    nodes.iter().position(|&node| node == target)
}

#[cfg(test)]
mod tests {
    use super::{energy_of_solution, expected_gse};
    use crate::errors::ValidationError;

    #[test]
    fn computes_energy_for_simple_problem() {
        let nodes = [0, 1];
        let edges = [(0, 1)];
        let h = [500, -1_000];
        let j = [250];
        let solution = [1, -1];

        let energy = energy_of_solution(&solution, &h, &edges, &j, &nodes).unwrap();

        assert_eq!(energy, 1_250);
    }

    #[test]
    fn rejects_invalid_spin_values() {
        let nodes = [0, 1];
        let edges = [(0, 1)];
        let h = [0, 0];
        let j = [1_000];
        let solution = [1, 0];

        let error = energy_of_solution(&solution, &h, &edges, &j, &nodes).unwrap_err();

        assert_eq!(
            error,
            ValidationError::InvalidSpinValue { index: 1, value: 0 }
        );
    }

    #[test]
    fn rejects_unknown_node_in_edge() {
        let nodes = [0, 1];
        let edges = [(0, 2)];
        let h = [0, 0];
        let j = [1_000];
        let solution = [1, -1];

        let error = energy_of_solution(&solution, &h, &edges, &j, &nodes).unwrap_err();

        assert_eq!(error, ValidationError::UnknownNodeInEdge { node: 2 });
    }

    #[test]
    fn expected_gse_is_zero_for_empty_topology() {
        assert_eq!(expected_gse(0, 100), 0);
        assert_eq!(expected_gse(100, 0), 0);
    }
}
