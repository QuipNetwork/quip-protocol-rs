use alloc::vec;
use alloc::vec::Vec;

use crate::types::{FrontRunner, RankedSolver};

/// Update a ranked top-N set with a new candidate.
pub fn update_ranked_solvers<AccountId: Clone + Eq>(
    current: &[RankedSolver<AccountId>],
    candidate: RankedSolver<AccountId>,
    limit: usize,
) -> Vec<RankedSolver<AccountId>> {
    let mut next = current.to_vec();

    if let Some(existing) = next
        .iter_mut()
        .find(|entry| entry.solver == candidate.solver)
    {
        if candidate.energy_milli < existing.energy_milli {
            *existing = candidate;
        }
    } else {
        next.push(candidate);
    }

    next.sort_by_key(|entry| entry.energy_milli);
    next.truncate(limit);
    next
}

/// Compute single-best payouts.
pub fn single_best_payouts<AccountId: Clone>(
    front_runner: &FrontRunner<AccountId>,
    reward: u128,
) -> Vec<(AccountId, u128, i64)> {
    vec![(
        front_runner.solver.clone(),
        reward,
        front_runner.energy_milli,
    )]
}

/// Compute equal-split payouts, assigning any remainder to the best-ranked solver.
pub fn top_n_equal_payouts<AccountId: Clone>(
    ranked: &[RankedSolver<AccountId>],
    reward: u128,
) -> Vec<(AccountId, u128, i64)> {
    if ranked.is_empty() {
        return Vec::new();
    }

    let len = ranked.len() as u128;
    let base = reward / len;
    let remainder = reward % len;

    ranked
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let extra = if index == 0 { remainder } else { 0 };
            (entry.solver.clone(), base + extra, entry.energy_milli)
        })
        .collect()
}

/// Compute weighted payouts using absolute energy magnitudes.
///
/// If all absolute energies are zero, falls back to equal split.
pub fn top_n_weighted_payouts<AccountId: Clone>(
    ranked: &[RankedSolver<AccountId>],
    reward: u128,
) -> Vec<(AccountId, u128, i64)> {
    if ranked.is_empty() {
        return Vec::new();
    }

    let total_weight: u128 = ranked
        .iter()
        .map(|entry| entry.energy_milli.unsigned_abs() as u128)
        .sum();

    if total_weight == 0 {
        return top_n_equal_payouts(ranked, reward);
    }

    let mut payouts = Vec::with_capacity(ranked.len());
    let mut distributed = 0_u128;

    for entry in ranked {
        let weight = entry.energy_milli.unsigned_abs() as u128;
        let payout = reward.saturating_mul(weight) / total_weight;
        distributed = distributed.saturating_add(payout);
        payouts.push((entry.solver.clone(), payout, entry.energy_milli));
    }

    let remainder = reward.saturating_sub(distributed);
    if let Some((_, payout, _)) = payouts.first_mut() {
        *payout = payout.saturating_add(remainder);
    }

    payouts
}
