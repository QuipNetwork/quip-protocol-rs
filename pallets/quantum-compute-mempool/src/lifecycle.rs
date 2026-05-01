use sp_runtime::traits::Saturating;

use crate::types::OrderTiming;

/// Compute the effective expiry of an order under the two-phase timing model.
pub fn effective_expiry<BlockNumber: Copy + Ord + Saturating>(
    created_at: BlockNumber,
    first_solution_at: Option<BlockNumber>,
    timing: &OrderTiming<BlockNumber>,
) -> BlockNumber {
    let hard_deadline = created_at.saturating_add(timing.deadline_blocks);
    match first_solution_at {
        Some(first) => hard_deadline.min(first.saturating_add(timing.block_wait)),
        None => hard_deadline,
    }
}

/// Return `true` when the current block is at or past the effective expiry.
pub fn is_expired<BlockNumber: Copy + Ord + Saturating>(
    now: BlockNumber,
    created_at: BlockNumber,
    first_solution_at: Option<BlockNumber>,
    timing: &OrderTiming<BlockNumber>,
) -> bool {
    now >= effective_expiry(created_at, first_solution_at, timing)
}
