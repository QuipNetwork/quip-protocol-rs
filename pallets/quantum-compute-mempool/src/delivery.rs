use crate::types::{JobMode, ResultDelivery};

/// Validate whether a delivery mode is allowed for a job mode.
pub fn validate_delivery_mode<AccountId, MinerTypes>(
    delivery: &ResultDelivery,
    mode: &JobMode<AccountId, MinerTypes>,
) -> bool {
    match (delivery, mode) {
        (ResultDelivery::OnChainOnly, _) => true,
        (ResultDelivery::Callback { .. }, JobMode::Open) => true,
        (
            ResultDelivery::Callback { .. },
            JobMode::Bid {
                miners: None,
                miner_types: Some(_),
            },
        ) => true,
        (
            ResultDelivery::CallbackWithPoll { .. },
            JobMode::Bid {
                miners: Some(_),
                miner_types: None,
            },
        ) => true,
        _ => false,
    }
}
