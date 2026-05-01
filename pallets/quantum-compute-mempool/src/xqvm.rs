use alloc::vec::Vec;

use sp_runtime::{DispatchError, DispatchResult};

use crate::types::WinnerSummary;

// TODO: Revisit whether this trait should live in the mempool pallet or in
// `pallet-xqvm` once the integration surface is no longer a no-op shim.
/// Minimal trait seam for future XQVM integration.
pub trait QuantumVm<AccountId, Balance, Hash> {
    /// Validate referenced validation/transform programs when a job spec is registered.
    fn validate_programs(
        validation_program: Option<&Hash>,
        transform_program: Option<&Hash>,
    ) -> DispatchResult;

    /// Transform submitted solutions before the pallet scores them.
    fn transform_solutions(
        spec_id: &Hash,
        validation_program: Option<&Hash>,
        transform_program: Option<&Hash>,
        solver: &AccountId,
        solutions: Vec<Vec<i8>>,
    ) -> Result<Vec<Vec<i8>>, DispatchError>;

    /// Validate the final winner payload before delivery or poll persistence.
    fn validate_result(
        spec_id: &Hash,
        validation_program: Option<&Hash>,
        transform_program: Option<&Hash>,
        winners: &[WinnerSummary<AccountId, Balance>],
    ) -> DispatchResult;
}

/// Default no-op VM wiring for v0.
pub struct NoOpVm;

impl<AccountId, Balance, Hash> QuantumVm<AccountId, Balance, Hash> for NoOpVm {
    fn validate_programs(
        _validation_program: Option<&Hash>,
        _transform_program: Option<&Hash>,
    ) -> DispatchResult {
        Ok(())
    }

    fn transform_solutions(
        _spec_id: &Hash,
        _validation_program: Option<&Hash>,
        _transform_program: Option<&Hash>,
        _solver: &AccountId,
        solutions: Vec<Vec<i8>>,
    ) -> Result<Vec<Vec<i8>>, DispatchError> {
        Ok(solutions)
    }

    fn validate_result(
        _spec_id: &Hash,
        _validation_program: Option<&Hash>,
        _transform_program: Option<&Hash>,
        _winners: &[WinnerSummary<AccountId, Balance>],
    ) -> DispatchResult {
        Ok(())
    }
}
