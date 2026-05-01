//! Benchmarking setup for pallet-quantum-compute-mempool.

use super::*;

#[allow(unused)]
use crate::Pallet as QuantumComputeMempool;
use alloc::{vec, vec::Vec};
use frame_benchmarking::v2::*;
use frame_support::{pallet_prelude::ConstU32, traits::{Currency, Get}, BoundedVec};
use frame_system::RawOrigin;
use sp_runtime::traits::{Hash as _, SaturatedConversion, Saturating};

fn bounded<T, S>(items: Vec<T>) -> BoundedVec<T, S>
where
    S: frame_support::traits::Get<u32>,
{
    items.try_into().ok().expect("benchmark input fits within bounds")
}

fn reward_of<T: Config>(amount: u128) -> BalanceOf<T> {
    amount.saturated_into()
}

fn fund_account<T: Config>(who: &T::AccountId, amount: u128) {
    let _ = T::Currency::make_free_balance_be(who, reward_of::<T>(amount));
}

fn sample_spec<T: Config>() -> (
    BoundedVec<u8, ConstU32<128>>,
    types::Formulation,
    Option<T::Hash>,
    Option<T::Hash>,
) {
    (
        bounded(b"max-cut".to_vec()),
        types::Formulation::Ising,
        None,
        None,
    )
}

fn sample_spec_id<T: Config>(
    name: &BoundedVec<u8, ConstU32<128>>,
    formulation: types::Formulation,
    validation_program: Option<T::Hash>,
    transform_program: Option<T::Hash>,
) -> T::Hash {
    T::Hashing::hash_of(&(name.clone(), formulation, validation_program, transform_program))
}

fn sample_params<T: Config>() -> IsingParamsOf<T> {
    types::IsingParams {
        nodes: bounded(vec![0, 1]),
        edges: bounded(vec![(0, 1)]),
        h_values: bounded(vec![0, 0]),
        j_values: bounded(vec![-1_000]),
        min_energy_milli: None,
        min_diversity_milli: None,
        min_solutions: None,
    }
}

fn sample_solution<T: Config>() -> SolutionsOf<T> {
    bounded(vec![bounded(vec![1, 1])])
}

fn register_spec_for<T: Config>(builder: &T::AccountId) -> T::Hash {
    let (name, formulation, validation_program, transform_program) = sample_spec::<T>();
    let spec_id = sample_spec_id::<T>(
        &name,
        formulation,
        validation_program,
        transform_program,
    );
    assert!(
        QuantumComputeMempool::<T>::register_job_spec(
            RawOrigin::Signed(builder.clone()).into(),
            name,
            formulation,
            validation_program,
            transform_program,
        )
        .is_ok()
    );
    spec_id
}

fn register_solver_for<T: Config>(solver: &T::AccountId) {
    assert!(
        QuantumComputeMempool::<T>::register_solver(
            RawOrigin::Signed(solver.clone()).into(),
            types::MinerType::Cpu,
        )
        .is_ok()
    );
}

fn propose_open_order_for<T: Config>(
    proposer: &T::AccountId,
    reward: u128,
    resolution: types::RewardResolution,
    deadline_blocks: BlockNumberOf<T>,
    block_wait: BlockNumberOf<T>,
    delivery: types::ResultDelivery,
) -> u64 {
    fund_account::<T>(proposer, reward.saturating_mul(10));
    let spec_id = register_spec_for::<T>(proposer);
    let order_id = NextOrderId::<T>::get();
    assert!(
        QuantumComputeMempool::<T>::propose_job(
            RawOrigin::Signed(proposer.clone()).into(),
            spec_id,
            sample_params::<T>(),
            reward_of::<T>(reward),
            types::JobMode::Open,
            resolution,
            deadline_blocks,
            block_wait,
            delivery,
        )
        .is_ok()
    );
    order_id
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn register_solver() {
        let caller: T::AccountId = whitelisted_caller();

        #[extrinsic_call]
        QuantumComputeMempool::register_solver(RawOrigin::Signed(caller.clone()), types::MinerType::Cpu);

        assert!(Solvers::<T>::contains_key(caller));
    }

    #[benchmark]
    fn deregister_solver() {
        let caller: T::AccountId = whitelisted_caller();
        register_solver_for::<T>(&caller);

        #[extrinsic_call]
        QuantumComputeMempool::deregister_solver(RawOrigin::Signed(caller.clone()));

        assert!(!Solvers::<T>::contains_key(caller));
    }

    #[benchmark]
    fn register_job_spec() {
        let caller: T::AccountId = whitelisted_caller();
        let (name, formulation, validation_program, transform_program) = sample_spec::<T>();
        let spec_id = sample_spec_id::<T>(
            &name,
            formulation,
            validation_program,
            transform_program,
        );

        #[extrinsic_call]
        QuantumComputeMempool::register_job_spec(
            RawOrigin::Signed(caller.clone()),
            name,
            formulation,
            validation_program,
            transform_program,
        );

        assert!(JobSpecs::<T>::contains_key(spec_id));
    }

    #[benchmark]
    fn propose_job() {
        let caller: T::AccountId = whitelisted_caller();
        fund_account::<T>(&caller, 1_000_000);
        let spec_id = register_spec_for::<T>(&caller);
        let reward = reward_of::<T>(100);

        #[extrinsic_call]
        QuantumComputeMempool::propose_job(
            RawOrigin::Signed(caller.clone()),
            spec_id,
            sample_params::<T>(),
            reward,
            types::JobMode::Open,
            types::RewardResolution::SingleBest,
            10u32.into(),
            5u32.into(),
            types::ResultDelivery::OnChainOnly,
        );

        assert!(JobOrders::<T>::contains_key(0));
    }

    #[benchmark]
    fn submit_solution() {
        let proposer: T::AccountId = whitelisted_caller();
        let solver: T::AccountId = account("solver", 0, 0);
        register_solver_for::<T>(&solver);
        let order_id = propose_open_order_for::<T>(
            &proposer,
            100,
            types::RewardResolution::SingleBest,
            10u32.into(),
            5u32.into(),
            types::ResultDelivery::OnChainOnly,
        );

        #[extrinsic_call]
        QuantumComputeMempool::submit_solution(
            RawOrigin::Signed(solver.clone()),
            order_id,
            sample_solution::<T>(),
        );

        assert!(OrderSolutions::<T>::contains_key(order_id, solver));
    }

    #[benchmark]
    fn claim_reward() {
        let proposer: T::AccountId = whitelisted_caller();
        let solver: T::AccountId = account("solver", 0, 0);
        register_solver_for::<T>(&solver);
        let order_id = propose_open_order_for::<T>(
            &proposer,
            100,
            types::RewardResolution::SingleBest,
            2u32.into(),
            1u32.into(),
            types::ResultDelivery::OnChainOnly,
        );
        assert!(
            QuantumComputeMempool::<T>::submit_solution(
                RawOrigin::Signed(solver.clone()).into(),
                order_id,
                sample_solution::<T>(),
            )
            .is_ok()
        );
        frame_system::Pallet::<T>::set_block_number(2u32.into());

        #[extrinsic_call]
        QuantumComputeMempool::claim_reward(RawOrigin::Signed(solver.clone()), order_id);

        let order = JobOrders::<T>::get(order_id).expect("order exists");
        assert_eq!(order.status, types::OrderStatus::Closed);
    }

    #[benchmark]
    fn reclaim_order() {
        let proposer: T::AccountId = whitelisted_caller();
        let order_id = propose_open_order_for::<T>(
            &proposer,
            100,
            types::RewardResolution::SingleBest,
            1u32.into(),
            1u32.into(),
            types::ResultDelivery::OnChainOnly,
        );
        frame_system::Pallet::<T>::set_block_number(2u32.into());

        #[extrinsic_call]
        QuantumComputeMempool::reclaim_order(RawOrigin::Signed(proposer.clone()), order_id);

        let order = JobOrders::<T>::get(order_id).expect("order exists");
        assert_eq!(order.status, types::OrderStatus::Closed);
    }

    #[benchmark]
    fn purge_result() {
        let proposer: T::AccountId = whitelisted_caller();
        let solver: T::AccountId = account("solver", 0, 0);
        let cleaner: T::AccountId = account("cleaner", 0, 0);
        register_solver_for::<T>(&solver);
        fund_account::<T>(&cleaner, 1_000);
        let spec_id = register_spec_for::<T>(&proposer);
        fund_account::<T>(&proposer, 1_000_000);
        let order_id = NextOrderId::<T>::get();
        assert!(
            QuantumComputeMempool::<T>::propose_job(
                RawOrigin::Signed(proposer.clone()).into(),
                spec_id,
                sample_params::<T>(),
                reward_of::<T>(100),
                types::JobMode::Bid {
                    miners: Some(bounded(vec![solver.clone()])),
                    miner_types: None,
                },
                types::RewardResolution::SingleBest,
                2u32.into(),
                1u32.into(),
                types::ResultDelivery::CallbackWithPoll {
                    endpoint: bounded(b"https://solver.example/poll".to_vec()),
                },
            )
            .is_ok()
        );
        assert!(
            QuantumComputeMempool::<T>::submit_solution(
                RawOrigin::Signed(solver.clone()).into(),
                order_id,
                sample_solution::<T>(),
            )
            .is_ok()
        );
        frame_system::Pallet::<T>::set_block_number(2u32.into());
        assert!(
            QuantumComputeMempool::<T>::claim_reward(
                RawOrigin::Signed(solver.clone()).into(),
                order_id,
            )
            .is_ok()
        );
        frame_system::Pallet::<T>::set_block_number(
            T::ResultTtlBlocks::get().saturating_add(2u32.into()),
        );

        #[extrinsic_call]
        QuantumComputeMempool::purge_result(RawOrigin::Signed(cleaner), order_id);

        assert!(OrderResults::<T>::get(order_id).is_none());
    }

    impl_benchmark_test_suite!(QuantumComputeMempool, crate::mock::new_test_ext(), crate::mock::Test);
}
