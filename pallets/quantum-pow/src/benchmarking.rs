//! Benchmarking setup for pallet-quantum-pow.

use super::*;

#[allow(unused)]
use crate::Pallet as QuantumPow;
use alloc::{vec, vec::Vec};
use codec::Encode;
use frame_benchmarking::v2::*;
use frame_support::{pallet_prelude::ConstU32, traits::Currency, BoundedVec};
use frame_system::RawOrigin;
use quantum_validation::derive_nonce;
use sp_runtime::traits::SaturatedConversion;

fn bounded<T, S>(items: Vec<T>) -> BoundedVec<T, S>
where
    S: frame_support::traits::Get<u32>,
{
    items
        .try_into()
        .ok()
        .expect("benchmark input fits within bounds")
}

fn balance_of<T: Config>(amount: u128) -> BalanceOf<T> {
    amount.saturated_into()
}

fn fund_account<T: Config>(who: &T::AccountId, amount: u128) {
    let _ = T::Currency::make_free_balance_be(who, balance_of::<T>(amount));
}

fn easy_difficulty() -> types::DifficultyConfig {
    types::DifficultyConfig {
        min_solutions: 1,
        max_energy_milli: i64::MAX,
        min_diversity_milli: 0,
        min_quality_milli: 0,
    }
}

fn sample_topology<T: Config>() -> (NodesOf<T>, EdgesOf<T>, sp_core::H256) {
    let nodes = bounded::<_, T::MaxNodes>(vec![0, 1]);
    let edges = bounded::<_, T::MaxEdges>(vec![(0, 1)]);
    let topology_hash = crate::topology::hash_topology(&nodes, &edges);
    (nodes, edges, topology_hash)
}

fn register_miner_for<T: Config>(who: &T::AccountId) {
    fund_account::<T>(who, 1_000_000);
    assert!(QuantumPow::<T>::register_miner(RawOrigin::Signed(who.clone()).into()).is_ok());
}

fn register_topology_for<T: Config>() -> (NodesOf<T>, EdgesOf<T>, sp_core::H256) {
    let (nodes, edges, topology_hash) = sample_topology::<T>();
    assert!(QuantumPow::<T>::register_topology(
        RawOrigin::Root.into(),
        nodes.clone(),
        edges.clone()
    )
    .is_ok());
    (nodes, edges, topology_hash)
}

fn valid_proof_for<T: Config>(
    miner: &T::AccountId,
    nodes: &NodesOf<T>,
    edges: &EdgesOf<T>,
    topology_hash: sp_core::H256,
) -> QuantumProofOf<T> {
    frame_system::Pallet::<T>::set_block_number(1u32.into());

    let salt = bounded::<u8, ConstU32<32>>(b"bench-salt".to_vec());
    let nonce = derive_nonce(
        &frame_system::Pallet::<T>::parent_hash().encode(),
        &miner.encode(),
        frame_system::Pallet::<T>::block_number().saturated_into::<u32>(),
        salt.as_slice(),
    );

    types::QuantumProof {
        topology_hash,
        nonce,
        salt,
        nodes: nodes.clone(),
        edges: edges.clone(),
        solutions: bounded::<_, T::MaxSolutions>(vec![bounded::<_, T::MaxNodes>(vec![1, 1])]),
        h_values: bounded::<_, T::MaxNodes>(vec![-1_000, 0, 1_000]),
    }
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn register_miner() {
        let caller: T::AccountId = whitelisted_caller();
        fund_account::<T>(&caller, 1_000_000);

        #[extrinsic_call]
        QuantumPow::register_miner(RawOrigin::Signed(caller.clone()));

        assert!(Miners::<T>::contains_key(caller));
    }

    #[benchmark]
    fn deregister_miner() {
        let caller: T::AccountId = whitelisted_caller();
        register_miner_for::<T>(&caller);

        #[extrinsic_call]
        QuantumPow::deregister_miner(RawOrigin::Signed(caller.clone()));

        assert!(!Miners::<T>::contains_key(caller));
    }

    #[benchmark]
    fn register_topology() {
        let (nodes, edges, topology_hash) = sample_topology::<T>();

        #[extrinsic_call]
        QuantumPow::register_topology(RawOrigin::Root, nodes, edges);

        assert!(RegisteredTopologies::<T>::contains_key(topology_hash));
    }

    #[benchmark]
    fn set_difficulty() {
        let difficulty = easy_difficulty();

        #[extrinsic_call]
        QuantumPow::set_difficulty(RawOrigin::Root, difficulty);

        assert_eq!(Difficulty::<T>::get(), difficulty);
    }

    #[benchmark]
    fn submit_proof() {
        let caller: T::AccountId = whitelisted_caller();
        register_miner_for::<T>(&caller);
        let (nodes, edges, topology_hash) = register_topology_for::<T>();
        Difficulty::<T>::put(easy_difficulty());
        let proof = valid_proof_for::<T>(&caller, &nodes, &edges, topology_hash);

        #[extrinsic_call]
        QuantumPow::submit_proof(RawOrigin::Signed(caller.clone()), proof);

        let miner = Miners::<T>::get(caller).expect("miner remains registered");
        assert_eq!(miner.proofs_submitted, 1);
        assert_eq!(BlockProofCount::<T>::get(), 1);
        assert!(BlockBestProof::<T>::get().is_some());
    }

    impl_benchmark_test_suite!(QuantumPow, crate::mock::new_test_ext(), crate::mock::Test);
}
