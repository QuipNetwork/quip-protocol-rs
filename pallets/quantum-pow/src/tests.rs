use super::mock::*;
use crate::{
    difficulty, topology,
    types::{DifficultyConfig, QuantumProof},
    BlockBestProof, BlockProofCount, DefaultTopology, Difficulty, LastProofBlock, Miners,
    RegisteredTopologies,
};
use codec::Encode;
use frame_support::{assert_noop, assert_ok, traits::Hooks, BoundedVec};
use quantum_validation::{derive_nonce, energy_of_solution, generate_ising_model};

fn bounded<T, S>(items: Vec<T>) -> BoundedVec<T, S>
where
    S: frame_support::traits::Get<u32>,
{
    items.try_into().ok().unwrap()
}

fn easy_difficulty() -> DifficultyConfig {
    DifficultyConfig {
        min_solutions: 1,
        max_energy_milli: i64::MAX,
        min_diversity_milli: 0,
        min_quality_milli: 0,
    }
}

fn registered_topology() -> (
    BoundedVec<u32, MaxNodes>,
    BoundedVec<(u32, u32), MaxEdges>,
    sp_core::H256,
) {
    let nodes = bounded::<_, MaxNodes>(vec![0, 1]);
    let edges = bounded::<_, MaxEdges>(vec![(0, 1)]);
    let hash = topology::hash_topology(&nodes, &edges);
    assert_ok!(QuantumPow::register_topology(
        RuntimeOrigin::root(),
        nodes.clone(),
        edges.clone(),
    ));
    (nodes, edges, hash)
}

fn proof_for(
    miner: u64,
    nodes: &BoundedVec<u32, MaxNodes>,
    edges: &BoundedVec<(u32, u32), MaxEdges>,
    topology_hash: sp_core::H256,
    allowed_h_values: Vec<i32>,
    solution_indexes: &[usize],
) -> QuantumProof<
    BoundedVec<u32, MaxNodes>,
    BoundedVec<(u32, u32), MaxEdges>,
    BoundedVec<BoundedVec<i8, MaxNodes>, MaxSolutions>,
    BoundedVec<i32, MaxNodes>,
> {
    let block_number = System::block_number() as u32;
    let salt = bounded::<_, frame_support::traits::ConstU32<32>>(b"salt".to_vec());
    let nonce = derive_nonce(
        &System::parent_hash().encode(),
        &miner.encode(),
        block_number,
        salt.as_slice(),
    );
    let (h, j) =
        generate_ising_model(nonce, nodes.as_slice(), edges.as_slice(), &allowed_h_values).unwrap();

    let candidates = [[-1, -1], [-1, 1], [1, -1], [1, 1]];
    let mut by_energy: Vec<(i64, Vec<i8>)> = candidates
        .iter()
        .map(|solution| {
            let energy =
                energy_of_solution(solution, &h, edges.as_slice(), &j, nodes.as_slice()).unwrap();
            (energy, solution.to_vec())
        })
        .collect();
    by_energy.sort_by_key(|(energy, _)| *energy);

    let solutions = solution_indexes
        .iter()
        .map(|&index| bounded::<_, MaxNodes>(by_energy[index].1.clone()))
        .collect::<Vec<_>>();

    QuantumProof {
        topology_hash,
        nonce,
        salt,
        nodes: nodes.clone(),
        edges: edges.clone(),
        solutions: bounded::<_, MaxSolutions>(solutions),
        h_values: bounded::<_, MaxNodes>(allowed_h_values),
    }
}

#[test]
fn register_miner_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));

        let miner = Miners::<Test>::get(1).unwrap();
        assert_eq!(miner.deposit, 100);
        assert_eq!(pallet_balances::Pallet::<Test>::reserved_balance(1), 100);
    });
}

#[test]
fn deregister_miner_works() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::deregister_miner(RuntimeOrigin::signed(1)));

        assert!(Miners::<Test>::get(1).is_none());
        assert_eq!(pallet_balances::Pallet::<Test>::reserved_balance(1), 0);
    });
}

#[test]
fn register_topology_works() {
    new_test_ext().execute_with(|| {
        let nodes = bounded::<_, MaxNodes>(vec![0, 1, 2]);
        let edges = bounded::<_, MaxEdges>(vec![(0, 1), (1, 2)]);
        let expected_hash = topology::hash_topology(&nodes, &edges);

        assert_ok!(QuantumPow::register_topology(
            RuntimeOrigin::root(),
            nodes.clone(),
            edges.clone(),
        ));

        assert!(RegisteredTopologies::<Test>::contains_key(expected_hash));
        assert_eq!(DefaultTopology::<Test>::get(), Some(expected_hash));
    });
}

#[test]
fn register_topology_rejects_small_graph() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            QuantumPow::register_topology(
                RuntimeOrigin::root(),
                bounded::<_, MaxNodes>(vec![0]),
                bounded::<_, MaxEdges>(vec![]),
            ),
            crate::Error::<Test>::GraphTooSmall
        );
    });
}

#[test]
fn register_topology_requires_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            QuantumPow::register_topology(
                RuntimeOrigin::signed(1),
                bounded::<_, MaxNodes>(vec![0, 1]),
                bounded::<_, MaxEdges>(vec![(0, 1)]),
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_difficulty_requires_root() {
    new_test_ext().execute_with(|| {
        let difficulty = DifficultyConfig {
            min_solutions: 2,
            max_energy_milli: -1_000,
            min_diversity_milli: 500,
            min_quality_milli: 750,
        };

        assert_noop!(
            QuantumPow::set_difficulty(RuntimeOrigin::signed(1), difficulty),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_difficulty_works() {
    new_test_ext().execute_with(|| {
        let difficulty = DifficultyConfig {
            min_solutions: 3,
            max_energy_milli: -2_000,
            min_diversity_milli: 800,
            min_quality_milli: 900,
        };

        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            difficulty
        ));
        assert_eq!(Difficulty::<Test>::get(), difficulty);
    });
}

#[test]
fn submit_proof_accepts_valid_proof() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();
        let proof = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));

        assert_eq!(BlockProofCount::<Test>::get(), 1);
        assert!(BlockBestProof::<Test>::get().is_some());
    });
}

#[test]
fn submit_proof_rejects_invalid_nonce() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();
        let mut proof = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);
        proof.nonce = proof.nonce.saturating_add(1);

        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof),
            crate::Error::<Test>::InvalidNonce
        );
    });
}

#[test]
fn submit_proof_rejects_invalid_spin_values() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();
        let mut proof = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);
        proof.solutions = bounded::<_, MaxSolutions>(vec![bounded::<_, MaxNodes>(vec![0, 1])]);

        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof),
            crate::Error::<Test>::InvalidSpinValues
        );
    });
}

#[test]
fn better_proof_replaces_worse_proof() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(2)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();

        let worse = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[3]);
        let better = proof_for(2, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), worse));
        let first = BlockBestProof::<Test>::get().unwrap();

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(2), better));
        let second = BlockBestProof::<Test>::get().unwrap();

        assert!(second.energy_milli <= first.energy_milli);
        assert_eq!(second.miner, 2);
    });
}

#[test]
fn on_finalize_pays_block_reward_for_best_proof() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();
        let proof = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);
        let initial_balance = pallet_balances::Pallet::<Test>::free_balance(1);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));
        QuantumPow::on_finalize(System::block_number());

        assert_eq!(
            pallet_balances::Pallet::<Test>::free_balance(1),
            initial_balance + 50
        );
        assert!(BlockBestProof::<Test>::get().is_none());
        assert_eq!(LastProofBlock::<Test>::get(), System::block_number());
        assert_eq!(Miners::<Test>::get(1).unwrap().proofs_won, 1);
        assert_eq!(Miners::<Test>::get(1).unwrap().rewards_earned, 50);
    });
}

#[test]
fn submit_proof_uses_decayed_difficulty_after_block_gap() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let difficulty = DifficultyConfig {
            min_solutions: 5,
            max_energy_milli: i64::MAX,
            min_diversity_milli: 0,
            min_quality_milli: 0,
        };
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            difficulty
        ));
        let (nodes, edges, topology_hash) = registered_topology();

        let early_proof = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);
        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), early_proof),
            crate::Error::<Test>::InsufficientSolutions
        );

        LastProofBlock::<Test>::put(1);
        System::set_block_number(81);
        let decayed_proof = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);

        assert_ok!(QuantumPow::submit_proof(
            RuntimeOrigin::signed(1),
            decayed_proof
        ));
        assert!(BlockBestProof::<Test>::get().is_some());
    });
}

#[test]
fn on_finalize_fast_proof_hardens_difficulty() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let initial = easy_difficulty();
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), initial));
        let (nodes, edges, topology_hash) = registered_topology();

        LastProofBlock::<Test>::put(1);
        System::set_block_number(10);
        let proof = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));
        QuantumPow::on_finalize(System::block_number());

        let next = Difficulty::<Test>::get();
        assert!(next.min_solutions > initial.min_solutions);
        assert!(next.max_energy_milli < initial.max_energy_milli);
        assert!(next.min_quality_milli > initial.min_quality_milli);
    });
}

#[test]
fn on_finalize_slow_proof_eases_difficulty_from_decayed_base() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let initial = DifficultyConfig {
            min_solutions: 3,
            max_energy_milli: 0,
            min_diversity_milli: 100,
            min_quality_milli: 100,
        };
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), initial));
        let (nodes, edges, topology_hash) = registered_topology();

        LastProofBlock::<Test>::put(1);
        System::set_block_number(250);
        let proof = proof_for(1, &nodes, &edges, topology_hash, vec![-1000, 0, 1000], &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));

        let decayed = difficulty::apply_decay(initial, (250_u32 - 1) / EpochLength::get() as u32);
        QuantumPow::on_finalize(System::block_number());

        let next = Difficulty::<Test>::get();
        assert!(next.max_energy_milli > decayed.max_energy_milli);
    });
}

#[test]
fn mining_snapshot_returns_default_and_selected_topology_views() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));

        let (default_nodes, default_edges, default_hash) = registered_topology();

        let other_nodes = bounded::<_, MaxNodes>(vec![10, 11, 12]);
        let other_edges = bounded::<_, MaxEdges>(vec![(10, 11), (11, 12)]);
        let other_hash = topology::hash_topology(&other_nodes, &other_edges);
        assert_ok!(QuantumPow::register_topology(
            RuntimeOrigin::root(),
            other_nodes.clone(),
            other_edges.clone(),
        ));

        let default_snapshot =
            QuantumPow::mining_snapshot(System::block_number(), System::parent_hash(), None)
                .expect("default topology snapshot exists");
        assert_eq!(default_snapshot.topology_hash, default_hash);
        assert_eq!(default_snapshot.nodes, default_nodes);
        assert_eq!(default_snapshot.edges, default_edges);
        assert_eq!(default_snapshot.difficulty, easy_difficulty());

        let selected_snapshot = QuantumPow::mining_snapshot(
            System::block_number(),
            System::parent_hash(),
            Some(other_hash),
        )
        .expect("selected topology snapshot exists");
        assert_eq!(selected_snapshot.topology_hash, other_hash);
        assert_eq!(selected_snapshot.nodes, other_nodes);
        assert_eq!(selected_snapshot.edges, other_edges);
    });
}
