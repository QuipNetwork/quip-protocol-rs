use super::mock::*;
use crate::{
    difficulty, topology,
    types::{DifficultyConfig, QuantumProof},
    AllowedValueSetOf, BlockBestProof, BlockProofCount, DefaultTopology, Difficulty,
    LastProofBlock, Miners, PackedSpinBytesOf, RegisteredTopologies, WinningSolutions,
};
use frame_support::{assert_noop, assert_ok, traits::Hooks, BoundedVec};
use quantum_validation::{
    derive_nonce, energy_of_solution, generate_ising_model, packed::pack_solution,
    AllowedValueSpec, MilliValue, MILLI_SCALE,
};

fn bounded<T, S>(items: Vec<T>) -> BoundedVec<T, S>
where
    S: frame_support::traits::Get<u32>,
{
    items.try_into().ok().unwrap()
}

const SCALE: MilliValue = MILLI_SCALE as MilliValue;

fn allowed_h_spec() -> AllowedValueSpec<AllowedValueSetOf<Test>> {
    AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![-SCALE, 0, SCALE]))
}

fn allowed_j_spec() -> AllowedValueSpec<AllowedValueSetOf<Test>> {
    AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![-SCALE, SCALE]))
}

fn allowed_spin_spec() -> AllowedValueSpec<AllowedValueSetOf<Test>> {
    AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![-SCALE, SCALE]))
}

fn easy_difficulty() -> DifficultyConfig {
    DifficultyConfig {
        min_solutions: 1,
        max_energy_milli: i64::MAX,
        min_diversity_milli: 0,
    }
}

/// Energy curve calibrated against the same `(2, 1)` topology that
/// `registered_topology()` registers. Tests that call `apply_decay` or
/// `adjust_on_proof` directly need this so their behaviour matches what
/// the pallet computes through `current_energy_curve()`.
fn test_curve() -> crate::difficulty::EnergyCurve {
    crate::difficulty::EnergyCurve::new(2, 1, 700, 750, 800)
}

fn registered_topology() -> (
    BoundedVec<u32, MaxNodes>,
    BoundedVec<(u32, u32), MaxEdges>,
    sp_core::H256,
) {
    let nodes = bounded::<_, MaxNodes>(vec![0, 1]);
    let edges = bounded::<_, MaxEdges>(vec![(0, 1)]);
    let hash = topology::hash_topology(
        &nodes,
        &edges,
        &allowed_h_spec().as_slice(),
        &allowed_j_spec().as_slice(),
        &allowed_spin_spec().as_slice(),
    );
    assert_ok!(QuantumPow::register_topology(
        RuntimeOrigin::root(),
        nodes.clone(),
        edges.clone(),
        allowed_h_spec(),
        allowed_j_spec(),
        allowed_spin_spec(),
    ));
    (nodes, edges, hash)
}

fn pack_spins(spins: &[i8]) -> PackedSpinBytesOf<Test> {
    let milli: Vec<MilliValue> = spins.iter().map(|&s| s as MilliValue * SCALE).collect();
    let spec = allowed_spin_spec();
    let bytes = pack_solution(&milli, &spec.as_slice()).expect("binary spin pack");
    bounded::<u8, MaxNodes>(bytes)
}

fn proof_for(
    miner: u64,
    nodes: &BoundedVec<u32, MaxNodes>,
    edges: &BoundedVec<(u32, u32), MaxEdges>,
    topology_hash: sp_core::H256,
    solution_indexes: &[usize],
) -> QuantumProof<crate::PackedSolutionsOf<Test>> {
    let salt: [u8; 32] = {
        let mut s = [0u8; 32];
        s[..4].copy_from_slice(b"salt");
        s
    };
    // Mirror the chain-side lookup: `block_hash(LastProofBlock)` is the
    // sole "time" input to the nonce. Reading the same value the
    // pallet does keeps the helper coupling-free with the test runtime.
    let last_proof_block_hash =
        frame_system::Pallet::<Test>::block_hash(LastProofBlock::<Test>::get());
    let last_proof_block_hash_bytes =
        crate::Pallet::<Test>::hash_to_bytes_32(last_proof_block_hash);
    let miner_bytes = crate::Pallet::<Test>::account_to_bytes(&miner);
    let nonce = derive_nonce(&last_proof_block_hash_bytes, &miner_bytes, &salt);

    let h_spec = allowed_h_spec();
    let j_spec = allowed_j_spec();
    let (h, j) = generate_ising_model(
        nonce,
        nodes.as_slice(),
        edges.as_slice(),
        &h_spec.as_slice(),
        &j_spec.as_slice(),
    )
    .unwrap();

    let candidates = [[-1i8, -1], [-1, 1], [1, -1], [1, 1]];
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
        .map(|&index| pack_spins(&by_energy[index].1))
        .collect::<Vec<_>>();

    QuantumProof {
        topology_hash,
        nonce,
        salt,
        solutions: bounded::<_, MaxSolutions>(solutions),
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
        let expected_hash = topology::hash_topology(
            &nodes,
            &edges,
            &allowed_h_spec().as_slice(),
            &allowed_j_spec().as_slice(),
            &allowed_spin_spec().as_slice(),
        );

        assert_ok!(QuantumPow::register_topology(
            RuntimeOrigin::root(),
            nodes.clone(),
            edges.clone(),
            allowed_h_spec(),
            allowed_j_spec(),
            allowed_spin_spec(),
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
                allowed_h_spec(),
                allowed_j_spec(),
                allowed_spin_spec(),
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
                allowed_h_spec(),
                allowed_j_spec(),
                allowed_spin_spec(),
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn register_topology_rejects_empty_spin_spec() {
    new_test_ext().execute_with(|| {
        let empty_spec = AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![]));
        assert_noop!(
            QuantumPow::register_topology(
                RuntimeOrigin::root(),
                bounded::<_, MaxNodes>(vec![0, 1]),
                bounded::<_, MaxEdges>(vec![(0, 1)]),
                allowed_h_spec(),
                allowed_j_spec(),
                empty_spec,
            ),
            crate::Error::<Test>::EmptyAllowedValues
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
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

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
        let mut proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
        proof.nonce = proof.nonce.saturating_add(sp_core::U256::one());

        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof),
            crate::Error::<Test>::InvalidNonce
        );
    });
}

#[test]
fn submit_proof_rejects_solution_with_wrong_byte_length() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();
        let mut proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
        // Replace the packed solution with one byte too many for a 2-spin
        // binary-encoded solution (1 byte is enough; we send 2 bytes).
        proof.solutions = bounded::<_, MaxSolutions>(vec![bounded::<u8, MaxNodes>(vec![0, 0])]);

        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof),
            crate::Error::<Test>::PackedSolutionLengthMismatch
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

        let worse = proof_for(1, &nodes, &edges, topology_hash, &[3]);
        let better = proof_for(2, &nodes, &edges, topology_hash, &[0]);

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
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
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
        // Regression: submit_proof must validate against the *decayed*
        // Self::current_difficulty(), not the raw Difficulty::<T>::get().
        // Under the new curve policy, only max_energy_milli decays — so we
        // build the discriminator out of energy: set the threshold to exactly
        // the proof's best energy (validation requires strict-less-than) so
        // the same-block submit fails, then wait an epoch for decay to raise
        // the threshold above the proof's energy and admit it.
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let (nodes, edges, topology_hash) = registered_topology();

        // Fix the nonce-derivation seed so both submissions use the same
        // proof contents.
        LastProofBlock::<Test>::put(1);
        System::set_block_number(1);

        // Build the proof once and compute its best energy.
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
        let h_spec = allowed_h_spec();
        let j_spec = allowed_j_spec();
        let (h, j) = generate_ising_model(
            proof.nonce,
            nodes.as_slice(),
            edges.as_slice(),
            &h_spec.as_slice(),
            &j_spec.as_slice(),
        )
        .unwrap();
        let best_energy_milli: i64 = [[-1i8, -1], [-1, 1], [1, -1], [1, 1]]
            .iter()
            .map(|s| energy_of_solution(s, &h, edges.as_slice(), &j, nodes.as_slice()).unwrap())
            .min()
            .unwrap();

        // Threshold == best energy: validation's strict-less-than gate
        // rejects same-block submissions (no decay yet).
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            DifficultyConfig {
                min_solutions: 1,
                max_energy_milli: best_energy_milli,
                min_diversity_milli: 0,
            },
        ));
        let early_proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), early_proof),
            crate::Error::<Test>::InsufficientEnergy
        );

        // One full epoch later: decay raises the threshold by at least
        // MIN_DECAY_DELTA_MILLI (= 3 milli), strictly above the proof's
        // energy. Validation now admits the same proof — proving submit_proof
        // consulted current_difficulty(), not the raw storage baseline.
        System::set_block_number(21); // (21 - 1) / EpochLength(20) = 1 decay step
        let decayed_proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
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
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));
        QuantumPow::on_finalize(System::block_number());

        let next = Difficulty::<Test>::get();
        // Only the energy threshold moves; the chain-static fields stay put.
        assert!(next.max_energy_milli < initial.max_energy_milli);
        assert_eq!(next.min_solutions, initial.min_solutions);
        assert_eq!(next.min_diversity_milli, initial.min_diversity_milli);
    });
}

#[test]
fn on_finalize_slow_proof_eases_difficulty_from_decayed_base() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        // min_solutions / min_diversity_milli are chain-static under the new
        // curve policy; only max_energy_milli decays. Set the chain-static
        // fields permissively so the proof passes those gates, and let the
        // assertion below measure the energy easing through both decay and
        // the post-win adjustment.
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: 0,
            min_diversity_milli: 0,
        };
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), initial));
        let (nodes, edges, topology_hash) = registered_topology();

        LastProofBlock::<Test>::put(1);
        System::set_block_number(250);
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));

        let decayed = difficulty::apply_decay(
            initial,
            (250_u32 - 1) / EpochLength::get() as u32,
            test_curve(),
        );
        QuantumPow::on_finalize(System::block_number());

        let next = Difficulty::<Test>::get();
        // Slow proof eases the threshold further past the decayed value.
        assert!(next.max_energy_milli > decayed.max_energy_milli);
        // Chain-static fields untouched throughout decay + adjust.
        assert_eq!(next.min_solutions, initial.min_solutions);
        assert_eq!(next.min_diversity_milli, initial.min_diversity_milli);
    });
}

#[test]
fn on_finalize_persists_winning_solution_with_recoverable_nonce() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();
        // Capture the seed the round will use, before submit_proof, so the
        // assertion below pins the chain-stored value against the value
        // the helper actually fed into derive_nonce.
        let expected_last_proof_block_hash =
            sp_core::H256::from(crate::Pallet::<Test>::hash_to_bytes_32(
                frame_system::Pallet::<Test>::block_hash(LastProofBlock::<Test>::get()),
            ));
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
        let original_nonce = proof.nonce;
        let original_salt = proof.salt;

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));
        let block = System::block_number();
        QuantumPow::on_finalize(block);

        let stored = WinningSolutions::<Test>::get(block).expect("winning solution persisted");
        assert_eq!(stored.miner, 1);
        assert_eq!(stored.salt, original_salt);
        assert_eq!(stored.reward, 50);
        // LastProofBlock was zero before this proof, so no decay applied —
        // the active threshold equals whatever set_difficulty just stored.
        assert_eq!(stored.difficulty, easy_difficulty());
        assert_eq!(stored.last_proof_block_hash, expected_last_proof_block_hash);

        // Re-derive the nonce via the runtime helper and confirm it matches
        // the value that was on the submitted proof. This is the round-trip
        // that lets dashboards recover the nonce from on-chain state alone.
        let view = crate::Pallet::<Test>::winning_solution_with_nonce(block)
            .expect("nonce derivation succeeds for a real winner");
        assert_eq!(view.nonce, original_nonce);
        assert_eq!(view.solution.salt, original_salt);
        assert_eq!(view.solution.difficulty, easy_difficulty());
        assert_eq!(
            view.solution.last_proof_block_hash,
            expected_last_proof_block_hash
        );
    });
}

#[test]
fn winning_solution_returns_none_for_genesis_block() {
    new_test_ext().execute_with(|| {
        // Genesis (block 0) never had a `submit_proof` call, so the storage
        // entry is absent and the helper short-circuits before any block-hash
        // arithmetic. Pins the contract that saturating subtraction on
        // `block_number - 1 == 0u32 - 1` never reaches the nonce derivation.
        assert!(crate::Pallet::<Test>::winning_solution_with_nonce(0).is_none());
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
        let other_hash = topology::hash_topology(
            &other_nodes,
            &other_edges,
            &allowed_h_spec().as_slice(),
            &allowed_j_spec().as_slice(),
            &allowed_spin_spec().as_slice(),
        );
        assert_ok!(QuantumPow::register_topology(
            RuntimeOrigin::root(),
            other_nodes.clone(),
            other_edges.clone(),
            allowed_h_spec(),
            allowed_j_spec(),
            allowed_spin_spec(),
        ));

        let expected_last_proof_block_hash =
            sp_core::H256::from(crate::Pallet::<Test>::hash_to_bytes_32(
                frame_system::Pallet::<Test>::block_hash(LastProofBlock::<Test>::get()),
            ));

        let default_snapshot =
            QuantumPow::mining_snapshot(None).expect("default topology snapshot exists");
        assert_eq!(default_snapshot.topology_hash, default_hash);
        assert_eq!(default_snapshot.nodes, default_nodes);
        assert_eq!(default_snapshot.edges, default_edges);
        assert_eq!(default_snapshot.difficulty, easy_difficulty());
        assert_eq!(
            default_snapshot.last_proof_block_hash,
            expected_last_proof_block_hash
        );

        let selected_snapshot = QuantumPow::mining_snapshot(Some(other_hash))
            .expect("selected topology snapshot exists");
        assert_eq!(selected_snapshot.topology_hash, other_hash);
        assert_eq!(selected_snapshot.nodes, other_nodes);
        assert_eq!(selected_snapshot.edges, other_edges);
        assert_eq!(
            selected_snapshot.last_proof_block_hash,
            expected_last_proof_block_hash
        );
    });
}

#[test]
fn winning_solution_records_active_difficulty_threshold() {
    new_test_ext().execute_with(|| {
        // Pin the contract that WinningSolution stores the *active* threshold
        // a proof had to clear (decay applied, pre-adjust) rather than the
        // post-adjustment value that lives in Difficulty<T> after on_finalize.
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: i64::MAX,
            min_diversity_milli: 0,
        };
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), initial));
        let (nodes, edges, topology_hash) = registered_topology();

        LastProofBlock::<Test>::put(1);
        System::set_block_number(45); // (45 - 1) / 20 = 2 decay steps
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));
        QuantumPow::on_finalize(System::block_number());

        let expected_active = difficulty::apply_decay(initial, 2, test_curve());
        let stored = WinningSolutions::<Test>::get(45).expect("winner persisted");
        assert_eq!(
            stored.difficulty, expected_active,
            "stored difficulty must be the decayed-but-pre-adjust threshold"
        );

        // Mining time blocks = 45 - 1 = 44 < TARGET_PROOF_BLOCKS (100), so the
        // adjustment hardens. Only the energy threshold moves now; chain-static
        // fields stay put.
        let next = Difficulty::<Test>::get();
        assert!(
            next.max_energy_milli < expected_active.max_energy_milli,
            "post-adjust energy must be harder (more negative) than the active threshold"
        );
        assert_eq!(next.min_solutions, expected_active.min_solutions);
        assert_eq!(
            next.min_diversity_milli,
            expected_active.min_diversity_milli
        );
    });
}

#[test]
fn mining_snapshot_returns_decayed_difficulty_after_epochs() {
    new_test_ext().execute_with(|| {
        // Pin the contract that mining_snapshot.difficulty applies decay so
        // miners querying the runtime API get the live threshold — not the
        // stale Difficulty<T> baseline that polkadot.js storage queries return.
        let initial = DifficultyConfig {
            min_solutions: 5,
            max_energy_milli: 0,
            min_diversity_milli: 100,
        };
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), initial));
        let _ = registered_topology();

        LastProofBlock::<Test>::put(1);
        System::set_block_number(121); // (121 - 1) / 20 = 6 decay steps
        let snapshot =
            QuantumPow::mining_snapshot(None).expect("snapshot exists for default topology");
        let expected = difficulty::apply_decay(initial, 6, test_curve());
        assert_eq!(snapshot.difficulty, expected);
        assert_ne!(
            snapshot.difficulty, initial,
            "snapshot must not echo the raw storage baseline once decay has elapsed"
        );

        // Direct storage query (the polkadot.js default path) must still
        // return the undecayed baseline — this is the visibility gap that the
        // runtime API closes.
        assert_eq!(Difficulty::<Test>::get(), initial);
    });
}

#[test]
fn submit_proof_survives_long_block_gap() {
    // Regression test for the txpool-delay race: a proof derived against
    // the current round's `last_proof_block_hash` must remain valid for as long
    // as no new proof has won, no matter how many blocks elapse between
    // derivation and validation. Under the old block-number-bound contract
    // this scenario produced InvalidNonce.
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();

        // Derive at block 1 (default after new_test_ext).
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        // Simulate a txpool that backed up by 500 blocks before the
        // extrinsic finally landed. No win happened in between, so
        // `LastProofBlock` is unchanged and the round is still the same.
        System::set_block_number(501);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));
        assert_eq!(BlockProofCount::<Test>::get(), 1);
        assert!(BlockBestProof::<Test>::get().is_some());
    });
}

#[test]
fn submit_proof_rejected_after_intervening_win() {
    // Mirror of the survives-gap test: if a *different* round closed
    // between derivation and submission, the last proof block hash has changed and
    // the proof must be rejected. Otherwise old proofs could replay
    // across rounds.
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        assert_ok!(QuantumPow::set_difficulty(
            RuntimeOrigin::root(),
            easy_difficulty()
        ));
        let (nodes, edges, topology_hash) = registered_topology();

        // Derive against the current last proof block hash (`block_hash(0)` in the
        // test env — defaults to zero, but the value itself is incidental
        // here; what matters is that we later mutate the lookup target).
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        // Force the last proof block hash to a distinct value by (a) pointing
        // `LastProofBlock` at a fresh block and (b) populating
        // `block_hash` for that block with a non-zero entry. Together
        // these simulate a winning on_finalize having run in the meantime.
        System::set_block_number(50);
        LastProofBlock::<Test>::put(10);
        frame_system::BlockHash::<Test>::insert(10u64, sp_core::H256::from([0xAB; 32]));

        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof),
            crate::Error::<Test>::InvalidNonce
        );
    });
}

// ---------------------------------------------------------------------------
// Curve and pure-function tests (no chain state required)
// ---------------------------------------------------------------------------

#[test]
fn current_difficulty_passes_through_when_no_decay_steps() {
    let curve = test_curve();
    let base = DifficultyConfig {
        min_solutions: 5,
        max_energy_milli: -2_500,
        min_diversity_milli: 200,
    };
    // block_number == last_proof_block: zero elapsed → no decay.
    assert_eq!(
        difficulty::current_difficulty(100, base, 100, 10, Some(curve)),
        base,
    );
    // Less than one full epoch elapsed: still no decay.
    assert_eq!(
        difficulty::current_difficulty(109, base, 100, 10, Some(curve)),
        base,
    );
}

#[test]
fn current_difficulty_applies_decay_per_full_epoch() {
    let curve = test_curve();
    let base = DifficultyConfig {
        min_solutions: 5,
        max_energy_milli: -2_500,
        min_diversity_milli: 200,
    };
    // 25 blocks elapsed, epoch_length=10 → 2 decay steps.
    let result = difficulty::current_difficulty(125, base, 100, 10, Some(curve));
    let expected = difficulty::apply_decay(base, 2, curve);
    assert_eq!(result, expected);
}

#[test]
fn current_difficulty_short_circuits_without_curve() {
    // Even with elapsed > epoch_length, missing curve → no decay applied.
    let base = DifficultyConfig {
        min_solutions: 5,
        max_energy_milli: -2_500,
        min_diversity_milli: 200,
    };
    assert_eq!(
        difficulty::current_difficulty(200, base, 100, 10, None),
        base,
    );
}

#[test]
fn current_difficulty_short_circuits_at_genesis() {
    let curve = test_curve();
    let base = DifficultyConfig {
        min_solutions: 5,
        max_energy_milli: -2_500,
        min_diversity_milli: 200,
    };
    // last_proof_block == 0 → genesis path → no decay.
    assert_eq!(
        difficulty::current_difficulty(500, base, 0, 10, Some(curve)),
        base,
    );
}

#[test]
fn adjust_on_proof_only_mutates_max_energy() {
    let curve = test_curve();
    let before = DifficultyConfig {
        min_solutions: 7,
        max_energy_milli: -2_500,
        min_diversity_milli: 400,
    };
    let after = difficulty::adjust_on_proof(before, 30, curve, b"seed");
    assert_eq!(after.min_solutions, before.min_solutions);
    assert_eq!(after.min_diversity_milli, before.min_diversity_milli);
    assert_ne!(after.max_energy_milli, before.max_energy_milli);
}

#[test]
fn apply_decay_only_mutates_max_energy() {
    let curve = test_curve();
    let before = DifficultyConfig {
        min_solutions: 7,
        max_energy_milli: -2_500,
        min_diversity_milli: 400,
    };
    let after = difficulty::apply_decay(before, 3, curve);
    assert_eq!(after.min_solutions, before.min_solutions);
    assert_eq!(after.min_diversity_milli, before.min_diversity_milli);
    assert!(
        after.max_energy_milli > before.max_energy_milli,
        "decay must ease the threshold (move toward zero)"
    );
}

#[test]
fn decay_moves_less_than_hardening_per_step() {
    let curve = test_curve();
    let start = DifficultyConfig {
        min_solutions: 1,
        max_energy_milli: -2_500,
        min_diversity_milli: 0,
    };
    let after_decay = difficulty::apply_decay(start, 5, curve);
    let after_harden = (0..5).fold(start, |d, _| {
        // mining_time = 30 blocks → fast/hardening branch.
        difficulty::adjust_on_proof(d, 30, curve, b"seed")
    });
    let decay_move = after_decay.max_energy_milli - start.max_energy_milli;
    let harden_move = start.max_energy_milli - after_harden.max_energy_milli;
    assert!(
        harden_move > decay_move,
        "hardening must move energy farther than decay at equal step count \
         (harden={harden_move}, decay={decay_move})",
    );
}

#[test]
fn curve_compresses_motion_near_boundaries() {
    let curve = test_curve();
    // Pick two starting points inside the curve range: one near the knee
    // (max curve_factor ≈ 1.0) and one near the max boundary (curve_factor ≈ 0.1).
    let mid_start = (curve.min_milli + curve.knee_milli) / 2;
    let near_max = curve.max_milli - 1;
    let mid_after = difficulty::adjust_on_proof(
        DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: mid_start,
            min_diversity_milli: 0,
        },
        30,
        curve,
        b"seed",
    )
    .max_energy_milli;
    let near_after = difficulty::adjust_on_proof(
        DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: near_max,
            min_diversity_milli: 0,
        },
        30,
        curve,
        b"seed",
    )
    .max_energy_milli;
    let mid_move = mid_start - mid_after;
    let near_move = near_max - near_after;
    assert!(
        mid_move > near_move,
        "curve must compress motion near boundaries (mid={mid_move}, near_max={near_move})",
    );
}

/// Enforces the miner-independence invariant from GitLab issue #5: the
/// energy curve must depend only on `DefaultTopology`, never on any
/// other registered topology. We register two topologies of different
/// sizes and verify that the decay magnitude observed via
/// `mining_snapshot` matches what the *default* topology's curve
/// produces — not the second registered topology's curve. If a future
/// "optimisation" routes `current_energy_curve()` through some
/// non-default topology, this test fails.
#[test]
fn energy_curve_uses_default_topology_not_other_registered() {
    new_test_ext().execute_with(|| {
        // Topology A is (2 nodes, 1 edge) — becomes DefaultTopology.
        let _ = registered_topology();
        let default_hash = DefaultTopology::<Test>::get().expect("default registered");

        // Register topology B with clearly different size so its curve
        // produces a clearly different decay magnitude.
        let b_nodes = bounded::<_, MaxNodes>(vec![0u32, 1, 2, 3]);
        let b_edges = bounded::<_, MaxEdges>(vec![(0u32, 1), (1, 2), (2, 3), (0, 3)]);
        assert_ok!(QuantumPow::register_topology(
            RuntimeOrigin::root(),
            b_nodes,
            b_edges,
            allowed_h_spec(),
            allowed_j_spec(),
            allowed_spin_spec(),
        ));
        // First-write-wins keeps A as the default.
        assert_eq!(DefaultTopology::<Test>::get(), Some(default_hash));

        // Set a stored difficulty and let decay elapse.
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: -10_000,
            min_diversity_milli: 0,
        };
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), initial));
        LastProofBlock::<Test>::put(1);
        System::set_block_number(101); // (101 - 1) / 20 = 5 decay steps

        // `mining_snapshot` populates `difficulty` via current_difficulty,
        // which builds its curve from DefaultTopology.
        let snapshot =
            QuantumPow::mining_snapshot(None).expect("snapshot exists for default topology");

        // Expected decay using A's curve (the default).
        let expected_default = difficulty::apply_decay(
            initial,
            5,
            crate::difficulty::EnergyCurve::new(2, 1, 700, 750, 800),
        );
        // Decay using B's curve (the *non-default* topology — this is what
        // a miner-controlled curve would produce if the invariant were broken).
        let expected_other = difficulty::apply_decay(
            initial,
            5,
            crate::difficulty::EnergyCurve::new(4, 4, 700, 750, 800),
        );

        assert_eq!(
            snapshot.difficulty, expected_default,
            "current_difficulty must calibrate the curve on DefaultTopology"
        );
        assert_ne!(
            expected_default.max_energy_milli, expected_other.max_energy_milli,
            "sanity: A and B must produce different decay magnitudes for the test to mean anything"
        );
    });
}
