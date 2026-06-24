use super::mock::*;
use crate::{
    difficulty, topology,
    types::{DifficultyConfig, ProofRecord, QuantumProof},
    AllowedValueSetOf, BlockBestProof, BlockProofCount, DefaultTopology, Difficulties,
    LastProofBlock, LastProofBlockHash, Miners, PackedSpinBytesOf, QBlockBlockById, QBlockCount,
    QBlockIdByBlock, QBlocks, RegisteredTopologies, WinnerStreak,
};
use frame_support::{
    assert_noop, assert_ok,
    traits::{Get, Hooks, StorageVersion},
    BoundedVec,
};
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

fn default_hash() -> sp_core::H256 {
    DefaultTopology::<Test>::get().expect("a default topology is registered")
}

/// Set the difficulty baseline for the current default topology.
fn set_difficulty_default(difficulty: DifficultyConfig) {
    assert_ok!(QuantumPow::set_difficulty(
        RuntimeOrigin::root(),
        difficulty
    ));
}

/// Read the (raw, pre-decay) difficulty baseline for the default topology.
fn difficulty_default() -> DifficultyConfig {
    Difficulties::<Test>::get(default_hash()).unwrap_or_default()
}

fn test_curve_c() -> crate::difficulty::CurveC {
    crate::difficulty::CurveC {
        easy_milli: <<Test as crate::Config>::CurveCEasyMilli as Get<u32>>::get(),
        knee_milli: <<Test as crate::Config>::CurveCKneeMilli as Get<u32>>::get(),
        hard_milli: <<Test as crate::Config>::CurveCHardMilli as Get<u32>>::get(),
    }
}

/// Energy curve calibrated against the same `(2, 1)` topology and value
/// specs that `registered_topology()` registers. Tests that call
/// `apply_decay` or `adjust_on_proof` directly need this so their behaviour
/// matches what the pallet computes through `current_energy_curve()`.
fn test_curve() -> crate::difficulty::EnergyCurve {
    crate::difficulty::EnergyCurve::new(
        2,
        1,
        test_curve_c(),
        &allowed_h_spec().as_slice(),
        &allowed_j_spec().as_slice(),
    )
    .expect("registered specs are non-empty")
}

#[test]
fn energy_curve_matches_gse_for_registered_ternary_specs() {
    // The registered ternary-h/binary-J specs reproduce the legacy magnitudes,
    // so the spec-aware curve must equal expected_gse at all three calibration
    // points when fed those same specs.
    let curve = test_curve();
    let gse = |c_milli: u32| {
        quantum_validation::expected_gse(
            2,
            1,
            f64::from(c_milli) / 1000.0,
            &allowed_h_spec().as_slice(),
            &allowed_j_spec().as_slice(),
        )
        .unwrap()
    };
    assert_eq!(curve.min_milli, gse(test_curve_c().hard_milli));
    assert_eq!(curve.knee_milli, gse(test_curve_c().knee_milli));
    assert_eq!(curve.max_milli, gse(test_curve_c().easy_milli));
}

#[test]
fn energy_curve_zero_field_spec_drops_h_contribution() {
    let zero_h: AllowedValueSpec<AllowedValueSetOf<Test>> =
        AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![0]));
    let curve = crate::difficulty::EnergyCurve::new(
        2,
        1,
        test_curve_c(),
        &zero_h.as_slice(),
        &allowed_j_spec().as_slice(),
    )
    .expect("zero-field spec is valid");

    // Every calibration point must equal the pure-J estimate…
    for (actual, c) in [
        (curve.min_milli, test_curve_c().hard_milli),
        (curve.knee_milli, test_curve_c().knee_milli),
        (curve.max_milli, test_curve_c().easy_milli),
    ] {
        let expected = quantum_validation::expected_gse(
            2,
            1,
            f64::from(c) / 1000.0,
            &zero_h.as_slice(),
            &allowed_j_spec().as_slice(),
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    // …and be strictly less negative than the ternary-h curve, which still
    // includes a field contribution.
    let legacy = test_curve();
    assert!(curve.min_milli > legacy.min_milli);
    assert!(curve.knee_milli > legacy.knee_milli);
    assert!(curve.max_milli > legacy.max_milli);
}

#[test]
fn energy_curve_rejects_empty_specs() {
    let empty: AllowedValueSpec<AllowedValueSetOf<Test>> =
        AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![]));
    assert!(crate::difficulty::EnergyCurve::new(
        2,
        1,
        test_curve_c(),
        &empty.as_slice(),
        &allowed_j_spec().as_slice(),
    )
    .is_err());
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

fn finalize_winner(miner: u64, block_number: u64) {
    System::set_block_number(block_number);
    BlockBestProof::<Test>::put(ProofRecord {
        miner,
        submitted_at: block_number,
        energy_milli: 0,
        salt: [0u8; 32],
        topology_hash: DefaultTopology::<Test>::get().unwrap_or_default(),
    });
    QuantumPow::on_finalize(block_number);
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
    // Mirror the chain-side lookup: the pallet reads from the cached
    // `LastProofBlockHash` storage value (populated lazily by
    // on_initialize), not directly from frame_system's ring buffer.
    let last_proof_block_hash_bytes = LastProofBlockHash::<Test>::get().0;
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

/// Registers a second, zero-field topology (4 nodes, ring of 4 edges,
/// h = {0}) alongside whatever is already registered. Returns its hash.
fn registered_zero_field_topology() -> sp_core::H256 {
    let nodes = bounded::<_, MaxNodes>(vec![0u32, 1, 2, 3]);
    let edges = bounded::<_, MaxEdges>(vec![(0u32, 1), (1, 2), (2, 3), (0, 3)]);
    let zero_h: AllowedValueSpec<AllowedValueSetOf<Test>> =
        AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![0]));
    let hash = topology::hash_topology(
        &nodes,
        &edges,
        &zero_h.as_slice(),
        &allowed_j_spec().as_slice(),
        &allowed_spin_spec().as_slice(),
    );
    assert_ok!(QuantumPow::register_topology(
        RuntimeOrigin::root(),
        nodes,
        edges,
        zero_h,
        allowed_j_spec(),
        allowed_spin_spec(),
    ));
    hash
}

#[test]
fn set_default_topology_requires_root() {
    new_test_ext().execute_with(|| {
        let (_, _, hash) = registered_topology();
        assert_noop!(
            QuantumPow::set_default_topology(RuntimeOrigin::signed(1), hash),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_default_topology_rejects_unregistered_hash() {
    new_test_ext().execute_with(|| {
        let _ = registered_topology();
        assert_noop!(
            QuantumPow::set_default_topology(RuntimeOrigin::root(), sp_core::H256::repeat_byte(7)),
            crate::Error::<Test>::TopologyNotRegistered
        );
    });
}

#[test]
fn set_default_topology_repoints_default_and_curve() {
    new_test_ext().execute_with(|| {
        // Topology A becomes the default by first-registration.
        let (_, _, hash_a) = registered_topology();
        let hash_b = registered_zero_field_topology();
        assert_eq!(DefaultTopology::<Test>::get(), Some(hash_a));

        assert_ok!(QuantumPow::set_default_topology(
            RuntimeOrigin::root(),
            hash_b
        ));
        assert_eq!(DefaultTopology::<Test>::get(), Some(hash_b));

        // The no-argument mining snapshot now serves topology B…
        let snapshot = QuantumPow::mining_snapshot(None).expect("snapshot exists");
        assert_eq!(snapshot.topology_hash, hash_b);

        // …and difficulty decay is calibrated against B's zero-field curve,
        // not A's ternary-field curve.
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: -10_000,
            min_diversity_milli: 0,
        };
        set_difficulty_default(initial);
        LastProofBlock::<Test>::put(1);
        System::set_block_number(101); // (101 - 1) / 20 = 5 decay steps

        let zero_h: AllowedValueSpec<AllowedValueSetOf<Test>> =
            AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![0]));
        let curve_b = crate::difficulty::EnergyCurve::new(
            4,
            4,
            test_curve_c(),
            &zero_h.as_slice(),
            &allowed_j_spec().as_slice(),
        )
        .expect("zero-field spec is valid");
        let expected = difficulty::apply_decay(initial, 5, curve_b);
        let decayed = QuantumPow::mining_snapshot(None).expect("snapshot exists");
        assert_eq!(decayed.difficulty, expected);
        assert_ne!(
            expected,
            difficulty::apply_decay(initial, 5, test_curve()),
            "sanity: A's and B's curves must differ for this test to mean anything"
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
        // Interim shape for Task 2: `set_difficulty` writes the default
        // topology's `Difficulties` entry. Task 4 gives it an explicit
        // `topology_hash` argument and this test changes shape accordingly.
        let _ = registered_topology();
        let difficulty = DifficultyConfig {
            min_solutions: 3,
            max_energy_milli: -2_000,
            min_diversity_milli: 800,
        };

        set_difficulty_default(difficulty);
        assert_eq!(difficulty_default(), difficulty);
    });
}

#[test]
fn submit_proof_accepts_valid_proof() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());
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
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());
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
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());
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
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());

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
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());
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
        // current_difficulty_for(topology), not the raw Difficulties entry.
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
        set_difficulty_default(DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: best_energy_milli,
            min_diversity_milli: 0,
        });
        let early_proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), early_proof),
            crate::Error::<Test>::InsufficientEnergy
        );

        // One full epoch later: decay raises the threshold by at least
        // MIN_DECAY_DELTA_MILLI (= 3000 milli), strictly above the proof's
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
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(initial);

        LastProofBlock::<Test>::put(1);
        System::set_block_number(10);
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));
        QuantumPow::on_finalize(System::block_number());

        let next = difficulty_default();
        // Only the energy threshold moves; the chain-static fields stay put.
        assert!(next.max_energy_milli < initial.max_energy_milli);
        assert_eq!(next.min_solutions, initial.min_solutions);
        assert_eq!(next.min_diversity_milli, initial.min_diversity_milli);
    });
}

#[test]
fn on_finalize_slow_proof_by_new_winner_hardens_from_decayed_base() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        // min_solutions / min_diversity_milli are chain-static under the new
        // curve policy; only max_energy_milli decays. Set the chain-static
        // fields permissively so the proof passes those gates. A slow win
        // by a non-dominant (first-streak) winner hardens gently from the
        // decayed base — the v0.1 rule restored from the original design.
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: 0,
            min_diversity_milli: 0,
        };
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(initial);

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

        let next = difficulty_default();
        // A slow proof by a non-dominant winner hardens the threshold below
        // the decayed value (gentle 5%±4% band — v0.1 different/new-winner
        // rule). Decay remains the easing pressure between wins.
        assert!(next.max_energy_milli < decayed.max_energy_milli);
        // Chain-static fields untouched throughout decay + adjust.
        assert_eq!(next.min_solutions, initial.min_solutions);
        assert_eq!(next.min_diversity_milli, initial.min_diversity_milli);
    });
}

#[test]
fn curve_constants_are_recalibrated() {
    assert_eq!(
        <<Test as crate::Config>::CurveCEasyMilli as Get<u32>>::get(),
        700
    );
    assert_eq!(
        <<Test as crate::Config>::CurveCKneeMilli as Get<u32>>::get(),
        725
    );
    assert_eq!(
        <<Test as crate::Config>::CurveCHardMilli as Get<u32>>::get(),
        750
    );

    let curve = test_curve();
    assert!(curve.min_milli < curve.knee_milli);
    assert!(curve.knee_milli < curve.max_milli);
}

#[test]
fn network_upgrade_wipes_pow_state_and_bumps_version() {
    new_test_ext().execute_with(|| {
        // Seed v0.2-style state.
        let (.., hash) = registered_topology();
        assert!(RegisteredTopologies::<Test>::contains_key(hash));
        assert_eq!(DefaultTopology::<Test>::get(), Some(hash));
        Difficulties::<Test>::insert(
            hash,
            DifficultyConfig {
                min_solutions: 7,
                max_energy_milli: 12_345,
                min_diversity_milli: 300,
            },
        );
        QBlockCount::<Test>::put(9);
        // Simulate the on-chain v0.2 storage version so the guard fires.
        StorageVersion::new(1).put::<QuantumPow>();

        QuantumPow::on_runtime_upgrade();

        // All PoW state is dropped rather than carried forward.
        assert!(RegisteredTopologies::<Test>::iter().next().is_none());
        assert_eq!(DefaultTopology::<Test>::get(), None);
        assert_eq!(QBlockCount::<Test>::get(), 0);
        // The per-topology difficulty entry is wiped along with the rest of
        // the pallet prefix, identical to a fresh chain.
        assert_eq!(Difficulties::<Test>::get(hash), None);
        assert_eq!(StorageVersion::get::<QuantumPow>(), StorageVersion::new(2));
    });
}

#[test]
fn dominant_winner_eases_at_fast_cutoff_but_hardens_below_it() {
    // The fast cutoff is strict `<`: exactly 60 elapsed blocks is a slow
    // win, so a dominant winner eases there — one block sooner and even a
    // dominant winner hardens (v0.1: fast wins always harden).
    new_test_ext().execute_with(|| {
        registered_topology();
        let curve = test_curve();
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: curve.knee_milli,
            min_diversity_milli: 0,
        };
        set_difficulty_default(initial);
        LastProofBlock::<Test>::put(1);
        // Seed a streak one short of the threshold (3); the next win makes
        // the miner dominant.
        WinnerStreak::<Test>::put(crate::types::WinnerStreak { miner: 1, count: 2 });

        finalize_winner(1, 61); // elapsed 60 == cutoff -> slow, dominant

        let next = difficulty_default();
        assert!(
            next.max_energy_milli > initial.max_energy_milli,
            "a dominant winner at 60 elapsed blocks must ease"
        );
    });

    new_test_ext().execute_with(|| {
        registered_topology();
        let curve = test_curve();
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: curve.knee_milli,
            min_diversity_milli: 0,
        };
        set_difficulty_default(initial);
        LastProofBlock::<Test>::put(1);
        WinnerStreak::<Test>::put(crate::types::WinnerStreak { miner: 1, count: 2 });

        finalize_winner(1, 60); // elapsed 59 < cutoff -> fast, dominance ignored

        let next = difficulty_default();
        assert!(
            next.max_energy_milli < initial.max_energy_milli,
            "a fast win must harden even for a dominant winner"
        );
    });
}

#[test]
fn slow_win_by_different_miner_hardens() {
    // Restored v0.1 rule: a slow block won by a *different* miner hardens
    // difficulty; only dominant repeat winners ease.
    new_test_ext().execute_with(|| {
        registered_topology();
        let curve = test_curve();
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: curve.knee_milli,
            min_diversity_milli: 0,
        };
        set_difficulty_default(initial);
        LastProofBlock::<Test>::put(1);

        // Make miner 1 dominant so its slow win eases the threshold up to
        // the curve ceiling — giving the next assertion room to observe a
        // strict hardening move.
        WinnerStreak::<Test>::put(crate::types::WinnerStreak { miner: 1, count: 2 });
        finalize_winner(1, 100);
        let after_dominant = difficulty_default();
        assert!(after_dominant.max_energy_milli > initial.max_energy_milli);

        finalize_winner(2, 200); // different miner, slow win

        let after_switch = difficulty_default();
        let streak = WinnerStreak::<Test>::get().expect("winner streak tracked");
        assert_eq!(streak.miner, 2);
        assert_eq!(streak.count, 1);
        assert!(
            after_switch.max_energy_milli < after_dominant.max_energy_milli,
            "a slow win by a different miner must harden (v0.1 rule)"
        );
    });
}

#[test]
fn repeated_same_winner_forces_easing() {
    new_test_ext().execute_with(|| {
        registered_topology();
        let curve = test_curve();
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: curve.knee_milli,
            min_diversity_milli: 0,
        };
        set_difficulty_default(initial);
        LastProofBlock::<Test>::put(1);

        // Slow wins (elapsed >= 60 blocks): dominance easing only applies
        // past the fast cutoff, so space the wins ~100 blocks apart.
        finalize_winner(1, 100);
        let after_first = difficulty_default();
        assert!(after_first.max_energy_milli < initial.max_energy_milli);

        finalize_winner(1, 200);
        let after_second = difficulty_default();
        // Streak count 2 is still below the threshold (3): slow wins by a
        // non-dominant winner must keep hardening (or hold at the clamp
        // floor) — easing here would fire one win early and raise the value.
        assert!(
            after_second.max_energy_milli <= after_first.max_energy_milli,
            "second consecutive win is below the easing threshold and must not ease"
        );

        finalize_winner(1, 300);
        let after_third = difficulty_default();
        let streak = WinnerStreak::<Test>::get().expect("winner streak tracked");

        assert_eq!(streak.miner, 1);
        assert_eq!(streak.count, 3);
        assert!(
            after_third.max_energy_milli > after_second.max_energy_milli,
            "third consecutive slow win must ease for the dominant winner"
        );
    });
}

#[test]
fn network_upgrade_is_noop_once_at_v2() {
    new_test_ext().execute_with(|| {
        // Already at the post-upgrade version (e.g. a fresh genesis chain):
        // the guard must keep the wipe from re-running and nuking live state.
        let (.., hash) = registered_topology();
        let difficulty = DifficultyConfig {
            min_solutions: 7,
            max_energy_milli: 12_345,
            min_diversity_milli: 300,
        };
        Difficulties::<Test>::insert(hash, difficulty);
        QBlockCount::<Test>::put(9);
        StorageVersion::new(2).put::<QuantumPow>();

        QuantumPow::on_runtime_upgrade();

        assert!(RegisteredTopologies::<Test>::contains_key(hash));
        assert_eq!(Difficulties::<Test>::get(hash), Some(difficulty));
        assert_eq!(QBlockCount::<Test>::get(), 9);
        assert_eq!(StorageVersion::get::<QuantumPow>(), StorageVersion::new(2));
    });
}

#[test]
fn zero_easing_threshold_disables_forced_easing() {
    new_test_ext().execute_with(|| {
        ConsecutiveWinnerEasingThreshold::set(0);
        registered_topology();
        let curve = test_curve();
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: curve.knee_milli,
            min_diversity_milli: 0,
        };
        set_difficulty_default(initial);
        LastProofBlock::<Test>::put(1);

        // Slow wins: with the default threshold (3) the third one would
        // ease for the dominant winner, so this spacing discriminates.
        finalize_winner(1, 100);
        finalize_winner(1, 200);
        let after_second = difficulty_default();
        finalize_winner(1, 300);
        let after_third = difficulty_default();

        // Without the `threshold > 0` guard, `count >= 0` would force
        // easing on every slow win. A threshold of 0 must mean "disabled":
        // slow wins keep hardening (or hold at the clamp floor) — easing
        // would raise the threshold and trip this.
        assert!(
            after_third.max_energy_milli <= after_second.max_energy_milli,
            "threshold 0 disables streak easing; a slow repeat win must never ease"
        );
        assert!(
            after_third.max_energy_milli >= curve.min_milli,
            "hardening must respect the curve floor"
        );
    });
}

#[test]
fn adjustment_from_in_range_never_leaves_curve_range() {
    let curve = test_curve();
    // Regression for the convergence bug this MR fixes: a max-roll fast win
    // from the knee could overshoot below `min_milli`, re-entering the
    // impossible range the v1 migration repairs. Sweep many seeds and
    // mining times; an in-range threshold must stay in range.
    for seed_byte in 0_u8..64 {
        for &mining_time in &[1_u64, 30, 59, 60, 61, 150, 200, 201, 500] {
            for &start in &[curve.min_milli, curve.knee_milli, curve.max_milli] {
                for dominant in [false, true] {
                    let adjusted = difficulty::adjust_on_proof_with_dominance(
                        DifficultyConfig {
                            min_solutions: 1,
                            max_energy_milli: start,
                            min_diversity_milli: 0,
                        },
                        mining_time,
                        curve,
                        &[seed_byte],
                        dominant,
                    );
                    assert!(
                        adjusted.max_energy_milli >= curve.min_milli
                            && adjusted.max_energy_milli <= curve.max_milli,
                        "seed {seed_byte}, time {mining_time}, start {start}, \
                         dominant {dominant}: adjusted threshold {} left [{}, {}]",
                        adjusted.max_energy_milli,
                        curve.min_milli,
                        curve.max_milli,
                    );
                }
            }
        }
    }
}

#[test]
fn winner_streak_resets_for_different_miner() {
    new_test_ext().execute_with(|| {
        registered_topology();
        let curve = test_curve();
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: curve.knee_milli,
            min_diversity_milli: 0,
        };
        set_difficulty_default(initial);
        LastProofBlock::<Test>::put(1);

        finalize_winner(1, 10);
        finalize_winner(1, 20);
        let before_reset = difficulty_default();

        finalize_winner(2, 30);
        let after_reset = difficulty_default();
        let streak = WinnerStreak::<Test>::get().expect("winner streak tracked");

        assert_eq!(streak.miner, 2);
        assert_eq!(streak.count, 1);
        // Two fast wins from the knee can already pin the threshold at the
        // clamp floor (`curve.min_milli`), so the reset win may have no room
        // left to harden further. The regression this guards is the streak
        // *not* resetting: count 3 would force easing, raising the threshold.
        assert!(
            after_reset.max_energy_milli <= before_reset.max_energy_milli,
            "new winner below cutoff must use normal hardening, never easing"
        );
        assert!(
            after_reset.max_energy_milli >= curve.min_milli,
            "hardening must respect the curve floor"
        );
    });
}

#[test]
fn on_finalize_persists_qblock_with_recoverable_nonce() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());
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

        let stored = QBlocks::<Test>::get(block).expect("qblock persisted");
        assert_eq!(stored.miner, 1);
        assert_eq!(stored.salt, original_salt);
        assert_eq!(stored.reward, 50);
        assert_eq!(QBlockCount::<Test>::get(), 1);
        assert_eq!(QBlockBlockById::<Test>::get(1), Some(block));
        assert_eq!(QBlockIdByBlock::<Test>::get(block), Some(1));
        assert_eq!(crate::Pallet::<Test>::latest_qblock_id(), Some(1));
        assert_eq!(crate::Pallet::<Test>::qblock_id_by_block(block), Some(1));
        assert_eq!(crate::Pallet::<Test>::qblock_block_by_id(1), Some(block));
        // LastProofBlock was zero before this proof, so no decay applied —
        // the active threshold equals whatever set_difficulty just stored.
        assert_eq!(stored.difficulty, easy_difficulty());
        assert_eq!(stored.last_proof_block_hash, expected_last_proof_block_hash);

        // Re-derive the nonce via the runtime helper and confirm it matches
        // the value that was on the submitted proof. This is the round-trip
        // that lets dashboards recover the nonce from on-chain state alone.
        let view = crate::Pallet::<Test>::qblock_with_nonce(block)
            .expect("nonce derivation succeeds for a real winner");
        assert_eq!(view.nonce, original_nonce);
        assert_eq!(view.solution.salt, original_salt);
        assert_eq!(view.solution.difficulty, easy_difficulty());
        assert_eq!(
            view.solution.last_proof_block_hash,
            expected_last_proof_block_hash
        );

        let by_id = crate::Pallet::<Test>::qblock_with_nonce_by_id(1)
            .expect("qblock id resolves to the persisted qblock");
        assert_eq!(by_id, view);
    });
}

#[test]
fn qblock_returns_none_for_genesis_block() {
    new_test_ext().execute_with(|| {
        // Genesis (block 0) never had a `submit_proof` call, so the storage
        // entry is absent and the helper short-circuits before any block-hash
        // arithmetic. Pins the contract that saturating subtraction on
        // `block_number - 1 == 0u32 - 1` never reaches the nonce derivation.
        assert!(crate::Pallet::<Test>::qblock_with_nonce(0).is_none());
        assert!(crate::Pallet::<Test>::latest_qblock_id().is_none());
        assert!(crate::Pallet::<Test>::qblock_with_nonce_by_id(1).is_none());
    });
}

#[test]
fn qblock_ids_increment_only_for_winning_qblocks() {
    new_test_ext().execute_with(|| {
        registered_topology();

        finalize_winner(1, 10);
        finalize_winner(2, 15);

        assert_eq!(QBlockCount::<Test>::get(), 2);
        assert_eq!(crate::Pallet::<Test>::latest_qblock_id(), Some(2));
        assert_eq!(QBlockBlockById::<Test>::get(1), Some(10));
        assert_eq!(QBlockBlockById::<Test>::get(2), Some(15));
        assert_eq!(QBlockIdByBlock::<Test>::get(10), Some(1));
        assert_eq!(QBlockIdByBlock::<Test>::get(15), Some(2));
        assert!(QBlockIdByBlock::<Test>::get(11).is_none());
        assert_eq!(
            crate::Pallet::<Test>::qblock_with_nonce_by_id(2)
                .expect("second qblock exists")
                .solution
                .miner,
            2
        );
    });
}

#[test]
fn mining_snapshot_returns_default_and_selected_topology_views() {
    new_test_ext().execute_with(|| {
        let (default_nodes, default_edges, default_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());

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
fn qblock_records_active_difficulty_threshold() {
    new_test_ext().execute_with(|| {
        // Pin the contract that the QBlock stores the *active* threshold
        // a proof had to clear (decay applied, pre-adjust) rather than the
        // post-adjustment value that lives in Difficulty<T> after on_finalize.
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: i64::MAX,
            min_diversity_milli: 0,
        };
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(initial);

        LastProofBlock::<Test>::put(1);
        System::set_block_number(45); // (45 - 1) / 20 = 2 decay steps
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);
        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));
        QuantumPow::on_finalize(System::block_number());

        let expected_active = difficulty::apply_decay(initial, 2, test_curve());
        let stored = QBlocks::<Test>::get(45).expect("winner persisted");
        assert_eq!(
            stored.difficulty, expected_active,
            "stored difficulty must be the decayed-but-pre-adjust threshold"
        );

        // Mining time blocks = 45 - 1 = 44 < harden cutoff (60), so the
        // adjustment hardens. Only the energy threshold moves now; chain-static
        // fields stay put.
        let next = difficulty_default();
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
        let _ = registered_topology();
        set_difficulty_default(initial);

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
        assert_eq!(difficulty_default(), initial);
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
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());

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
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());

        // Derive against the current last proof block hash (`block_hash(0)` in the
        // test env — defaults to zero, but the value itself is incidental
        // here; what matters is that we later mutate the lookup target).
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        // Force the last proof block hash to a distinct value by (a) pointing
        // `LastProofBlock` at a fresh block, (b) populating `block_hash`
        // for that block, and (c) writing the cached `LastProofBlockHash`
        // that the pallet's submit_proof reads. The on_initialize hook is
        // what would normally refresh the cache from parent_hash() on the
        // block immediately after the proof block; tests don't run hooks
        // automatically, so we mimic that side-effect explicitly.
        System::set_block_number(50);
        LastProofBlock::<Test>::put(10);
        frame_system::BlockHash::<Test>::insert(10u64, sp_core::H256::from([0xAB; 32]));
        LastProofBlockHash::<Test>::put(sp_core::H256::from([0xAB; 32]));

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
    // Production-scale curve (v0.1's documented -16000/-15600/-14000 energy
    // units, in milli). The tiny (2, 1) test curve's range sits below the
    // 5000-milli proof floor, which would flatten every delta to the floor
    // and hide the compression this test pins.
    let curve = crate::difficulty::EnergyCurve {
        min_milli: -16_000_000,
        knee_milli: -15_600_000,
        max_milli: -14_000_000,
    };
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

        // Set a stored difficulty and let decay elapse. Start inside A's
        // curve range: the 3000-milli decay floor exceeds both tiny test
        // curves' spans, so an out-of-range start would decay by identical
        // floored linear steps under either curve and defeat the sanity
        // check below. In-range, A's decay clamps at A's ceiling while B's
        // (out-of-range for B) walks linearly — observably different.
        let curve_a = test_curve();
        let initial = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: curve_a.knee_milli,
            min_diversity_milli: 0,
        };
        set_difficulty_default(initial);
        LastProofBlock::<Test>::put(1);
        System::set_block_number(101); // (101 - 1) / 20 = 5 decay steps

        // `mining_snapshot` populates `difficulty` via current_difficulty,
        // which builds its curve from DefaultTopology.
        let snapshot =
            QuantumPow::mining_snapshot(None).expect("snapshot exists for default topology");

        // Expected decay using A's curve (the default).
        let expected_default = difficulty::apply_decay(initial, 5, test_curve());
        // Decay using B's curve (the *non-default* topology — this is what
        // a miner-controlled curve would produce if the invariant were broken).
        let expected_other = difficulty::apply_decay(
            initial,
            5,
            crate::difficulty::EnergyCurve::new(
                4,
                4,
                test_curve_c(),
                &allowed_h_spec().as_slice(),
                &allowed_j_spec().as_slice(),
            )
            .expect("registered specs are non-empty"),
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

/// Two registrations with identical Set values in different orders must
/// collide via `topology_hash` (the design intent of `canonical_bytes`
/// sorting). Before the canonicalize_spec fix the stored order matched the
/// caller-supplied order, so the second registration would be rejected as
/// already-registered but the stored representation would be whichever
/// order won the race — meaning sample()/decode_value() walked the unsorted
/// order while the hash claimed canonical-sorted equivalence.
#[test]
fn register_topology_canonicalizes_set_order() {
    new_test_ext().execute_with(|| {
        let nodes = bounded::<_, MaxNodes>(vec![0, 1]);
        let edges = bounded::<_, MaxEdges>(vec![(0, 1)]);
        let reordered_spin_spec: AllowedValueSpec<AllowedValueSetOf<Test>> =
            AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![SCALE, -SCALE]));

        assert_ok!(QuantumPow::register_topology(
            RuntimeOrigin::root(),
            nodes.clone(),
            edges.clone(),
            allowed_h_spec(),
            allowed_j_spec(),
            reordered_spin_spec,
        ));

        let hash = topology::hash_topology(
            &nodes,
            &edges,
            &allowed_h_spec().as_slice(),
            &allowed_j_spec().as_slice(),
            &allowed_spin_spec().as_slice(),
        );
        let stored =
            RegisteredTopologies::<Test>::get(hash).expect("topology stored under canonical hash");
        match stored.allowed_spin_values {
            AllowedValueSpec::Set(values) => {
                let v: Vec<MilliValue> = values.into_inner();
                assert_eq!(v, vec![-SCALE, SCALE], "stored Set must be sorted");
            }
            _ => panic!("expected Set variant"),
        }
    });
}

/// `ContinuousRange` spin specs need 4 bytes per spin, which would overflow
/// the `BoundedVec<u8, MaxNodes>` packed-solution bound for any topology
/// with `nodes > MaxNodes / 4`. Reject at registration so operators see a
/// concrete error instead of shipping a topology that no valid proof can
/// satisfy.
#[test]
fn register_topology_rejects_unmineable_continuous_spin_spec() {
    new_test_ext().execute_with(|| {
        let mut node_ids: Vec<u32> = (0..(MaxNodes::get() / 2)).collect();
        // Drop one node to make sure the test still exceeds MaxNodes/4 even
        // for very small MaxNodes. (MaxNodes/2 > MaxNodes/4 for MaxNodes >= 2.)
        if node_ids.len() < 2 {
            node_ids = vec![0, 1, 2, 3];
        }
        let nodes = bounded::<_, MaxNodes>(node_ids);
        let edges = bounded::<_, MaxEdges>(vec![(0, 1)]);
        let continuous_spin: AllowedValueSpec<AllowedValueSetOf<Test>> =
            AllowedValueSpec::ContinuousRange {
                min: -SCALE,
                max: SCALE,
            };

        assert_noop!(
            QuantumPow::register_topology(
                RuntimeOrigin::root(),
                nodes,
                edges,
                allowed_h_spec(),
                allowed_j_spec(),
                continuous_spin,
            ),
            crate::Error::<Test>::PackedSolutionTooLarge
        );
    });
}

/// `LastProofBlockHash` must remain stable for the entire mining round even
/// after `frame_system::block_hash(LastProofBlock)` ages out of its
/// `BlockHashCount` ring buffer. Before the fix, a long-running round
/// (longer than `BlockHashCount`) would see the nonce seed silently flip
/// to the zero hash mid-round and reject every in-flight proof.
#[test]
fn last_proof_block_hash_stable_after_block_hash_ages_out() {
    use frame_support::traits::Hooks;

    new_test_ext().execute_with(|| {
        // Simulate a winning proof at block 5: write LastProofBlock and the
        // expected parent_hash, then run on_initialize for block 6 — which
        // is what captures the cache from parent_hash() (== block_hash(5)
        // in production). `set_parent_hash` is the test-only frame_system
        // helper for setting up this storage value.
        let proof_block_hash = sp_core::H256::from([0x77; 32]);
        LastProofBlock::<Test>::put(5u64);
        System::set_block_number(6);
        frame_system::Pallet::<Test>::set_parent_hash(proof_block_hash);
        QuantumPow::on_initialize(6);

        let cached = LastProofBlockHash::<Test>::get();
        assert_eq!(
            cached, proof_block_hash,
            "captured hash must equal block_hash(LastProofBlock)"
        );

        // Now jump far past `BlockHashCount` (production default 256) and
        // run on_initialize again with a different parent_hash. The cache
        // must NOT be overwritten — LastProofBlock hasn't changed, so the
        // round's nonce seed is still bound to block 5's hash.
        System::set_block_number(1000);
        frame_system::Pallet::<Test>::set_parent_hash(sp_core::H256::from([0x99; 32]));
        QuantumPow::on_initialize(1000);

        assert_eq!(
            LastProofBlockHash::<Test>::get(),
            cached,
            "LastProofBlockHash must not change on a no-op on_initialize"
        );
    });
}

/// `adjust_energy_along_curve` must apply `min_delta_milli` when the raw
/// float delta is in (0, 0.5). Before the fix, `libm::round(0.4) = 0` made
/// the guard `delta > 0` fail and difficulty stalled instead of advancing.
#[test]
fn difficulty_adjust_applies_min_delta_for_small_positive_floats() {
    // Construct a curve and inputs where the raw delta falls in (0, 0.5).
    // Pick numbers that make total_range * rate * curve_factor < 0.5 milli.
    // total_range = 1000, rate = 0.0001 (rate_milli=0). 1000 * 0.0001 = 0.1.
    // round(0.1) = 0 → without the fix, delta stays 0, function returns
    // current. With the fix, raw_delta_f > 0.0 triggers the floor.
    let current = -500_000i64;
    let curve = test_curve();

    let result = crate::difficulty::adjust_energy_along_curve(
        current,
        /* rate_milli */ 1,
        crate::difficulty::Direction::Harder,
        curve,
        /* min_delta_milli */ 100,
    );
    assert_ne!(
        result, current,
        "difficulty must advance by min_delta_milli when raw float delta is small but positive"
    );
}

#[test]
fn submit_proof_records_topology_hash() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));

        let record = BlockBestProof::<Test>::get().expect("best proof recorded");
        assert_eq!(record.topology_hash, topology_hash);
    });
}

#[test]
fn winning_topology_does_not_move_other_topology_difficulty() {
    new_test_ext().execute_with(|| {
        // Topology A (ternary-h) is default; topology B (zero-field) is a
        // second registered topology. Each gets its own difficulty entry.
        let (_, _, hash_a) = registered_topology();
        let hash_b = registered_zero_field_topology();

        let diff_a = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: -10_000,
            min_diversity_milli: 0,
        };
        let diff_b = DifficultyConfig {
            min_solutions: 1,
            max_energy_milli: -20_000,
            min_diversity_milli: 0,
        };
        Difficulties::<Test>::insert(hash_a, diff_a);
        Difficulties::<Test>::insert(hash_b, diff_b);

        // A wins (finalize against A). B's difficulty must be untouched.
        LastProofBlock::<Test>::put(1);
        System::set_block_number(80);
        BlockBestProof::<Test>::put(ProofRecord {
            miner: 1,
            submitted_at: 80,
            energy_milli: -10_000,
            salt: [0u8; 32],
            topology_hash: hash_a,
        });
        QuantumPow::on_finalize(80);

        assert_ne!(
            Difficulties::<Test>::get(hash_a),
            Some(diff_a),
            "A's difficulty must have been adjusted"
        );
        assert_eq!(
            Difficulties::<Test>::get(hash_b),
            Some(diff_b),
            "B's difficulty must NOT move when A wins"
        );
    });
}
