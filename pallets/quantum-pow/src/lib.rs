#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

pub mod difficulty;
pub mod topology;
pub mod types;
pub mod weights;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub use weights::*;

use frame_support::traits::Currency;

type AccountIdOf<T> = <T as frame_system::Config>::AccountId;
type BlockNumberOf<T> = frame_system::pallet_prelude::BlockNumberFor<T>;
type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

type NodesOf<T> = frame_support::pallet_prelude::BoundedVec<u32, <T as Config>::MaxNodes>;
type EdgesOf<T> = frame_support::pallet_prelude::BoundedVec<(u32, u32), <T as Config>::MaxEdges>;
type AllowedValueSetOf<T> = frame_support::pallet_prelude::BoundedVec<
    quantum_validation::MilliValue,
    <T as Config>::MaxAllowedValues,
>;
type PackedSpinBytesOf<T> = frame_support::pallet_prelude::BoundedVec<u8, <T as Config>::MaxNodes>;
type PackedSolutionsOf<T> =
    frame_support::pallet_prelude::BoundedVec<PackedSpinBytesOf<T>, <T as Config>::MaxSolutions>;
type QuantumProofOf<T> = types::QuantumProof<PackedSolutionsOf<T>>;
type TopologyMetaOf<T> =
    types::TopologyMeta<NodesOf<T>, EdgesOf<T>, AllowedValueSetOf<T>, BlockNumberOf<T>>;
type MinerInfoOf<T> = types::MinerInfo<BalanceOf<T>, BlockNumberOf<T>>;
type ProofRecordOf<T> = types::ProofRecord<AccountIdOf<T>, BlockNumberOf<T>>;
type MiningSnapshotOf<T> = types::MiningSnapshot<NodesOf<T>, EdgesOf<T>, AllowedValueSetOf<T>>;
type WinningSolutionOf<T> = types::WinningSolution<AccountIdOf<T>, BalanceOf<T>, BlockNumberOf<T>>;
type WinningSolutionWithNonceOf<T> =
    types::WinningSolutionWithNonce<AccountIdOf<T>, BalanceOf<T>, BlockNumberOf<T>>;

sp_api::decl_runtime_apis! {
    pub trait QuantumPowApi<BlockNumber, AccountId, Balance, Nodes, Edges, AllowedValues>
    where
        BlockNumber: codec::Codec,
        AccountId: codec::Codec,
        Balance: codec::Codec,
        Nodes: codec::Codec,
        Edges: codec::Codec,
        AllowedValues: codec::Codec,
    {
        fn mining_snapshot(topology_hash: Option<sp_core::H256>) -> Option<
            crate::types::MiningSnapshot<Nodes, Edges, AllowedValues>
        >;

        /// Look up a registered topology by hash (nodes, edges, allowed value
        /// sets). Returns `None` if the hash has never been registered.
        fn topology_meta(hash: sp_core::H256) -> Option<
            crate::types::TopologyMeta<Nodes, Edges, AllowedValues, BlockNumber>
        >;

        /// Winning solution for `block_number`, augmented with its derived
        /// nonce. The nonce is reconstructed from the persisted
        /// `last_proof_block_hash`, miner, and salt — no `frame_system::block_hash`
        /// lookup needed, so this stays correct even for blocks pruned beyond
        /// `BlockHashCount`. Returns `None` if the block had no accepted
        /// proof (e.g. genesis, or any block where no `submit_proof` cleared
        /// difficulty).
        fn winning_solution(block_number: BlockNumber) -> Option<
            crate::types::WinningSolutionWithNonce<AccountId, Balance, BlockNumber>
        >;

        /// Live difficulty threshold a miner has to clear *right now*.
        ///
        /// Differs from `api.query.quantumPow.difficulty()` (the raw storage
        /// value): that one is the post-last-adjust baseline and does *not*
        /// reflect decay applied since the last winning proof. This API
        /// returns the decayed value, matching what `submit_proof` validation
        /// will actually require.
        fn current_difficulty() -> crate::types::DifficultyConfig;
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use codec::Encode;
    use frame_support::{pallet_prelude::*, traits::ReservableCurrency};
    use frame_system::pallet_prelude::*;
    use quantum_validation::{
        calculate_diversity, derive_nonce, energy_of_solution, generate_ising_model,
        packed::unpack_solution, select_diverse, validate_spins, validate_topology_consistency,
        AllowedValueSpec, MilliValue,
    };
    use sp_core::H256;
    use sp_runtime::traits::{SaturatedConversion, Saturating, Zero};

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_balances::Config {
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type Currency: ReservableCurrency<Self::AccountId>;

        #[pallet::constant]
        type MaxNodes: Get<u32>;
        #[pallet::constant]
        type MaxEdges: Get<u32>;
        #[pallet::constant]
        type MaxSolutions: Get<u32>;
        #[pallet::constant]
        type MinNodes: Get<u32>;
        /// Upper bound on |allowed_h_values|, |allowed_j_values|, and
        /// |allowed_spin_values| per topology. Small (e.g., 32) is plenty —
        /// these are discrete sets like `{-1, +1}` or `{-6, 0, 6}`, not
        /// per-node arrays.
        #[pallet::constant]
        type MaxAllowedValues: Get<u32>;
        #[pallet::constant]
        type EpochLength: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type MinerDeposit: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type BlockReward: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type MaxProofsPerBlock: Get<u32>;

        /// Per-mille `c` value for the easiest (least-negative) end of the
        /// energy curve. The difficulty curve is calibrated against the
        /// default topology's `(num_nodes, num_edges)` and these three c
        /// values; see `crate::difficulty::EnergyCurve`.
        #[pallet::constant]
        type CurveCEasyMilli: Get<u32>;
        /// Per-mille `c` value for the curve's knee (where motion is most
        /// aggressive). Conventionally the canonical `c = 0.75` used by
        /// `quantum_validation::expected_gse`.
        #[pallet::constant]
        type CurveCKneeMilli: Get<u32>;
        /// Per-mille `c` value for the hardest (most-negative) end of the
        /// energy curve.
        #[pallet::constant]
        type CurveCHardMilli: Get<u32>;

        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    pub type RegisteredTopologies<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, TopologyMetaOf<T>>;

    #[pallet::storage]
    pub type DefaultTopology<T: Config> = StorageValue<_, H256>;

    #[pallet::storage]
    pub type Difficulty<T: Config> = StorageValue<_, types::DifficultyConfig, ValueQuery>;

    #[pallet::storage]
    pub type Miners<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, MinerInfoOf<T>>;

    #[pallet::storage]
    pub type BlockBestProof<T: Config> = StorageValue<_, ProofRecordOf<T>>;

    #[pallet::storage]
    /// Block number of the last finalized winning proof.
    ///
    /// Difficulty adjustment and decay are block-based, not timestamp-based.
    /// We intentionally use elapsed blocks as the protocol time unit so the
    /// difficulty path stays coherent with `EpochLength` and does not depend on
    /// mixing wall-clock moments with block numbers.
    pub type LastProofBlock<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    #[pallet::storage]
    pub type BlockProofCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Persisted record of each block's winning proof, written in
    /// `on_finalize` alongside the `BlockWinner` event.
    ///
    /// Consumers derive the winning nonce by hashing
    /// `(last_proof_block_hash, miner, salt)` with BLAKE3, or call the
    /// `QuantumPowApi::winning_solution` runtime API which does it
    /// server-side. `last_proof_block_hash` for each entry is the value the
    /// round used at submission time, persisted in the `WinningSolution`
    /// itself so re-derivation needs no chain-state lookup.
    #[pallet::storage]
    pub type WinningSolutions<T: Config> =
        StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, WinningSolutionOf<T>>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        MinerRegistered {
            who: T::AccountId,
            deposit: BalanceOf<T>,
        },
        MinerDeregistered {
            who: T::AccountId,
        },
        TopologyRegistered {
            topology_hash: H256,
            node_count: u32,
            edge_count: u32,
        },
        DifficultyUpdated {
            difficulty: types::DifficultyConfig,
        },
        ProofAccepted {
            miner: T::AccountId,
            energy_milli: i64,
            diversity_milli: u32,
            valid_solution_count: u32,
        },
        BlockWinner {
            miner: T::AccountId,
            reward: BalanceOf<T>,
            energy_milli: i64,
            submitted_at: BlockNumberFor<T>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        MinerAlreadyRegistered,
        MinerNotRegistered,
        TopologyAlreadyRegistered,
        TopologyNotRegistered,
        GraphTooSmall,
        InvalidTopology,
        ProofLimitReached,
        InvalidNonce,
        NoSolutionsSubmitted,
        InvalidSpinValues,
        SolutionLengthMismatch,
        InsufficientEnergy,
        InsufficientDiversity,
        InsufficientSolutions,
        ArithmeticOverflow,
        /// One of the allowed value specs is empty or has inverted bounds.
        EmptyAllowedValues,
        /// An allowed value spec requires more bits per value than the
        /// protocol supports (max 8 for indexed encodings).
        EncodingTooWide,
        /// A submitted packed solution did not have the byte length implied
        /// by the topology's allowed_spin_values spec and node count.
        PackedSolutionLengthMismatch,
        /// A submitted packed solution contained a bit pattern that does not
        /// map to any value in the allowed_spin_values spec.
        InvalidEncodedSpin,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
            BlockProofCount::<T>::put(0);
            <T as Config>::WeightInfo::register_miner()
        }

        fn on_finalize(n: BlockNumberFor<T>) {
            let Some(record) = BlockBestProof::<T>::take() else {
                return;
            };

            let reward = T::BlockReward::get();
            let _ = T::Currency::deposit_creating(&record.miner, reward);

            if let Some(mut miner) = Miners::<T>::get(&record.miner) {
                miner.proofs_won = miner.proofs_won.saturating_add(1);
                miner.rewards_earned = miner.rewards_earned.saturating_add(reward);
                Miners::<T>::insert(&record.miner, miner);
            }

            let previous_proof_block = LastProofBlock::<T>::get();
            // Capture the hash the just-won round actually used in its
            // `derive_nonce` input. Read here, before the `LastProofBlock`
            // mutation below makes the next round's hash visible. Persisting
            // it in `WinningSolution` lets `winning_solution_with_nonce`
            // re-derive the nonce without a `frame_system::block_hash`
            // lookup — which means re-derivation stays correct even after
            // the original block is pruned beyond `BlockHashCount`.
            let last_proof_block_hash = H256::from(Self::hash_to_bytes_32(
                frame_system::Pallet::<T>::block_hash(previous_proof_block),
            ));

            let mining_time_blocks = if previous_proof_block.is_zero() || n <= previous_proof_block
            {
                T::EpochLength::get().saturated_into::<u64>()
            } else {
                n.saturating_sub(previous_proof_block)
                    .saturated_into::<u64>()
            };

            // Snapshot the live (decay-applied) threshold this proof had to
            // clear before adjust_on_proof rewrites it. WinningSolutions stores
            // this so explorers and miners can answer "what difficulty did
            // block N actually clear?" without replaying decay client-side.
            let active = Self::current_difficulty(n);
            // Curve calibration MUST come from chain state (DefaultTopology),
            // not from the winning proof. See `current_energy_curve` docs and
            // GitLab issue #5 for the invariant rationale.
            let next = match Self::current_energy_curve() {
                Some(curve) => crate::difficulty::adjust_on_proof(
                    active,
                    mining_time_blocks,
                    curve,
                    &(frame_system::Pallet::<T>::parent_hash(), &record.miner, n).encode(),
                ),
                // Unreachable in normal operation: a proof would not have
                // been submitted without a registered topology, and the
                // first registration also seeds `DefaultTopology`.
                None => active,
            };
            Difficulty::<T>::put(next);
            LastProofBlock::<T>::put(n);

            WinningSolutions::<T>::insert(
                n,
                types::WinningSolution {
                    miner: record.miner.clone(),
                    salt: record.salt,
                    energy_milli: record.energy_milli,
                    reward,
                    submitted_at: record.submitted_at,
                    difficulty: active,
                    last_proof_block_hash,
                },
            );

            Self::deposit_event(Event::DifficultyUpdated { difficulty: next });
            Self::deposit_event(Event::BlockWinner {
                miner: record.miner,
                reward,
                energy_milli: record.energy_milli,
                submitted_at: record.submitted_at,
            });
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::register_miner())]
        pub fn register_miner(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                !Miners::<T>::contains_key(&who),
                Error::<T>::MinerAlreadyRegistered
            );

            let deposit = T::MinerDeposit::get();
            T::Currency::reserve(&who, deposit)?;

            Miners::<T>::insert(
                &who,
                MinerInfoOf::<T> {
                    registered_at: frame_system::Pallet::<T>::block_number(),
                    deposit,
                    proofs_submitted: 0,
                    proofs_won: 0,
                    rewards_earned: Zero::zero(),
                },
            );

            Self::deposit_event(Event::MinerRegistered { who, deposit });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::deregister_miner())]
        pub fn deregister_miner(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let miner = Miners::<T>::get(&who).ok_or(Error::<T>::MinerNotRegistered)?;

            T::Currency::unreserve(&who, miner.deposit);
            Miners::<T>::remove(&who);

            Self::deposit_event(Event::MinerDeregistered { who });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::register_topology())]
        pub fn register_topology(
            origin: OriginFor<T>,
            nodes: NodesOf<T>,
            edges: EdgesOf<T>,
            allowed_h_values: AllowedValueSpec<AllowedValueSetOf<T>>,
            allowed_j_values: AllowedValueSpec<AllowedValueSetOf<T>>,
            allowed_spin_values: AllowedValueSpec<AllowedValueSetOf<T>>,
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(
                nodes.len() >= T::MinNodes::get() as usize,
                Error::<T>::GraphTooSmall
            );

            // Validate each spec is non-empty and fits the protocol's bit-width
            // cap. `bits_per_value` returns the per-variant errors that the
            // pallet maps to dispatch errors.
            Self::check_spec(&allowed_h_values)?;
            Self::check_spec(&allowed_j_values)?;
            Self::check_spec(&allowed_spin_values)?;

            ensure!(
                validate_topology_consistency(
                    &nodes,
                    &edges,
                    &vec![0; nodes.len()],
                    &vec![0; edges.len()],
                    None,
                    None,
                )
                .is_empty(),
                Error::<T>::InvalidTopology
            );

            let topology_hash = crate::topology::hash_topology(
                &nodes,
                &edges,
                &allowed_h_values.as_slice(),
                &allowed_j_values.as_slice(),
                &allowed_spin_values.as_slice(),
            );
            ensure!(
                !RegisteredTopologies::<T>::contains_key(topology_hash),
                Error::<T>::TopologyAlreadyRegistered
            );

            RegisteredTopologies::<T>::insert(
                topology_hash,
                TopologyMetaOf::<T> {
                    nodes: nodes.clone(),
                    edges: edges.clone(),
                    allowed_h_values,
                    allowed_j_values,
                    allowed_spin_values,
                    registered_at: frame_system::Pallet::<T>::block_number(),
                },
            );

            if DefaultTopology::<T>::get().is_none() {
                DefaultTopology::<T>::put(topology_hash);
            }

            Self::deposit_event(Event::TopologyRegistered {
                topology_hash,
                node_count: nodes.len() as u32,
                edge_count: edges.len() as u32,
            });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::set_difficulty())]
        pub fn set_difficulty(
            origin: OriginFor<T>,
            difficulty: types::DifficultyConfig,
        ) -> DispatchResult {
            ensure_root(origin)?;
            Difficulty::<T>::put(difficulty);
            Self::deposit_event(Event::DifficultyUpdated { difficulty });
            Ok(())
        }

        #[pallet::call_index(4)]
        #[pallet::weight(<T as Config>::WeightInfo::submit_proof())]
        pub fn submit_proof(origin: OriginFor<T>, proof: QuantumProofOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                Miners::<T>::contains_key(&who),
                Error::<T>::MinerNotRegistered
            );
            ensure!(
                BlockProofCount::<T>::get() < T::MaxProofsPerBlock::get(),
                Error::<T>::ProofLimitReached
            );
            ensure!(
                !proof.solutions.is_empty(),
                Error::<T>::NoSolutionsSubmitted
            );

            // Topology lookup is the source of truth for nodes, edges, and the
            // allowed value sets. The proof's `topology_hash` is the only
            // identity claim; there are no `proof.nodes`/`proof.edges` to
            // cross-check.
            let topology = RegisteredTopologies::<T>::get(proof.topology_hash)
                .ok_or(Error::<T>::TopologyNotRegistered)?;
            ensure!(
                topology.nodes.len() >= T::MinNodes::get() as usize,
                Error::<T>::GraphTooSmall
            );

            // Nonce is bound to `block_hash(LastProofBlock)`, not to the
            // executing block's number or parent hash. That value only
            // changes when a new proof wins, so a miner's submission stays
            // valid for as long as the current round runs — no txpool-delay
            // race (the original bug).
            let last_proof_block_hash =
                frame_system::Pallet::<T>::block_hash(LastProofBlock::<T>::get());
            let last_proof_block_hash_bytes = Self::hash_to_bytes_32(last_proof_block_hash);
            let miner_bytes = Self::account_to_bytes(&who);

            let expected_nonce =
                derive_nonce(&last_proof_block_hash_bytes, &miner_bytes, &proof.salt);
            ensure!(proof.nonce == expected_nonce, Error::<T>::InvalidNonce);

            let (h, j) = generate_ising_model(
                proof.nonce,
                topology.nodes.as_slice(),
                topology.edges.as_slice(),
                &topology.allowed_h_values.as_slice(),
                &topology.allowed_j_values.as_slice(),
            )
            .map_err(|_| Error::<T>::InvalidTopology)?;

            let current = Self::current_difficulty(frame_system::Pallet::<T>::block_number());
            let validation = Self::validate_proof(&proof, &topology, &h, &j, &current)?;

            ensure!(
                validation.best_energy_milli < current.max_energy_milli,
                Error::<T>::InsufficientEnergy
            );
            ensure!(
                validation.valid_solution_count >= current.min_solutions,
                Error::<T>::InsufficientSolutions
            );
            ensure!(
                validation.diversity_milli >= current.min_diversity_milli,
                Error::<T>::InsufficientDiversity
            );

            let mut miner = Miners::<T>::get(&who).ok_or(Error::<T>::MinerNotRegistered)?;
            miner.proofs_submitted = miner.proofs_submitted.saturating_add(1);
            Miners::<T>::insert(&who, miner);

            let record = ProofRecordOf::<T> {
                miner: who.clone(),
                submitted_at: frame_system::Pallet::<T>::block_number(),
                energy_milli: validation.best_energy_milli,
                salt: proof.salt,
            };

            let should_replace = match BlockBestProof::<T>::get() {
                Some(existing) => record.energy_milli < existing.energy_milli,
                None => true,
            };
            if should_replace {
                BlockBestProof::<T>::put(record);
            }

            BlockProofCount::<T>::mutate(|count| {
                *count = count.saturating_add(1);
            });

            Self::deposit_event(Event::ProofAccepted {
                miner: who,
                energy_milli: validation.best_energy_milli,
                diversity_milli: validation.diversity_milli,
                valid_solution_count: validation.valid_solution_count,
            });

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn default_topology() -> Option<H256> {
            DefaultTopology::<T>::get()
        }

        pub fn topology_meta(hash: H256) -> Option<TopologyMetaOf<T>> {
            RegisteredTopologies::<T>::get(hash)
        }

        pub fn default_topology_meta() -> Option<(H256, TopologyMetaOf<T>)> {
            let topology_hash = DefaultTopology::<T>::get()?;
            let topology = RegisteredTopologies::<T>::get(topology_hash)?;
            Some((topology_hash, topology))
        }

        pub fn miner_info(account: &T::AccountId) -> Option<MinerInfoOf<T>> {
            Miners::<T>::get(account)
        }

        pub fn current_difficulty_for(block_number: BlockNumberFor<T>) -> types::DifficultyConfig {
            Self::current_difficulty(block_number)
        }

        pub fn mining_snapshot(topology_hash: Option<H256>) -> Option<MiningSnapshotOf<T>> {
            let (topology_hash, topology) = match topology_hash {
                Some(hash) => (hash, Self::topology_meta(hash)?),
                None => Self::default_topology_meta()?,
            };

            // Difficulty still tracks the current block (decay is block-based)
            // even though the nonce input no longer is.
            let block_number = frame_system::Pallet::<T>::block_number();
            let last_proof_block_hash = H256::from(Self::hash_to_bytes_32(
                frame_system::Pallet::<T>::block_hash(LastProofBlock::<T>::get()),
            ));

            Some(types::MiningSnapshot {
                last_proof_block_hash,
                difficulty: Self::current_difficulty_for(block_number),
                topology_hash,
                nodes: topology.nodes,
                edges: topology.edges,
                allowed_h_values: topology.allowed_h_values,
                allowed_j_values: topology.allowed_j_values,
                allowed_spin_values: topology.allowed_spin_values,
            })
        }

        /// 32-byte representation of an account, suitable for use as a fixed-size
        /// input to `derive_nonce`. Hashes the SCALE-encoded `AccountId` so any
        /// underlying encoding width (8-byte `u64`, 32-byte `AccountId32`, etc.)
        /// produces a deterministic 32-byte digest.
        pub fn account_to_bytes(account: &T::AccountId) -> [u8; 32] {
            sp_io::hashing::blake2_256(&account.encode())
        }

        /// Look up a persisted winning solution and re-derive its nonce.
        ///
        /// Returns `None` if the block had no accepted proof (e.g. genesis
        /// where no `submit_proof` ever ran). Re-derivation reads the
        /// `last_proof_block_hash` stored alongside the solution, so this stays
        /// correct even when `block_number` is older than `BlockHashCount`
        /// (no `frame_system::block_hash` lookup is involved).
        pub fn winning_solution_with_nonce(
            block_number: BlockNumberFor<T>,
        ) -> Option<WinningSolutionWithNonceOf<T>> {
            let solution = WinningSolutions::<T>::get(block_number)?;
            let last_proof_block_hash_bytes = solution.last_proof_block_hash.0;
            let miner_bytes = Self::account_to_bytes(&solution.miner);
            let nonce = derive_nonce(&last_proof_block_hash_bytes, &miner_bytes, &solution.salt);
            Some(types::WinningSolutionWithNonce { solution, nonce })
        }

        /// 32-byte representation of a block hash, suitable for use as a
        /// fixed-size input to `derive_nonce`. Works for any `T::Hash`
        /// whose SCALE encoding is exactly 32 bytes (the substrate default
        /// `BlakeTwo256` `H256`). Falls back to `blake2_256` of the encoded
        /// form so non-32-byte `T::Hash` configurations are also covered.
        pub fn hash_to_bytes_32(hash: <T as frame_system::Config>::Hash) -> [u8; 32] {
            let encoded = hash.encode();
            if let Ok(arr) = <[u8; 32]>::try_from(encoded.as_slice()) {
                arr
            } else {
                sp_io::hashing::blake2_256(&encoded)
            }
        }

        fn check_spec(spec: &AllowedValueSpec<AllowedValueSetOf<T>>) -> DispatchResult {
            match spec.as_slice().bits_per_value() {
                Ok(_) => Ok(()),
                Err(quantum_validation::ValidationError::EmptyAllowedValues) => {
                    Err(Error::<T>::EmptyAllowedValues.into())
                }
                Err(quantum_validation::ValidationError::EncodingTooWide { .. }) => {
                    Err(Error::<T>::EncodingTooWide.into())
                }
                Err(_) => Err(Error::<T>::InvalidTopology.into()),
            }
        }

        /// Build the energy curve used by `adjust_on_proof` and
        /// `apply_decay`.
        ///
        /// CRITICAL INVARIANT (see GitLab issue #5 and the topology-registry
        /// fix that addressed `h_values`-in-proof): the curve depends only
        /// on chain state. It must never be derived from any field of a
        /// submitted proof.
        ///
        /// Specifically: even though `submit_proof` accepts proofs against
        /// any hash in `RegisteredTopologies`, the curve is calibrated
        /// against `DefaultTopology::<T>::get()`. Miners cannot shift
        /// difficulty by choosing a different registered topology to mine
        /// against.
        ///
        /// Returns `None` when `DefaultTopology` is unset (no topology has
        /// been registered yet). Callers treat that as a defensive no-op —
        /// in practice the case is unreachable during mining because
        /// `submit_proof` requires the proof's topology to be registered
        /// first, and the first registration also seeds `DefaultTopology`.
        fn current_energy_curve() -> Option<crate::difficulty::EnergyCurve> {
            let (_, topology) = Self::default_topology_meta()?;
            Some(crate::difficulty::EnergyCurve::new(
                topology.nodes.len() as u32,
                topology.edges.len() as u32,
                T::CurveCEasyMilli::get(),
                T::CurveCKneeMilli::get(),
                T::CurveCHardMilli::get(),
            ))
        }

        fn current_difficulty(block_number: BlockNumberFor<T>) -> types::DifficultyConfig {
            crate::difficulty::current_difficulty(
                block_number.saturated_into::<u32>(),
                Difficulty::<T>::get(),
                LastProofBlock::<T>::get().saturated_into::<u32>(),
                T::EpochLength::get().saturated_into::<u32>(),
                Self::current_energy_curve(),
            )
        }

        fn validate_proof(
            proof: &QuantumProofOf<T>,
            topology: &TopologyMetaOf<T>,
            h: &[MilliValue],
            j: &[MilliValue],
            difficulty: &types::DifficultyConfig,
        ) -> Result<types::ProofValidation, DispatchError> {
            let spin_spec = topology.allowed_spin_values.as_slice();
            let num_spins = topology.nodes.len();
            let mut decoded: Vec<Vec<i8>> = Vec::with_capacity(proof.solutions.len());

            for packed in proof.solutions.iter() {
                let milli =
                    unpack_solution(packed.as_slice(), num_spins, &spin_spec).map_err(|err| {
                        match err {
                            quantum_validation::ValidationError::PackedSolutionLengthMismatch {
                                ..
                            } => DispatchError::from(Error::<T>::PackedSolutionLengthMismatch),
                            quantum_validation::ValidationError::InvalidEncodedValue { .. } => {
                                DispatchError::from(Error::<T>::InvalidEncodedSpin)
                            }
                            _ => DispatchError::from(Error::<T>::InvalidTopology),
                        }
                    })?;
                let mut spins = Vec::with_capacity(milli.len());
                for value in milli {
                    let sign = value.signum();
                    ensure!(sign == -1 || sign == 1, Error::<T>::InvalidSpinValues);
                    spins.push(sign as i8);
                }
                ensure!(validate_spins(&spins), Error::<T>::InvalidSpinValues);
                decoded.push(spins);
            }

            let mut energies = Vec::with_capacity(decoded.len());
            for spins in decoded.iter() {
                let energy = energy_of_solution(
                    spins,
                    h,
                    topology.edges.as_slice(),
                    j,
                    topology.nodes.as_slice(),
                )
                .map_err(|err| match err {
                    quantum_validation::ValidationError::SolutionLengthMismatch { .. } => {
                        DispatchError::from(Error::<T>::SolutionLengthMismatch)
                    }
                    quantum_validation::ValidationError::InvalidSpinValue { .. } => {
                        DispatchError::from(Error::<T>::InvalidSpinValues)
                    }
                    _ => DispatchError::from(Error::<T>::InvalidTopology),
                })?;
                energies.push(energy);
            }

            let energy_valid_indices: Vec<usize> = energies
                .iter()
                .enumerate()
                .filter_map(|(index, &energy)| {
                    (energy < difficulty.max_energy_milli).then_some(index)
                })
                .collect();
            ensure!(
                !energy_valid_indices.is_empty(),
                Error::<T>::InsufficientEnergy
            );

            let energy_valid_solutions: Vec<&[i8]> = energy_valid_indices
                .iter()
                .map(|&index| decoded[index].as_slice())
                .collect();

            let target_count = energy_valid_solutions
                .len()
                .min(difficulty.min_solutions.max(1) as usize);
            let selected_indices = select_diverse(&energy_valid_solutions, target_count)
                .map_err(|_| DispatchError::from(Error::<T>::InvalidSpinValues))?;
            let selected_solutions: Vec<&[i8]> = selected_indices
                .iter()
                .map(|&index| energy_valid_solutions[index])
                .collect();

            let diversity_milli = calculate_diversity(&selected_solutions)
                .map_err(|_| DispatchError::from(Error::<T>::InvalidSpinValues))?;

            let best_energy_milli = selected_indices
                .iter()
                .map(|&index| energies[energy_valid_indices[index]])
                .min()
                .ok_or(Error::<T>::InsufficientEnergy)?;

            Ok(types::ProofValidation {
                best_energy_milli,
                diversity_milli,
                valid_solution_count: energy_valid_solutions.len() as u32,
            })
        }
    }
}
