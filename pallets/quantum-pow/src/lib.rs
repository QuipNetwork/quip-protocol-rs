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
type WinnerStreakOf<T> = types::WinnerStreak<AccountIdOf<T>>;
type MiningSnapshotOf<T> = types::MiningSnapshot<NodesOf<T>, EdgesOf<T>, AllowedValueSetOf<T>>;
type QBlockOf<T> = types::QBlock<AccountIdOf<T>, BalanceOf<T>, BlockNumberOf<T>>;
type QBlockWithNonceOf<T> = types::QBlockWithNonce<AccountIdOf<T>, BalanceOf<T>, BlockNumberOf<T>>;

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
            crate::types::QBlockWithNonce<AccountId, Balance, BlockNumber>
        >;

        /// Latest assigned monotonic qblock id, or `None` before the first
        /// qblock. qblock ids are 1-based ordinals and are distinct from
        /// substrate block numbers.
        fn latest_qblock_id() -> Option<u64>;

        /// qblock id assigned to `block_number`, or `None` if that substrate
        /// block was not a qblock.
        fn qblock_id_by_block(block_number: BlockNumber) -> Option<u64>;

        /// Winning qblock for a monotonic qblock id, augmented with its
        /// derived nonce.
        fn qblock_by_id(qblock_id: u64) -> Option<
            crate::types::QBlockWithNonce<AccountId, Balance, BlockNumber>
        >;

        /// Winning qblock for a substrate block number, augmented with its
        /// derived nonce. This is the qblock-named alias for
        /// `winning_solution`.
        fn qblock_by_block(block_number: BlockNumber) -> Option<
            crate::types::QBlockWithNonce<AccountId, Balance, BlockNumber>
        >;

        /// Live difficulty threshold a miner has to clear *right now*.
        ///
        /// Differs from `api.query.quantumPow.difficulty()` (the raw storage
        /// value): that one is the post-last-adjust baseline and does *not*
        /// reflect decay applied since the last winning proof. This API
        /// returns the decayed value, matching what `submit_proof` validation
        /// will actually require.
        fn current_difficulty() -> crate::types::DifficultyConfig;

        /// Client-facing alias for the live difficulty threshold.
        fn current_hardness() -> crate::types::DifficultyConfig;
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use codec::Encode;
    use frame_support::{
        pallet_prelude::*,
        traits::{ReservableCurrency, StorageVersion},
    };
    use frame_system::pallet_prelude::*;
    use quantum_validation::{
        calculate_diversity, derive_nonce, energy_of_solution, generate_ising_model,
        packed::{packed_solution_byte_len, unpack_solution},
        select_diverse, validate_spins, validate_topology_consistency, AllowedValueSpec,
        MilliValue,
    };
    use sp_core::H256;
    use sp_runtime::traits::{One, SaturatedConversion, Saturating, Zero};

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
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

        /// Consecutive qblocks won by the same account at or above this
        /// threshold mark the winner as dominant: slow qblocks (at or past
        /// the fast-proof cutoff) then ease difficulty instead of hardening
        /// it. Fast qblocks always harden regardless of dominance (v0.1
        /// policy). Setting this to `0` disables dominant-winner easing
        /// entirely.
        #[pallet::constant]
        type ConsecutiveWinnerEasingThreshold: Get<u32>;

        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    pub type RegisteredTopologies<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, TopologyMetaOf<T>>;

    #[pallet::storage]
    pub type DefaultTopology<T: Config> = StorageValue<_, H256>;

    /// Per-topology difficulty baseline (post-last-adjust; decay is applied
    /// on read by `current_difficulty_for`). Keyed by `topology_hash` so a
    /// `DefaultTopology` switch is clean and one topology's winners can never
    /// pin another's difficulty. Unset entries read back as
    /// `DifficultyConfig::default()`.
    #[pallet::storage]
    pub type Difficulties<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, types::DifficultyConfig>;

    #[pallet::storage]
    pub type Miners<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, MinerInfoOf<T>>;

    #[pallet::storage]
    pub type BlockBestProof<T: Config> = StorageValue<_, ProofRecordOf<T>>;

    #[pallet::storage]
    pub type WinnerStreak<T: Config> = StorageValue<_, WinnerStreakOf<T>, OptionQuery>;

    #[pallet::storage]
    /// Block number of the last finalized winning proof.
    ///
    /// Difficulty adjustment and decay are block-based, not timestamp-based.
    /// We intentionally use elapsed blocks as the protocol time unit so the
    /// difficulty path stays coherent with `EpochLength` and does not depend on
    /// mixing wall-clock moments with block numbers.
    pub type LastProofBlock<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    /// Hash of the block recorded in `LastProofBlock`. Captured lazily in
    /// `on_initialize` of the *next* block (when `parent_hash()` first equals
    /// `block_hash(LastProofBlock)`) and held in storage thereafter. Reading
    /// from this storage value — instead of calling
    /// `frame_system::block_hash(LastProofBlock)` directly — keeps the nonce
    /// seed stable across the entire mining round, even if no proof clears
    /// difficulty for longer than `BlockHashCount` (~25 minutes at 6s
    /// blocks). Without this cache the seed would silently flip to the
    /// zero hash once the ring buffer aged past the proof block.
    #[pallet::storage]
    pub type LastProofBlockHash<T: Config> = StorageValue<_, H256, ValueQuery>;

    #[pallet::storage]
    pub type BlockProofCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// Persisted record of each qblock (PoW-won block), written in
    /// `on_finalize` alongside the `BlockWinner` event.
    ///
    /// Consumers derive the winning nonce by hashing
    /// `(last_proof_block_hash, miner, salt)` with BLAKE3, or call the
    /// `QuantumPowApi::winning_solution` runtime API which does it
    /// server-side. `last_proof_block_hash` for each entry is the value the
    /// round used at submission time, persisted in the `QBlock` itself so
    /// re-derivation needs no chain-state lookup.
    #[pallet::storage]
    pub type QBlocks<T: Config> = StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, QBlockOf<T>>;

    /// Number of accepted qblocks. Because qblock ids are 1-based, this is
    /// also the latest assigned qblock id when non-zero.
    #[pallet::storage]
    pub type QBlockCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Monotonic qblock id to substrate block number index.
    #[pallet::storage]
    pub type QBlockBlockById<T: Config> = StorageMap<_, Blake2_128Concat, u64, BlockNumberFor<T>>;

    /// Substrate block number to monotonic qblock id index.
    #[pallet::storage]
    pub type QBlockIdByBlock<T: Config> = StorageMap<_, Blake2_128Concat, BlockNumberFor<T>, u64>;

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
        /// `DefaultTopology` was repointed by root. The difficulty energy
        /// curve is calibrated against this topology from now on.
        DefaultTopologySet {
            topology_hash: H256,
        },
        ProofAccepted {
            miner: T::AccountId,
            energy_milli: i64,
            diversity_milli: u32,
            valid_solution_count: u32,
        },
        BlockWinner {
            qblock_id: u64,
            block_number: BlockNumberFor<T>,
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
        /// The topology's allowed_spin_values spec and node count combine to
        /// require more packed-solution bytes than the runtime's MaxNodes
        /// bound permits. Most often hit when a ContinuousRange spin spec
        /// (32 bits per spin) is paired with more than `MaxNodes / 4` nodes,
        /// which would leave the topology accepted but unmineable.
        PackedSolutionTooLarge,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn on_initialize(n: BlockNumberFor<T>) -> Weight {
            BlockProofCount::<T>::put(0);

            // Capture `block_hash(LastProofBlock)` permanently as soon as it
            // becomes available. The only place this hash is freshly known
            // without depending on `frame_system::block_hash` (which ages
            // out after `BlockHashCount` blocks) is `parent_hash()` of the
            // very next block after the winning proof was finalized.
            //
            // Trigger conditions:
            //   - `n > 0` and `LastProofBlock == n - 1`: this is the block
            //     right after a fresh winning proof; `parent_hash()` is
            //     exactly `block_hash(LastProofBlock)`.
            //   - On the first block of any chain we also seed the cache
            //     with the genesis hash so pre-proof nonce derivation
            //     remains stable.
            let last_proof_block = LastProofBlock::<T>::get();
            let one: BlockNumberFor<T> = One::one();
            if n == one || (n > one && last_proof_block.saturating_add(one) == n) {
                let parent = frame_system::Pallet::<T>::parent_hash();
                LastProofBlockHash::<T>::put(H256::from(Self::hash_to_bytes_32(parent)));
            }

            <T as Config>::WeightInfo::register_miner()
        }

        /// Network upgrade (v0.2 → v2): drop all PoW state instead of carrying
        /// it forward.
        ///
        /// The v0.2 storage layout (legacy `WinningSolutions` prefix, old
        /// `QBlock`/miner encodings, difficulty, topologies) is intentionally
        /// not migrated. Rather than translate stale encodings we clear the
        /// entire pallet prefix — which also reaps the renamed `WinningSolutions`
        /// entries that the current `QBlocks` type no longer references — and
        /// let the chain repopulate from mining. `Difficulty` reads back at its
        /// `Default`, identical to a fresh genesis.
        ///
        /// The version guard makes this run exactly once: v0.2 chains sit at
        /// version 1, fresh chains are seeded at version 2 by genesis and skip.
        fn on_runtime_upgrade() -> Weight {
            use frame_support::{traits::PalletInfoAccess, StorageHasher};

            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain >= STORAGE_VERSION {
                return T::DbWeight::get().reads(1);
            }

            let pallet_prefix =
                frame_support::Twox128::hash(<Pallet<T> as PalletInfoAccess>::name().as_bytes());
            let cleared =
                frame_support::storage::unhashed::clear_prefix(&pallet_prefix, None, None).backend;

            STORAGE_VERSION.put::<Pallet<T>>();

            // 1 read (version) + 1 write per cleared key + 1 write (version).
            T::DbWeight::get().reads_writes(1, u64::from(cleared).saturating_add(1))
        }

        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
            Ok(Vec::new())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(_state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            ensure!(
                Pallet::<T>::on_chain_storage_version() >= STORAGE_VERSION,
                "storage version must be bumped by the network upgrade"
            );
            ensure!(
                QBlockCount::<T>::get() == 0 && Miners::<T>::iter().next().is_none(),
                "network upgrade must leave PoW state wiped"
            );
            Ok(())
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
            // `derive_nonce` input. Read from the `LastProofBlockHash` cache
            // (populated lazily in `on_initialize`) rather than calling
            // `frame_system::block_hash(previous_proof_block)` directly: if
            // the round ran longer than `BlockHashCount`, the live lookup
            // would return the zero hash instead of the value miners
            // actually used to derive their nonce.
            let last_proof_block_hash = LastProofBlockHash::<T>::get();

            let mining_time_blocks = if previous_proof_block.is_zero() || n <= previous_proof_block
            {
                T::EpochLength::get().saturated_into::<u64>()
            } else {
                n.saturating_sub(previous_proof_block)
                    .saturated_into::<u64>()
            };

            let topology_hash = record.topology_hash;
            // Snapshot the live (decay-applied) threshold this proof had to
            // clear before adjustment rewrites it.
            let active = Self::current_difficulty_for(topology_hash, n);
            let winner_streak = Self::update_winner_streak(&record.miner);
            let dominant_winner = Self::is_dominant_streak(&winner_streak);
            // Adjust ONLY the winning topology's difficulty, using ITS curve.
            let next = match Self::energy_curve_for(topology_hash) {
                Some(curve) => crate::difficulty::adjust_on_proof_with_dominance(
                    active,
                    mining_time_blocks,
                    curve,
                    &(frame_system::Pallet::<T>::parent_hash(), &record.miner, n).encode(),
                    dominant_winner,
                ),
                None => {
                    frame_support::defensive!(
                        "energy curve missing during on_finalize difficulty adjustment"
                    );
                    active
                }
            };
            Difficulties::<T>::insert(topology_hash, next);
            LastProofBlock::<T>::put(n);
            let qblock_id = Self::next_qblock_id();

            QBlocks::<T>::insert(
                n,
                types::QBlock {
                    miner: record.miner.clone(),
                    salt: record.salt,
                    energy_milli: record.energy_milli,
                    reward,
                    submitted_at: record.submitted_at,
                    difficulty: active,
                    last_proof_block_hash,
                },
            );
            QBlockBlockById::<T>::insert(qblock_id, n);
            QBlockIdByBlock::<T>::insert(n, qblock_id);

            Self::deposit_event(Event::DifficultyUpdated { difficulty: next });
            Self::deposit_event(Event::BlockWinner {
                qblock_id,
                block_number: n,
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

            // Canonicalize Set ordering so the stored representation matches
            // the order-independent topology hash. Without this, registering
            // [a, b, c] and [b, a, c] in different orders hash to the same
            // value but produce different deterministic puzzles from the same
            // nonce.
            let allowed_h_values = Self::canonicalize_spec(allowed_h_values)?;
            let allowed_j_values = Self::canonicalize_spec(allowed_j_values)?;
            let allowed_spin_values = Self::canonicalize_spec(allowed_spin_values)?;

            // A submitted solution is a `BoundedVec<u8, MaxNodes>` per the
            // PackedSpinBytesOf type alias. Indexed spin specs (Set,
            // IntegerRange) pack <= 8 bits per spin so num_nodes spins always
            // fit, but ContinuousRange uses 32 bits per spin (4 bytes), making
            // any topology with num_nodes > MaxNodes/4 unmineable. Reject at
            // registration so the operator gets a clear error instead of
            // silently shipping a dead topology.
            let packed_bytes =
                packed_solution_byte_len(nodes.len(), &allowed_spin_values.as_slice())
                    .map_err(|_| Error::<T>::InvalidTopology)?;
            ensure!(
                packed_bytes <= T::MaxNodes::get() as usize,
                Error::<T>::PackedSolutionTooLarge
            );

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

        /// Repoint `DefaultTopology` to an already-registered topology.
        ///
        /// `register_topology` only seeds `DefaultTopology` on the very
        /// first registration; this call is the operator path for upgrading
        /// a live chain to a new topology (e.g. tracking a QPU's working
        /// graph across calibrations). The difficulty energy curve follows
        /// the default topology, so operators should re-baseline
        /// `set_difficulty` after repointing when the curves differ
        /// materially.
        #[pallet::call_index(5)]
        #[pallet::weight(<T as Config>::WeightInfo::set_default_topology())]
        pub fn set_default_topology(origin: OriginFor<T>, topology_hash: H256) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                RegisteredTopologies::<T>::contains_key(topology_hash),
                Error::<T>::TopologyNotRegistered
            );
            DefaultTopology::<T>::put(topology_hash);
            Self::deposit_event(Event::DefaultTopologySet { topology_hash });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::set_difficulty())]
        pub fn set_difficulty(
            origin: OriginFor<T>,
            difficulty: types::DifficultyConfig,
        ) -> DispatchResult {
            ensure_root(origin)?;
            if let Some(hash) = DefaultTopology::<T>::get() {
                Difficulties::<T>::insert(hash, difficulty);
            }
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
            // race (the original bug). Read from the `LastProofBlockHash`
            // cache rather than `frame_system::block_hash`, which falls off
            // the ring buffer after `BlockHashCount` (~25 min) and would
            // otherwise silently flip the nonce seed to zero for any round
            // that runs longer than that window.
            let last_proof_block_hash_bytes = LastProofBlockHash::<T>::get().0;
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

            let current = Self::current_difficulty_for(
                proof.topology_hash,
                frame_system::Pallet::<T>::block_number(),
            );
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
                topology_hash: proof.topology_hash,
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

        /// Active (decay-applied) difficulty a miner must clear for
        /// `topology_hash` at `block_number`. Reads the per-topology baseline
        /// (`Difficulties[hash]`, defaulting when unset) and applies global
        /// block-based decay since the last winning proof.
        pub fn current_difficulty_for(
            topology_hash: H256,
            block_number: BlockNumberFor<T>,
        ) -> types::DifficultyConfig {
            crate::difficulty::current_difficulty(
                block_number.saturated_into::<u32>(),
                Difficulties::<T>::get(topology_hash).unwrap_or_default(),
                LastProofBlock::<T>::get().saturated_into::<u32>(),
                T::EpochLength::get().saturated_into::<u32>(),
                Self::energy_curve_for(topology_hash),
            )
        }

        pub fn latest_qblock_id() -> Option<u64> {
            let count = QBlockCount::<T>::get();
            (count > 0).then_some(count)
        }

        pub fn qblock_id_by_block(block_number: BlockNumberFor<T>) -> Option<u64> {
            QBlockIdByBlock::<T>::get(block_number)
        }

        pub fn qblock_block_by_id(qblock_id: u64) -> Option<BlockNumberFor<T>> {
            QBlockBlockById::<T>::get(qblock_id)
        }

        pub fn mining_snapshot(topology_hash: Option<H256>) -> Option<MiningSnapshotOf<T>> {
            let (topology_hash, topology) = match topology_hash {
                Some(hash) => (hash, Self::topology_meta(hash)?),
                None => Self::default_topology_meta()?,
            };

            // Difficulty still tracks the current block (decay is block-based)
            // even though the nonce input no longer is. Read the nonce seed
            // from the `LastProofBlockHash` cache so the snapshot remains
            // stable across the full mining round, even after the underlying
            // proof block ages out of `frame_system::block_hash`.
            let block_number = frame_system::Pallet::<T>::block_number();
            let last_proof_block_hash = LastProofBlockHash::<T>::get();

            Some(types::MiningSnapshot {
                last_proof_block_hash,
                difficulty: Self::current_difficulty_for(topology_hash, block_number),
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

        /// Look up a persisted qblock and re-derive its nonce.
        ///
        /// Returns `None` if the block had no accepted proof (e.g. genesis
        /// where no `submit_proof` ever ran). Re-derivation reads the
        /// `last_proof_block_hash` stored alongside the qblock, so this stays
        /// correct even when `block_number` is older than `BlockHashCount`
        /// (no `frame_system::block_hash` lookup is involved).
        pub fn qblock_with_nonce(block_number: BlockNumberFor<T>) -> Option<QBlockWithNonceOf<T>> {
            let solution = QBlocks::<T>::get(block_number)?;
            let last_proof_block_hash_bytes = solution.last_proof_block_hash.0;
            let miner_bytes = Self::account_to_bytes(&solution.miner);
            let nonce = derive_nonce(&last_proof_block_hash_bytes, &miner_bytes, &solution.salt);
            Some(types::QBlockWithNonce { solution, nonce })
        }

        pub fn qblock_with_nonce_by_id(qblock_id: u64) -> Option<QBlockWithNonceOf<T>> {
            let block_number = Self::qblock_block_by_id(qblock_id)?;
            Self::qblock_with_nonce(block_number)
        }

        fn next_qblock_id() -> u64 {
            QBlockCount::<T>::mutate(|count| {
                *count = count.saturating_add(1);
                *count
            })
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

        /// Sort the inner Set values so the stored spec matches the
        /// order-independent layout used by `canonical_bytes` / `hash_topology`.
        /// `IntegerRange` and `ContinuousRange` carry no order to canonicalize.
        fn canonicalize_spec(
            spec: AllowedValueSpec<AllowedValueSetOf<T>>,
        ) -> Result<AllowedValueSpec<AllowedValueSetOf<T>>, DispatchError> {
            match spec {
                AllowedValueSpec::Set(values) => {
                    let mut inner: alloc::vec::Vec<MilliValue> = values.into_inner();
                    inner.sort_unstable();
                    let sorted = AllowedValueSetOf::<T>::try_from(inner)
                        .map_err(|_| Error::<T>::InvalidTopology)?;
                    Ok(AllowedValueSpec::Set(sorted))
                }
                other => Ok(other),
            }
        }

        /// Build the difficulty energy curve for a specific topology.
        ///
        /// Historically this was hard-pinned to `DefaultTopology` so a miner
        /// could not shift difficulty by choosing a different *registered*
        /// topology to mine against (the old anti-gaming invariant). That
        /// guard is now provided by the **mineable-topology whitelist**: only
        /// whitelisted topologies can be mined, and each owns its own
        /// root-set `Difficulties` entry. Deriving the curve from the proof's
        /// own topology is therefore safe — there is no shared difficulty to
        /// pin.
        ///
        /// Returns `None` when the topology is not registered (defensive: a
        /// proof would not validate, and `set_difficulty` requires
        /// registration).
        fn energy_curve_for(topology_hash: H256) -> Option<crate::difficulty::EnergyCurve> {
            let topology = RegisteredTopologies::<T>::get(topology_hash)?;
            crate::difficulty::EnergyCurve::new(
                topology.nodes.len() as u32,
                topology.edges.len() as u32,
                crate::difficulty::CurveC {
                    easy_milli: T::CurveCEasyMilli::get(),
                    knee_milli: T::CurveCKneeMilli::get(),
                    hard_milli: T::CurveCHardMilli::get(),
                },
                &topology.allowed_h_values.as_slice(),
                &topology.allowed_j_values.as_slice(),
            )
            .ok()
        }

        fn update_winner_streak(miner: &T::AccountId) -> WinnerStreakOf<T> {
            let next = match WinnerStreak::<T>::get() {
                Some(mut streak) if streak.miner == *miner => {
                    streak.count = streak.count.saturating_add(1);
                    streak
                }
                _ => WinnerStreakOf::<T> {
                    miner: miner.clone(),
                    count: 1,
                },
            };
            WinnerStreak::<T>::put(&next);
            next
        }

        /// A winner is dominant when the same account has won at least
        /// `ConsecutiveWinnerEasingThreshold` consecutive qblocks. Dominance
        /// flips slow-qblock adjustments to easing (fast qblocks always
        /// harden — see `difficulty::adjust_on_proof_with_dominance`).
        fn is_dominant_streak(streak: &WinnerStreakOf<T>) -> bool {
            let threshold = T::ConsecutiveWinnerEasingThreshold::get();
            threshold > 0 && streak.count >= threshold
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
