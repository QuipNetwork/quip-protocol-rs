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
type FieldsOf<T> = frame_support::pallet_prelude::BoundedVec<i32, <T as Config>::MaxNodes>;
type SolutionsOf<T> = frame_support::pallet_prelude::BoundedVec<
    frame_support::pallet_prelude::BoundedVec<i8, <T as Config>::MaxNodes>,
    <T as Config>::MaxSolutions,
>;
type QuantumProofOf<T> = types::QuantumProof<NodesOf<T>, EdgesOf<T>, SolutionsOf<T>, FieldsOf<T>>;
type TopologyMetaOf<T> = types::TopologyMeta<NodesOf<T>, EdgesOf<T>, BlockNumberOf<T>>;
type MinerInfoOf<T> = types::MinerInfo<BalanceOf<T>, BlockNumberOf<T>>;
type ProofRecordOf<T> = types::ProofRecord<AccountIdOf<T>, BlockNumberOf<T>>;
type MiningSnapshotOf<T> = types::MiningSnapshot<
    BlockNumberOf<T>,
    <T as frame_system::Config>::Hash,
    NodesOf<T>,
    EdgesOf<T>,
>;

sp_api::decl_runtime_apis! {
    pub trait QuantumPowApi<BlockNumber, Hash, Nodes, Edges>
    where
        BlockNumber: codec::Codec,
        Hash: codec::Codec,
        Nodes: codec::Codec,
        Edges: codec::Codec,
    {
        fn mining_snapshot(topology_hash: Option<sp_core::H256>) -> Option<
            crate::types::MiningSnapshot<BlockNumber, Hash, Nodes, Edges>
        >;
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
        calculate_diversity, derive_nonce, energy_of_solution, expected_gse, generate_ising_model,
        select_diverse, validate_spins, validate_topology_consistency,
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
        #[pallet::constant]
        type EpochLength: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type MinerDeposit: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type BlockReward: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type MaxProofsPerBlock: Get<u32>;

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
            quality_milli: u32,
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
        QualityTooLow,
        ArithmeticOverflow,
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
            let mining_time_blocks = if previous_proof_block.is_zero() || n <= previous_proof_block
            {
                T::EpochLength::get().saturated_into::<u64>()
            } else {
                n.saturating_sub(previous_proof_block)
                    .saturated_into::<u64>()
            };

            let next = crate::difficulty::adjust_on_proof(
                Self::current_difficulty(n),
                mining_time_blocks,
                &(frame_system::Pallet::<T>::parent_hash(), &record.miner, n).encode(),
            );
            Difficulty::<T>::put(next);
            LastProofBlock::<T>::put(n);

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
        ) -> DispatchResult {
            ensure_root(origin)?;

            ensure!(
                nodes.len() >= T::MinNodes::get() as usize,
                Error::<T>::GraphTooSmall
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

            let topology_hash = crate::topology::hash_topology(&nodes, &edges);
            ensure!(
                !RegisteredTopologies::<T>::contains_key(topology_hash),
                Error::<T>::TopologyAlreadyRegistered
            );

            RegisteredTopologies::<T>::insert(
                topology_hash,
                TopologyMetaOf::<T> {
                    nodes: nodes.clone(),
                    edges: edges.clone(),
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
            ensure!(
                proof.nodes.len() >= T::MinNodes::get() as usize,
                Error::<T>::GraphTooSmall
            );
            ensure!(
                RegisteredTopologies::<T>::contains_key(proof.topology_hash),
                Error::<T>::TopologyNotRegistered
            );
            ensure!(
                crate::topology::verify_topology_hash(
                    proof.nodes.as_slice(),
                    proof.edges.as_slice(),
                    proof.topology_hash,
                ),
                Error::<T>::InvalidTopology
            );

            let block_number = frame_system::Pallet::<T>::block_number().saturated_into::<u32>();
            let expected_nonce = derive_nonce(
                &frame_system::Pallet::<T>::parent_hash().encode(),
                &who.encode(),
                block_number,
                proof.salt.as_slice(),
            );
            ensure!(proof.nonce == expected_nonce, Error::<T>::InvalidNonce);

            let (h, j) = generate_ising_model(
                proof.nonce,
                proof.nodes.as_slice(),
                proof.edges.as_slice(),
                proof.h_values.as_slice(),
            )
            .map_err(|_| Error::<T>::InvalidTopology)?;

            let current = Self::current_difficulty(frame_system::Pallet::<T>::block_number());
            let validation = Self::validate_proof(&proof, &h, &j, &current)?;

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
            ensure!(
                validation.quality_milli >= current.min_quality_milli,
                Error::<T>::QualityTooLow
            );

            let mut miner = Miners::<T>::get(&who).ok_or(Error::<T>::MinerNotRegistered)?;
            miner.proofs_submitted = miner.proofs_submitted.saturating_add(1);
            Miners::<T>::insert(&who, miner);

            let record = ProofRecordOf::<T> {
                miner: who.clone(),
                submitted_at: frame_system::Pallet::<T>::block_number(),
                energy_milli: validation.best_energy_milli,
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
                quality_milli: validation.quality_milli,
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

        pub fn mining_snapshot(
            block_number: BlockNumberFor<T>,
            parent_hash: <T as frame_system::Config>::Hash,
            topology_hash: Option<H256>,
        ) -> Option<MiningSnapshotOf<T>> {
            let (topology_hash, topology) = match topology_hash {
                Some(hash) => (hash, Self::topology_meta(hash)?),
                None => Self::default_topology_meta()?,
            };

            Some(types::MiningSnapshot {
                block_number,
                parent_hash,
                difficulty: Self::current_difficulty_for(block_number),
                topology_hash,
                nodes: topology.nodes,
                edges: topology.edges,
            })
        }

        fn current_difficulty(block_number: BlockNumberFor<T>) -> types::DifficultyConfig {
            let current = Difficulty::<T>::get();
            let last_proof_block = LastProofBlock::<T>::get();
            if last_proof_block.is_zero() || T::EpochLength::get().is_zero() {
                return current;
            }

            let elapsed_blocks = block_number
                .saturating_sub(last_proof_block)
                .saturated_into::<u32>();
            let steps = elapsed_blocks / T::EpochLength::get().saturated_into::<u32>();

            if steps == 0 {
                current
            } else {
                crate::difficulty::apply_decay(current, steps)
            }
        }

        fn validate_proof(
            proof: &QuantumProofOf<T>,
            h: &[i32],
            j: &[i32],
            difficulty: &types::DifficultyConfig,
        ) -> Result<types::ProofValidation, DispatchError> {
            let mut energies = Vec::with_capacity(proof.solutions.len());
            for solution in proof.solutions.iter() {
                ensure!(
                    validate_spins(solution.as_slice()),
                    Error::<T>::InvalidSpinValues
                );
                let energy = energy_of_solution(
                    solution.as_slice(),
                    h,
                    proof.edges.as_slice(),
                    j,
                    proof.nodes.as_slice(),
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
                .map(|&index| proof.solutions[index].as_slice())
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
                quality_milli: Self::quality_milli(
                    best_energy_milli,
                    proof.nodes.len() as u32,
                    proof.edges.len() as u32,
                ),
            })
        }

        fn quality_milli(energy_milli: i64, num_nodes: u32, num_edges: u32) -> u32 {
            let expected = expected_gse(num_nodes, num_edges);
            if expected == 0 {
                return 0;
            }

            let numerator = (energy_milli as i128).abs().saturating_mul(1000);
            let denominator = (expected as i128).abs();
            if denominator == 0 {
                return 0;
            }
            numerator.saturating_div(denominator).min(u32::MAX as i128) as u32
        }
    }
}
