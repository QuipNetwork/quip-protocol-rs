use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::H256;

#[derive(
    Clone, Debug, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, TypeInfo, MaxEncodedLen,
)]
pub struct QuantumProof<Nodes, Edges, Solutions, Fields> {
    /// Claimed topology identity for the submitted graph.
    ///
    /// The spec does not currently include this field; the pallet can always
    /// recompute it from `nodes` and `edges`. It is kept for now as a cheap
    /// lookup/comparison seam against the registered topology set during
    /// `submit_proof`, but can be dropped later if the extra redundancy is not
    /// worth the proof-size cost.
    pub topology_hash: H256,
    pub nonce: u64,
    pub salt: frame_support::pallet_prelude::BoundedVec<u8, frame_support::traits::ConstU32<32>>,
    pub nodes: Nodes,
    pub edges: Edges,
    pub solutions: Solutions,
    pub h_values: Fields,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Encode,
    Decode,
    DecodeWithMemTracking,
    Eq,
    PartialEq,
    TypeInfo,
    MaxEncodedLen,
)]
pub struct DifficultyConfig {
    pub min_solutions: u32,
    pub max_energy_milli: i64,
    pub min_diversity_milli: u32,
    pub min_quality_milli: u32,
}

#[derive(
    Clone, Debug, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, TypeInfo, MaxEncodedLen,
)]
pub struct TopologyMeta<Nodes, Edges, BlockNumber> {
    pub nodes: Nodes,
    pub edges: Edges,
    pub registered_at: BlockNumber,
}

#[derive(
    Clone, Debug, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, TypeInfo, MaxEncodedLen,
)]
pub struct MinerInfo<Balance, BlockNumber> {
    pub registered_at: BlockNumber,
    pub deposit: Balance,
    pub proofs_submitted: u32,
    /// Cached win count for cheap miner stats.
    ///
    /// This is not required for protocol correctness and can be dropped later
    /// in favor of deriving the same view from emitted reward/winner events.
    pub proofs_won: u32,
    pub rewards_earned: Balance,
}

#[derive(
    Clone, Debug, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, TypeInfo, MaxEncodedLen,
)]
pub struct ProofRecord<AccountId, BlockNumber> {
    pub miner: AccountId,
    pub submitted_at: BlockNumber,
    /// Best energy found within the submitted proof.
    ///
    /// The doc uses `energy_milli`; this field keeps that meaning while making
    /// the "best among submitted solutions" interpretation explicit in the
    /// record documentation rather than in the field name.
    pub energy_milli: i64,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Encode,
    Decode,
    DecodeWithMemTracking,
    Eq,
    PartialEq,
    TypeInfo,
    MaxEncodedLen,
)]
pub struct ProofValidation {
    pub best_energy_milli: i64,
    pub diversity_milli: u32,
    pub valid_solution_count: u32,
    pub quality_milli: u32,
}

#[derive(
    Clone, Debug, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, TypeInfo, MaxEncodedLen,
)]
pub struct MiningSnapshot<BlockNumber, Hash, Nodes, Edges> {
    pub block_number: BlockNumber,
    pub parent_hash: Hash,
    pub difficulty: DifficultyConfig,
    pub topology_hash: H256,
    pub nodes: Nodes,
    pub edges: Edges,
}
