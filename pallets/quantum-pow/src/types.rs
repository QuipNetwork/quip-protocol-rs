use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use quantum_validation::AllowedValueSpec;
use scale_info::TypeInfo;
use sp_core::{H256, U256};

/// A submitted proof-of-work payload.
///
/// The proof carries only the strictly-non-derivable inputs to validation:
///
/// - `topology_hash` identifies the registered puzzle definition. The
///   pallet looks up nodes, edges, and the allowed value sets from
///   `RegisteredTopologies`.
/// - `nonce` is the full 256-bit BLAKE3 digest of
///   `(parent_hash, miner, block_number, salt)`. The verifier re-derives it
///   for free; carrying it in the proof lets `submit_proof` reject mismatched
///   salts before doing any topology work.
/// - `salt` is the only freely-chosen miner input. Fixed at 32 bytes so the
///   PoW search space is statically known and identical across every call.
/// - `solutions` is a list of bit-packed spin vectors. Each entry is decoded
///   under the registered topology's `allowed_spin_values` spec, so the
///   wire-format width per spin matches the on-chain spec (e.g., 1 bit per
///   spin for the default binary Ising topology).
#[derive(
    Clone, Debug, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, TypeInfo, MaxEncodedLen,
)]
pub struct QuantumProof<PackedSolutions> {
    pub topology_hash: H256,
    pub nonce: U256,
    pub salt: [u8; 32],
    pub solutions: PackedSolutions,
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

/// On-chain record of a registered topology.
///
/// A `topology_hash` uniquely identifies the full puzzle definition: graph
/// structure plus the allowed h, j, and spin value sets. The hash is computed
/// by [`crate::topology::hash_topology`] over all five inputs so two
/// topologies that differ only in their allowed value sets get distinct hashes.
#[derive(
    Clone, Debug, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, TypeInfo, MaxEncodedLen,
)]
pub struct TopologyMeta<Nodes, Edges, AllowedValues, BlockNumber> {
    pub nodes: Nodes,
    pub edges: Edges,
    /// How the nonce-seeded RNG selects per-node h field values.
    pub allowed_h_values: AllowedValueSpec<AllowedValues>,
    /// How the nonce-seeded RNG selects per-edge j coupling values.
    /// Replaces the historical hardcoded `±MILLI_SCALE` magnitude.
    pub allowed_j_values: AllowedValueSpec<AllowedValues>,
    /// Which milli values a spin in a submitted solution may take. The
    /// variant also implies the bit-width used to encode each spin in the
    /// `QuantumProof::solutions` payload.
    pub allowed_spin_values: AllowedValueSpec<AllowedValues>,
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
pub struct MiningSnapshot<BlockNumber, Hash, Nodes, Edges, AllowedValues> {
    pub block_number: BlockNumber,
    pub parent_hash: Hash,
    pub difficulty: DifficultyConfig,
    pub topology_hash: H256,
    pub nodes: Nodes,
    pub edges: Edges,
    /// Same value sets as the registered topology; miners need these to know
    /// what h/j the verifier will reconstruct and what spin encoding to use.
    pub allowed_h_values: AllowedValueSpec<AllowedValues>,
    pub allowed_j_values: AllowedValueSpec<AllowedValues>,
    pub allowed_spin_values: AllowedValueSpec<AllowedValues>,
}

