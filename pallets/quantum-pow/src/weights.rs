#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::{constants::RocksDbWeight, Weight}};

pub trait WeightInfo {
	fn register_miner() -> Weight;
	fn deregister_miner() -> Weight;
	fn register_topology() -> Weight;
	fn set_default_topology() -> Weight;
	fn set_difficulty() -> Weight;
	fn set_topology_curve() -> Weight;
	/// Calculate weight for submit_proof based on proof dimensions.
	///
	/// # Arguments
	/// * `nodes` - Number of nodes in the topology
	/// * `edges` - Number of edges in the topology
	/// * `solutions` - Number of solutions submitted
	///
	/// # Weight Formula
	/// Weight(n, e, s) = BASE + k₁·n + k₂·e + k₃·s·n + k₄·s·e + k₅·s²·n
	///
	/// Components:
	/// - BASE: Fixed overhead for extrinsic dispatch
	/// - k₁·n: Node traversal cost (topology validation)
	/// - k₂·e: Edge traversal cost (topology validation)
	/// - k₃·s·n: Solution validation cost (spin validation)
	/// - k₄·s·e: Energy calculation cost (solutions × edges)
	/// - k₅·s²·n: Diversity/quality calculation cost (pairwise solution comparison)
	fn submit_proof(nodes: u32, edges: u32, solutions: u32) -> Weight;
	fn add_mineable_topology() -> Weight;
	fn remove_mineable_topology() -> Weight;
}

// TODO: Generate these weights from the pallet benchmark output now that the
// benchmark suite exists.
// TODO: Read through and verify the benchmark setup and coverage before
// replacing these placeholder weights with generated output.
// NOTE: the `submit_proof` benchmark takes no Linear<> complexity parameters,
// so it can neither validate the k₁..k₅ constants below nor regenerate the
// parameterized `submit_proof(nodes, edges, solutions)` signature. The
// constants are hand-derived upper bounds from complexity analysis of
// validate_proof / generate_ising_model; parameterize the benchmark over
// n/e/s before treating them as measured values.

// QIP-03 dimension-scaled submit_proof weight:
//
//   W(n, e, s) = BASE + k₁·n + k₂·e + k₃·s·n + k₄·s·e + k₅·s²·n
//
// - BASE = 10_000_000 — extrinsic overhead (charged DB weight is added on top)
// - k₁ = 1_000  per node: topology traversal / Ising h-term sampling
// - k₂ = 2_000  per edge: topology traversal / Ising J-term sampling
// - k₃ = 5_000  per solution·node: spin validation
// - k₄ = 50_000 per solution·edge: energy calculation (dominant term)
// - k₅ = 1_000  per solution²·node: pairwise diversity/quality comparison
//
// Worst case at production bounds (n=5_000, e=50_000, s=32):
// 10M + 5M + 100M + 800M + 80_000M + 5_120M ≈ 86_035M ref_time ≈ 86ms
// (1 ref_time unit = 1ps), plus ~625M of charged DB weight (9 reads +
// 4 writes at RocksDb costs). Eight proofs (MaxProofsPerBlock) ≈ 0.7s of
// the 2s block ref_time budget.
const SUBMIT_PROOF_BASE_REF_TIME: u64 = 10_000_000;
const SUBMIT_PROOF_K1_NODE: u64 = 1_000;
const SUBMIT_PROOF_K2_EDGE: u64 = 2_000;
const SUBMIT_PROOF_K3_SOLUTION_NODE: u64 = 5_000;
const SUBMIT_PROOF_K4_SOLUTION_EDGE: u64 = 50_000;
const SUBMIT_PROOF_K5_SOLUTION_SQ_NODE: u64 = 1_000;

// Distinct storage items touched on the submit_proof accept path. Reads:
// RegisteredTopologies (weight closure + body, overlay-cached), Miners,
// BlockProofCount, MineableTopologies, LastProofBlockHash, Difficulties,
// LastProofBlock, TopologyCurveC (energy curve), BlockBestProof.
// Writes (worst case): Miners, BlockBestProof, BlockProofCount; 4 kept as a
// conservative carry-over from the pre-QIP-03 flat weight.
const SUBMIT_PROOF_READS: u64 = 9;
const SUBMIT_PROOF_WRITES: u64 = 4;

/// Dimension-dependent portion of `submit_proof`'s weight (BASE plus every
/// k-term), shared by both `WeightInfo` impls so the formula cannot silently
/// diverge between the runtime (`SubstrateWeight`) and the mock/native
/// fallback (`()`).
fn submit_proof_dimension_weight(nodes: u32, edges: u32, solutions: u32) -> Weight {
	let node_cost = Weight::from_parts(SUBMIT_PROOF_K1_NODE, 0).saturating_mul(nodes.into());
	let edge_cost = Weight::from_parts(SUBMIT_PROOF_K2_EDGE, 0).saturating_mul(edges.into());
	let solution_node_cost = Weight::from_parts(SUBMIT_PROOF_K3_SOLUTION_NODE, 0)
		.saturating_mul(solutions.into())
		.saturating_mul(nodes.into());
	let solution_edge_cost = Weight::from_parts(SUBMIT_PROOF_K4_SOLUTION_EDGE, 0)
		.saturating_mul(solutions.into())
		.saturating_mul(edges.into());
	let solution_squared_cost = Weight::from_parts(SUBMIT_PROOF_K5_SOLUTION_SQ_NODE, 0)
		.saturating_mul(solutions.into())
		.saturating_mul(solutions.into())
		.saturating_mul(nodes.into());

	Weight::from_parts(SUBMIT_PROOF_BASE_REF_TIME, 0)
		.saturating_add(node_cost)
		.saturating_add(edge_cost)
		.saturating_add(solution_node_cost)
		.saturating_add(solution_edge_cost)
		.saturating_add(solution_squared_cost)
}

pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn register_miner() -> Weight {
		Weight::from_parts(15_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn deregister_miner() -> Weight {
		Weight::from_parts(15_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn register_topology() -> Weight {
		Weight::from_parts(35_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(2_u64))
	}

	fn set_default_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn set_difficulty() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn set_topology_curve() -> Weight {
		Weight::from_parts(12_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn submit_proof(nodes: u32, edges: u32, solutions: u32) -> Weight {
		// See submit_proof_dimension_weight for the QIP-03 formula and constants.
		submit_proof_dimension_weight(nodes, edges, solutions)
			.saturating_add(T::DbWeight::get().reads(SUBMIT_PROOF_READS))
			.saturating_add(T::DbWeight::get().writes(SUBMIT_PROOF_WRITES))
	}

	fn add_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn remove_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(2_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
}

impl WeightInfo for () {
	fn register_miner() -> Weight {
		Weight::from_parts(15_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn deregister_miner() -> Weight {
		Weight::from_parts(15_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn register_topology() -> Weight {
		Weight::from_parts(35_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
	}

	fn set_default_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn set_difficulty() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn set_topology_curve() -> Weight {
		Weight::from_parts(12_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn submit_proof(nodes: u32, edges: u32, solutions: u32) -> Weight {
		// Same formula as SubstrateWeight, with RocksDbWeight DB costs.
		submit_proof_dimension_weight(nodes, edges, solutions)
			.saturating_add(RocksDbWeight::get().reads(SUBMIT_PROOF_READS))
			.saturating_add(RocksDbWeight::get().writes(SUBMIT_PROOF_WRITES))
	}

	fn add_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn remove_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
}
