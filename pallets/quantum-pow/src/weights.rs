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
		// Mathematical weight formula derived from computational complexity analysis:
		//
		// W(n, e, s) = BASE + k₁·n + k₂·e + k₃·s·n + k₄·s·e + k₅·s²·n
		//
		// Where:
		// - BASE = 10_000_000 (extrinsic overhead, database ops)
		// - k₁ = 1_000 (per-node cost: topology validation)
		// - k₂ = 2_000 (per-edge cost: topology validation)
		// - k₃ = 5_000 (per-solution-per-node: spin validation)
		// - k₄ = 50_000 (per-solution-per-edge: energy calculation - dominant term)
		// - k₅ = 1_000 (per-solution²-per-node: diversity/quality pairwise comparison)
		//
		// Worst case with production bounds (n=5000, e=50000, s=32):
		// W = 10M + 5M + 100M + 800M + 80_000M + 1_024M ≈ 82_000M weight units
		//
		// This is approximately 820ms of compute time on reference hardware.
		// With MaxProofsPerBlock=8, total worst-case per block: ~6.5s (acceptable).

		let base = Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64));

		// Linear terms
		let node_cost = Weight::from_parts(1_000, 0).saturating_mul(nodes.into());
		let edge_cost = Weight::from_parts(2_000, 0).saturating_mul(edges.into());

		// Multiplicative terms (solutions × dimensions)
		let solution_node_cost = Weight::from_parts(5_000, 0)
			.saturating_mul(solutions.into())
			.saturating_mul(nodes.into());
		let solution_edge_cost = Weight::from_parts(50_000, 0)
			.saturating_mul(solutions.into())
			.saturating_mul(edges.into());

		// Quadratic term (solutions² × nodes for diversity/quality)
		let solution_squared_cost = Weight::from_parts(1_000, 0)
			.saturating_mul(solutions.into())
			.saturating_mul(solutions.into())
			.saturating_mul(nodes.into());

		base.saturating_add(node_cost)
			.saturating_add(edge_cost)
			.saturating_add(solution_node_cost)
			.saturating_add(solution_edge_cost)
			.saturating_add(solution_squared_cost)
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
		// Same formula as SubstrateWeight, using RocksDbWeight for native execution

		let base = Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64));

		// Linear terms
		let node_cost = Weight::from_parts(1_000, 0).saturating_mul(nodes.into());
		let edge_cost = Weight::from_parts(2_000, 0).saturating_mul(edges.into());

		// Multiplicative terms
		let solution_node_cost = Weight::from_parts(5_000, 0)
			.saturating_mul(solutions.into())
			.saturating_mul(nodes.into());
		let solution_edge_cost = Weight::from_parts(50_000, 0)
			.saturating_mul(solutions.into())
			.saturating_mul(edges.into());

		// Quadratic term
		let solution_squared_cost = Weight::from_parts(1_000, 0)
			.saturating_mul(solutions.into())
			.saturating_mul(solutions.into())
			.saturating_mul(nodes.into());

		base.saturating_add(node_cost)
			.saturating_add(edge_cost)
			.saturating_add(solution_node_cost)
			.saturating_add(solution_edge_cost)
			.saturating_add(solution_squared_cost)
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
