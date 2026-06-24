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
	fn submit_proof() -> Weight;
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
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn set_difficulty() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn submit_proof() -> Weight {
		Weight::from_parts(60_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(5_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}

	fn add_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(1_u64))
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
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn set_difficulty() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn submit_proof() -> Weight {
		Weight::from_parts(60_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(5_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}

	fn add_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn remove_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(2_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
}
