#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use core::marker::PhantomData;
use frame_support::{
	traits::Get,
	weights::{constants::RocksDbWeight, Weight},
};

/// Weight functions for `pallet-faucet-ops`.
pub trait WeightInfo {
	/// Weight of the root-only `mint` dispatchable.
	fn mint() -> Weight;
}

/// Default substrate database-backed weights for the faucet ops pallet.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn mint() -> Weight {
		Weight::from_parts(15_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
}

/// Test and fallback weights for the faucet ops pallet.
impl WeightInfo for () {
	fn mint() -> Weight {
		Weight::from_parts(15_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
}
