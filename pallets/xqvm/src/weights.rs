#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions for pallet_xqvm.
pub trait WeightInfo {
    fn store_program(s: u32) -> Weight;
    fn execute_base() -> Weight;
}

/// Placeholder weights (pre-benchmarking).
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    /// Store a program of `s` bytes.
    /// 1 read (existence check) + 2 writes (program + owner).
    fn store_program(s: u32) -> Weight {
        Weight::from_parts(20_000_000_u64.saturating_add(u64::from(s).saturating_mul(1_000)), 0)
            .saturating_add(T::DbWeight::get().reads(1_u64))
            .saturating_add(T::DbWeight::get().writes(2_u64))
    }

    /// Base cost of execute (excluding per-step weight).
    /// 1 read (load program) + decode + VM init.
    fn execute_base() -> Weight {
        Weight::from_parts(30_000_000, 0)
            .saturating_add(T::DbWeight::get().reads(1_u64))
    }
}

impl WeightInfo for () {
    fn store_program(s: u32) -> Weight {
        Weight::from_parts(20_000_000_u64.saturating_add(u64::from(s).saturating_mul(1_000)), 0)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
            .saturating_add(RocksDbWeight::get().writes(2_u64))
    }

    fn execute_base() -> Weight {
        Weight::from_parts(30_000_000, 0)
            .saturating_add(RocksDbWeight::get().reads(1_u64))
    }
}
