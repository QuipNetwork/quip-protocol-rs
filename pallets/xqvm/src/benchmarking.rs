//! Benchmarking setup for pallet-xqvm.

use super::*;

#[allow(unused)]
use crate::Pallet as Xqvm;
use aglais_xqvm_bytecode::Program;
use alloc::vec::Vec;
use frame_benchmarking::v2::*;
use frame_support::BoundedVec;
use frame_system::RawOrigin;
use sp_runtime::traits::Hash as _;

/// Build a valid XQVM program whose encoded byte length equals
/// `target_len`.
///
/// Layout: 2-byte jump-table header + (target_len - 3) NOPs + HALT.
/// Minimum `target_len` is 3 (header + HALT).
fn build_padded_program(target_len: u32) -> Vec<u8> {
    let len = target_len as usize;
    assert!(len >= 3, "minimum encoded program is 3 bytes");

    // 2-byte empty jump-table header
    let mut bytes = alloc::vec![0x00u8; len];
    // Last byte is HALT (opcode 0x0F); interior bytes stay 0x00 (NOP).
    bytes[len - 1] = 0x09; // HALT opcode

    // Sanity: must round-trip through Program::decode.
    debug_assert!(Program::decode(&bytes).is_ok());
    bytes
}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn store_program(
        s: Linear<3, { 65_536 }>,
    ) {
        let caller: T::AccountId = whitelisted_caller();
        let bytecode = build_padded_program(s);
        let bounded: BoundedVec<u8, T::MaxProgramSize> = bytecode
            .try_into()
            .expect("s <= MaxProgramSize");

        #[extrinsic_call]
        store_program(RawOrigin::Signed(caller), bounded);
    }

    #[benchmark]
    fn execute_base() {
        let caller: T::AccountId = whitelisted_caller();

        // Store a minimal HALT program.
        let bytecode = build_padded_program(3);
        let hash = T::Hashing::hash(&bytecode);
        let bounded: BoundedVec<u8, T::MaxProgramSize> = bytecode
            .try_into()
            .expect("3 <= MaxProgramSize");
        crate::Programs::<T>::insert(&hash, bounded);

        let calldata: BoundedVec<i64, T::MaxCallDataLen> =
            BoundedVec::default();

        #[extrinsic_call]
        execute(
            RawOrigin::Signed(caller),
            hash,
            calldata,
            0u32,
            1u64,
        );
    }

    impl_benchmark_test_suite!(
        Xqvm,
        crate::mock::new_test_ext(),
        crate::mock::Test
    );
}
