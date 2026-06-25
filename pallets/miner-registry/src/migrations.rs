//! Storage migrations for `pallet-miner-registry`.

/// v1 → v2: the stored `NodeDescriptor` gained a trailing optional `system_info`
/// field, changing its SCALE layout so existing records can no longer be
/// decoded. Descriptors are self-healing — every miner re-files on its next
/// restart — so the migration drops all records rather than translating them.
///
/// Single-block drain: this assumes a small `NodeDescriptors` set (one
/// self-healing row per registered account), which holds on the current
/// testnet. The returned weight is accounting only and does not cap iteration,
/// so if the registry could ever hold tens of thousands of rows at upgrade
/// time this must become a multi-block `SteppedMigration`.
pub mod v2 {
    use crate::{Config, NodeDescriptors, Pallet};
    #[cfg(feature = "try-runtime")]
    use alloc::vec::Vec;
    use frame_support::{
        traits::{Get, ReservableCurrency, UncheckedOnRuntimeUpgrade},
        weights::Weight,
    };
    use sp_runtime::traits::Zero;

    /// The unversioned clear step. Wrapped by [`MigrateToV2`], which only runs
    /// it when the on-chain version is exactly 1.
    pub struct InnerMigrateToV2<T>(core::marker::PhantomData<T>);

    impl<T: Config> UncheckedOnRuntimeUpgrade for InnerMigrateToV2<T> {
        fn on_runtime_upgrade() -> Weight {
            let mut reads = 0u64;
            let mut writes = 0u64;
            // Return each descriptor's reserved deposit before dropping the
            // record. A bare `clear` would strand those reserves, and
            // `set_descriptor` would then reserve the full deposit again on
            // re-file — double-locking the balance.
            for (who, descriptor) in NodeDescriptors::<T>::drain() {
                // The reserved amount always equals the stored deposit, so the
                // full amount is returnable; a non-zero remainder signals
                // reserve/unreserve drift, as elsewhere in the pallet.
                let remaining = T::Currency::unreserve(&who, descriptor.deposit);
                debug_assert!(remaining.is_zero());
                reads = reads.saturating_add(1);
                // descriptor removal + balance unreserve.
                writes = writes.saturating_add(2);
            }
            T::DbWeight::get().reads_writes(reads, writes)
        }

        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
            Ok(Vec::new())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(_state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            frame_support::ensure!(
                NodeDescriptors::<T>::iter().next().is_none(),
                "miner-registry v2 migration left NodeDescriptors non-empty"
            );
            Ok(())
        }
    }

    /// Version-gated migration: runs [`InnerMigrateToV2`] only when the pallet's
    /// on-chain storage version is 1, then sets it to 2. Registered in the
    /// runtime's `Executive` migrations tuple.
    pub type MigrateToV2<T> = frame_support::migrations::VersionedMigration<
        1,
        2,
        InnerMigrateToV2<T>,
        Pallet<T>,
        <T as frame_system::Config>::DbWeight,
    >;
}
