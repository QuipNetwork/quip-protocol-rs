#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

pub mod apis;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
pub mod configs;

extern crate alloc;
use alloc::vec::Vec;
use quip_transaction_crypto::HybridTxSignature;
use sp_runtime::{
    generic, impl_opaque_keys,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiAddress,
};
#[cfg(feature = "std")]
use sp_version::NativeVersion;
use sp_version::RuntimeVersion;

pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_timestamp::Call as TimestampCall;
#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

pub mod genesis_config_presets;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;
    use sp_runtime::{
        generic,
        traits::{BlakeTwo256, Hash as HashT},
    };

    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;
    /// Opaque block hash type.
    pub type Hash = <BlakeTwo256 as HashT>::Output;
}

impl_opaque_keys! {
    pub struct SessionKeys {
        pub babe: Babe,
        pub grandpa: Grandpa,
    }
}

// To learn more about runtime versioning, see:
// https://docs.substrate.io/main-docs/build/upgrade#runtime-versioning
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: alloc::borrow::Cow::Borrowed("quip"),
    impl_name: alloc::borrow::Cow::Borrowed("quip"),
    authoring_version: 1,
    // The version of the runtime specification. A full node will not attempt to use its native
    //   runtime in substitute for the on-chain Wasm runtime unless all of `spec_name`,
    //   `spec_version`, and `authoring_version` are the same between Wasm and native.
    // Bumped to 101 (and `transaction_version` to 2) when the signed-extrinsic
    // wire format switched from `MultiSignature` to the hybrid envelope. Without
    // these bumps, peers/clients could treat the new format as the old one.
    // Bumped to 102 for v0.2.0: adds `pallet_faucet_ops` (idx 11) and
    // `pallet_session` (idx 12). New dispatchables, events, and storage entries
    // change the runtime metadata; the signed-extrinsic wire format is
    // unchanged, so `transaction_version` stays at 2.
    // Bumped to 103 for QUI-567: adds the canonical default plain Ising job
    // spec, root-gates `QuantumComputeMempool::register_job_spec`, and changes
    // that call's argument encoding, so `transaction_version` moves to 3.
    // Bumped to 104 for the topology-upgrade path: adds
    // `QuantumPow::set_default_topology` (call_index 5) and makes the
    // difficulty energy curve spec-aware (h/J magnitudes derived from the
    // default topology's allowed-value specs instead of hardcoded ternary-h /
    // binary-J). Existing call encodings are unchanged, so
    // `transaction_version` stays at 3.
    // Bumped to 105 for indexer-free quantum reads: adds monotonic qblock ids,
    // qblock/hardness runtime APIs, and the mempool open-order recovery index.
    // Existing call encodings are unchanged, so `transaction_version` stays at
    // 3.
    // Bumped to 106 for on-chain miner descriptors and qblock participation:
    // adds `MinerRegistry` (idx 13) with descriptor/participation calls,
    // events, and storage. Existing call encodings are unchanged, so
    // `transaction_version` stays at 3.
    // Bumped to 107 for the participants-per-qblock reverse index
    // (`ParticipantsByQBlock`, `ParticipantCountByQBlock`) and the
    // `MinerRegistryApi` runtime API. Call encodings are unchanged, so
    // `transaction_version` stays at 3.
    // Bumped to 108 for per-topology difficulty + the mineable-topology
    // whitelist: `QuantumPow.Difficulty` (global StorageValue) becomes
    // `Difficulties` (StorageMap keyed by topology hash), `MineableTopologies`
    // is added, `set_difficulty` gains a `topology_hash` argument, and
    // `add_mineable_topology`/`remove_mineable_topology` (call_index 6/7) are
    // added. `set_difficulty`'s argument encoding changed, so
    // `transaction_version` moves to 4. Pallet storage version 2 → 3 with a
    // carry-forward migration.
    // Bumped to 109 to restore on-chain `system_info`: `MinerRegistry` adds a
    // schema-v2 descriptor input (`NodeDescriptorInput::V2`) carrying an
    // optional typed hardware survey, plus a v1 → v2 storage migration that
    // drops existing descriptors (miners re-file on restart). The V1 call
    // variant keeps index 0 and encodes identically, so `transaction_version`
    // stays at 4. MinerRegistry pallet storage version 1 → 2.
    // Bumped to 110 to add the optional `runtime` block (node software identity:
    // python / quip_version / protocol_version / in_docker / docker_image) to
    // the MinerRegistry V2 descriptor. Additive trailing field on the V2 input;
    // V1 is unaffected and V2 was not yet deployed, so `transaction_version`
    // stays at 4 and no new migration is needed (the v1 → v2 migration already
    // wipes descriptors; pallet storage version stays 2).
    spec_version: 110,
    impl_version: 1,
    apis: apis::RUNTIME_API_VERSIONS,
    transaction_version: 4,
    system_version: 1,
};

mod block_times {
    /// This determines the average expected block time that we are targeting. Blocks will be
    /// produced at a minimum duration defined by `SLOT_DURATION`. `SLOT_DURATION` is picked up by
    /// `pallet_timestamp` which is in turn picked up by `pallet_babe`.
    ///
    /// Change this to adjust the block time.
    pub const MILLI_SECS_PER_BLOCK: u64 = 6000;

    // NOTE: Currently it is not possible to change the slot duration after the chain has started.
    // Attempting to do so will brick block production.
    pub const SLOT_DURATION: u64 = MILLI_SECS_PER_BLOCK;
}
pub use block_times::*;

// Time is measured by number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLI_SECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

pub const BLOCK_HASH_COUNT: BlockNumber = 2400;

// Unit = the base number of indivisible units for balances
pub const UNIT: Balance = 1_000_000_000_000;
pub const MILLI_UNIT: Balance = 1_000_000_000;
pub const MICRO_UNIT: Balance = 1_000_000;

/// Existential deposit.
pub const EXISTENTIAL_DEPOSIT: Balance = MILLI_UNIT;

/// The BABE epoch configuration at genesis.
pub const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
    sp_consensus_babe::BabeEpochConfiguration {
        c: (1, 4),
        allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryPlainSlots,
    };

/// The version information used to identify this runtime when compiled natively.
#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

/// Hybrid transaction signature used for runtime extrinsics.
pub type Signature = HybridTxSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// An index to a block.
pub type BlockNumber = u32;

/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;

/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// The `TransactionExtension` to the basic transaction logic.
pub type TxExtension = (
    frame_system::AuthorizeCall<Runtime>,
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
    frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
    frame_system::WeightReclaim<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, TxExtension>;

/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, TxExtension>;

/// Runtime storage migrations, run on upgrade before every pallet's
/// `on_runtime_upgrade`.
pub type Migrations = (pallet_miner_registry::migrations::v2::MigrateToV2<Runtime>,);

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
    Migrations,
>;

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;
    use quip_transaction_crypto::{account_id_from_public, HybridPair, HybridTxSignature};
    use sp_core::Pair as _;
    use sp_runtime::{traits::Checkable, transaction_validity::InvalidTransaction, BuildStorage};

    fn signed_test_extrinsic(
        sender: &HybridPair,
        address: Address,
        call: RuntimeCall,
        nonce: u32,
    ) -> UncheckedExtrinsic {
        let tx_ext: TxExtension = (
            frame_system::AuthorizeCall::<Runtime>::new(),
            frame_system::CheckNonZeroSender::<Runtime>::new(),
            frame_system::CheckSpecVersion::<Runtime>::new(),
            frame_system::CheckTxVersion::<Runtime>::new(),
            frame_system::CheckGenesis::<Runtime>::new(),
            frame_system::CheckEra::<Runtime>::from(generic::Era::Immortal),
            frame_system::CheckNonce::<Runtime>::from(nonce),
            frame_system::CheckWeight::<Runtime>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(0),
            frame_metadata_hash_extension::CheckMetadataHash::<Runtime>::new(false),
            frame_system::WeightReclaim::<Runtime>::new(),
        );

        let payload = SignedPayload::new(call.clone(), tx_ext.clone()).unwrap();
        let signature = payload.using_encoded(|encoded| HybridTxSignature::sign(sender, encoded));

        UncheckedExtrinsic::new_signed(call, address, signature, tx_ext)
    }

    #[test]
    fn hybrid_signed_extrinsic_checks_successfully() {
        let mut ext =
            sp_io::TestExternalities::new(RuntimeGenesisConfig::default().build_storage().unwrap());

        ext.execute_with(|| {
            System::set_block_number(1);

            let sender = HybridPair::from_string("//Alice", None).unwrap();
            let account_id = account_id_from_public(&sender.public());
            let xt = signed_test_extrinsic(
                &sender,
                account_id.clone().into(),
                SystemCall::remark { remark: vec![] }.into(),
                0,
            );

            let lookup = frame_system::ChainContext::<Runtime>::default();
            let checked =
                <UncheckedExtrinsic as Checkable<frame_system::ChainContext<Runtime>>>::check(
                    xt, &lookup,
                );

            assert!(checked.is_ok());
        });
    }

    /// Confirms the runtime's `CanonicalDefaultIsingSpecId` resolves to the
    /// same hash that the pallet's mock test pins. SDKs and downstream docs
    /// embed this hash; a mock-vs-runtime divergence would silently break
    /// every client that hardcodes it.
    #[test]
    fn default_ising_spec_id_matches_pinned_hash() {
        use frame_support::traits::Get as _;
        let id = <Runtime as pallet_quantum_compute_mempool::Config>::DefaultIsingSpecId::get();
        assert_eq!(
            format!("{id:?}"),
            "0x8f46f3a31321d1d093314fc769c42cbe7a83d71a0b69e6571a0f68e2a04067f0",
        );
    }

    #[test]
    fn hybrid_signed_extrinsic_rejects_wrong_account() {
        let mut ext =
            sp_io::TestExternalities::new(RuntimeGenesisConfig::default().build_storage().unwrap());

        ext.execute_with(|| {
            System::set_block_number(1);

            let sender = HybridPair::from_string("//Alice", None).unwrap();
            let wrong = HybridPair::from_string("//Bob", None).unwrap();
            let wrong_account = account_id_from_public(&wrong.public());
            let xt = signed_test_extrinsic(
                &sender,
                wrong_account.into(),
                SystemCall::remark { remark: vec![] }.into(),
                0,
            );

            let lookup = frame_system::ChainContext::<Runtime>::default();
            let checked =
                <UncheckedExtrinsic as Checkable<frame_system::ChainContext<Runtime>>>::check(
                    xt, &lookup,
                );

            assert_eq!(checked.unwrap_err(), InvalidTransaction::BadProof.into());
        });
    }
}

// Create the runtime by composing the FRAME pallets that were previously configured.
#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Runtime;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;

    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp;

    #[runtime::pallet_index(2)]
    pub type Babe = pallet_babe;

    #[runtime::pallet_index(3)]
    pub type Grandpa = pallet_grandpa;

    #[runtime::pallet_index(4)]
    pub type Balances = pallet_balances;

    #[runtime::pallet_index(5)]
    pub type TransactionPayment = pallet_transaction_payment;

    #[runtime::pallet_index(6)]
    pub type Sudo = pallet_sudo;

    // Include the custom logic from the pallet-template in the runtime.
    #[runtime::pallet_index(7)]
    pub type Template = pallet_template;

    #[runtime::pallet_index(8)]
    pub type Xqvm = pallet_xqvm;

    #[runtime::pallet_index(9)]
    pub type QuantumComputeMempool = pallet_quantum_compute_mempool;

    #[runtime::pallet_index(10)]
    pub type QuantumPow = pallet_quantum_pow;

    #[runtime::pallet_index(11)]
    pub type FaucetOps = pallet_faucet_ops;

    #[runtime::pallet_index(12)]
    pub type Session = pallet_session;

    #[runtime::pallet_index(13)]
    pub type MinerRegistry = pallet_miner_registry;
}
