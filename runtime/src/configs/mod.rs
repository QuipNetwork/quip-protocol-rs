// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org>

// Substrate and Polkadot dependencies
use frame_support::{
    derive_impl, parameter_types,
    traits::{ConstU128, ConstU32, ConstU64, ConstU8, VariantCountOf},
    weights::{
        constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
        IdentityFee, Weight,
    },
};
use frame_system::limits::{BlockLength, BlockWeights};
use pallet_transaction_payment::{ConstFeeMultiplier, FungibleAdapter, Multiplier};
use sp_runtime::{
    traits::{ConvertInto, One, OpaqueKeys},
    Perbill,
};
use sp_version::RuntimeVersion;

use pallet_xqvm::WeightInfo as _;

// Local module imports
use super::{
    AccountId, Babe, Balance, Balances, Block, BlockNumber, Hash, Nonce, PalletInfo, Runtime,
    RuntimeCall, RuntimeEvent, RuntimeFreezeReason, RuntimeHoldReason, RuntimeOrigin, RuntimeTask,
    SessionKeys, System, EXISTENTIAL_DEPOSIT, SLOT_DURATION, UNIT, VERSION,
};

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
    pub const BlockHashCount: BlockNumber = 2400;
    pub const Version: RuntimeVersion = VERSION;

    /// We allow for 2 seconds of compute with a 6 second average block time.
    pub RuntimeBlockWeights: BlockWeights = BlockWeights::with_sensible_defaults(
        Weight::from_parts(2u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
        NORMAL_DISPATCH_RATIO,
    );
    // Replacement for the now-deprecated `BlockLength::max_with_normal_ratio` —
    // reconstruct the same shape via the builder: max = 5 MiB for all dispatch
    // classes, but the Normal class is scaled down by `NORMAL_DISPATCH_RATIO`.
    pub RuntimeBlockLength: BlockLength = BlockLength::builder()
        .max_length(5 * 1024 * 1024)
        .modify_max_length_for_class(frame_support::dispatch::DispatchClass::Normal, |len| {
            *len = NORMAL_DISPATCH_RATIO * (5u32 * 1024 * 1024);
        })
        .build();
    pub const SS58Prefix: u8 = 42;
}

/// All migrations of the runtime, aside from the ones declared in the pallets.
///
/// This can be a tuple of types, each implementing `OnRuntimeUpgrade`.
#[allow(unused_parens)]
type SingleBlockMigrations = ();

/// The default types are being injected by [`derive_impl`](`frame_support::derive_impl`) from
/// [`SoloChainDefaultConfig`](`struct@frame_system::config_preludes::SolochainDefaultConfig`),
/// but overridden as needed.
#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
    /// The block type for the runtime.
    type Block = Block;
    /// Block & extrinsics weights: base values and limits.
    type BlockWeights = RuntimeBlockWeights;
    /// The maximum length of a block (in bytes).
    type BlockLength = RuntimeBlockLength;
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The type for storing how many extrinsics an account has signed.
    type Nonce = Nonce;
    /// The type for hashing blocks and tries.
    type Hash = Hash;
    /// Maximum number of block number to block hash mappings to keep (oldest pruned first).
    type BlockHashCount = BlockHashCount;
    /// The weight of database operations that the runtime can invoke.
    type DbWeight = RocksDbWeight;
    /// Version of the runtime.
    type Version = Version;
    /// The data to be stored in an account.
    type AccountData = pallet_balances::AccountData<Balance>;
    /// This is used as an identifier of the chain. 42 is the generic substrate prefix.
    type SS58Prefix = SS58Prefix;
    type MaxConsumers = frame_support::traits::ConstU32<16>;
    type SingleBlockMigrations = SingleBlockMigrations;
}

parameter_types! {
    // BABE epochs are defined in slots. Keep them short enough for local development.
    pub const EpochDuration: u64 = 10 * super::MINUTES as u64;
    pub const ExpectedBlockTime: u64 = SLOT_DURATION;
}

impl pallet_babe::Config for Runtime {
    type EpochDuration = EpochDuration;
    type ExpectedBlockTime = ExpectedBlockTime;
    type EpochChangeTrigger = pallet_babe::SameAuthoritiesForever;
    type DisabledValidators = ();
    type WeightInfo = ();
    type MaxAuthorities = ConstU32<32>;
    type MaxNominators = ConstU32<0>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

impl pallet_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;

    type WeightInfo = ();
    type MaxAuthorities = ConstU32<32>;
    type MaxNominators = ConstU32<0>;
    type MaxSetIdSessionEntries = ConstU64<0>;

    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

/// Session keys (BABE + GRANDPA) are registered at genesis and never rotated by
/// the runtime — `SessionManager = ()` returns `None` on `new_session`, so the
/// pallet retains the genesis validator set forever. The session API exists so
/// that explorers and the polkadot.js client can surface
/// `api.query.session.validators` and so that hybrid session keys can be
/// rotated via the standard `author_rotateKeys` RPC flow once that work lands.
impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = <Self as frame_system::Config>::AccountId;
    type ValidatorIdOf = ConvertInto;
    type ShouldEndSession = Babe;
    type NextSessionRotation = Babe;
    type SessionManager = ();
    type SessionHandler = <SessionKeys as OpaqueKeys>::KeyTypeIdProviders;
    type Keys = SessionKeys;
    type DisablingStrategy = ();
    type WeightInfo = pallet_session::weights::SubstrateWeight<Runtime>;
    type Currency = Balances;
    type KeyDeposit = ();
}

impl pallet_timestamp::Config for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = u64;
    type OnTimestampSet = Babe;
    type MinimumPeriod = ConstU64<{ SLOT_DURATION / 2 }>;
    type WeightInfo = ();
}

impl pallet_balances::Config for Runtime {
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ConstU128<EXISTENTIAL_DEPOSIT>;
    type AccountStore = System;
    type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
    type FreezeIdentifier = RuntimeFreezeReason;
    type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type DoneSlashHandler = ();
}

parameter_types! {
    pub FeeMultiplier: Multiplier = Multiplier::one();
}

impl pallet_transaction_payment::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type OnChargeTransaction = FungibleAdapter<Balances, ()>;
    type OperationalFeeMultiplier = ConstU8<5>;
    type WeightToFee = IdentityFee<Balance>;
    type LengthToFee = IdentityFee<Balance>;
    type FeeMultiplierUpdate = ConstFeeMultiplier<FeeMultiplier>;
    type WeightInfo = pallet_transaction_payment::weights::SubstrateWeight<Runtime>;
}

impl pallet_sudo::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = pallet_sudo::weights::SubstrateWeight<Runtime>;
}

/// Configure the pallet-template in pallets/template.
impl pallet_template::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_template::weights::SubstrateWeight<Runtime>;
}

impl pallet_faucet_ops::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type WeightInfo = pallet_faucet_ops::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const MaxProgramSize: u32 = 65_536;
    pub const MaxCallDataLen: u32 = 256;
    pub const MaxOutputSlots: u32 = 256;
    pub const XqvmWeightPerStep: Weight = Weight::from_parts(1_000, 0);

    /// Derived from block weight budget so a single execute call always
    /// fits in one block.  Uses 50 % of the normal dispatch budget to
    /// leave room for other extrinsics in the same block.
    pub MaxStepLimit: u64 = {
        let normal = RuntimeBlockWeights::get()
            .get(frame_support::dispatch::DispatchClass::Normal)
            .max_total
            .unwrap_or(RuntimeBlockWeights::get().max_block);
        // Reserve half for other extrinsics.
        let budget = normal.ref_time() / 2;
        // Subtract execute_base overhead, then divide by per-step cost.
        let base = pallet_xqvm::SubstrateWeight::<Runtime>::execute_base()
            .ref_time();
        let per_step = XqvmWeightPerStep::get().ref_time();
        budget.saturating_sub(base) / per_step
    };
}

/// Configure the XQVM pallet for on-chain bytecode execution.
impl pallet_xqvm::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type MaxProgramSize = MaxProgramSize;
    type MaxCallDataLen = MaxCallDataLen;
    type MaxOutputSlots = MaxOutputSlots;
    type MaxStepLimit = MaxStepLimit;
    type WeightPerStep = XqvmWeightPerStep;
    type WeightInfo = pallet_xqvm::SubstrateWeight<Runtime>;
}

parameter_types! {
    pub const QuantumMaxNodes: u32 = 5_000;
    pub const QuantumMaxEdges: u32 = 50_000;
    pub const QuantumMaxSolutions: u32 = 20;
    pub const QuantumMaxBidMiners: u32 = 16;
    pub const QuantumMaxOrdersPerProposer: u32 = 32;
    pub const QuantumMaxDeadlineBlocks: BlockNumber = 1_000;
    pub const QuantumMaxBlockWait: BlockNumber = 100;
    pub const QuantumMinReward: Balance = UNIT;
    pub const QuantumResultTtlBlocks: BlockNumber = 10_000;
    pub const QuantumPowMaxNodes: u32 = 5_000;
    pub const QuantumPowMaxEdges: u32 = 50_000;
    pub const QuantumPowMaxSolutions: u32 = 32;
    pub const QuantumPowMinNodes: u32 = 16;
    pub const QuantumPowEpochLength: BlockNumber = 100;
    pub const QuantumPowMinerDeposit: Balance = UNIT;
    pub const QuantumPowBlockReward: Balance = UNIT;
    pub const QuantumPowMaxProofsPerBlock: u32 = 8;
    /// Upper bound on the cardinality of `allowed_h_values`, `allowed_j_values`,
    /// and `allowed_spin_values` per registered topology. Set well above the
    /// expected real-world maximum (Advantage2_system1 uses 3 for h, 2 for j,
    /// 2 for spin) so future hardware-spec changes don't force a runtime
    /// upgrade.
    pub const QuantumPowMaxAllowedValues: u32 = 32;
    /// Energy-curve calibration: per-mille `c` values that define the
    /// `(max_energy, knee_energy, min_energy)` triple via `expected_gse_with_c`
    /// on the default topology. Defaults `(0.700, 0.750, 0.800)` centre the
    /// curve's knee on the canonical `c = 0.75` used elsewhere in validation.
    pub const QuantumPowCurveCEasyMilli: u32 = 700;
    pub const QuantumPowCurveCKneeMilli: u32 = 750;
    pub const QuantumPowCurveCHardMilli: u32 = 800;
}

impl pallet_quantum_compute_mempool::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type MaxNodes = QuantumMaxNodes;
    type MaxEdges = QuantumMaxEdges;
    type MaxSolutions = QuantumMaxSolutions;
    type MaxBidMiners = QuantumMaxBidMiners;
    type MaxOrdersPerProposer = QuantumMaxOrdersPerProposer;
    type MaxDeadlineBlocks = QuantumMaxDeadlineBlocks;
    type MaxBlockWait = QuantumMaxBlockWait;
    type MinReward = QuantumMinReward;
    type ResultTtlBlocks = QuantumResultTtlBlocks;
    type VM = pallet_quantum_compute_mempool::xqvm::NoOpVm;
    type WeightInfo = pallet_quantum_compute_mempool::weights::SubstrateWeight<Runtime>;
}

impl pallet_quantum_pow::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type MaxNodes = QuantumPowMaxNodes;
    type MaxEdges = QuantumPowMaxEdges;
    type MaxSolutions = QuantumPowMaxSolutions;
    type MinNodes = QuantumPowMinNodes;
    type EpochLength = QuantumPowEpochLength;
    type MinerDeposit = QuantumPowMinerDeposit;
    type BlockReward = QuantumPowBlockReward;
    type MaxProofsPerBlock = QuantumPowMaxProofsPerBlock;
    type MaxAllowedValues = QuantumPowMaxAllowedValues;
    type CurveCEasyMilli = QuantumPowCurveCEasyMilli;
    type CurveCKneeMilli = QuantumPowCurveCKneeMilli;
    type CurveCHardMilli = QuantumPowCurveCHardMilli;
    type WeightInfo = pallet_quantum_pow::weights::SubstrateWeight<Runtime>;
}
