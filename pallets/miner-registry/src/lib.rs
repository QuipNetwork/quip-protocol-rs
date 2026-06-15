#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

pub mod weights;
pub use weights::*;

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use frame_support::{pallet_prelude::BoundedVec, traits::Currency};
use scale_info::TypeInfo;

type BlockNumberOf<T> = frame_system::pallet_prelude::BlockNumberFor<T>;
type BalanceOf<T> =
    <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

type NodeIdOf<T> = BoundedVec<u8, <T as Config>::MaxNodeIdBytes>;
type NodeNameOf<T> = BoundedVec<u8, <T as Config>::MaxNodeNameBytes>;
type PublicHostOf<T> = BoundedVec<u8, <T as Config>::MaxPublicHostBytes>;
type RpcEndpointOf<T> = BoundedVec<u8, <T as Config>::MaxRpcEndpointBytes>;
type RpcEndpointsOf<T> = BoundedVec<RpcEndpointOf<T>, <T as Config>::MaxRpcEndpoints>;
type MinerLabelOf<T> = BoundedVec<u8, <T as Config>::MaxMinerLabelBytes>;
type MinerBackendOf<T> = BoundedVec<u8, <T as Config>::MaxMinerBackendBytes>;
type MinerDeviceIdOf<T> = BoundedVec<u8, <T as Config>::MaxMinerDeviceIdBytes>;
type MinerSpecOf<T> = MinerSpec<MinerLabelOf<T>, MinerBackendOf<T>, MinerDeviceIdOf<T>>;
type MinerSpecsOf<T> = BoundedVec<MinerSpecOf<T>, <T as Config>::MaxMinerSpecs>;
type NodeDescriptorV1InputOf<T> = NodeDescriptorV1Input<
    NodeIdOf<T>,
    NodeNameOf<T>,
    PublicHostOf<T>,
    RpcEndpointsOf<T>,
    MinerSpecsOf<T>,
>;
type NodeDescriptorInputOf<T> = NodeDescriptorInput<NodeDescriptorV1InputOf<T>>;
type NodeDescriptorOf<T> = NodeDescriptor<
    NodeIdOf<T>,
    NodeNameOf<T>,
    PublicHostOf<T>,
    RpcEndpointsOf<T>,
    MinerSpecsOf<T>,
    BlockNumberOf<T>,
    BalanceOf<T>,
>;
type ParticipationRecordOf<T> = ParticipationRecord<BlockNumberOf<T>>;

pub const NODE_DESCRIPTOR_SCHEMA_V1: u16 = 1;

pub trait QBlockIdProvider {
    fn latest_qblock_id() -> Option<u64>;

    fn candidate_qblock_id() -> u64 {
        Self::latest_qblock_id().unwrap_or(0).saturating_add(1)
    }
}

impl QBlockIdProvider for () {
    fn latest_qblock_id() -> Option<u64> {
        None
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Decode,
    DecodeWithMemTracking,
    Encode,
    Eq,
    MaxEncodedLen,
    PartialEq,
    TypeInfo,
)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Decode,
    DecodeWithMemTracking,
    Encode,
    Eq,
    MaxEncodedLen,
    PartialEq,
    TypeInfo,
)]
pub enum MinerKind {
    Cpu,
    Gpu,
    QpuDwave,
    QpuIbm,
    QpuIonq,
    QpuPasqal,
    Asic,
}

#[derive(
    Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, TypeInfo,
)]
pub struct MinerSpec<Label, Backend, DeviceId> {
    pub kind: MinerKind,
    pub label: Option<Label>,
    pub backend: Option<Backend>,
    pub device_id: Option<DeviceId>,
}

#[derive(
    Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, TypeInfo,
)]
pub struct NodeDescriptorV1Input<NodeId, NodeName, PublicHost, RpcEndpoints, MinerSpecs> {
    pub node_id: NodeId,
    pub node_name: NodeName,
    pub public_host: Option<PublicHost>,
    pub public_port: Option<u16>,
    pub rpc_endpoints: RpcEndpoints,
    pub auto_mine: bool,
    pub log_level: LogLevel,
    pub miners: MinerSpecs,
}

#[derive(
    Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, TypeInfo,
)]
pub enum NodeDescriptorInput<V1> {
    V1(V1),
}

#[derive(
    Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, TypeInfo,
)]
pub struct NodeDescriptor<
    NodeId,
    NodeName,
    PublicHost,
    RpcEndpoints,
    MinerSpecs,
    BlockNumber,
    Balance,
> {
    pub schema_version: u16,
    pub node_id: NodeId,
    pub node_name: NodeName,
    pub public_host: Option<PublicHost>,
    pub public_port: Option<u16>,
    pub rpc_endpoints: RpcEndpoints,
    pub auto_mine: bool,
    pub log_level: LogLevel,
    pub miners: MinerSpecs,
    pub payload_hash: sp_core::H256,
    pub updated_at: BlockNumber,
    pub deposit: Balance,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Decode,
    DecodeWithMemTracking,
    Encode,
    Eq,
    MaxEncodedLen,
    PartialEq,
    TypeInfo,
)]
pub struct ParticipationRecord<BlockNumber> {
    pub qblock_id: u64,
    pub kind: MinerKind,
    pub budget_seconds: Option<u32>,
    pub updated_at: BlockNumber,
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{
        pallet_prelude::*,
        traits::{ReservableCurrency, StorageVersion},
    };
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::{SaturatedConversion, Saturating, Zero};

    const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_balances::Config {
        #[allow(deprecated)]
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        type Currency: ReservableCurrency<Self::AccountId>;

        type QBlockIds: QBlockIdProvider;

        #[pallet::constant]
        type MaxNodeIdBytes: Get<u32>;
        #[pallet::constant]
        type MaxNodeNameBytes: Get<u32>;
        #[pallet::constant]
        type MaxPublicHostBytes: Get<u32>;
        #[pallet::constant]
        type MaxRpcEndpointBytes: Get<u32>;
        #[pallet::constant]
        type MaxRpcEndpoints: Get<u32>;
        #[pallet::constant]
        type MaxMinerSpecs: Get<u32>;
        #[pallet::constant]
        type MaxMinerLabelBytes: Get<u32>;
        #[pallet::constant]
        type MaxMinerBackendBytes: Get<u32>;
        #[pallet::constant]
        type MaxMinerDeviceIdBytes: Get<u32>;
        #[pallet::constant]
        type DescriptorDepositBase: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type DescriptorDepositPerByte: Get<BalanceOf<Self>>;

        type WeightInfo: WeightInfo;
    }

    #[pallet::storage]
    pub type NodeDescriptors<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, NodeDescriptorOf<T>>;

    #[pallet::storage]
    pub type LatestParticipation<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, ParticipationRecordOf<T>>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        DescriptorUpdated {
            who: T::AccountId,
            payload_hash: sp_core::H256,
            payload_len: u32,
        },
        DescriptorCleared {
            who: T::AccountId,
        },
        MinerParticipated {
            qblock_id: u64,
            who: T::AccountId,
            kind: MinerKind,
            budget_seconds: Option<u32>,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        EmptyNodeId,
        EmptyNodeName,
        EmptyPublicHost,
        EmptyRpcEndpoint,
        EmptyMinerLabel,
        EmptyMinerBackend,
        EmptyMinerDeviceId,
        NoMiners,
        InvalidPort,
        DescriptorNotFound,
        DescriptorRequired,
        InvalidQBlockId,
        DuplicateParticipation,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(<T as Config>::WeightInfo::set_descriptor())]
        pub fn set_descriptor(
            origin: OriginFor<T>,
            descriptor: NodeDescriptorInputOf<T>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let payload_hash =
                sp_core::H256::from(sp_io::hashing::blake2_256(&descriptor.encode()));
            let (stored, payload_len) = Self::validate_and_store_descriptor(descriptor)?;
            Self::replace_descriptor(&who, stored, payload_hash)?;

            Self::deposit_event(Event::DescriptorUpdated {
                who,
                payload_hash,
                payload_len,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(<T as Config>::WeightInfo::clear_descriptor())]
        pub fn clear_descriptor(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let descriptor =
                NodeDescriptors::<T>::take(&who).ok_or(Error::<T>::DescriptorNotFound)?;
            let _ = T::Currency::unreserve(&who, descriptor.deposit);
            Self::deposit_event(Event::DescriptorCleared { who });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(<T as Config>::WeightInfo::participate())]
        pub fn participate(
            origin: OriginFor<T>,
            qblock_id: u64,
            kind: MinerKind,
            budget_seconds: Option<u32>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                NodeDescriptors::<T>::contains_key(&who),
                Error::<T>::DescriptorRequired
            );
            ensure!(
                qblock_id == T::QBlockIds::candidate_qblock_id(),
                Error::<T>::InvalidQBlockId
            );
            ensure!(
                LatestParticipation::<T>::get(&who)
                    .map(|record| record.qblock_id != qblock_id)
                    .unwrap_or(true),
                Error::<T>::DuplicateParticipation
            );

            LatestParticipation::<T>::insert(
                &who,
                ParticipationRecord {
                    qblock_id,
                    kind,
                    budget_seconds,
                    updated_at: frame_system::Pallet::<T>::block_number(),
                },
            );
            Self::deposit_event(Event::MinerParticipated {
                qblock_id,
                who,
                kind,
                budget_seconds,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn validate_and_store_descriptor(
            descriptor: NodeDescriptorInputOf<T>,
        ) -> Result<(NodeDescriptorOf<T>, u32), DispatchError> {
            match descriptor {
                NodeDescriptorInput::V1(input) => Self::validate_and_store_v1(input),
            }
        }

        fn validate_and_store_v1(
            input: NodeDescriptorV1InputOf<T>,
        ) -> Result<(NodeDescriptorOf<T>, u32), DispatchError> {
            ensure!(!input.node_id.is_empty(), Error::<T>::EmptyNodeId);
            ensure!(!input.node_name.is_empty(), Error::<T>::EmptyNodeName);
            if let Some(host) = &input.public_host {
                ensure!(!host.is_empty(), Error::<T>::EmptyPublicHost);
            }
            if let Some(port) = input.public_port {
                ensure!(port > 0, Error::<T>::InvalidPort);
            }
            for endpoint in &input.rpc_endpoints {
                ensure!(!endpoint.is_empty(), Error::<T>::EmptyRpcEndpoint);
            }
            ensure!(!input.miners.is_empty(), Error::<T>::NoMiners);
            for miner in &input.miners {
                if let Some(label) = &miner.label {
                    ensure!(!label.is_empty(), Error::<T>::EmptyMinerLabel);
                }
                if let Some(backend) = &miner.backend {
                    ensure!(!backend.is_empty(), Error::<T>::EmptyMinerBackend);
                }
                if let Some(device_id) = &miner.device_id {
                    ensure!(!device_id.is_empty(), Error::<T>::EmptyMinerDeviceId);
                }
            }

            let payload_len = Self::descriptor_payload_len(
                &input.node_id,
                &input.node_name,
                input.public_host.as_ref(),
                &input.rpc_endpoints,
                &input.miners,
            );
            let deposit = Self::descriptor_deposit(payload_len);
            let stored = NodeDescriptor {
                schema_version: NODE_DESCRIPTOR_SCHEMA_V1,
                node_id: input.node_id,
                node_name: input.node_name,
                public_host: input.public_host,
                public_port: input.public_port,
                rpc_endpoints: input.rpc_endpoints,
                auto_mine: input.auto_mine,
                log_level: input.log_level,
                miners: input.miners,
                payload_hash: sp_core::H256::zero(),
                updated_at: frame_system::Pallet::<T>::block_number(),
                deposit,
            };
            Ok((stored, payload_len))
        }

        fn replace_descriptor(
            who: &T::AccountId,
            mut descriptor: NodeDescriptorOf<T>,
            payload_hash: sp_core::H256,
        ) -> DispatchResult {
            let previous = NodeDescriptors::<T>::get(who).map(|d| d.deposit);
            let previous_deposit = previous.unwrap_or_else(Zero::zero);
            let next_deposit = descriptor.deposit;

            if next_deposit > previous_deposit {
                T::Currency::reserve(who, next_deposit.saturating_sub(previous_deposit))?;
            } else if previous_deposit > next_deposit {
                let _ = T::Currency::unreserve(who, previous_deposit.saturating_sub(next_deposit));
            }

            descriptor.payload_hash = payload_hash;
            NodeDescriptors::<T>::insert(who, descriptor);
            Ok(())
        }

        fn descriptor_payload_len(
            node_id: &NodeIdOf<T>,
            node_name: &NodeNameOf<T>,
            public_host: Option<&PublicHostOf<T>>,
            rpc_endpoints: &RpcEndpointsOf<T>,
            miners: &MinerSpecsOf<T>,
        ) -> u32 {
            let mut bytes = node_id.len().saturating_add(node_name.len());
            if let Some(host) = public_host {
                bytes = bytes.saturating_add(host.len());
            }
            for endpoint in rpc_endpoints {
                bytes = bytes.saturating_add(endpoint.len());
            }
            for miner in miners {
                if let Some(label) = &miner.label {
                    bytes = bytes.saturating_add(label.len());
                }
                if let Some(backend) = &miner.backend {
                    bytes = bytes.saturating_add(backend.len());
                }
                if let Some(device_id) = &miner.device_id {
                    bytes = bytes.saturating_add(device_id.len());
                }
            }
            bytes.saturated_into::<u32>()
        }

        fn descriptor_deposit(payload_len: u32) -> BalanceOf<T> {
            T::DescriptorDepositBase::get().saturating_add(
                T::DescriptorDepositPerByte::get()
                    .saturating_mul(payload_len.saturated_into::<BalanceOf<T>>()),
            )
        }
    }
}
