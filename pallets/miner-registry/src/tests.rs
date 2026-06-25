use crate::{
    mock::*, CpuInfo, Error, Event, GpuInfo, LatestParticipation, LogLevel, MinerKind, MinerSpec,
    NodeDescriptorInput, NodeDescriptorV1Input, NodeDescriptorV2Input, NodeDescriptors, OsInfo,
    SystemInfo,
};
use codec::{Decode, Encode};
use frame_support::{assert_noop, assert_ok, BoundedVec};

fn bounded<T, S>(items: Vec<T>) -> BoundedVec<T, S>
where
    S: frame_support::traits::Get<u32>,
{
    items.try_into().ok().unwrap()
}

fn bytes<const N: u32>(value: &[u8]) -> BoundedVec<u8, frame_support::traits::ConstU32<N>> {
    bounded(value.to_vec())
}

fn miner_spec() -> crate::MinerSpecOf<Test> {
    MinerSpec {
        kind: MinerKind::Cpu,
        label: Some(bytes::<64>(b"cpu-0")),
        backend: Some(bytes::<32>(b"local")),
        device_id: Some(bytes::<64>(b"0")),
    }
}

fn v1_input() -> crate::NodeDescriptorV1InputOf<Test> {
    NodeDescriptorV1Input {
        node_id: bytes::<64>(b"node-1"),
        node_name: bytes::<64>(b"Node One"),
        public_host: Some(bytes::<253>(b"miner.example.com")),
        public_port: Some(20050),
        rpc_endpoints: bounded(vec![bytes::<256>(b"https://miner.example.com/rpc")]),
        auto_mine: true,
        log_level: LogLevel::Info,
        miners: bounded(vec![miner_spec()]),
    }
}

fn descriptor() -> crate::NodeDescriptorInputOf<Test> {
    NodeDescriptorInput::V1(v1_input())
}

fn system_info() -> crate::SystemInfoOf<Test> {
    SystemInfo {
        os: OsInfo {
            system: bytes::<64>(b"Linux"),
            release: bytes::<64>(b"6.1.0-rpi"),
            machine: bytes::<64>(b"x86_64"),
        },
        cpu: CpuInfo {
            logical_cores: Some(16),
            physical_cores: Some(8),
            brand: bytes::<96>(b"AMD EPYC 7763"),
            arch: bytes::<16>(b"x86_64"),
        },
        memory_mb: Some(64_000),
        gpus: bounded(vec![GpuInfo {
            index: 0,
            vendor: bytes::<16>(b"NVIDIA"),
            name: bytes::<96>(b"NVIDIA H100 80GB HBM3"),
            memory_mb: Some(81_920),
            utilization_pct: Some(50),
        }]),
    }
}

fn v2_input() -> crate::NodeDescriptorV2InputOf<Test> {
    let v1 = v1_input();
    NodeDescriptorV2Input {
        node_id: v1.node_id,
        node_name: v1.node_name,
        public_host: v1.public_host,
        public_port: v1.public_port,
        rpc_endpoints: v1.rpc_endpoints,
        auto_mine: v1.auto_mine,
        log_level: v1.log_level,
        miners: v1.miners,
        system_info: Some(system_info()),
    }
}

#[test]
fn set_descriptor_stores_typed_descriptor_and_reserves_deposit() {
    new_test_ext().execute_with(|| {
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));

        let stored = NodeDescriptors::<Test>::get(1).expect("descriptor stored");
        assert_eq!(stored.schema_version, crate::NODE_DESCRIPTOR_SCHEMA_V1);
        assert_eq!(stored.node_id.as_slice(), b"node-1");
        assert_eq!(stored.node_name.as_slice(), b"Node One");
        assert_eq!(stored.public_port, Some(20050));
        assert_eq!(stored.miners.len(), 1);
        assert_ne!(stored.payload_hash, sp_core::H256::zero());
        assert!(stored.system_info.is_none());
        assert_eq!(Balances::reserved_balance(1), stored.deposit);

        System::assert_last_event(
            Event::DescriptorUpdated {
                who: 1,
                payload_hash: stored.payload_hash,
                payload_len: 71,
            }
            .into(),
        );
    });
}

#[test]
fn set_descriptor_rejects_empty_required_fields() {
    new_test_ext().execute_with(|| {
        let mut input = v1_input();
        input.node_id = bytes::<64>(b"");

        assert_noop!(
            MinerRegistry::set_descriptor(RuntimeOrigin::signed(1), NodeDescriptorInput::V1(input)),
            Error::<Test>::EmptyNodeId
        );
    });
}

#[test]
fn set_descriptor_rejects_empty_optional_strings_when_present() {
    new_test_ext().execute_with(|| {
        let mut input = v1_input();
        input.rpc_endpoints = bounded(vec![bytes::<256>(b"")]);

        assert_noop!(
            MinerRegistry::set_descriptor(RuntimeOrigin::signed(1), NodeDescriptorInput::V1(input)),
            Error::<Test>::EmptyRpcEndpoint
        );
    });
}

#[test]
fn set_descriptor_rejects_descriptor_without_miners() {
    new_test_ext().execute_with(|| {
        let mut input = v1_input();
        input.miners = bounded(vec![]);

        assert_noop!(
            MinerRegistry::set_descriptor(RuntimeOrigin::signed(1), NodeDescriptorInput::V1(input)),
            Error::<Test>::NoMiners
        );
    });
}

#[test]
fn set_descriptor_rejects_zero_public_port() {
    new_test_ext().execute_with(|| {
        let mut input = v1_input();
        input.public_port = Some(0);

        assert_noop!(
            MinerRegistry::set_descriptor(RuntimeOrigin::signed(1), NodeDescriptorInput::V1(input)),
            Error::<Test>::InvalidPort
        );
    });
}

#[test]
fn updating_descriptor_adjusts_reserved_deposit() {
    new_test_ext().execute_with(|| {
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        let first_reserved = Balances::reserved_balance(1);

        let mut input = v1_input();
        input.public_host = None;
        input.rpc_endpoints = bounded(vec![]);
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            NodeDescriptorInput::V1(input)
        ));

        let second_reserved = Balances::reserved_balance(1);
        assert!(second_reserved < first_reserved);
        assert_eq!(
            NodeDescriptors::<Test>::get(1)
                .expect("descriptor stored")
                .deposit,
            second_reserved
        );
    });
}

#[test]
fn clear_descriptor_removes_storage_and_unreserves_deposit() {
    new_test_ext().execute_with(|| {
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        assert!(Balances::reserved_balance(1) > 0);

        assert_ok!(MinerRegistry::clear_descriptor(RuntimeOrigin::signed(1)));

        assert!(NodeDescriptors::<Test>::get(1).is_none());
        assert_eq!(Balances::reserved_balance(1), 0);
        System::assert_last_event(Event::DescriptorCleared { who: 1 }.into());
    });
}

#[test]
fn clear_descriptor_drops_participation_record() {
    new_test_ext().execute_with(|| {
        set_latest_qblock_id(Some(4));
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        assert_ok!(MinerRegistry::participate(
            RuntimeOrigin::signed(1),
            5,
            MinerKind::Cpu,
            None,
        ));
        assert!(LatestParticipation::<Test>::get(1).is_some());

        assert_ok!(MinerRegistry::clear_descriptor(RuntimeOrigin::signed(1)));

        assert!(LatestParticipation::<Test>::get(1).is_none());
    });
}

#[test]
fn participate_requires_descriptor() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            MinerRegistry::participate(RuntimeOrigin::signed(1), 1, MinerKind::Cpu, None),
            Error::<Test>::DescriptorRequired
        );
    });
}

#[test]
fn participate_records_current_candidate_qblock() {
    new_test_ext().execute_with(|| {
        set_latest_qblock_id(Some(4));
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));

        assert_ok!(MinerRegistry::participate(
            RuntimeOrigin::signed(1),
            5,
            MinerKind::QpuDwave,
            Some(30),
        ));

        let stored = LatestParticipation::<Test>::get(1).expect("participation stored");
        assert_eq!(stored.qblock_id, 5);
        assert_eq!(stored.kind, MinerKind::QpuDwave);
        assert_eq!(stored.budget_seconds, Some(30));
        System::assert_last_event(
            Event::MinerParticipated {
                qblock_id: 5,
                who: 1,
                kind: MinerKind::QpuDwave,
                budget_seconds: Some(30),
            }
            .into(),
        );
    });
}

#[test]
fn participate_rejects_stale_or_future_qblock_id() {
    new_test_ext().execute_with(|| {
        set_latest_qblock_id(Some(4));
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));

        assert_noop!(
            MinerRegistry::participate(RuntimeOrigin::signed(1), 4, MinerKind::Cpu, None),
            Error::<Test>::InvalidQBlockId
        );
        assert_noop!(
            MinerRegistry::participate(RuntimeOrigin::signed(1), 6, MinerKind::Cpu, None),
            Error::<Test>::InvalidQBlockId
        );
    });
}

#[test]
fn participate_rejects_duplicate_for_same_qblock() {
    new_test_ext().execute_with(|| {
        set_latest_qblock_id(None);
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        assert_ok!(MinerRegistry::participate(
            RuntimeOrigin::signed(1),
            1,
            MinerKind::Cpu,
            None
        ));

        assert_noop!(
            MinerRegistry::participate(RuntimeOrigin::signed(1), 1, MinerKind::Cpu, None),
            Error::<Test>::DuplicateParticipation
        );

        set_latest_qblock_id(Some(1));
        assert_ok!(MinerRegistry::participate(
            RuntimeOrigin::signed(1),
            2,
            MinerKind::Cpu,
            None
        ));
    });
}

#[test]
fn participants_by_qblock_lists_all_sorted_with_pagination() {
    new_test_ext().execute_with(|| {
        set_latest_qblock_id(Some(4)); // candidate qblock = 5

        // Register and participate out of account order to prove sorting.
        for who in [2u64, 1u64] {
            assert_ok!(MinerRegistry::set_descriptor(
                RuntimeOrigin::signed(who),
                descriptor()
            ));
            assert_ok!(MinerRegistry::participate(
                RuntimeOrigin::signed(who),
                5,
                MinerKind::Cpu,
                None
            ));
        }

        assert_eq!(MinerRegistry::participant_count_by_qblock(5), 2);
        assert_eq!(MinerRegistry::participant_count_by_qblock(4), 0);

        let all = MinerRegistry::participants_by_qblock(5, None, 100);
        assert_eq!(
            all.iter().map(|(who, _)| *who).collect::<Vec<_>>(),
            vec![1, 2]
        );

        // limit caps the page...
        let first = MinerRegistry::participants_by_qblock(5, None, 1);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, 1);

        // ...and start_after resumes strictly after the cursor.
        let next = MinerRegistry::participants_by_qblock(5, Some(1), 100);
        assert_eq!(
            next.iter().map(|(who, _)| *who).collect::<Vec<_>>(),
            vec![2]
        );

        // limit 0 returns nothing.
        assert!(MinerRegistry::participants_by_qblock(5, None, 0).is_empty());
    });
}

#[test]
fn participants_are_indexed_per_qblock() {
    new_test_ext().execute_with(|| {
        set_latest_qblock_id(Some(4)); // candidate qblock = 5
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        assert_ok!(MinerRegistry::participate(
            RuntimeOrigin::signed(1),
            5,
            MinerKind::Cpu,
            None
        ));

        set_latest_qblock_id(Some(5)); // candidate qblock = 6
        assert_ok!(MinerRegistry::participate(
            RuntimeOrigin::signed(1),
            6,
            MinerKind::Gpu,
            Some(10)
        ));

        // The reverse index keeps history across qblocks, unlike
        // LatestParticipation which only holds the most recent record.
        assert_eq!(MinerRegistry::participant_count_by_qblock(5), 1);
        assert_eq!(MinerRegistry::participant_count_by_qblock(6), 1);

        let p5 = MinerRegistry::participants_by_qblock(5, None, 100);
        assert_eq!(p5[0].1.kind, MinerKind::Cpu);

        let p6 = MinerRegistry::participants_by_qblock(6, None, 100);
        assert_eq!(p6[0].1.kind, MinerKind::Gpu);
        assert_eq!(p6[0].1.budget_seconds, Some(10));
    });
}

#[test]
fn set_descriptor_v2_stores_and_returns_system_info() {
    new_test_ext().execute_with(|| {
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            NodeDescriptorInput::V2(v2_input())
        ));

        let stored = NodeDescriptors::<Test>::get(1).expect("descriptor stored");
        assert_eq!(stored.schema_version, crate::NODE_DESCRIPTOR_SCHEMA_V2);
        let si = stored.system_info.expect("system_info stored");
        assert_eq!(si.os.system.as_slice(), b"Linux");
        assert_eq!(si.os.machine.as_slice(), b"x86_64");
        assert_eq!(si.cpu.brand.as_slice(), b"AMD EPYC 7763");
        assert_eq!(si.cpu.logical_cores, Some(16));
        assert_eq!(si.memory_mb, Some(64_000));
        assert_eq!(si.gpus.len(), 1);
        assert_eq!(si.gpus[0].name.as_slice(), b"NVIDIA H100 80GB HBM3");
        assert_eq!(si.gpus[0].utilization_pct, Some(50));
    });
}

#[test]
fn set_descriptor_v2_without_system_info_stores_none() {
    new_test_ext().execute_with(|| {
        let mut input = v2_input();
        input.system_info = None;

        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            NodeDescriptorInput::V2(input)
        ));

        let stored = NodeDescriptors::<Test>::get(1).expect("descriptor stored");
        assert_eq!(stored.schema_version, crate::NODE_DESCRIPTOR_SCHEMA_V2);
        assert!(stored.system_info.is_none());
    });
}

#[test]
fn set_descriptor_v2_rejects_empty_required_system_info_fields() {
    new_test_ext().execute_with(|| {
        let cases: [(fn(&mut crate::SystemInfoOf<Test>), Error<Test>); 5] = [
            (
                |si| si.os.system = bytes::<64>(b""),
                Error::<Test>::EmptyOsSystem,
            ),
            (
                |si| si.cpu.brand = bytes::<96>(b""),
                Error::<Test>::EmptyCpuBrand,
            ),
            (
                |si| si.cpu.arch = bytes::<16>(b""),
                Error::<Test>::EmptyCpuArch,
            ),
            (
                |si| si.gpus[0].vendor = bytes::<16>(b""),
                Error::<Test>::EmptyGpuVendor,
            ),
            (
                |si| si.gpus[0].name = bytes::<96>(b""),
                Error::<Test>::EmptyGpuName,
            ),
        ];

        for (mutate, expected) in cases {
            let mut si = system_info();
            mutate(&mut si);
            let mut input = v2_input();
            input.system_info = Some(si);
            assert_noop!(
                MinerRegistry::set_descriptor(
                    RuntimeOrigin::signed(1),
                    NodeDescriptorInput::V2(input)
                ),
                expected
            );
        }
    });
}

#[test]
fn set_descriptor_v2_rejects_gpu_utilization_over_100() {
    new_test_ext().execute_with(|| {
        let mut si = system_info();
        si.gpus[0].utilization_pct = Some(101);
        let mut input = v2_input();
        input.system_info = Some(si);

        assert_noop!(
            MinerRegistry::set_descriptor(RuntimeOrigin::signed(1), NodeDescriptorInput::V2(input)),
            Error::<Test>::InvalidGpuUtilization
        );
    });
}

#[test]
fn system_info_bounds_reject_over_length_input() {
    // A GPU name longer than MaxGpuNameBytes (96) cannot even be constructed.
    let too_long_name: Result<crate::GpuNameOf<Test>, _> = vec![b'x'; 97].try_into();
    assert!(too_long_name.is_err());

    // Neither can more GPUs than MaxGpus (16).
    let gpu = GpuInfo {
        index: 0,
        vendor: bytes::<16>(b"NVIDIA"),
        name: bytes::<96>(b"GPU"),
        memory_mb: None,
        utilization_pct: None,
    };
    let too_many: Result<crate::GpusOf<Test>, _> = vec![gpu.clone(); 17].try_into();
    assert!(too_many.is_err());

    // The decode boundary an attacker actually hits: a `Vec<u8>`/`Vec<T>`
    // encodes with the same compact-length prefix as a `BoundedVec`, so feeding
    // over-length raw bytes through `Decode` must be rejected by the bound.
    let raw_name = vec![b'x'; 97].encode();
    assert!(crate::GpuNameOf::<Test>::decode(&mut &raw_name[..]).is_err());
    let raw_gpus = vec![gpu; 17].encode();
    assert!(crate::GpusOf::<Test>::decode(&mut &raw_gpus[..]).is_err());
}

#[test]
fn node_descriptor_input_pins_variant_indices_and_round_trips() {
    // V1 must encode to byte 0x00 and V2 to 0x01 so in-flight V1 signed
    // extrinsics keep decoding identically regardless of variant source order.
    let v1 = descriptor();
    assert_eq!(v1.encode()[0], 0);
    let v2 = NodeDescriptorInput::V2(v2_input());
    assert_eq!(v2.encode()[0], 1);

    // Full SCALE round-trip with system_info both Some and None.
    let decoded =
        crate::NodeDescriptorInputOf::<Test>::decode(&mut &v2.encode()[..]).expect("v2 decodes");
    assert_eq!(decoded, v2);

    let mut none_input = v2_input();
    none_input.system_info = None;
    let v2_none = NodeDescriptorInput::V2(none_input);
    let decoded_none =
        crate::NodeDescriptorInputOf::<Test>::decode(&mut &v2_none.encode()[..]).expect("decodes");
    assert_eq!(decoded_none, v2_none);
}

#[test]
fn set_descriptor_v2_stores_empty_gpu_list() {
    new_test_ext().execute_with(|| {
        let mut si = system_info();
        si.gpus = bounded(vec![]);
        let mut input = v2_input();
        input.system_info = Some(si);

        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            NodeDescriptorInput::V2(input)
        ));

        let stored = NodeDescriptors::<Test>::get(1).expect("descriptor stored");
        let si = stored.system_info.expect("system_info stored");
        assert!(si.gpus.is_empty());
    });
}

#[test]
fn set_descriptor_v2_allows_empty_os_release_and_machine() {
    // os.release and os.machine are intentionally optional (not required
    // non-empty), unlike os.system / cpu.brand / cpu.arch. Pin that contract.
    new_test_ext().execute_with(|| {
        let mut si = system_info();
        si.os.release = bytes::<64>(b"");
        si.os.machine = bytes::<64>(b"");
        let mut input = v2_input();
        input.system_info = Some(si);

        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            NodeDescriptorInput::V2(input)
        ));

        let stored = NodeDescriptors::<Test>::get(1).expect("descriptor stored");
        let si = stored.system_info.expect("system_info stored");
        assert!(si.os.release.is_empty());
        assert!(si.os.machine.is_empty());
    });
}

#[test]
fn v2_deposit_exceeds_v1_by_system_info_bytes() {
    new_test_ext().execute_with(|| {
        // V1 baseline (account 1) and V2 with the same base + system_info
        // (account 2) so the only deposit difference is the survey bytes.
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        let v1_deposit = NodeDescriptors::<Test>::get(1).expect("v1 stored").deposit;

        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(2),
            NodeDescriptorInput::V2(v2_input())
        ));
        let v2_stored = NodeDescriptors::<Test>::get(2).expect("v2 stored");
        let si = v2_stored.system_info.clone().expect("system_info stored");

        let si_bytes: u128 = (si.os.system.len()
            + si.os.release.len()
            + si.os.machine.len()
            + si.cpu.brand.len()
            + si.cpu.arch.len()
            + si.gpus
                .iter()
                .map(|g| g.vendor.len() + g.name.len())
                .sum::<usize>()) as u128;

        // mock DescriptorDepositPerByte = 2.
        assert_eq!(v2_stored.deposit - v1_deposit, si_bytes * 2);
    });
}

#[test]
fn migrate_v1_to_v2_clears_descriptors_and_returns_deposits() {
    use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};

    new_test_ext().execute_with(|| {
        // Simulate an on-chain v1 pallet holding two descriptors with distinct
        // deposits (V1 vs larger V2), so the drain loop must unreserve each
        // account's OWN deposit — catching wrong-account / early-break bugs.
        StorageVersion::new(1).put::<crate::Pallet<Test>>();
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(2),
            NodeDescriptorInput::V2(v2_input())
        ));
        let reserved_1 = Balances::reserved_balance(1);
        let reserved_2 = Balances::reserved_balance(2);
        assert!(reserved_1 > 0 && reserved_2 > 0);
        assert_ne!(reserved_1, reserved_2);

        let _weight =
            <crate::migrations::v2::MigrateToV2<Test> as OnRuntimeUpgrade>::on_runtime_upgrade();

        // Every descriptor dropped, every deposit returned, version advanced.
        assert!(NodeDescriptors::<Test>::get(1).is_none());
        assert!(NodeDescriptors::<Test>::get(2).is_none());
        assert_eq!(Balances::reserved_balance(1), 0);
        assert_eq!(Balances::reserved_balance(2), 0);
        assert_eq!(
            crate::Pallet::<Test>::on_chain_storage_version(),
            StorageVersion::new(2)
        );

        // Self-healing: a re-file reserves exactly the new deposit (not double).
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        let refiled = NodeDescriptors::<Test>::get(1).expect("re-filed");
        assert_eq!(Balances::reserved_balance(1), refiled.deposit);
    });
}

#[test]
fn migrate_v1_to_v2_is_noop_when_not_at_version_1() {
    use frame_support::traits::{GetStorageVersion, OnRuntimeUpgrade, StorageVersion};

    new_test_ext().execute_with(|| {
        // Already at v2: the version gate must skip the drain entirely.
        StorageVersion::new(2).put::<crate::Pallet<Test>>();
        assert_ok!(MinerRegistry::set_descriptor(
            RuntimeOrigin::signed(1),
            descriptor()
        ));
        let reserved = Balances::reserved_balance(1);

        let _weight =
            <crate::migrations::v2::MigrateToV2<Test> as OnRuntimeUpgrade>::on_runtime_upgrade();

        assert!(NodeDescriptors::<Test>::get(1).is_some());
        assert_eq!(Balances::reserved_balance(1), reserved);
        assert_eq!(
            crate::Pallet::<Test>::on_chain_storage_version(),
            StorageVersion::new(2)
        );
    });
}
