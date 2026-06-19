use crate::{
    mock::*, Error, Event, LatestParticipation, LogLevel, MinerKind, MinerSpec,
    NodeDescriptorInput, NodeDescriptorV1Input, NodeDescriptors,
};
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

fn descriptor() -> crate::NodeDescriptorInputOf<Test> {
    NodeDescriptorInput::V1(NodeDescriptorV1Input {
        node_id: bytes::<64>(b"node-1"),
        node_name: bytes::<64>(b"Node One"),
        public_host: Some(bytes::<253>(b"miner.example.com")),
        public_port: Some(20050),
        rpc_endpoints: bounded(vec![bytes::<256>(b"https://miner.example.com/rpc")]),
        auto_mine: true,
        log_level: LogLevel::Info,
        miners: bounded(vec![miner_spec()]),
    })
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
        let NodeDescriptorInput::V1(mut input) = descriptor();
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
        let NodeDescriptorInput::V1(mut input) = descriptor();
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
        let NodeDescriptorInput::V1(mut input) = descriptor();
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
        let NodeDescriptorInput::V1(mut input) = descriptor();
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

        let NodeDescriptorInput::V1(mut input) = descriptor();
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
