# Quip Protocol On-Chain Miner Data Plan

## General Idea

Goals are:

1. `quip-miner` in isolation should not require an indexer.
2. The indexer should do less work when possible, and should not need to query
   both the miner and the chain for the same data. Only one source should be
   needed when possible.

A consequence is that the dashboard becomes less complicated: it should be
limited to talking with the indexer, which should provide all necessary data.
That said, the chain should not compute aggregate statistics. Aggregate
statistics are the indexer's job.

## Current Remark Mechanism

`../quip-protocol` currently uses `System.remark_with_event` or
`System.remark` for two pieces of miner-observability data:

- node descriptors, filed by startup auto-identify and by
  `quip-miner identify`;
- per-qblock participation markers, filed once per node and solution number.

This should be thrown away in favor of explicit on-chain data. Remarks make the
indexer parse opaque JSON events, make fallback behavior runtime-dependent, and
force dashboard/indexer code to understand miner-local conventions instead of
typed chain state.

## Python Client Changes

### PoW qblock queries

Add wrappers in `../quip-protocol/substrate/client.py`:

```python
query_latest_qblock_id() -> Optional[int]
query_qblock_by_id(qblock_id: int) -> Optional[WinningSolutionWithNonce]
query_qblock_by_block(block_number: int) -> Optional[WinningSolutionWithNonce]
query_qblock_id_by_block(block_number: int) -> Optional[int]
query_current_hardness() -> SubstrateDifficulty
```

Expose the same calls through:

- `../quip-protocol/substrate/pool_client.py`;
- `../quip-protocol/substrate/pool.py` idempotent operation list;
- pool/client tests.

Keep `query_winning_solution_count()` only as a temporary compatibility
fallback.

### PoW solution number

Replace the current `count(WinningSolutions) + 1` logic with:

```text
solution_number = latest_qblock_id + 1
fresh chain     = 1
```

Primary call sites:

- `SubstrateMinerController._query_winning_solution_count_safe`;
- `SubstrateMinerController._resolve_solution_number`;
- comments and log metadata that still describe solution numbers as a
  `WinningSolutions` key count.

After a successful proof submission, continue verifying by substrate block
number, but prefer the qblock-named runtime API:

```text
qblock_by_block(block_number)
qblock_id_by_block(block_number)
```

Record `qblock_id` alongside `chain_block_number` in local submission logs.

### Mempool discovery

Add wrappers:

```python
query_open_order_ids(start_after: Optional[int] = None, limit: int = 100) -> list[int]
query_order_result(order_id: int)
query_order_top_solvers(order_id: int)
```

The mempool controller should become state-first:

1. On startup, page through `open_order_ids`.
2. Feed each id into the existing `_consider_order(order_id)` path.
3. Periodically rescan open ids, or rescan on block wakeups with throttling.
4. Keep `JobProposed` events only as a low-latency fast path.
5. Keep `OrderExpired` events only as hints; status reads remain authoritative.

This lets a standalone miner recover after downtime without replaying events.

## Runtime Change

### Preferred shape

Add a new pallet, tentatively `pallet-miner-registry`, instead of overloading
`pallet-quantum-pow` or `pallet-quantum-compute-mempool`.

Rationale:

- descriptors apply to both PoW miners and mempool solvers;
- participation is observability data, not PoW validation data;
- keeping this in one pallet gives the indexer one typed chain source for miner
  metadata;
- the chain stores raw facts only and does not compute dashboard aggregates.

Because the network will be recreated with the new schema, no migration is
needed.

### Runtime integration

Add the pallet to the runtime with the next stable pallet index. Since the
network will be recreated, index selection only needs to be stable from this
schema onward.

The registry pallet needs access to the current candidate qblock id:

```text
candidate_qblock_id = QuantumPow.latest_qblock_id().unwrap_or(0) + 1
```

Prefer a small trait boundary so the registry does not hard-code storage access:

```rust
pub trait QBlockIdProvider {
    fn latest_qblock_id() -> Option<u64>;

    fn candidate_qblock_id() -> u64 {
        Self::latest_qblock_id().unwrap_or(0).saturating_add(1)
    }
}
```

Implement that trait for `pallet_quantum_pow::Pallet<T>` and wire it into the
registry pallet config.

### Storage

Store the latest descriptor per account:

```rust
NodeDescriptors<AccountId> -> NodeDescriptor
```

Suggested type:

```rust
pub struct NodeDescriptor<BoundedString, MinerSpecs, RpcEndpoints, BlockNumber> {
    pub schema_version: u16,
    pub node_id: BoundedString,
    pub node_name: BoundedString,
    pub public_host: Option<BoundedString>,
    pub public_port: Option<u16>,
    pub rpc_endpoints: RpcEndpoints,
    pub auto_mine: bool,
    pub log_level: LogLevel,
    pub miners: MinerSpecs,
    pub payload_hash: H256,
    pub updated_at: BlockNumber,
}
```

Descriptor data should be decoded into typed runtime fields instead of stored
as opaque JSON bytes. This prevents miners from submitting irrelevant data and
makes schema migrations formal: a runtime upgrade can add a new descriptor
version and either continue accepting older versions or reject them with an
explicit error.

Every bounded string field must have a reasonable maximum length. Field-specific
bounds prevent descriptor storage from becoming an unstructured large-byte
escape hatch.

Suggested descriptor string bounds:

```text
node_id              <= 64 bytes
node_name            <= 64 bytes
public_host          <= 253 bytes
rpc_endpoint         <= 256 bytes each
rpc_endpoints        <= 8 entries
miner label/name     <= 64 bytes
miner backend/vendor <= 32 bytes
miner device id      <= 64 bytes
```

Prefer enums for small controlled vocabularies (`log_level`, miner kind,
backend/vendor where practical) instead of bounded strings. Use bounded strings
only for operator-provided labels, hostnames, endpoint URLs, and device ids.

Keep the original `payload_hash` as a stable off-chain audit handle. It can be
the hash of the canonical descriptor bytes submitted by `../quip-protocol`, but
the chain must validate and store the typed fields that matter to the protocol
and indexer.

Store only the latest participation per account, not historical per-qblock
participation storage:

```rust
LatestParticipation<AccountId> -> ParticipationRecord
```

Suggested type:

```rust
pub enum MinerKind {
    Cpu,
    Gpu,
    QpuDwave,
    QpuIbm,
    QpuIonq,
    QpuPasqal,
    Asic,
}

pub struct ParticipationRecord<BlockNumber> {
    pub qblock_id: u64,
    pub kind: MinerKind,
    pub budget_seconds: Option<u32>,
    pub updated_at: BlockNumber,
}
```

The indexer gets historical participation from typed events. The storage entry
is only for deduplication and latest-state queries, so chain state grows by
account, not by `(qblock_id, account)`.

### Extrinsics

Add signed calls:

```rust
set_descriptor(descriptor: NodeDescriptorInput)
clear_descriptor()
participate(qblock_id: u64, kind: MinerKind, budget_seconds: Option<u32>)
```

Validation:

- `set_descriptor` validates `schema_version` against the runtime-supported
  descriptor versions.
- `set_descriptor` validates required fields, bounded string lengths, bounded
  lists, enum values, port ranges, and miner inventory structure.
- `set_descriptor` rejects descriptors with no miner specs or no useful
  identity fields.
- `set_descriptor` rejects unsupported/irrelevant data by construction because
  `NodeDescriptorInput` contains only known fields.
- `set_descriptor` stores the typed descriptor and stores
  `blake2_256(canonical_descriptor_bytes)` as `payload_hash` for audit.
- Off-chain JSON validation in `../quip-protocol` remains useful for operator
  errors before signing, but on-chain validation is authoritative.
- `participate` requires `qblock_id == candidate_qblock_id`.
- `participate` rejects duplicate participation by the same account for the
  same qblock id.
- Prefer requiring a descriptor before participation. Startup already treats
  descriptor filing as mandatory, and this keeps anonymous participation spam
  out of the typed stream.

Consider reserving balance for descriptor storage:

```rust
DescriptorDepositBase
DescriptorDepositPerByte
```

On descriptor update, adjust the reserved amount to the new payload size. On
clear, unreserve it.

### Events

Emit typed events:

```rust
DescriptorUpdated {
    who,
    payload_hash,
    payload_len,
}

DescriptorCleared {
    who,
}

MinerParticipated {
    qblock_id,
    who,
    kind,
    budget_seconds,
}
```

The descriptor event does not need to include the full payload because the
payload is stored in `NodeDescriptors`. The participation event should include
all participation fields so the indexer does not need an immediate storage
read.

### Runtime APIs

Storage queries are enough for `substrate-interface`, but runtime APIs can make
the Python client less dependent on storage names:

```rust
node_descriptor(account) -> Option<NodeDescriptor>
latest_participation(account) -> Option<ParticipationRecord>
```

These are convenience APIs only. They should not return aggregate statistics.

### Descriptor schema versioning

The registry should define a formal descriptor schema in Rust types. Avoid
accepting arbitrary JSON payloads into storage.

Suggested approach:

```rust
pub enum NodeDescriptorInput<...> {
    V1(NodeDescriptorV1Input<...>),
}
```

`set_descriptor` matches the versioned input, validates it, and converts it
into the stored `NodeDescriptor`. Future schema changes add `V2` rather than
overloading loose byte payloads. This gives the runtime a clear migration path
and gives `../quip-protocol` a precise target for SCALE encoding.

## Replacing Remarks in `../quip-protocol`

### Descriptor flow

Keep the existing descriptor builder and validator in Python.

Replace remark submission with:

```python
set_node_descriptor(payload: bytes)
query_node_descriptor(account: bytes)
```

Update:

- startup auto-identify in `quip_cli.py`;
- `quip-miner identify`;
- dry-run behavior, which can still print canonical JSON without submitting;
- retry/verification logic, which should verify `payload_hash` from storage
  instead of waiting for a remark event.

### Participation flow

Replace `_mark_participating` and `_submit_participation_remark` with:

```python
participate_qblock(
    qblock_id=solution_number,
    kind=miner_kind,
    budget_seconds=optional_budget,
)
```

The existing worker `"participating"` message can remain as the internal
trigger, but the controller should submit the typed runtime call instead of a
remark.

Once this is wired:

- remove `../quip-protocol/substrate/remark.py`;
- remove `System.remark_with_event` fallback tests;
- remove remark-specific comments from `quip_cli.py` and
  `substrate/miner_controller.py`;
- update `quip-miner.example.toml` comments that mention descriptor remarks.

## Indexer Contract

The indexer should use:

- `NodeDescriptors` storage for the latest node descriptor by account;
- `DescriptorUpdated` and `DescriptorCleared` events to know when to refresh;
- `MinerParticipated` events for participation history;
- qblock runtime APIs or storage for qblock identity and winning payloads;
- mempool open-order APIs or storage for current job discovery.

The indexer should continue to compute aggregate statistics itself. The runtime
should not add counters, charts, participation rates, fleet summaries, or
dashboard-specific rollups.

## Implementation Order

1. Add `pallet-miner-registry` with descriptor storage and typed events.
2. Add participation storage, validation, and typed events.
3. Wire the pallet into `runtime`, bump `spec_version`, and add tests.
4. Add Python client/pool wrappers for qblock, open-order, descriptor, and
   participation APIs.
5. Switch PoW solution numbering to `latest_qblock_id + 1`.
6. Switch mempool discovery to `open_order_ids` plus `job_order`.
7. Replace auto-identify and `quip-miner identify` remarks with
   `set_descriptor`.
8. Replace participation remarks with `participate`.
9. Remove `substrate/remark.py` and remark-specific tests.
10. Update miner, indexer, and dashboard-facing docs.

## Test Plan

Runtime tests:

- descriptor set stores payload, hash, block number, and reserves deposit;
- descriptor update adjusts reserved deposit;
- descriptor clear removes storage and unreserves deposit;
- oversized and empty descriptors are rejected;
- participation for the current candidate qblock id succeeds;
- duplicate participation for the same account and qblock id is rejected;
- stale and future qblock ids are rejected;
- participation after a qblock win succeeds for the next candidate id;
- descriptor requirement for participation is enforced if adopted.

Python tests:

- pool/client wrappers encode and route the new runtime API calls;
- solution number resolution uses `latest_qblock_id + 1`;
- fresh chain solution number resolves to `1`;
- qblock id is recorded in submission logs after verification;
- mempool controller seeds work from `open_order_ids`;
- event-based `JobProposed` remains a fast path but not the only path;
- identify submits `set_descriptor` and verifies storage hash;
- participation submits the typed runtime call and no longer composes a System
  remark.
