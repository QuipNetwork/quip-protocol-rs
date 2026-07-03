# Indexer-Free Quantum Storage and RPC Plan

## Context

`../quip-protocol` and `../dashboard.quip.network` should be able to read the
quantum PoW and quantum compute mempool state directly from the node without a
separate indexer.

The chain should expose enough state for:

- current PoW hardness;
- qblock lookup by monotonic qblock id;
- qblock lookup by substrate block number;
- mempool job discovery after client downtime;
- live event subscriptions for low-latency UI and miner updates.

## General Idea

Goals are:

1. `quip-miner` in isolation should not require an indexer.
2. The indexer overall should do less work if possible, and should not need to
   query both the miner and the chain for the same data. Only one source should
   be needed when possible.

A consequence is that the dashboard becomes less complicated: it should be
limited to talking with the indexer, which should provide all necessary data.
That said, the chain should not compute aggregate statistics. Aggregate
statistics are the indexer's job.

## Terminology

A **qblock** is a substrate block that contains a winning quantum PoW proof.

`qblock_id` is a chain-assigned integer ordinal. It is monotonic and increments
only when a new qblock is accepted. It is not the substrate block number.

Recommended convention:

```text
first qblock_id = 1
next qblock_id = previous qblock_id + 1
```

## Current State

`pallet-quantum-pow` already has runtime APIs for:

- `mining_snapshot(topology_hash)`;
- `topology_meta(hash)`;
- `winning_solution(block_number)`;
- `current_difficulty()`.

This is enough for current hardness if clients treat hardness as the effective
`DifficultyConfig`.

It is not enough for ordinal qblock lookup because `WinningSolutions` is keyed
by substrate block number.

`pallet-quantum-compute-mempool` already supports point lookups for job orders,
solutions, top solvers, solver records, proposer orders, and stored results.
However, it does not expose a restart-safe open-job index. Today clients can
discover jobs from block events, but a client that was offline must scan history
or know the relevant order ids.

## Goals

- Keep existing storage and runtime APIs compatible where practical.
- Add ordinal qblock ids as durable chain state.
- Expose qblock lookup by id and by block number.
- Expose current hardness with a stable client-facing name.
- Add enough mempool indexing for miner and dashboard clients to recover from
  downtime without an indexer.
- Prefer runtime APIs and metadata-backed storage queries before adding custom
  node JSON-RPC.

## Non-Goals

- Do not replace archive-node or indexer workflows for deep historical
  analytics.
- Do not write a data-preserving migration: the network upgrade wipes PoW and
  mempool state rather than carrying v0.2 data forward (see Migration Decision).
- Do not require clients to consume events as their only source of truth.
- Do not add custom JSON-RPC unless runtime APIs and storage queries are not
  sufficient for the dashboard deployment model.

## Quantum PoW Changes

### Storage

Keep the block-number keyed qblock store, now under its natural `QBlocks`
prefix (the legacy `WinningSolutions` storage alias is dropped — the network
upgrade wipes the old data, so there is nothing to stay prefix-compatible with):

```rust
QBlocks<BlockNumber, QBlock>
```

Add ordinal qblock indexes:

```rust
QBlockCount: u64
QBlockBlockById: qblock_id -> block_number
QBlockIdByBlock: block_number -> qblock_id
```

`QBlocks` remains the canonical qblock payload store. The new maps provide
stable lookup paths for clients that address qblocks by ordinal id.

### Runtime APIs

Add or document these runtime APIs:

```rust
current_hardness() -> DifficultyConfig
latest_qblock_id() -> Option<u64>
qblock_by_id(qblock_id: u64) -> Option<QBlockWithNonce>
qblock_by_block(block_number: BlockNumber) -> Option<QBlockWithNonce>
qblock_id_by_block(block_number: BlockNumber) -> Option<u64>
```

`current_hardness()` may be an alias for `current_difficulty()` if the returned
shape stays `DifficultyConfig`.

### Events

When a winning qblock is accepted, emit enough identifiers for live consumers:

```text
qblock_id
block_number
miner
energy_milli
```

This lets `../quip-protocol` and `../dashboard.quip.network` update live views
without deriving the ordinal id from storage scans.

## Quantum Compute Mempool Changes

### Storage Indexes

Add maintained indexes for discovery:

```rust
OpenOrders: order_id -> ()
```

Consider additional indexes if the clients need them:

```rust
ClosedOrders: order_id -> ()
ExpiredOrders: order_id -> ()
SolverOrders: solver -> bounded/order-id index
ClaimableOrdersBySolver: solver -> bounded/order-id index
```

The minimum useful change is `OpenOrders`. It lets miners and dashboards recover
the active job set without replaying historical events.

#### Ordering and Pagination Consideration

`OpenOrders` as a map is good for metadata-backed storage prefix queries, but
its storage keys are not a naturally ordered numeric cursor. The initial
runtime API can scan the maintained `OpenOrders` index, filter by
`start_after`, sort the resulting ids, and return a bounded page. This is
acceptable while the active job set is expected to stay small.

Revisit this if active order counts grow enough that scanning the full open
index becomes too expensive. At that point, consider an explicitly ordered
index, such as a bounded active-order list, a page-bucketed index, or another
storage layout designed around cursor-based iteration.

### Runtime APIs

Add query APIs around the indexed state:

```rust
open_order_ids(cursor: Option<u64>, limit: u32) -> Vec<u64>
job_order(order_id: u64) -> Option<JobOrder>
order_result(order_id: u64) -> Option<StoredResult>
order_top_solvers(order_id: u64) -> Vec<RankedSolver>
solver_orders(solver: AccountId, cursor: Option<u64>, limit: u32) -> Vec<u64>
claimable_orders(solver: AccountId, cursor: Option<u64>, limit: u32) -> Vec<u64>
```

`solver_orders` and `claimable_orders` can be deferred if `../quip-protocol`
can derive them safely from local submitted-order state plus point lookups.

### Events

Keep events for subscriptions, but do not make them the only recovery path.
Useful event payloads should include the affected `order_id`, status transition,
and any solver account needed by live clients.

## Node RPC Direction

The preferred first step is runtime APIs plus metadata-backed storage queries.
This keeps read semantics versioned with the runtime and works with
`substrate-interface` and polkadot.js.

Custom node JSON-RPC should be added only if the dashboard must call a node
directly without SCALE metadata handling. If needed, expose thin read-only
facades:

```text
quantumPow_currentHardness
quantumPow_qblockById
quantumPow_qblockByBlock
quantumMempool_openOrders
quantumMempool_order
```

## Client Changes

### `../quip-protocol`

- Use `current_hardness()` or `current_difficulty()` for hardness.
- Use `latest_qblock_id()` and `qblock_by_id()` for qblock ordinal lookups.
- Use `qblock_by_block()` for compatibility with block-number based paths.
- Replace mempool open-job discovery from event replay with `open_order_ids()`
  plus `job_order(order_id)`.
- Keep event subscriptions for fast updates.

### `../dashboard.quip.network`

- Use ordinal qblock ids for qblock detail pages and latest qblock displays.
- Use paged qblock id lookup if historical qblock lists are required.
- Use `OpenOrders` or `open_order_ids()` for current mempool views.
- Keep a lightweight cache if the UI needs charts or aggregates that would
  otherwise require broad historical scans.

## Migration Decision

The network upgrade runs a migration, but it does not carry any v0.2 data
forward — it drops it.

Each of `pallet-quantum-pow` and `pallet-quantum-compute-mempool` bumps its
`STORAGE_VERSION` (1 → 2) and, in `on_runtime_upgrade`, clears its entire pallet
prefix once on the live chain (which also reaps the renamed `WinningSolutions`
entries). The mempool then reseeds the canonical default Ising spec exactly as
genesis would; PoW needs no reseed (`Difficulty` reads back at its `Default`).

Because the data is wiped, no qblock index backfill and no data-preserving
migration are needed: historical `WinningSolutions` entries are simply dropped
rather than translated into the new ordinal qblock index. Fresh chains are
seeded at version 2 by genesis and skip the migration via its version guard.

## Implementation Order

1. Add PoW qblock id storage and runtime APIs.
2. Add qblock id event payloads.
3. Add minimum mempool discovery index, starting with open orders.
4. Add mempool runtime APIs around indexed state.
5. Update `../quip-protocol` to prefer runtime APIs and indexed storage.
6. Update `../dashboard.quip.network` to remove indexer-only assumptions.
7. Add pallet, runtime API, and client tests for the new query paths.
