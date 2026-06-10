# Quantum Compute Mempool

## Canonical Plain Ising Job Spec

`QuantumComputeMempool` seeds a default plain Ising job spec at genesis so SDKs
can call `propose_job` without first registering a spec.

Canonical tuple:

```text
name = "plain-ising-v1"
formulation = Ising
validation_program = None
transform_program = None
```

The `spec_id` is the runtime hash of the SCALE-encoded tuple:

```text
(name, formulation, validation_program, transform_program)
```

Pinned `spec_id`:  
NOTE: This value is verified by CI (default_ising_spec_id_is_pinned and default_ising_spec_id_matches_pinned_hash);
if any tuple field changes, those tests will fail.

```text
0x8f46f3a31321d1d093314fc769c42cbe7a83d71a0b69e6571a0f68e2a04067f0
```

SDKs may hardcode this value or read the `DefaultIsingSpecId` pallet constant
from metadata. Additional job specs are team-controlled: `register_job_spec`
requires root origin and records an explicit builder account supplied by root.

## Coefficient and Solution Domains

`QuantumComputeMempool` stores plain Ising problems. The on-chain solution
domain is spin space:

```text
s_i in {-1, +1}
```

The pallet does not accept binary solution values such as `0` and `1` for
plain Ising jobs. If an SDK accepts a QUBO or binary-domain model from a user,
the SDK should transform it off-chain before calling `propose_job`, and should
map returned spin solutions back to the user's binary domain if needed:

```text
x_i = (s_i + 1) / 2
s_i = 2x_i - 1
```

Coefficients are fixed-point milli values. `h_values` and `j_values` are
`i32` values where `1000` represents `1.0`. For example:

```text
5.0   -> 5000
0.25  -> 250
-1.5  -> -1500
```

The same milli convention is used for `best_energy_milli`,
`min_energy_milli`, `diversity_milli`, and `min_diversity_milli`. Keep any
constant offset introduced by a QUBO-to-Ising transform in the adapter, or
adjust user-facing energy thresholds before submitting the job.

## Accepted Solution Storage

Accepted solver submissions are stored in `OrderSolutions`, a `DoubleMap`
keyed first by `order_id` and second by solver account:

```rust
pub type OrderSolutions<T: Config> = StorageDoubleMap<
    _,
    Blake2_128Concat,
    u64,
    Blake2_128Concat,
    T::AccountId,
    JobSolutionOf<T>,
>;
```

Each stored `JobSolution` contains:

```text
solver
solver_type
solutions
best_energy_milli
diversity_milli
num_valid
submitted_at
```

Because this storage item is exposed through runtime metadata, SDKs can query
it through the standard Substrate storage RPC. No custom RPC is needed unless a
client cannot perform or decode metadata-backed `DoubleMap` prefix queries.

### Query with substrate-interface

Install the Python client:

```bash
pip install substrate-interface
```

Connect to a node over websocket:

```python
from substrateinterface import SubstrateInterface

substrate = SubstrateInterface(url="ws://127.0.0.1:9944")
```

Read one solver's accepted submission for an order:

```python
order_id = 0
solver_ss58 = "5..."

solution = substrate.query(
    module="QuantumComputeMempool",
    storage_function="OrderSolutions",
    params=[order_id, solver_ss58],
)

if solution.value is not None:
    print(solution.value["solver"])
    print(solution.value["solutions"])
    print(solution.value["best_energy_milli"])
    print(solution.value["diversity_milli"])
```

Read all accepted submissions for one order by querying the `DoubleMap` with
only the first key:

```python
order_id = 0

rows = substrate.query_map(
    module="QuantumComputeMempool",
    storage_function="OrderSolutions",
    params=[order_id],
    page_size=100,
)

for solver_key, solution in rows:
    print("solver key:", solver_key.value)
    print("stored solver:", solution.value["solver"])
    print("solutions:", solution.value["solutions"])
    print("best energy:", solution.value["best_energy_milli"])
    print("diversity:", solution.value["diversity_milli"])
```

Use `block_hash=` on `query` or `query_map` when an adapter needs a historical
or finalized view instead of the current best block.

## Job Lifecycle Events

`QuantumComputeMempool` emits lifecycle events that SDKs can monitor through
`System.Events`. The most useful events for result retrieval are:

```text
JobProposed
SolutionAccepted
FirstSolutionReceived
BlockWaitStarted
FrontRunnerChanged
OrderExpired
OrderClosed
ResultReady
```

`SolutionAccepted` is emitted when a solver submission is accepted and written
to `OrderSolutions`. `ResultReady` is emitted when settlement produces a final
winner payload for callback delivery modes.

`OrderExpired` is emitted lazily when an extrinsic touches an expired open
order and the pallet updates the status. It is not emitted automatically at the
exact expiry block, so SDKs that need exact deadline handling should also read
`JobOrders` and compute the effective expiry from `created_at`,
`first_solution_at`, `deadline_blocks`, and `block_wait`.

### Read events from a block with substrate-interface

```python
EVENTS = {
    "JobProposed",
    "SolutionAccepted",
    "FirstSolutionReceived",
    "BlockWaitStarted",
    "FrontRunnerChanged",
    "OrderExpired",
    "OrderClosed",
    "ResultReady",
}


def mempool_events_at(block_hash=None):
    for event in substrate.get_events(block_hash=block_hash):
        if (
            event.event_module.name == "QuantumComputeMempool"
            and event.event.name in EVENTS
        ):
            yield event


for event in mempool_events_at():
    print(event.event.name, event.params)
```

### Subscribe to event storage with substrate-interface

For live best-block monitoring, subscribe to `System.Events` and filter the
decoded event records:

```python
def event_name_from_storage_record(record):
    event = record.get("event", {})
    module = event.get("module_id") or event.get("module")
    name = event.get("event_id") or event.get("name")
    return module, name


def handle_events(events_obj, update_nr, subscription_id):
    if update_nr == 0:
        return None

    for record in events_obj.value:
        module, name = event_name_from_storage_record(record)
        if module == "QuantumComputeMempool" and name in EVENTS:
            print(name, record)

    return None


substrate.query(
    module="System",
    storage_function="Events",
    subscription_handler=handle_events,
)
```

For finalized-only processing, subscribe to finalized or imported block
headers in the adapter process, then call `get_events(block_hash=...)` for each
block hash before acting on the events.
