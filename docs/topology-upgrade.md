# Live Topology Upgrade (Operator Procedure)

How to repoint a running chain to a new default quantum PoW topology — for
example tracking D-Wave `Advantage2_system1` working-graph snapshots across
calibrations, or switching the puzzle class (the v0.2 → h = 0 spin-glass
upgrade).

Topologies are immutable once registered, and `register_topology` only seeds
`DefaultTopology` on the very first registration. Upgrading a live chain is a
three-step sudo sequence (the quip-testnet sudo holder is operator 1; see
`docs/genesis-quip-testnet.md`):

## 1. Register the new topology

`Sudo.sudo(QuantumPow.register_topology(nodes, edges, allowed_h_values,
allowed_j_values, allowed_spin_values))`

For the h = 0 spin-glass class on Advantage2_system1:

| Field | Value | Notes |
| --- | --- | --- |
| `nodes`, `edges` | working-graph snapshot | Active qubits/couplers from `solver.properties` (`qubits`, `couplers`) at the current calibration, **not** the pristine `zephyr(12,4)` graph. Node labels must match the sampler's linear indices. |
| `allowed_h_values` | `Set([0])` | Every puzzle h is exactly 0. A single-value set is valid; h is never wire-encoded (only spins are packed), so payload size is unaffected. |
| `allowed_j_values` | `Set([-1000, 1000])` | Binary ±J in milli units; inside every solver's `j_range = [-1, 1]`, 1 bit per coupling. |
| `allowed_spin_values` | `Set([-1000, 1000])` | Binary spins, 1 bit per spin in packed solutions. |

Snapshot registrations are expected to recur: each D-Wave recalibration that
changes the working graph gets a fresh registration (a new hash) and a
repoint. Bounds to respect: `QuantumPowMaxNodes = 5000`,
`QuantumPowMaxEdges = 50000`, `MinNodes = 16` — a full Zephyr Z(12,4)
working graph (≤ 4800 nodes) fits.

## 2. Repoint the default

`Sudo.sudo(QuantumPow.set_default_topology(topology_hash))`

The hash must already be registered (`TopologyNotRegistered` otherwise). The
difficulty energy curve is calibrated against the default topology's node and
edge counts *and its h/J value specs* (`expected_gse_for_specs`), so the
curve adjusts to the new puzzle class at the same block. Emits
`DefaultTopologySet`.

Miners submitting against other registered topologies are unaffected in
validity, but the curve — and therefore difficulty motion — follows only the
default (see the miner-independence invariant on `current_energy_curve`).

## 3. Re-baseline difficulty

`Sudo.sudo(QuantumPow.set_difficulty(config))`

The stored `max_energy_milli` was adjusted along the old topology's curve and
may sit outside the new curve's `[min, max]` band (a zero-field curve is
strictly less negative than a ternary-field curve of the same graph). Pick a
starting threshold inside the new band — the `c = 0.700` easy point of the
new curve is a sane reset; decay and proof adjustment take over from there.

## Why h = 0 changes the curve

The expected ground-state energy estimate is

```
E ≈ -c·⟨|J|⟩·√(d̄)·n  -  c·α·⟨|h|⟩·n/√(d̄)        (d̄ = mean degree, α = 0.88)
```

with `⟨|h|⟩` and `⟨|J|⟩` derived from the registered specs. The legacy
ternary spec has `⟨|h|⟩ = 2/3`; `Set([0])` has `⟨|h|⟩ = 0`, dropping the
field term. Without the spec-aware curve, an h = 0 topology would inherit
thresholds targeting energy that no zero-field puzzle can produce.

The empirical `c` calibration constants
(`QuantumPowCurveC{Easy,Knee,Hard}Milli`) were fitted with the field term
present; expect to re-measure them against real solver runs on the new
puzzle class and adjust via runtime upgrade if mining times drift.

## Follow-ups outside this repo

- `quip-protocol-2`: working-graph snapshot tooling (dump `solver.properties`
  qubits/couplers into a `register_topology` payload) belongs next to
  `shared/miner_bootstrap.py`, which already builds dev-chain payloads; its
  `--seed-chain` defaults still register the legacy ternary-h spec.
- Miner energy/expectation models that mirror `expected_gse` must mirror the
  spec-aware form for the new default topology.
