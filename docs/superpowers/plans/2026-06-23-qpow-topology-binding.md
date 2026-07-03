# QPoW Per-Topology Difficulty + Mineable Whitelist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind PoW difficulty to each topology hash and gate mining on a root-controlled whitelist, so a switch of `DefaultTopology` is clean and one topology's miners can never pin another topology's difficulty.

**Architecture:** Replace the single global `Difficulty: StorageValue<DifficultyConfig>` with `Difficulties: StorageMap<H256, DifficultyConfig>`; key every difficulty read/write/adjustment on a `topology_hash`. Add `MineableTopologies: StorageMap<H256, ()>` as a root-managed whitelist that `submit_proof` and `set_default_topology` enforce. Carry the old global value forward in a storage migration. Round/decay/last-proof state stays global (model A — single active topology). Thread the new surface through the runtime API and the Python client.

**Tech Stack:** Rust / Substrate (FRAME) pallet, `frame_benchmarking::v2`, `sp_api::decl_runtime_apis`; Python `substrateinterface` client (sibling repo `../quip-protocol`).

## Global Constraints

- **Concurrency model (A), DECIDED:** at most one topology is actively mined at a time. `LastProofBlock`, `LastProofBlockHash`, `WinnerStreak`, `BlockProofCount`, and the decay step **stay GLOBAL**. Only `DifficultyConfig` becomes per-topology. Do **not** build per-topology rounds or any cross-topology winner rule (that is deferred model B).
- **Whitelist storage:** `MineableTopologies: StorageMap<_, Blake2_128Concat, H256, ()>` (a set). Membership is `contains_key`; enumeration for the runtime API is `iter_keys`. No new `MaxMineableTopologies` config bound.
- **`set_default_topology` semantics (DECIDED):** reject a non-whitelisted hash with `Error::TopologyNotMineable`. No auto-whitelist.
- **`remove_mineable_topology` semantics (DECIDED):** refuse to remove the current `DefaultTopology` with `Error::TopologyIsDefault`.
- **Migration (DECIDED — defensive):** bump pallet `STORAGE_VERSION` 2 → 3. Rewrite `on_runtime_upgrade` to branch on the on-chain version: `==2` ⇒ carry-forward (global `Difficulty` → `Difficulties[DefaultTopology]`, seed `MineableTopologies[DefaultTopology]`, kill old `Difficulty`); `<2` ⇒ legacy wipe then init (preserve existing behavior for any un-upgraded v0.2 chain); `>=3` ⇒ noop. Keep the migration **in-pallet** (the `on_runtime_upgrade` hook), matching the existing pattern; `SingleBlockMigrations` stays `()`.
- **Runtime-API changes are ADDITIVE.** `mining_snapshot(Option<H256>)`, `current_difficulty()`, `current_hardness()` keep their signatures (now resolved per-topology / against the default). Add `difficulty_for(H256) -> Option<DifficultyConfig>` and `mineable_topologies() -> Vec<H256>`.
- **Versioning (per the team's documented rule in `runtime/src/lib.rs:64-104`):** `spec_version` 107 → 108; `transaction_version` 3 → 4 (because `set_difficulty`'s call-argument encoding changes). Append a `// Bumped to 108 …` comment block to the `VERSION` literal.
- **Call indices:** `add_mineable_topology` = `call_index 6`, `remove_mineable_topology` = `call_index 7`. Existing indices (0–5) are immutable.
- **Crate/package names:** pallet `pallet-quantum-pow`, runtime `quip-protocol-runtime`, node `quip-network-node`.
- Follow the repo's standard AGPL-3.0-or-later license header convention for any *new* file (the Python `tools/*` files already carry it; new Rust files are not required here — all Rust edits are to existing files).
- **Self-consistency invariant for model (A):** with exactly one registered/whitelisted topology, per-topology behavior is byte-identical to the old global behavior. Existing difficulty-adjustment tests must keep passing after the storage-access rewrite.
- **Global decay/hardness on a default switch (DECIDED — leave as-is):** `LastProofBlock` (decay anchor) and the just-won hardness adjustment stay global. When `DefaultTopology` switches A→B, B's per-topology difficulty is read through global decay anchored to A's last win. This is a non-issue under model (A): only one topology is mined at a time, and on an actively-mining chain `LastProofBlock` is always ~one win old (~25s) so the read is effectively undecayed at switch time. It would only matter under concurrent multi-topology mining (model B); when model B lands, **reset hardness/round state at the switch** (the per-topology `Difficulties` map built here is the reset target). Document this in a code comment on `set_default_topology`; do **not** change `LastProofBlock` semantics in this PR.
- **Default difficulty fallback is intentionally hard:** an entry-less topology reads `DifficultyConfig::default()` (`max_energy_milli = -1_200_000` milli ≈ −1200 energy units — far below any achievable solution energy for realistic topologies, whose best energies sit near −15 units / −15_000 milli). So a whitelisted-but-not-yet-`set_difficulty`'d topology is effectively **unmineable** (fails closed), never trivially clearable. Operator runbook ordering: `register_topology` → `set_difficulty(hash, calibrated)` → `add_mineable_topology(hash)` → `set_default_topology(hash)`.

---

## File Structure

| File | Responsibility / change |
|------|-------------------------|
| `pallets/quantum-pow/src/types.rs` | Add `topology_hash: H256` to `ProofRecord`. |
| `pallets/quantum-pow/src/lib.rs` | Storage (`Difficulties` map, `MineableTopologies`); errors/events; per-topology internal fns (`energy_curve_for`, `current_difficulty_for`); `submit_proof`/`on_finalize`/`mining_snapshot` rewrites; `set_difficulty` arg; new whitelist extrinsics; whitelist enforcement; rewritten `on_runtime_upgrade` (v3); `decl_runtime_apis` additions + their pallet impls. |
| `pallets/quantum-pow/src/difficulty.rs` | **No code change.** (Pure fns already take all inputs.) Only a doc comment touch-up in `lib.rs` references it. |
| `pallets/quantum-pow/src/weights.rs` | Add `add_mineable_topology`/`remove_mineable_topology` to the trait + both impls; bump `set_difficulty` reads by 1. |
| `pallets/quantum-pow/src/benchmarking.rs` | New benchmarks for the two whitelist extrinsics; update `set_difficulty`/`submit_proof` benchmarks for per-topology storage. |
| `pallets/quantum-pow/src/mock.rs` | **No change** (`WeightInfo = ()` is covered by `weights.rs`'s `()` impl). |
| `pallets/quantum-pow/src/tests.rs` | New helpers (`default_hash`, `set_difficulty_default`, `difficulty_default`, auto-whitelist in `registered_topology`); per-topology rewrite of difficulty sites; new whitelist + per-topology-independence + migration tests; rewrite the two old migration tests. |
| `runtime/src/apis.rs` | Resolve default topology in `current_difficulty`/`current_hardness`; implement `difficulty_for`/`mineable_topologies`. |
| `runtime/src/lib.rs` | `spec_version` 108, `transaction_version` 4, changelog comment. |
| `../quip-protocol/substrate/client.py` | `query_difficulty(topology_hash=None)` per-topology; `query_mineable_topologies()`; `add_mineable_topology`/`remove_mineable_topology` helpers. |
| `../quip-protocol/substrate/miner_bootstrap.py` | Thread `topology_hash` into the `set_difficulty` sudo call; optional whitelist seeding. |
| `../quip-protocol/tools/register_advantage2.py` | Thread `target_hash` into `set_difficulty`; add `--mineable` → `add_mineable_topology`. |
| `../quip-protocol/tools/download_and_validate_wins.py` | Confirm per-topology difficulty selection (already snapshot-driven). |

---

## Phase R1 — Per-topology difficulty (consensus core)

### Task 1: `ProofRecord` carries the winning proof's topology hash

`on_finalize` adjusts the **winning proof's** topology difficulty, but the record it consumes (`BlockBestProof`) currently has no topology hash. Add it.

**Files:**
- Modify: `pallets/quantum-pow/src/types.rs:113-126` (`ProofRecord`)
- Modify: `pallets/quantum-pow/src/lib.rs:759-764` (record construction in `submit_proof`)
- Modify: `pallets/quantum-pow/src/tests.rs:176-185` (`finalize_winner` helper)
- Test: `pallets/quantum-pow/src/tests.rs` (new test)

**Interfaces:**
- Produces: `ProofRecord { miner, submitted_at, energy_milli, salt, topology_hash: H256 }`.

- [ ] **Step 1: Write the failing test.** Add to `tests.rs`:

```rust
#[test]
fn submit_proof_records_topology_hash() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        let (nodes, edges, topology_hash) = registered_topology();
        set_difficulty_default(easy_difficulty());
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        assert_ok!(QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof));

        let record = BlockBestProof::<Test>::get().expect("best proof recorded");
        assert_eq!(record.topology_hash, topology_hash);
    });
}
```

> NOTE: `set_difficulty_default` and the per-topology `registered_topology` whitelist arrive in later tasks. Until then, this test references `set_difficulty_default`, which does not yet exist — that is expected; this task's compile target is the `ProofRecord` field. If executing strictly task-by-task, temporarily inline `assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), topology_hash, easy_difficulty()));` will not compile either (set_difficulty arg lands in Task 4). **Therefore: in Task 1, write the assertion body but gate the difficulty setup through whatever `set_difficulty` signature currently exists** — i.e. for Task 1 in isolation use the *current* global form `assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), easy_difficulty()));` and `Difficulty::<Test>::put` is untouched. Reconcile to `set_difficulty_default` in Task 4's test sweep.

- [ ] **Step 2: Add the field.** In `types.rs`, inside `ProofRecord`, after `salt`:

```rust
    pub salt: [u8; 32],
    /// Topology the winning proof was mined against. `on_finalize` adjusts
    /// the difficulty entry for *this* topology only — never another's.
    pub topology_hash: H256,
}
```

(`H256` is already imported at `types.rs:4`.)

- [ ] **Step 3: Populate it in `submit_proof`.** In `lib.rs`, the record built around line 759:

```rust
            let record = ProofRecordOf::<T> {
                miner: who.clone(),
                submitted_at: frame_system::Pallet::<T>::block_number(),
                energy_milli: validation.best_energy_milli,
                salt: proof.salt,
                topology_hash: proof.topology_hash,
            };
```

- [ ] **Step 4: Fix the `finalize_winner` test helper.** In `tests.rs:178-183`:

```rust
    BlockBestProof::<Test>::put(ProofRecord {
        miner,
        submitted_at: block_number,
        energy_milli: 0,
        salt: [0u8; 32],
        topology_hash: DefaultTopology::<Test>::get().unwrap_or_default(),
    });
```

- [ ] **Step 5: Run tests.** `cargo test -p pallet-quantum-pow` → green (new field, behavior unchanged).
- [ ] **Step 6: Commit** `feat(qpow): record topology_hash on the winning proof`.

---

### Task 2: Difficulty keyed by topology hash

The heart of the change. Replace the global `Difficulty` value with a per-topology map, generalize the energy curve and difficulty wrapper to a `topology_hash`, and point `submit_proof`/`on_finalize`/`mining_snapshot` at each proof's own topology. `set_difficulty`'s new `topology_hash` arg lands in **Task 4** (kept separate so the call-encoding/`transaction_version` change is isolated); in this task `set_difficulty` writes `Difficulties[DefaultTopology]` to stay compilable.

**Files:**
- Modify: `pallets/quantum-pow/src/lib.rs` — storage (206-207), `submit_proof` (739), `on_finalize` (456-482), `mining_snapshot` (825-849), helpers (808-810, 950-977), `set_difficulty` (676-684, interim).
- Modify: `runtime/src/apis.rs:263-269` (resolve default for `current_difficulty`/`current_hardness`).
- Modify: `pallets/quantum-pow/src/tests.rs` — add helpers; mechanically rewrite global-difficulty sites; add independence regression test.
- Modify: `pallets/quantum-pow/src/benchmarking.rs:186` (`Difficulty::<T>::put` → `Difficulties::<T>::insert`).

**Interfaces:**
- Produces (pallet `impl` block):
  - `pub fn current_difficulty_for(topology_hash: H256, block_number: BlockNumberFor<T>) -> types::DifficultyConfig`
  - `fn energy_curve_for(topology_hash: H256) -> Option<crate::difficulty::EnergyCurve>`
  - storage `Difficulties<T> = StorageMap<_, Blake2_128Concat, H256, types::DifficultyConfig>` (no `ValueQuery`; reads use `.unwrap_or_default()`).
- Consumes: `ProofRecord.topology_hash` (Task 1).

- [ ] **Step 1: Write the failing regression test** (the bug's acceptance criterion — independent difficulties). Add to `tests.rs`:

```rust
#[test]
fn winning_topology_does_not_move_other_topology_difficulty() {
    new_test_ext().execute_with(|| {
        // Topology A (ternary-h) is default; topology B (zero-field) is a
        // second registered topology. Each gets its own difficulty entry.
        let (_, _, hash_a) = registered_topology();
        let hash_b = registered_zero_field_topology();

        let diff_a = DifficultyConfig { min_solutions: 1, max_energy_milli: -10_000, min_diversity_milli: 0 };
        let diff_b = DifficultyConfig { min_solutions: 1, max_energy_milli: -20_000, min_diversity_milli: 0 };
        Difficulties::<Test>::insert(hash_a, diff_a);
        Difficulties::<Test>::insert(hash_b, diff_b);

        // A wins (finalize against A). B's difficulty must be untouched.
        LastProofBlock::<Test>::put(1);
        System::set_block_number(80);
        BlockBestProof::<Test>::put(ProofRecord {
            miner: 1, submitted_at: 80, energy_milli: -10_000, salt: [0u8; 32], topology_hash: hash_a,
        });
        QuantumPow::on_finalize(80);

        assert_ne!(Difficulties::<Test>::get(hash_a), Some(diff_a), "A's difficulty must have been adjusted");
        assert_eq!(Difficulties::<Test>::get(hash_b), Some(diff_b), "B's difficulty must NOT move when A wins");
    });
}
```

- [ ] **Step 2: Run it.** `cargo test -p pallet-quantum-pow winning_topology_does_not_move` → FAIL to compile (`Difficulties` undefined). Expected.

- [ ] **Step 3: Swap the storage item.** In `lib.rs`, replace lines 206-207:

```rust
    /// Per-topology difficulty baseline (post-last-adjust; decay is applied
    /// on read by `current_difficulty_for`). Keyed by `topology_hash` so a
    /// `DefaultTopology` switch is clean and one topology's winners can never
    /// pin another's difficulty. Unset entries read back as
    /// `DifficultyConfig::default()`.
    #[pallet::storage]
    pub type Difficulties<T: Config> =
        StorageMap<_, Blake2_128Concat, H256, types::DifficultyConfig>;
```

- [ ] **Step 4: Generalize the energy curve.** In `lib.rs`, replace `current_energy_curve` (950-967) with a hash-parameterized version. Keep the old name removed:

```rust
        /// Build the difficulty energy curve for a specific topology.
        ///
        /// Historically this was hard-pinned to `DefaultTopology` so a miner
        /// could not shift difficulty by choosing a different *registered*
        /// topology to mine against (the old anti-gaming invariant). That
        /// guard is now provided by the **mineable-topology whitelist**: only
        /// whitelisted topologies can be mined, and each owns its own
        /// root-set `Difficulties` entry. Deriving the curve from the proof's
        /// own topology is therefore safe — there is no shared difficulty to
        /// pin.
        ///
        /// Returns `None` when the topology is not registered (defensive: a
        /// proof would not validate, and `set_difficulty` requires
        /// registration).
        fn energy_curve_for(topology_hash: H256) -> Option<crate::difficulty::EnergyCurve> {
            let topology = RegisteredTopologies::<T>::get(topology_hash)?;
            crate::difficulty::EnergyCurve::new(
                topology.nodes.len() as u32,
                topology.edges.len() as u32,
                crate::difficulty::CurveC {
                    easy_milli: T::CurveCEasyMilli::get(),
                    knee_milli: T::CurveCKneeMilli::get(),
                    hard_milli: T::CurveCHardMilli::get(),
                },
                &topology.allowed_h_values.as_slice(),
                &topology.allowed_j_values.as_slice(),
            )
            .ok()
        }
```

- [ ] **Step 5: Generalize the difficulty wrapper.** In `lib.rs`, replace both `current_difficulty_for` (808-810) and the private `current_difficulty` (969-977) with a single per-topology fn:

```rust
        /// Active (decay-applied) difficulty a miner must clear for
        /// `topology_hash` at `block_number`. Reads the per-topology baseline
        /// (`Difficulties[hash]`, defaulting when unset) and applies global
        /// block-based decay since the last winning proof.
        pub fn current_difficulty_for(
            topology_hash: H256,
            block_number: BlockNumberFor<T>,
        ) -> types::DifficultyConfig {
            crate::difficulty::current_difficulty(
                block_number.saturated_into::<u32>(),
                Difficulties::<T>::get(topology_hash).unwrap_or_default(),
                LastProofBlock::<T>::get().saturated_into::<u32>(),
                T::EpochLength::get().saturated_into::<u32>(),
                Self::energy_curve_for(topology_hash),
            )
        }
```

- [ ] **Step 6: Point `submit_proof` at the proof's topology.** In `lib.rs:739`:

```rust
            let current =
                Self::current_difficulty_for(proof.topology_hash, frame_system::Pallet::<T>::block_number());
```

- [ ] **Step 7: Rewrite `on_finalize` to adjust the winning topology.** In `lib.rs`, change the block at 456-482. The winning topology hash comes from `record.topology_hash`:

```rust
            let topology_hash = record.topology_hash;
            // Snapshot the live (decay-applied) threshold this proof had to
            // clear before adjustment rewrites it.
            let active = Self::current_difficulty_for(topology_hash, n);
            let winner_streak = Self::update_winner_streak(&record.miner);
            let dominant_winner = Self::is_dominant_streak(&winner_streak);
            // Adjust ONLY the winning topology's difficulty, using ITS curve.
            let next = match Self::energy_curve_for(topology_hash) {
                Some(curve) => crate::difficulty::adjust_on_proof_with_dominance(
                    active,
                    mining_time_blocks,
                    curve,
                    &(frame_system::Pallet::<T>::parent_hash(), &record.miner, n).encode(),
                    dominant_winner,
                ),
                None => {
                    frame_support::defensive!(
                        "energy curve missing during on_finalize difficulty adjustment"
                    );
                    active
                }
            };
            Difficulties::<T>::insert(topology_hash, next);
```

(The `QBlocks::insert(... difficulty: active ...)` block and `LastProofBlock::put(n)` immediately following are unchanged. Note `active` is still in scope for the `QBlock`.)

- [ ] **Step 8: Per-topology `mining_snapshot`.** In `lib.rs:841`, the snapshot already resolves `topology_hash` at the top; change the difficulty line:

```rust
                difficulty: Self::current_difficulty_for(topology_hash, block_number),
```

- [ ] **Step 9: Interim `set_difficulty`** (keeps the crate compiling; real arg in Task 4). In `lib.rs:676-684`, write to the default topology's entry:

```rust
        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::set_difficulty())]
        pub fn set_difficulty(
            origin: OriginFor<T>,
            difficulty: types::DifficultyConfig,
        ) -> DispatchResult {
            ensure_root(origin)?;
            if let Some(hash) = DefaultTopology::<T>::get() {
                Difficulties::<T>::insert(hash, difficulty);
            }
            Self::deposit_event(Event::DifficultyUpdated { difficulty });
            Ok(())
        }
```

- [ ] **Step 10: Fix the runtime API call sites.** In `runtime/src/apis.rs:263-269`:

```rust
        fn current_difficulty() -> pallet_quantum_pow::types::DifficultyConfig {
            QuantumPow::default_topology()
                .map(|h| QuantumPow::current_difficulty_for(h, System::block_number()))
                .unwrap_or_default()
        }

        fn current_hardness() -> pallet_quantum_pow::types::DifficultyConfig {
            QuantumPow::default_topology()
                .map(|h| QuantumPow::current_difficulty_for(h, System::block_number()))
                .unwrap_or_default()
        }
```

- [ ] **Step 11: Fix the benchmark storage write.** In `benchmarking.rs`, the `submit_proof` benchmark setup (`Difficulty::<T>::put(easy_difficulty())`, ~line 186):

```rust
        Difficulties::<T>::insert(topology_hash, easy_difficulty());
```

> **Benchmark sequencing:** `benchmarking.rs` is only compiled under `--features runtime-benchmarks`, which the plan does not exercise until **Task 6 Step 6**. So the `set_difficulty` benchmark (still single-arg + `assert_eq!(Difficulty::<T>::get(), …)` at ~lines 176-178) is left stale here and is fully rewritten in **Task 4 Step 9** — before Task 6 compiles the file. Use grep-for-pattern (`Difficulty::<T>::`, `set_difficulty(`) rather than fixed line numbers when applying these edits, since earlier edits shift line numbers.

- [ ] **Step 12: Add the three test helpers** to `tests.rs` (near `easy_difficulty`, ~line 46):

```rust
fn default_hash() -> sp_core::H256 {
    DefaultTopology::<Test>::get().expect("a default topology is registered")
}

/// Set the difficulty baseline for the current default topology.
fn set_difficulty_default(difficulty: DifficultyConfig) {
    assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), difficulty));
}

/// Read the (raw, pre-decay) difficulty baseline for the default topology.
fn difficulty_default() -> DifficultyConfig {
    Difficulties::<Test>::get(default_hash()).unwrap_or_default()
}
```

> In Task 4, `set_difficulty_default`'s body becomes `set_difficulty(root, default_hash(), difficulty)`. Defining it now means Task 4 only edits one helper, not 24 call sites.

- [ ] **Step 13: Mechanical site rewrite.** Update the import line `tests.rs:5` (`Difficulty` → `Difficulties`) and apply these two transforms across `tests.rs`:
  - `assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), <d>));` → `set_difficulty_default(<d>);` (the ~17 winning/decay tests that set then read the default topology's difficulty).
  - `Difficulty::<Test>::get()` → `difficulty_default()`; `Difficulty::<Test>::put(<d>)` → `Difficulties::<Test>::insert(default_hash(), <d>)`.
  - Leave `set_difficulty_requires_root` (asserts `BadOrigin`) calling the extrinsic directly with the **current** single-arg form for now; Task 4 adds the hash arg there.
  - `set_difficulty_works` (456-470): defer to Task 4 (it asserts exact storage and will change shape).

  Each rewritten test must still assert the same energy outcome — with one registered topology, per-topology == old global, so assertions are unchanged.

- [ ] **Step 14: Run the suite.** `cargo test -p pallet-quantum-pow` → green, including `winning_topology_does_not_move_other_topology_difficulty`.
- [ ] **Step 15: Compile the runtime.** `cargo check -p quip-protocol-runtime` → clean.
- [ ] **Step 16: Commit** `feat(qpow): key difficulty by topology hash`.

---

## Phase R2 — Mineable-topology whitelist

### Task 3: Whitelist storage, extrinsics, and enforcement

**Files:**
- Modify: `pallets/quantum-pow/src/lib.rs` — storage, errors (307-340), events (267-304), two new extrinsics, enforcement in `submit_proof` (707-708) and `set_default_topology` (663-672).
- Modify: `pallets/quantum-pow/src/tests.rs` — auto-whitelist in `registered_topology`/`registered_zero_field_topology`; new whitelist tests; new `submit_proof` not-mineable test.

**Interfaces:**
- Produces: storage `MineableTopologies<T> = StorageMap<_, Blake2_128Concat, H256, ()>`; errors `TopologyNotMineable`, `TopologyIsDefault`; events `TopologyMineableAdded { topology_hash }`, `TopologyMineableRemoved { topology_hash }`; extrinsics `add_mineable_topology(origin, topology_hash)` (idx 6), `remove_mineable_topology(origin, topology_hash)` (idx 7).

- [ ] **Step 1: Failing test — non-whitelisted proof is rejected.** Add to `tests.rs`:

```rust
#[test]
fn submit_proof_rejects_non_mineable_topology() {
    new_test_ext().execute_with(|| {
        assert_ok!(QuantumPow::register_miner(RuntimeOrigin::signed(1)));
        // Register WITHOUT whitelisting (raw call, not the helper).
        let nodes = bounded::<_, MaxNodes>(vec![0, 1]);
        let edges = bounded::<_, MaxEdges>(vec![(0, 1)]);
        let topology_hash = topology::hash_topology(
            &nodes, &edges,
            &allowed_h_spec().as_slice(), &allowed_j_spec().as_slice(), &allowed_spin_spec().as_slice(),
        );
        assert_ok!(QuantumPow::register_topology(
            RuntimeOrigin::root(), nodes.clone(), edges.clone(),
            allowed_h_spec(), allowed_j_spec(), allowed_spin_spec(),
        ));
        Difficulties::<Test>::insert(topology_hash, easy_difficulty());
        let proof = proof_for(1, &nodes, &edges, topology_hash, &[0]);

        assert_noop!(
            QuantumPow::submit_proof(RuntimeOrigin::signed(1), proof),
            crate::Error::<Test>::TopologyNotMineable
        );
    });
}
```

- [ ] **Step 2: Run it.** `cargo test -p pallet-quantum-pow submit_proof_rejects_non_mineable` → FAIL to compile (`TopologyNotMineable` undefined). Expected.

- [ ] **Step 3: Add storage.** After `Difficulties` in `lib.rs`:

```rust
    /// Root-controlled set of topologies that may be mined. Registration adds
    /// a topology to the catalog (`RegisteredTopologies`); membership here is
    /// what makes it mineable. Steady state is `{ DefaultTopology }`.
    #[pallet::storage]
    pub type MineableTopologies<T: Config> = StorageMap<_, Blake2_128Concat, H256, ()>;
```

- [ ] **Step 4: Add errors.** In the `Error` enum (after `PackedSolutionTooLarge`):

```rust
        /// The proof's topology is registered but not on the mineable
        /// whitelist (`MineableTopologies`).
        TopologyNotMineable,
        /// Refused to remove the current `DefaultTopology` from the mineable
        /// whitelist; repoint the default first.
        TopologyIsDefault,
```

- [ ] **Step 5: Add events.** In the `Event` enum (after `DefaultTopologySet`):

```rust
        TopologyMineableAdded {
            topology_hash: H256,
        },
        TopologyMineableRemoved {
            topology_hash: H256,
        },
```

- [ ] **Step 6: Enforce in `submit_proof`.** In `lib.rs`, right after the `RegisteredTopologies` lookup (708) and before the `GraphTooSmall` check:

```rust
            let topology = RegisteredTopologies::<T>::get(proof.topology_hash)
                .ok_or(Error::<T>::TopologyNotRegistered)?;
            ensure!(
                MineableTopologies::<T>::contains_key(proof.topology_hash),
                Error::<T>::TopologyNotMineable
            );
```

- [ ] **Step 7: Enforce in `set_default_topology`.** In `lib.rs:663-672`, add the whitelist guard after the registration guard:

```rust
            ensure_root(origin)?;
            ensure!(
                RegisteredTopologies::<T>::contains_key(topology_hash),
                Error::<T>::TopologyNotRegistered
            );
            ensure!(
                MineableTopologies::<T>::contains_key(topology_hash),
                Error::<T>::TopologyNotMineable
            );
            // NOTE (model A): `LastProofBlock` (global decay anchor) is NOT
            // reset here. Under single-active-topology mining this is fine —
            // the new default's difficulty reads through decay anchored to the
            // previous win, which on an actively-mining chain is ~one win old.
            // If concurrent multi-topology mining (model B) is added, reset
            // hardness/round state at the switch (see "Future work").
            // Operators should re-baseline via `set_difficulty(hash, …)` before
            // repointing when the curves differ materially.
            DefaultTopology::<T>::put(topology_hash);
```

- [ ] **Step 8: Add the two extrinsics.** In `lib.rs`, after `submit_proof` (end of the `#[pallet::call]` block, ~line 786):

```rust
        /// Add a registered topology to the mineable whitelist. Root only.
        #[pallet::call_index(6)]
        #[pallet::weight(<T as Config>::WeightInfo::add_mineable_topology())]
        pub fn add_mineable_topology(origin: OriginFor<T>, topology_hash: H256) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                RegisteredTopologies::<T>::contains_key(topology_hash),
                Error::<T>::TopologyNotRegistered
            );
            MineableTopologies::<T>::insert(topology_hash, ());
            Self::deposit_event(Event::TopologyMineableAdded { topology_hash });
            Ok(())
        }

        /// Remove a topology from the mineable whitelist. Root only. Refuses
        /// to remove the current `DefaultTopology` so the default is always
        /// mineable.
        #[pallet::call_index(7)]
        #[pallet::weight(<T as Config>::WeightInfo::remove_mineable_topology())]
        pub fn remove_mineable_topology(origin: OriginFor<T>, topology_hash: H256) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                DefaultTopology::<T>::get() != Some(topology_hash),
                Error::<T>::TopologyIsDefault
            );
            MineableTopologies::<T>::remove(topology_hash);
            Self::deposit_event(Event::TopologyMineableRemoved { topology_hash });
            Ok(())
        }
```

- [ ] **Step 9: Auto-whitelist in the test helpers** so existing `submit_proof`/`finalize` tests keep passing. In `tests.rs`, append to `registered_topology` (before its `(nodes, edges, hash)` return, after the `register_topology` `assert_ok!`):

```rust
    MineableTopologies::<Test>::insert(hash, ());
    (nodes, edges, hash)
```

  And to `registered_zero_field_topology` (before `hash` return):

```rust
    MineableTopologies::<Test>::insert(hash, ());
    hash
```

  Add `MineableTopologies` to the `crate::{…}` import at `tests.rs:5-7`.

- [ ] **Step 10: Add whitelist extrinsic tests.** Append to `tests.rs`:

```rust
#[test]
fn add_mineable_topology_requires_root() {
    new_test_ext().execute_with(|| {
        let (_, _, hash) = registered_topology();
        assert_noop!(
            QuantumPow::add_mineable_topology(RuntimeOrigin::signed(1), hash),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn add_mineable_topology_rejects_unregistered() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            QuantumPow::add_mineable_topology(RuntimeOrigin::root(), sp_core::H256::repeat_byte(9)),
            crate::Error::<Test>::TopologyNotRegistered
        );
    });
}

#[test]
fn remove_mineable_topology_refuses_default() {
    new_test_ext().execute_with(|| {
        let (_, _, hash) = registered_topology(); // becomes default + whitelisted
        assert_noop!(
            QuantumPow::remove_mineable_topology(RuntimeOrigin::root(), hash),
            crate::Error::<Test>::TopologyIsDefault
        );
        assert!(MineableTopologies::<Test>::contains_key(hash));
    });
}

#[test]
fn remove_mineable_topology_works_for_non_default() {
    new_test_ext().execute_with(|| {
        let _ = registered_topology();          // default A
        let hash_b = registered_zero_field_topology(); // whitelisted, not default
        assert_ok!(QuantumPow::remove_mineable_topology(RuntimeOrigin::root(), hash_b));
        assert!(!MineableTopologies::<Test>::contains_key(hash_b));
    });
}

#[test]
fn set_default_topology_rejects_non_mineable() {
    new_test_ext().execute_with(|| {
        let _ = registered_topology();          // default A, whitelisted
        // Register B without whitelisting.
        let nodes = bounded::<_, MaxNodes>(vec![0u32, 1, 2, 3]);
        let edges = bounded::<_, MaxEdges>(vec![(0u32, 1), (1, 2), (2, 3), (0, 3)]);
        let zero_h: AllowedValueSpec<AllowedValueSetOf<Test>> =
            AllowedValueSpec::Set(bounded::<_, MaxAllowedValues>(vec![0]));
        let hash_b = topology::hash_topology(
            &nodes, &edges, &zero_h.as_slice(), &allowed_j_spec().as_slice(), &allowed_spin_spec().as_slice(),
        );
        assert_ok!(QuantumPow::register_topology(
            RuntimeOrigin::root(), nodes, edges, zero_h, allowed_j_spec(), allowed_spin_spec(),
        ));
        assert_noop!(
            QuantumPow::set_default_topology(RuntimeOrigin::root(), hash_b),
            crate::Error::<Test>::TopologyNotMineable
        );
    });
}
```

> The existing `set_default_topology_repoints_default_and_curve` test (355) uses `registered_zero_field_topology`, which now auto-whitelists `hash_b` — so that test continues to pass through the new whitelist guard. Confirm it stays green.

- [ ] **Step 11: Run.** `cargo test -p pallet-quantum-pow` → green.
- [ ] **Step 12: Commit** `feat(qpow): add mineable-topology whitelist with enforcement`.

---

## Phase R3 — Storage migration (v2 → v3)

### Task 4: Versioned carry-forward migration + `set_difficulty` topology arg

This task makes the consensus-affecting call-encoding change (`set_difficulty` gains `topology_hash`) and the storage migration together, since both are "v3 cutover" concerns.

**Files:**
- Modify: `pallets/quantum-pow/src/lib.rs` — `STORAGE_VERSION` (135), `on_runtime_upgrade` (383-400), `pre/post_upgrade` (402-418), `set_difficulty` (call_index 3), a migration helper module.
- Modify: `pallets/quantum-pow/src/tests.rs` — rewrite the two migration tests; finalize `set_difficulty_default`, `set_difficulty_requires_root`, `set_difficulty_works`.
- Modify: `pallets/quantum-pow/src/benchmarking.rs` — `set_difficulty` benchmark.

**Interfaces:**
- Produces: `set_difficulty(origin, topology_hash: H256, difficulty: DifficultyConfig)`.

- [ ] **Step 1: Bump the version.** `lib.rs:135`:

```rust
    const STORAGE_VERSION: StorageVersion = StorageVersion::new(3);
```

- [ ] **Step 2: Add `topology_hash` to `set_difficulty`.** Replace the interim body from Task 2 (`lib.rs`):

```rust
        /// Set the difficulty baseline for a specific registered topology.
        /// Root only. The topology must be registered so no orphan difficulty
        /// entries can be created.
        #[pallet::call_index(3)]
        #[pallet::weight(<T as Config>::WeightInfo::set_difficulty())]
        pub fn set_difficulty(
            origin: OriginFor<T>,
            topology_hash: H256,
            difficulty: types::DifficultyConfig,
        ) -> DispatchResult {
            ensure_root(origin)?;
            ensure!(
                RegisteredTopologies::<T>::contains_key(topology_hash),
                Error::<T>::TopologyNotRegistered
            );
            Difficulties::<T>::insert(topology_hash, difficulty);
            Self::deposit_event(Event::DifficultyUpdated { difficulty });
            Ok(())
        }
```

- [ ] **Step 3: Rewrite `on_runtime_upgrade`.** Replace `lib.rs:383-400`:

```rust
        /// v2 → v3: difficulty becomes per-topology and a mineable whitelist
        /// is introduced.
        ///
        /// - on-chain `>= 3`: nothing to do.
        /// - on-chain `== 2`: carry the single global `Difficulty` into
        ///   `Difficulties[DefaultTopology]`, seed `MineableTopologies` with
        ///   the default, and remove the old global value.
        /// - on-chain `< 2`: legacy v0.2 wipe (old encodings cannot be
        ///   carried), then proceed to v3 with empty per-topology state.
        fn on_runtime_upgrade() -> Weight {
            let on_chain = Pallet::<T>::on_chain_storage_version();
            if on_chain >= STORAGE_VERSION {
                return T::DbWeight::get().reads(1);
            }

            let weight = if on_chain == StorageVersion::new(2) {
                crate::migration::v3::carry_forward::<T>()
            } else {
                crate::migration::v3::wipe::<T>()
            };

            STORAGE_VERSION.put::<Pallet<T>>();
            weight.saturating_add(T::DbWeight::get().reads_writes(1, 1))
        }
```

- [ ] **Step 4: Add the migration module.** Place it at the **end of the file, outside** the `#[frame_support::pallet] pub mod pallet { … }` block (so `on_runtime_upgrade` reaches it via `crate::migration::…`). Read the pre-v3 global `Difficulty` value through the **raw storage key** (`twox128(pallet) ++ twox128("Difficulty")`) rather than a `storage_alias` — this matches the existing `wipe` idiom (which already uses `Twox128`/`unhashed`), has zero macro risk, and there is no `storage_alias` precedent in this workspace:

```rust
pub(crate) mod migration {
    pub(crate) mod v3 {
        use crate::pallet::{Config, Difficulties, MineableTopologies, Pallet};
        use crate::{types, BlockBestProof, DefaultTopology};
        use frame_support::traits::PalletInfoAccess;
        use frame_support::weights::Weight;
        use frame_support::{StorageHasher, Twox128};

        /// Raw storage key of the pre-v3 global `Difficulty` StorageValue:
        /// `twox128(pallet_name) ++ twox128("Difficulty")`.
        pub(crate) fn old_difficulty_key<T: Config>() -> [u8; 32] {
            let mut key = [0u8; 32];
            key[..16]
                .copy_from_slice(&Twox128::hash(<Pallet<T> as PalletInfoAccess>::name().as_bytes()));
            key[16..].copy_from_slice(&Twox128::hash(b"Difficulty"));
            key
        }

        /// 2 → 3: carry the global difficulty into the per-topology map keyed
        /// by the default topology, whitelist the default, drop the old value.
        pub(crate) fn carry_forward<T: Config>() -> Weight {
            let key = old_difficulty_key::<T>();
            let old: types::DifficultyConfig =
                frame_support::storage::unhashed::get(&key).unwrap_or_default();
            let reads = 2u64; // DefaultTopology + old Difficulty
            let mut writes = 0u64;
            if let Some(default_hash) = DefaultTopology::<T>::get() {
                Difficulties::<T>::insert(default_hash, old);
                MineableTopologies::<T>::insert(default_hash, ());
                writes = writes.saturating_add(2);
            }
            // Drop the old global value. Also kill any transient pre-v3
            // `BlockBestProof`: `ProofRecord` gains a `topology_hash` field in
            // v3, so a stale entry would be a different shape. It is always
            // empty across an upgrade boundary (`on_finalize` take()s it every
            // block) and `BlockBestProof` is `OptionQuery` (decode failure ⇒
            // `None`, never a panic) — `kill()` removes all doubt for free.
            frame_support::storage::unhashed::kill(&key);
            BlockBestProof::<T>::kill();
            writes = writes.saturating_add(2);
            T::DbWeight::get().reads_writes(reads, writes)
        }

        /// `< 2`: clear the whole pallet prefix (legacy v0.2 encodings).
        pub(crate) fn wipe<T: Config>() -> Weight {
            let pallet_prefix = Twox128::hash(<Pallet<T> as PalletInfoAccess>::name().as_bytes());
            let cleared =
                frame_support::storage::unhashed::clear_prefix(&pallet_prefix, None, None).backend;
            T::DbWeight::get().reads_writes(1, u64::from(cleared))
        }
    }
}
```

> `Difficulties`, `MineableTopologies`, `DefaultTopology`, `BlockBestProof` are `pub` storage items in the `pallet` mod, re-exported at the crate root via `pub use pallet::*` — confirm the `use` paths resolve when the module is added (they compile against frame-support 46.0.0).

- [ ] **Step 5: Rewrite `pre_upgrade`/`post_upgrade`.** Replace `lib.rs:402-418`:

```rust
        #[cfg(feature = "try-runtime")]
        fn pre_upgrade() -> Result<Vec<u8>, sp_runtime::TryRuntimeError> {
            // Capture whether the chain was at v2 (as a bool) + the default
            // topology so post_upgrade can assert the carry-forward preserved
            // it. NOTE: this SDK fork's `StorageVersion` has NO `Into<u16>` —
            // only `==`/`PartialOrd` against u16 — so a `u16` cast fails to
            // compile under `--features try-runtime`. A `bool` is Encode/Decode
            // and `== StorageVersion::new(2)` is available.
            let was_v2 = Pallet::<T>::on_chain_storage_version() == StorageVersion::new(2);
            Ok((was_v2, DefaultTopology::<T>::get()).encode())
        }

        #[cfg(feature = "try-runtime")]
        fn post_upgrade(state: Vec<u8>) -> Result<(), sp_runtime::TryRuntimeError> {
            ensure!(
                Pallet::<T>::on_chain_storage_version() >= STORAGE_VERSION,
                "storage version must be >= 3 after upgrade"
            );
            let (was_v2, default): (bool, Option<H256>) =
                Decode::decode(&mut &state[..]).map_err(|_| "pre_upgrade state decode failed")?;
            if was_v2 {
                // The old global `Difficulty` value must be gone.
                ensure!(
                    frame_support::storage::unhashed::get::<types::DifficultyConfig>(
                        &crate::migration::v3::old_difficulty_key::<T>()
                    )
                    .is_none(),
                    "v2→v3 must remove the old global Difficulty value"
                );
                if let Some(hash) = default {
                    ensure!(
                        Difficulties::<T>::contains_key(hash),
                        "v2→v3 must seed Difficulties[DefaultTopology]"
                    );
                    ensure!(
                        MineableTopologies::<T>::contains_key(hash),
                        "v2→v3 must whitelist the default topology"
                    );
                }
            }
            Ok(())
        }
```

(`Decode` is in scope via `pallet_prelude::*`; `H256` is imported. Do **not** cast `StorageVersion` to `u16` — this SDK fork has no `Into<u16>` for it; use the `bool` round-trip above. **Verify with `cargo check -p pallet-quantum-pow --features try-runtime`** — the normal build does not compile these hooks.)

- [ ] **Step 6: Finalize the `set_difficulty` test helper.** In `tests.rs`, change `set_difficulty_default`:

```rust
fn set_difficulty_default(difficulty: DifficultyConfig) {
    assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), default_hash(), difficulty));
}
```

- [ ] **Step 7: Fix `set_difficulty_requires_root` and `set_difficulty_works`.** Replace `tests.rs:440-470`:

```rust
#[test]
fn set_difficulty_requires_root() {
    new_test_ext().execute_with(|| {
        let (_, _, hash) = registered_topology();
        let difficulty = DifficultyConfig { min_solutions: 2, max_energy_milli: -1_000, min_diversity_milli: 500 };
        assert_noop!(
            QuantumPow::set_difficulty(RuntimeOrigin::signed(1), hash, difficulty),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_difficulty_rejects_unregistered_topology() {
    new_test_ext().execute_with(|| {
        let difficulty = DifficultyConfig { min_solutions: 3, max_energy_milli: -2_000, min_diversity_milli: 800 };
        assert_noop!(
            QuantumPow::set_difficulty(RuntimeOrigin::root(), sp_core::H256::repeat_byte(5), difficulty),
            crate::Error::<Test>::TopologyNotRegistered
        );
    });
}

#[test]
fn set_difficulty_works() {
    new_test_ext().execute_with(|| {
        let (_, _, hash) = registered_topology();
        let difficulty = DifficultyConfig { min_solutions: 3, max_energy_milli: -2_000, min_diversity_milli: 800 };
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), hash, difficulty));
        assert_eq!(Difficulties::<Test>::get(hash), Some(difficulty));
    });
}
```

- [ ] **Step 8: Rewrite the migration tests.** Replace `network_upgrade_wipes_pow_state_and_bumps_version` (732) and `network_upgrade_is_noop_once_at_v2` (888). The carry-forward test seeds the OLD global layout by writing to the same raw key the migration reads (no `storage_alias`):

```rust
#[test]
fn migration_v2_to_v3_carries_difficulty_and_whitelists_default() {
    new_test_ext().execute_with(|| {
        let (_, _, hash) = registered_topology(); // also whitelists in the helper
        // Simulate a pre-v3 chain: remove the per-topology entry + whitelist
        // the helper added, write the OLD global value at its raw key, drop to v2.
        Difficulties::<Test>::remove(hash);
        MineableTopologies::<Test>::remove(hash);
        let old = DifficultyConfig { min_solutions: 7, max_energy_milli: -14_620, min_diversity_milli: 300 };
        let old_key = crate::migration::v3::old_difficulty_key::<Test>();
        frame_support::storage::unhashed::put(&old_key, &old);
        StorageVersion::new(2).put::<QuantumPow>();

        QuantumPow::on_runtime_upgrade();

        assert_eq!(Difficulties::<Test>::get(hash), Some(old), "global difficulty carried to default topology");
        assert!(MineableTopologies::<Test>::contains_key(hash), "default topology whitelisted");
        assert!(
            frame_support::storage::unhashed::get::<DifficultyConfig>(&old_key).is_none(),
            "old global value removed"
        );
        assert_eq!(StorageVersion::get::<QuantumPow>(), StorageVersion::new(3));
        // The live threshold for the default now equals the carried value.
        assert_eq!(QuantumPow::current_difficulty_for(hash, System::block_number()), old);
    });
}

#[test]
fn migration_below_v2_wipes_then_bumps_to_v3() {
    new_test_ext().execute_with(|| {
        let (_, _, hash) = registered_topology();
        QBlockCount::<Test>::put(9);
        StorageVersion::new(1).put::<QuantumPow>();

        QuantumPow::on_runtime_upgrade();

        assert!(RegisteredTopologies::<Test>::iter().next().is_none());
        assert_eq!(DefaultTopology::<Test>::get(), None);
        assert_eq!(QBlockCount::<Test>::get(), 0);
        assert!(!MineableTopologies::<Test>::contains_key(hash));
        assert_eq!(StorageVersion::get::<QuantumPow>(), StorageVersion::new(3));
    });
}

#[test]
fn migration_noop_at_v3() {
    new_test_ext().execute_with(|| {
        let (_, _, hash) = registered_topology();
        let d = DifficultyConfig { min_solutions: 7, max_energy_milli: -1_000, min_diversity_milli: 300 };
        Difficulties::<Test>::insert(hash, d);
        QBlockCount::<Test>::put(9);
        StorageVersion::new(3).put::<QuantumPow>();

        QuantumPow::on_runtime_upgrade();

        assert!(RegisteredTopologies::<Test>::contains_key(hash));
        assert_eq!(Difficulties::<Test>::get(hash), Some(d));
        assert_eq!(QBlockCount::<Test>::get(), 9);
        assert_eq!(StorageVersion::get::<QuantumPow>(), StorageVersion::new(3));
    });
}
```

- [ ] **Step 9: Update the `set_difficulty` benchmark.** In `benchmarking.rs:171-179`:

```rust
    #[benchmark]
    fn set_difficulty() {
        let (_nodes, _edges, topology_hash) = register_topology_for::<T>();
        let difficulty = easy_difficulty();

        #[extrinsic_call]
        QuantumPow::set_difficulty(RawOrigin::Root, topology_hash, difficulty);

        assert_eq!(Difficulties::<T>::get(topology_hash), Some(difficulty));
    }
```

- [ ] **Step 10: Run.** `cargo test -p pallet-quantum-pow` → green; `cargo check -p quip-protocol-runtime` → clean.
- [ ] **Step 11: Commit** `feat(qpow): v2→v3 carry-forward migration; per-topology set_difficulty`.

---

## Phase R4 — Runtime API surface

### Task 5: `difficulty_for` + `mineable_topologies` runtime APIs

**Files:**
- Modify: `pallets/quantum-pow/src/lib.rs` — `decl_runtime_apis!` (48-113); pallet `impl` helpers.
- Modify: `runtime/src/apis.rs:224-270` — implement the two new methods.

**Interfaces:**
- Produces (runtime API): `fn difficulty_for(topology_hash: H256) -> Option<DifficultyConfig>`, `fn mineable_topologies() -> Vec<H256>`.
- Produces (pallet): `pub fn difficulty_for_api(H256) -> Option<DifficultyConfig>`, `pub fn mineable_topologies() -> alloc::vec::Vec<H256>`.

- [ ] **Step 1: Extend the API trait.** In `lib.rs`, inside the `decl_runtime_apis!` trait (after `current_hardness`, before the closing brace at 112):

```rust
        /// Per-topology live difficulty (decay applied), or `None` if the
        /// topology is not registered.
        fn difficulty_for(topology_hash: sp_core::H256) -> Option<crate::types::DifficultyConfig>;

        /// Hashes of every topology currently on the mineable whitelist.
        fn mineable_topologies() -> alloc::vec::Vec<sp_core::H256>;
```

- [ ] **Step 2: Add the pallet helpers.** In the `impl<T: Config> Pallet<T>` block (near `mining_snapshot`):

```rust
        pub fn difficulty_for_api(topology_hash: H256) -> Option<types::DifficultyConfig> {
            RegisteredTopologies::<T>::contains_key(topology_hash).then(|| {
                Self::current_difficulty_for(topology_hash, frame_system::Pallet::<T>::block_number())
            })
        }

        pub fn mineable_topologies() -> Vec<H256> {
            MineableTopologies::<T>::iter_keys().collect()
        }
```

- [ ] **Step 3: Implement in the runtime.** In `runtime/src/apis.rs`, inside the `QuantumPowApi` impl (after `current_hardness`, before the closing brace at 270):

```rust
        fn difficulty_for(
            topology_hash: sp_core::H256,
        ) -> Option<pallet_quantum_pow::types::DifficultyConfig> {
            QuantumPow::difficulty_for_api(topology_hash)
        }

        fn mineable_topologies() -> alloc::vec::Vec<sp_core::H256> {
            QuantumPow::mineable_topologies()
        }
```

- [ ] **Step 4: Add pallet-level tests** for the new helpers + per-topology snapshot. Append to `tests.rs`:

```rust
#[test]
fn difficulty_for_api_returns_per_topology() {
    new_test_ext().execute_with(|| {
        let (_, _, hash_a) = registered_topology();
        let hash_b = registered_zero_field_topology();
        let da = DifficultyConfig { min_solutions: 1, max_energy_milli: -10_000, min_diversity_milli: 0 };
        let db = DifficultyConfig { min_solutions: 2, max_energy_milli: -20_000, min_diversity_milli: 5 };
        set_difficulty_default(da); // A is the default
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), hash_b, db));

        assert_eq!(QuantumPow::difficulty_for_api(hash_a), Some(da));
        assert_eq!(QuantumPow::difficulty_for_api(hash_b), Some(db));
        assert_eq!(QuantumPow::difficulty_for_api(sp_core::H256::repeat_byte(3)), None);
    });
}

#[test]
fn mining_snapshot_some_returns_that_topology_difficulty() {
    new_test_ext().execute_with(|| {
        let _ = registered_topology();
        let hash_b = registered_zero_field_topology();
        let db = DifficultyConfig { min_solutions: 2, max_energy_milli: -20_000, min_diversity_milli: 5 };
        assert_ok!(QuantumPow::set_difficulty(RuntimeOrigin::root(), hash_b, db));

        let snap = QuantumPow::mining_snapshot(Some(hash_b)).expect("snapshot exists");
        assert_eq!(snap.topology_hash, hash_b);
        assert_eq!(snap.difficulty, db); // B's difficulty, not the default's
    });
}

#[test]
fn mineable_topologies_enumerates_whitelist() {
    new_test_ext().execute_with(|| {
        let (_, _, hash_a) = registered_topology();        // whitelisted (default)
        let hash_b = registered_zero_field_topology();     // whitelisted
        let mut got = QuantumPow::mineable_topologies();
        got.sort();
        let mut want = vec![hash_a, hash_b];
        want.sort();
        assert_eq!(got, want);
    });
}

#[test]
fn unset_whitelisted_topology_reads_default_hard_difficulty() {
    new_test_ext().execute_with(|| {
        let _ = registered_topology();
        let hash_b = registered_zero_field_topology(); // whitelisted, no set_difficulty
        // Fails closed: returns the conservative (hard) default until calibrated.
        assert_eq!(
            QuantumPow::current_difficulty_for(hash_b, System::block_number()),
            DifficultyConfig::default()
        );
    });
}
```

- [ ] **Step 5: Build.** `cargo check -p quip-protocol-runtime` → clean (the `apis::RUNTIME_API_VERSIONS` literal recomputes automatically from the macro; `alloc::vec::Vec` is the correct path at the `decl_runtime_apis` site — `extern crate alloc` is at the crate root and a bare `Vec` is NOT in scope there).
- [ ] **Step 6: Run pallet tests.** `cargo test -p pallet-quantum-pow` → green.
- [ ] **Step 7: Commit** `feat(qpow): difficulty_for + mineable_topologies runtime APIs`.

---

## Phase R5 — Weights, benchmarks, runtime version

### Task 6: Weights + benchmarks for the new extrinsics

**Files:**
- Modify: `pallets/quantum-pow/src/weights.rs` (trait + both impls).
- Modify: `pallets/quantum-pow/src/benchmarking.rs` (two new benchmarks; `submit_proof` whitelist setup).

- [ ] **Step 1: Extend the `WeightInfo` trait.** `weights.rs:8-15`:

```rust
pub trait WeightInfo {
	fn register_miner() -> Weight;
	fn deregister_miner() -> Weight;
	fn register_topology() -> Weight;
	fn set_default_topology() -> Weight;
	fn set_difficulty() -> Weight;
	fn submit_proof() -> Weight;
	fn add_mineable_topology() -> Weight;
	fn remove_mineable_topology() -> Weight;
}
```

- [ ] **Step 2: `SubstrateWeight` impl** — add (and bump `set_difficulty` reads to 1 for the new `RegisteredTopologies` check):

```rust
	fn set_difficulty() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn add_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}

	fn remove_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
```

- [ ] **Step 3: `()` impl** — mirror with `RocksDbWeight`:

```rust
	fn set_difficulty() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn add_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}

	fn remove_mineable_topology() -> Weight {
		Weight::from_parts(10_000_000, 0)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
```

- [ ] **Step 4: Whitelist `submit_proof` benchmark setup.** In `benchmarking.rs:182-196`, after `register_topology_for`:

```rust
        let (_nodes, _edges, topology_hash) = register_topology_for::<T>();
        MineableTopologies::<T>::insert(topology_hash, ());
        Difficulties::<T>::insert(topology_hash, easy_difficulty());
```

- [ ] **Step 5: Add the two whitelist benchmarks.** In `benchmarking.rs`, before `impl_benchmark_test_suite!`:

```rust
    #[benchmark]
    fn add_mineable_topology() {
        let (_nodes, _edges, topology_hash) = register_topology_for::<T>();
        MineableTopologies::<T>::remove(topology_hash);

        #[extrinsic_call]
        QuantumPow::add_mineable_topology(RawOrigin::Root, topology_hash);

        assert!(MineableTopologies::<T>::contains_key(topology_hash));
    }

    #[benchmark]
    fn remove_mineable_topology() {
        let (_nodes, _edges, topology_hash) = register_topology_for::<T>();
        MineableTopologies::<T>::insert(topology_hash, ());
        // Clear the first-registration default so the remove is not blocked
        // by the default-topology guard.
        DefaultTopology::<T>::kill();

        #[extrinsic_call]
        QuantumPow::remove_mineable_topology(RawOrigin::Root, topology_hash);

        assert!(!MineableTopologies::<T>::contains_key(topology_hash));
    }
```

- [ ] **Step 6: Compile benchmarks.** `cargo check -p pallet-quantum-pow --features runtime-benchmarks` → clean.
- [ ] **Step 7: Run tests.** `cargo test -p pallet-quantum-pow` → green.
- [ ] **Step 8: Commit** `feat(qpow): weights + benchmarks for whitelist extrinsics`.

### Task 7: Runtime version bump

**Files:** Modify `runtime/src/lib.rs:95-104`.

- [ ] **Step 1: Bump + document.** Append before `spec_version: 107,` and update the two version lines:

```rust
    // Bumped to 108 for per-topology difficulty + the mineable-topology
    // whitelist: `QuantumPow.Difficulty` (global StorageValue) becomes
    // `Difficulties` (StorageMap keyed by topology hash), `MineableTopologies`
    // is added, `set_difficulty` gains a `topology_hash` argument, and
    // `add_mineable_topology`/`remove_mineable_topology` (call_index 6/7) are
    // added. `set_difficulty`'s argument encoding changed, so
    // `transaction_version` moves to 4. Pallet storage version 2 → 3 with a
    // carry-forward migration.
    spec_version: 108,
    impl_version: 1,
    apis: apis::RUNTIME_API_VERSIONS,
    transaction_version: 4,
```

- [ ] **Step 2: Build.** `cargo build -p quip-protocol-runtime` → clean.
- [ ] **Step 3: Commit** `chore(runtime): bump to spec_version 108 / tx_version 4`.

---

## Phase R6 — Full Rust verification

### Task 8: Workspace build, tests, try-runtime

- [ ] **Step 1:** `cargo test -p pallet-quantum-pow` → all green (record `N passed; 0 failed`).
- [ ] **Step 2:** `cargo check -p pallet-quantum-pow --features runtime-benchmarks` → clean.
- [ ] **Step 2b:** `cargo check -p pallet-quantum-pow --features try-runtime` → clean. **This is the only build that compiles the `pre_upgrade`/`post_upgrade` hooks** — the normal build and the test suite do NOT, so a try-runtime-gated compile error is invisible without this check (it slipped through once in Task 4).
- [ ] **Step 3:** `cargo build -p quip-protocol-runtime` → clean.
- [ ] **Step 4:** `cargo clippy -p pallet-quantum-pow --all-targets -- -D warnings` → zero warnings (per repo lang-rust policy).
- [ ] **Step 5:** Build the node and run a `try-runtime` migration dry-run against a testnet snapshot (operator path):

```bash
cargo build --release -p quip-network-node --features try-runtime
# Against a live/snapshot endpoint (operator supplies URI):
try-runtime --runtime ./target/release/wbuild/quip-protocol-runtime/quip_protocol_runtime.wasm \
    on-runtime-upgrade --checks=all live --uri wss://<testnet-rpc>
```
Expected: `pre_upgrade`/`post_upgrade` pass; `Difficulties[DefaultTopology]` populated; default whitelisted.

- [ ] **Step 6: Commit** any fixes; tag the Rust work complete.

---

## Phase P1 — Python client lockstep (`../quip-protocol`)

> Separate repo → separate PR, coordinated with the runtime release. **Before editing, read each target file fully** (the line numbers below are from the codebase map and must be re-confirmed). Match the repo's async/`substrateinterface` idioms and existing `_hx`/dict conventions.

### Task 9: `client.py` — per-topology difficulty + whitelist surface

**File:** `substrate/client.py`

- [ ] **Step 1:** Change `query_difficulty` (≈605) to take `topology_hash: Optional[bytes] = None`. Resolve `None` → read `QuantumPow.DefaultTopology`, then query the `QuantumPow.Difficulties` **map** with the topology hash (`query('QuantumPow', 'Difficulties', ['0x'+hash.hex()])`) instead of the old `Difficulty` value. Return `Optional[SubstrateDifficulty]` (the map entry may be absent).
- [ ] **Step 2:** Add a `Vec<H256>` SCALE decoder to `substrate/scale_codec.py` (none exists) — a compact-`u32` length prefix followed by N×32-byte hashes, e.g. `def _decode_h256_vec(data) -> List[bytes]: n = _decode_compact_u32(data); return [_read_exact(data, 32) for _ in range(n)]` (match the module's existing decoder signatures). Then add `query_mineable_topologies() -> List[bytes]` to `client.py` calling `_state_call('QuantumPowApi_mineable_topologies', '0x', block_hash)` and decoding with it.
- [ ] **Step 3:** Add `set_mineable_topology(self, signer, topology_hash: bytes, *, add: bool)` (or two thin helpers) that submit `QuantumPow.add_mineable_topology` / `remove_mineable_topology` via `submit_extrinsic` with `{'topology_hash': '0x'+hash.hex()}`.
- [ ] **Step 4:** Add a `query_difficulty_for(topology_hash: bytes)` thin wrapper over the new `QuantumPowApi_difficulty_for` runtime API for callers that want the decayed value rather than the raw map entry.
- [ ] **Step 5:** Update any unit tests/mocks that patch `query_difficulty` for the new signature.
- [ ] **Step 6: Commit** `feat(client): per-topology difficulty + mineable-topology helpers`.

### Task 10: `miner_bootstrap.py` — seed per-topology difficulty

**File:** `substrate/miner_bootstrap.py`

- [ ] **Step 1:** In `_maybe_seed_chain` (≈296), the `set_difficulty` sudo call (≈326-331) must include `topology_hash` in `inner_params`. Use the topology hash the bootstrap registered/targets (resolve `DefaultTopology` if seeding the default).
- [ ] **Step 2:** The `query_difficulty(...)` seeding check now passes the seeded topology hash (or default).
- [ ] **Step 3 (optional):** Add `mineable_topologies: Optional[List[bytes]]` to `BootstrapConfig`; when set, `_sudo_call` `add_mineable_topology` for each during seeding. Guard behind the existing dev-chain name/sudo check.
- [ ] **Step 4: Commit** `feat(bootstrap): seed difficulty per topology + optional whitelist`.

### Task 11: `register_advantage2.py` — thread hash + `--mineable`

**File:** `tools/register_advantage2.py`

- [ ] **Step 1:** The `set_difficulty` sudo call (≈189-192) must pass `topology_hash` = the `target_hash` already computed at ≈214-216 (the just-registered topology), not a default fallback.
- [ ] **Step 2:** Add a `--mineable` flag; when set, after `register_topology` (≈229-238), `_sudo_call('QuantumPow', 'add_mineable_topology', {'topology_hash': '0x'+target_hash.hex()})`. Document that `set_default_topology` (≈259-262) now requires the target to be whitelisted first — order the calls add → set_difficulty → set_default.
- [ ] **Step 3: Commit** `feat(register_advantage2): per-topology difficulty + --mineable`.

### Task 12: `download_and_validate_wins.py` — confirm per-topology difficulty

**File:** `tools/download_and_validate_wins.py`

- [ ] **Step 1:** Confirm `_validate` selects the right topology's difficulty. It already fetches per-topology snapshots via `_topology_for` (≈127) which calls `get_mining_snapshot(topology_hash=…)`; verify the re-validation uses `snapshot.difficulty` (now per-topology) and the win record carries the `topology_hash` needed to pick it. Adjust only if a global difficulty read remains.
- [ ] **Step 2: Commit** `fix(validate-wins): re-validate against per-topology difficulty`.

---

## Self-Review

**1. Spec coverage:**
- Part 1 — per-topology difficulty: storage (Task 2), `set_difficulty` arg (Task 4), internal APIs `current_difficulty_for`/`energy_curve_for` (Task 2), `submit_proof` gate (Task 2), `on_finalize` per-topology adjust (Task 2), `mining_snapshot` (Task 2), runtime API (Tasks 2 + 5). ✓
- Part 2 — whitelist: storage + extrinsics + `submit_proof`/`set_default_topology` enforcement (Task 3), `mineable_topologies()` API (Task 5). ✓
- Concurrency model A — round/decay/last-proof stay global: no change to `LastProofBlock`/`LastProofBlockHash`/`WinnerStreak`/`BlockProofCount`. ✓
- Migration — storage version bump + version-branching carry-forward + tests (Task 4); try-runtime (Task 8). ✓
- Python lockstep — Tasks 9-12. ✓
- Acceptance criteria — `TopologyNotMineable` test (Task 3), independent-difficulty regression (Task 2), `set_default_topology` rejection (Task 3), migration pre/post (Task 4/8), benchmarks (Task 6). ✓

**2. Placeholder scan:** Python phase steps reference line numbers that must be re-confirmed against the files (called out explicitly); all Rust steps carry exact code. No "add error handling"/"TBD" steps.

**3. Type consistency:** `Difficulties` (map), `MineableTopologies` (set), `current_difficulty_for(H256, BlockNumberFor<T>)`, `energy_curve_for(H256)`, `difficulty_for_api`/`difficulty_for`, `mineable_topologies`, errors `TopologyNotMineable`/`TopologyIsDefault`, events `TopologyMineableAdded`/`TopologyMineableRemoved`, call indices 6/7 — names used identically across Tasks 2-9. `ProofRecord.topology_hash` defined in Task 1, consumed in Task 2's `on_finalize`. ✓

**Known execution-time checks (flag, don't pre-solve):**
- Re-confirm no other in-tree caller references the removed global `Difficulty` storage item or the old `set_difficulty` arity (grep `Difficulty::` and `set_difficulty(` workspace-wide before Task 8). *(Pre-checked: only `runtime/src/apis.rs`, `weights.rs`, `benchmarking.rs`, and in-pallet sites — all covered.)*
- Python phase line numbers (Tasks 9-12) are from the codebase map; re-read each file before editing.

### Adversarial-review reconciliation

A 5-dimension adversarial review (consensus, migration, compile-coherence, test coverage, Python) was run against this plan and the real code. Resolved into the plan above:

- **Migration uses raw `unhashed` key reads, not `storage_alias`** (Task 4 Step 4) — matches the existing `wipe` idiom; zero macro-version risk (frame-support 46.0.0).
- **Defensive `BlockBestProof::<T>::kill()` in `carry_forward`** (Task 4 Step 4) — `ProofRecord` gains a field; the entry is transient + `OptionQuery` (no panic risk), but `kill()` removes all doubt.
- **`on_runtime_upgrade` calls `crate::migration::v3::…`** (Task 4 Step 3) — the hook is inside the pallet mod; the module is at crate root.
- **`pre/post_upgrade` round-trips a `u16`, not `StorageVersion`** (Task 4 Step 5), and `post_upgrade` asserts the old raw key is gone.
- **Global decay-on-switch:** confirmed acceptable for model (A); documented in code + constraints; **no `LastProofBlock` change** (reset hardness if/when model B lands).
- **Default-difficulty fallback documented as fail-closed (hard/unmineable until calibrated)**; operator ordering recorded; covered by a test (Task 5 Step 4).
- **Added tests:** `difficulty_for_api`, `mining_snapshot(Some(B))`, `mineable_topologies` enumeration, unset-whitelisted-default (Task 5 Step 4).
- **Benchmark sequencing clarified** (Task 2 Step 11) — benches compile only at Task 6; `set_difficulty` bench rewritten in Task 4 Step 9.
- **Python `Vec<H256>` decoder** added to Task 9 Step 2 (none existed in `scale_codec.py`).
- *Dismissed as critic misreads:* findings that reported the **current** code lacking the planned changes (the consensus + test-coverage critics treated the plan's intended edits as "missing"); and "Rust type aliases cannot be generic" (false — generic aliases are valid; moot anyway since `storage_alias` was dropped).

## Future work — model (B), deferred (do NOT build here)

Concurrent multi-topology mining (N topologies mineable at once, each with its own round/decay/last-proof state, competing for the block reward via an explicit cross-topology winner rule). The per-topology `Difficulties` map + whitelist built here are B's foundation. B adds per-topology round state + the winner-resolution spec, and **resets hardness/round state at a topology switch** — which is why this PR keeps round state global and difficulty per-topology.
