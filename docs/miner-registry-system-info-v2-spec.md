# MinerRegistry descriptor V2 — restore on-chain `system_info`

## Problem

The node hardware survey (`system_info`: OS / CPU / memory / GPUs) used to be
recorded on-chain. Before the registry integration, `../quip-protocol` posted the
**full** `NodeDescriptor` JSON (including `system_info`) as a `System.remark`.

MR !119 (commit `4451cf7`, "feat: integrate miner registry") replaced that remark
with the typed `MinerRegistry.set_descriptor` extrinsic. The typed `V1` schema is
a compact projection that **omits `system_info` entirely** — see the
`// add hardware spec blob` TODO at `pallets/miner-registry/src/lib.rs:120`. So
hardware data is still gathered by miners and exposed on their local REST API
(`/api/v1/system`), but no longer reaches the chain.

This spec adds a `V2` descriptor variant that carries `system_info` as typed,
bounded runtime fields. It follows the path the pallet was designed for: the
`NodeDescriptorInput<V1>` enum (`lib.rs:152`) exists precisely so new schemas are
additive — `V1` call encodings stay byte-identical.

## Decision: typed fields, not an opaque blob

Measured encoded sizes of a real `system_info` payload:

| profile             | typed SCALE | opaque JSON `BoundedVec<u8>` |
|---------------------|-------------|------------------------------|
| 1-GPU laptop        | 94 B        | 290 B                        |
| cloud 1× A100       | 139 B       | 329 B                        |
| worst 8× H100       | 787 B       | 1462 B                       |

Typed is ~50% smaller, decodes in polkadot.js without a client-side parser,
is per-field length-bounded, and matches the existing pallet philosophy
("compact, bounded typed descriptor rather than the richer JSON document",
`lib.rs:3-7`). Chosen over the opaque blob.

## Runtime types (`pallets/miner-registry/src/lib.rs`)

Mirror the Python dataclasses in `../quip-protocol/shared/system_info.py`
(`SystemInfo`, `CPUInfo`, `GPUInfo`). All variable-length fields are
`BoundedVec<u8, ...>` so `MaxEncodedLen` stays finite.

```rust
pub const NODE_DESCRIPTOR_SCHEMA_V2: u16 = 2;

#[derive(Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq,
         MaxEncodedLen, PartialEq, TypeInfo)]
pub struct OsInfo<S> {            // S = BoundedVec<u8, MaxOsStringBytes>
    pub system: S,               // "Linux" / "Darwin" / "Windows"
    pub release: S,              // kernel/build string
    pub machine: S,              // "x86_64" / "arm64"
}

#[derive(Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq,
         MaxEncodedLen, PartialEq, TypeInfo)]
pub struct CpuInfo<Brand, Arch> {
    pub logical_cores: Option<u32>,
    pub physical_cores: Option<u32>,
    pub brand: Brand,            // BoundedVec<u8, MaxCpuBrandBytes>
    pub arch: Arch,              // BoundedVec<u8, MaxArchBytes>
}

#[derive(Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq,
         MaxEncodedLen, PartialEq, TypeInfo)]
pub struct GpuInfo<Vendor, Name> {
    pub index: u8,               // 0..=255; rigs top out well under this
    pub vendor: Vendor,          // BoundedVec<u8, MaxGpuVendorBytes>
    pub name: Name,              // BoundedVec<u8, MaxGpuNameBytes>
    pub memory_mb: Option<u32>,  // up to ~4 PB; u32 is fine
    pub utilization_pct: Option<u8>, // 0..=100
}

#[derive(Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq,
         MaxEncodedLen, PartialEq, TypeInfo)]
pub struct SystemInfo<OsStr, Brand, Arch, Vendor, Name, Gpus> {
    pub os: OsInfo<OsStr>,
    pub cpu: CpuInfo<Brand, Arch>,
    pub memory_mb: Option<u32>,
    pub gpus: Gpus,              // BoundedVec<GpuInfo<Vendor, Name>, MaxGpus>
}
```

Type aliases (alongside the existing `*Of<T>` aliases near `lib.rs:34-53`):

```rust
type OsStringOf<T>   = BoundedVec<u8, <T as Config>::MaxOsStringBytes>;
type CpuBrandOf<T>   = BoundedVec<u8, <T as Config>::MaxCpuBrandBytes>;
type ArchOf<T>       = BoundedVec<u8, <T as Config>::MaxArchBytes>;
type GpuVendorOf<T>  = BoundedVec<u8, <T as Config>::MaxGpuVendorBytes>;
type GpuNameOf<T>    = BoundedVec<u8, <T as Config>::MaxGpuNameBytes>;
type GpuOf<T>        = GpuInfo<GpuVendorOf<T>, GpuNameOf<T>>;
type GpusOf<T>       = BoundedVec<GpuOf<T>, <T as Config>::MaxGpus>;
type SystemInfoOf<T> = SystemInfo<OsStringOf<T>, CpuBrandOf<T>, ArchOf<T>,
                                  GpuVendorOf<T>, GpuNameOf<T>, GpusOf<T>>;
```

## Input variant (additive; V1 stays byte-identical)

```rust
pub struct NodeDescriptorV2Input<NodeId, NodeName, PublicHost, RpcEndpoints,
                                 MinerSpecs, SystemInfoInput> {
    // identical to V1 ...
    pub node_id: NodeId,
    pub node_name: NodeName,
    pub public_host: Option<PublicHost>,
    pub public_port: Option<u16>,
    pub rpc_endpoints: RpcEndpoints,
    pub auto_mine: bool,
    pub log_level: LogLevel,
    pub miners: MinerSpecs,
    // ... plus:
    pub system_info: Option<SystemInfoInput>,
}

pub enum NodeDescriptorInput<V1, V2> {
    V1(V1),
    V2(V2),
}
```

The caller submits the same `BoundedVec` shapes it already builds for the V1
inner fields; `system_info` is the only new payload. Reuse the V1 input field
types — the V2 input is V1 + one `Option<SystemInfoInput>`.

## Stored record

Add one trailing optional field to the stored `NodeDescriptor` (`lib.rs:161`):

```rust
pub struct NodeDescriptor<.., SystemInfo> {
    // ... existing fields, unchanged order ...
    pub deposit: Balance,
    pub system_info: Option<SystemInfo>,   // None for records filed via V1
}
```

`validate_and_store_v1` sets `system_info: None`; a new
`validate_and_store_v2` sets it from the input after validation.
`validate_and_store_v2` stamps `schema_version: NODE_DESCRIPTOR_SCHEMA_V2`.

`validate_and_store_descriptor` (`lib.rs:479`) gains the arm:

```rust
NodeDescriptorInput::V2(input) => Self::validate_and_store_v2(input),
```

## Config constants (`pallets/miner-registry/src/lib.rs` + `runtime/src/configs/mod.rs`)

New `#[pallet::constant]` bounds (add next to the existing `Max*Bytes` block at
`lib.rs:251-268`), with proposed runtime values (sized off the measurements;
the worst-case 8-GPU payload is 787 B, so these leave generous headroom):

| constant            | value | rationale                                  |
|---------------------|-------|--------------------------------------------|
| `MaxOsStringBytes`  | 64    | kernel build strings run ~40 B             |
| `MaxCpuBrandBytes`  | 96    | longest real brand strings ~70 B           |
| `MaxArchBytes`      | 16    | "x86_64" / "aarch64"                        |
| `MaxGpuVendorBytes` | 16    | "NVIDIA" / "Apple" / "AMD"                  |
| `MaxGpuNameBytes`   | 96    | "NVIDIA H100 80GB HBM3 PCIe ..." ~60 B      |
| `MaxGpus`           | 16    | matches existing `MaxMinerSpecs = 16`       |

Worst-case bounded `MaxEncodedLen` for `Option<SystemInfo>` ≈ **2.3 KB** —
that is the per-descriptor storage ceiling increase. Acceptable.

Validation in `validate_and_store_v2` (mirror the V1 `ensure!` style at
`lib.rs:491-513`): reject empty `os.system` / `cpu.brand` / `cpu.arch` and
empty GPU `vendor`/`name`; clamp/reject `utilization_pct > 100`. `BoundedVec`
construction already enforces the length caps at decode/convert time.

## Deposit

Extend `descriptor_payload_len` (`lib.rs:567`) to add the `system_info` byte
count so the per-byte deposit reflects it:

```rust
fn system_info_payload_len(si: &SystemInfoOf<T>) -> usize {
    let mut n = si.os.system.len() + si.os.release.len() + si.os.machine.len()
              + si.cpu.brand.len() + si.cpu.arch.len();
    for g in &si.gpus { n += g.vendor.len() + g.name.len(); }
    n
}
```

`descriptor_deposit` (`lib.rs:595`) is unchanged — it already scales linearly
with `payload_len`. Net effect: ≤ ~0.0008 UNIT extra reserved for an 8-GPU node
(`PerByte = MICRO_UNIT`), below the `MILLI_UNIT` base.

## Storage migration (STORAGE_VERSION 1 → 2)

Adding a trailing field changes the stored SCALE layout, so existing
`NodeDescriptors` entries must be migrated. Two options:

- **Recommended — clear and let miners re-file.** Descriptors are
  self-healing: every miner re-files on startup auto-identify
  (`../quip-protocol/quip_cli.py:1409`), and the testnet pallet storage was
  already wiped on the last upgrade. A `VersionedMigration` that
  `NodeDescriptors::<T>::clear(..)` and bumps the version is minimal and
  correct; descriptors repopulate within one miner restart cycle.
- **Lossless translate.** If preserving existing V1 records matters, use
  `NodeDescriptors::translate_values` with an `old::NodeDescriptor` (the
  pre-V2 struct) → re-encode with `system_info: None`.

Bump `STORAGE_VERSION` (`lib.rs:236`) to `2` and register the migration in the
runtime's `Executive` migrations tuple. Add a `tests.rs` case asserting a V1
record survives (or is cleared, per the chosen option) and that a V2 record
round-trips `system_info`.

## Tests (`pallets/miner-registry/src/tests.rs`)

- `set_descriptor` with a `V2` input stores and returns `system_info`.
- `V1` input still stores `system_info: None` (no behavior change).
- Each bound rejects an over-length field (`MaxGpuNameBytes`, `MaxGpus`, ...).
- `utilization_pct > 100` rejected.
- Deposit for a V2 descriptor exceeds the equivalent V1 by
  `system_info_payload_len * PerByte`.
- Migration test per the chosen option above.

## Client side (`../quip-protocol`)

1. `substrate/miner_registry.py` — add a `_system_info_params(descriptor)`
   projection that maps `descriptor.system_info` (the `SystemInfo` dataclass)
   to the V2 SCALE shape (`os`/`cpu`/`memory_mb`/`gpus`), and have
   `descriptor_call_params` emit `{"V2": {... , "system_info": <opt>}}` instead
   of `{"V1": {...}}`. Apply the existing `_scrub` / secret-value rejection
   before encoding (already done upstream in `system_info.to_dict`, but the
   typed path must not regress it).
2. Keep `include_system_info=True` defaults (`quip_cli.py:254`, `:2385`) — they
   already gather the data; it now actually ships.
3. Bump the emitted schema version to match `NODE_DESCRIPTOR_SCHEMA_V2`.
4. Tests in `tests/test_miner_registry.py`: V2 call-params round-trip incl.
   GPUs and `None` system_info (CPU-only / `--no-system-info`).

## Out of scope (note for later)

The `Runtime` block (`python` / `quip_version` / `protocol_version` /
`in_docker` / `docker_image`, `shared/system_info.py:140`) was dropped by the
same migration. It is the same change shape (another optional typed field on
V2). Not included here to keep the V2 surface focused on hardware `system_info`;
add it as a second optional field on the V2 input if client-version visibility
on-chain is wanted.
