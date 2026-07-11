# Hybrid Signature Size and Storage Impact

This document quantifies the encoded-size impact of Quip's hybrid signature
options relative to the classical Substrate `MultiSignature` setup.

The important distinction is that transaction signatures, consensus signatures,
authority public keys, and account state do not all carry the same data.

## Constants

Quip currently uses fixed-size hybrid signatures:

- Current H3 option: `sr25519 + ML-DSA-44` for transactions and BABE,
  `ed25519 + ML-DSA-44` for GRANDPA.
- Smaller-footprint option: `sr25519 + Falcon-512` for transactions and, if
  selected later, `ed25519 + Falcon-512` / `sr25519 + Falcon-512` for
  consensus.

The Falcon-512 numbers below use the `fn-dsa` crate's fixed Falcon-512 sizes:
897-byte verifying key and 666-byte signature. `fn-dsa` is still pre-1.0, and
its documentation warns that encodings may change before the final FN-DSA
standard. If this option is adopted, pin the crate version and treat golden
vectors as protocol-critical release fixtures.

| Item | Size |
|---|---:|
| Classical sr25519 public key | 32 bytes |
| Classical ed25519 public key | 32 bytes |
| Classical sr25519/ed25519 signature | 64 bytes |
| Classical ECDSA signature | 65 bytes |
| ML-DSA-44 public key component | 1312 bytes |
| ML-DSA-44 signature component | 2420 bytes |
| Falcon-512 public key component | 897 bytes |
| Falcon-512 signature component | 666 bytes |

The transaction envelope carries the full hybrid public key and signature:

```text
HybridTxSignature {
  public: [u8; HYBRID_PUBLIC_LEN],
  signature: [u8; HYBRID_SIGNATURE_LEN],
}
```

It SCALE-encodes as fixed-size fields. The current and Falcon-sized options are:

| Transaction scheme | Public key | Signature | Envelope |
|---|---:|---:|---:|
| `sr25519_mldsa44` | 32 + 1312 = 1344 bytes | 64 + 2420 = 2484 bytes | 3828 bytes |
| `sr25519_fndsa512` | 32 + 897 = 929 bytes | 64 + 666 = 730 bytes | 1659 bytes |

The Falcon-sized option saves:

```text
3828 - 1659 = 2169 bytes
```

per signed transaction compared with the current ML-DSA-44 hybrid envelope.

The runtime uses the selected envelope as its transaction signature type:

```text
Signature = HybridTxSignature
```

The type name can stay stable even when the selected backing suite changes.

## Transaction Impact

A classical sr25519/ed25519 Substrate transaction signature field usually uses
`MultiSignature`, which encodes as an enum variant byte plus the 64-byte
signature:

```text
1 + 64 = 65 bytes
```

For ECDSA:

```text
1 + 65 = 66 bytes
```

Quip's transaction signature field is the full hybrid envelope. The
per-signed-extrinsic deltas versus classical sr25519/ed25519 are:

| Transaction scheme | Signature field | Delta vs 65-byte `MultiSignature` |
|---|---:|---:|
| `sr25519_mldsa44` | 3828 bytes | +3763 bytes |
| `sr25519_fndsa512` | 1659 bytes | +1594 bytes |

The signer address remains effectively unchanged. Quip derives a compact
32-byte `AccountId` from the full hybrid public key and uses:

```text
Address = MultiAddress<AccountId, ()>
```

For the common `MultiAddress::Id(AccountId32)` case, the encoded address is:

```text
1-byte variant + 32-byte account id = 33 bytes
```

That means the signed-authentication part of the extrinsic is:

| Component | Classical sr25519/ed25519 | `sr25519_mldsa44` | `sr25519_fndsa512` |
|---|---:|---:|---:|
| Address | 33 bytes | 33 bytes | 33 bytes |
| Signature field | 65 bytes | 3828 bytes | 1659 bytes |
| Total | 98 bytes | 3861 bytes | 1692 bytes |
| Delta vs classical |  | +3763 bytes | +1594 bytes |

The signature-field delta is the same as the signed-authentication delta because
the address side stays compact.

## Archive and Bandwidth Impact

Extrinsic signatures live in block bodies, not ordinary account state. The main
impact is therefore block-body size, archive database size, RPC response size,
and network bandwidth.

With 6-second blocks:

```text
blocks_per_day = 24 * 60 * 60 / 6 = 14400
```

For an average of one signed extrinsic per block:

| Transaction scheme | Extra per signed extrinsic | Extra per day | Extra per year |
|---|---:|---:|---:|
| `sr25519_mldsa44` | 3763 bytes | 51.7 MiB | 18.4 GiB |
| `sr25519_fndsa512` | 1594 bytes | 21.9 MiB | 7.8 GiB |

Examples:

| Average signed extrinsics per block | `sr25519_mldsa44` extra per day | `sr25519_mldsa44` extra per year | `sr25519_fndsa512` extra per day | `sr25519_fndsa512` extra per year |
|---:|---:|---:|---:|---:|
| 1 | 51.7 MiB | 18.4 GiB | 21.9 MiB | 7.8 GiB |
| 5 | 258.4 MiB | 92.1 GiB | 109.5 MiB | 39.0 GiB |
| 10 | 516.8 MiB | 184.2 GiB | 218.9 MiB | 78.0 GiB |
| 25 | 1.26 GiB | 460.5 GiB | 547.3 MiB | 195.1 GiB |

These figures only cover the signature-field delta. They do not include
database indexing overhead, compression, pruning policy, RocksDB behavior, RPC
JSON expansion, or any application payload changes.

## Fee Impact

The current runtime config uses:

```text
LengthToFee = IdentityFee<Balance>
```

So the transaction length delta directly adds about:

| Transaction scheme | Added length fee per signed extrinsic |
|---|---:|
| `sr25519_mldsa44` | 3763 fee units |
| `sr25519_fndsa512` | 1594 fee units |

per signed extrinsic before weight fees, tips, fee multipliers, or any pallet
specific dispatch weight.

If the chain wants classical-sized user fees while retaining hybrid
transactions, `LengthToFee` or the broader fee model needs to account for this
larger fixed authentication cost.

## Account State Impact

Ordinary account state does not grow by the full hybrid public-key length.

Quip derives:

```text
AccountId = blake2b_256("quip-account-v1" || full_hybrid_public_key_bytes)
```

The account id stored in balances, system account storage, nonces, events, and
addresses remains 32 bytes. The full hybrid public key is carried in the signed
transaction envelope so the runtime can verify the signature and derive the
claimed `AccountId`.

Changing the selected hybrid suite changes the public-key bytes and therefore
changes derived account ids. A network reset avoids any account migration. A
non-reset upgrade would need an explicit migration or a transitional signature
enum that accepts both public-key formats.

The practical result:

| Area | Growth from hybrid tx signatures |
|---|---|
| `System::Account` key size | none |
| Balance account ids | none |
| Signed block body | +3763 bytes per `sr25519_mldsa44` signed extrinsic, or +1594 bytes per `sr25519_fndsa512` signed extrinsic |
| Transaction pool memory | same per-extrinsic signature-field delta |
| RPC block/extrinsic payloads | same per-extrinsic delta before JSON expansion |

## Consensus and Session Key Impact

Consensus uses the hybrid Substrate application-crypto wrappers, not the
transaction envelope. This section matters only if BABE/GRANDPA are also moved
to Falcon-sized wrappers. A transaction-only Falcon switch leaves consensus at
the current ML-DSA-44 sizes.

For public keys:

| Consensus public key option | Public key | Delta vs classical |
|---|---:|---:|
| Classical sr25519/ed25519 | 32 bytes |  |
| `*_mldsa44` | 1344 bytes | +1312 bytes |
| `*_fndsa512` | 929 bytes | +897 bytes |

The runtime session keys contain both BABE and GRANDPA keys:

```text
SessionKeys {
  babe,
  grandpa,
}
```

So each validator session key pair is approximately:

| Item | Classical | `*_mldsa44` | `*_fndsa512` |
|---|---:|---:|---:|
| BABE public key | 32 bytes | 1344 bytes | 929 bytes |
| GRANDPA public key | 32 bytes | 1344 bytes | 929 bytes |
| Combined session keys | 64 bytes | 2688 bytes | 1858 bytes |
| Delta vs classical |  | +2624 bytes | +1794 bytes |

This affects session key storage and authority lists. Exact storage overhead
also includes SCALE container overhead and pallet-specific storage layout, but
the key bytes dominate.

For consensus signatures:

| Item | Classical | `*_mldsa44` | `*_fndsa512` |
|---|---:|---:|---:|
| BABE/GRANDPA seal signature | 64 bytes | 2484 bytes | 730 bytes |
| Delta vs classical |  | +2420 bytes | +666 bytes |

BABE VRF pre-digests are a separate case. The hybrid H3 VRF proof keeps the
classical sr25519 VRF proof material and adds the PQ binding signature.

The classical sr25519 VRF proof material is:

```text
pre_output: 32 bytes
proof: 64 bytes
total: 96 bytes
```

The hybrid VRF proof is approximately:

| BABE VRF proof option | sr25519 VRF material | PQ binding signature | Total | Delta vs classical |
|---|---:|---:|---:|---:|
| Classical sr25519 | 96 bytes |  | 96 bytes |  |
| `sr25519_mldsa44` | 96 bytes | 2420 bytes | 2516 bytes | +2420 bytes |
| `sr25519_fndsa512` | 96 bytes | 666 bytes | 762 bytes | +666 bytes |

This chain is configured with:

```text
AllowedSlots::PrimaryAndSecondaryPlainSlots
```

Primary BABE pre-digests carry VRF proof material. Secondary-plain pre-digests
do not. Every authored block still carries a BABE seal signature.

## Type Alias Viability

A feature-flagged type alias is viable if both concrete suites expose the same
Rust surface:

- `quip_crypto_primitives_core::HybridSignatureScheme`
- Substrate wrapper module exports: `Public`, `Signature`, `Pair`, `CRYPTO_ID`
- fixed-size constants for public key and signature length
- `sp_core::Pair` verification and signing through the shared substrate wrapper

The current code already uses this shape for `sr25519_mldsa44`. A Falcon suite
can conform by adding an `sr25519_fndsa512` module with the same exports, then
selecting the module once near the boundary:

```rust
#[cfg(all(feature = "tx-mldsa44", feature = "tx-fndsa512"))]
compile_error!("choose exactly one transaction signature suite");

#[cfg(feature = "tx-fndsa512")]
use quip_crypto_primitives::substrate::sr25519_fndsa512 as tx_scheme;

#[cfg(all(feature = "tx-mldsa44", not(feature = "tx-fndsa512")))]
use quip_crypto_primitives::substrate::sr25519_mldsa44 as tx_scheme;

pub type HybridPublic = tx_scheme::Public;
pub type HybridSignatureBytes = tx_scheme::Signature;
pub type HybridPair = tx_scheme::Pair;
```

The bytes-level signer crate needs the same feature selection for the pure core
suite so `HYBRID_PUBLIC_LEN`, `HYBRID_SIGNATURE_LEN`, public-key derivation,
signing, and verification all resolve to the same backing algorithm.

The shared Substrate signature wrapper is already parameterized by public-key
and signature length, so the Falcon transaction wrapper should not require a
new runtime transaction type. The current 2484-byte signature has a metadata
workaround because of its large array size; the 730-byte Falcon signature should
fit the generic metadata path.

Use mutually exclusive Cargo features, for example:

```text
tx-mldsa44    # default/current
tx-fndsa512   # smaller-footprint reset-network option
```

Switching the feature changes the transaction signature SCALE shape and the
derived account ids, so it still requires runtime `spec_version` and
`transaction_version` bumps. With a network reset, no account migration or
dual-signature compatibility enum is needed.

## Summary

The high-level cost profile is:

| Scope | `sr25519_mldsa44` / `*_mldsa44` | `sr25519_fndsa512` / `*_fndsa512` |
|---|---:|---:|
| Signed transaction signature field | +3763 bytes | +1594 bytes |
| Average 1 signed tx per 6s block | +51.7 MiB/day, +18.4 GiB/year | +21.9 MiB/day, +7.8 GiB/year |
| Authority public key | +1312 bytes | +897 bytes |
| BABE + GRANDPA session keys per validator | +2624 bytes | +1794 bytes |
| BABE/GRANDPA seal signature | +2420 bytes | +666 bytes |
| BABE primary VRF proof | +2420 bytes | +666 bytes |
| Ordinary account id/state key | no growth; still 32 bytes | no growth; still 32 bytes |

The main operational impact is not account-state bloat. It is block-body,
archive, RPC, transaction-pool, network, and fee impact from carrying the full
hybrid transaction authentication envelope on every signed extrinsic. The
Falcon-512 option materially reduces that footprint while preserving the same
high-level envelope and wrapper interfaces.
