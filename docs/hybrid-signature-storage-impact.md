# Hybrid Signature Size and Storage Impact

This document quantifies the encoded-size impact of Quip's hybrid signatures
relative to the classical Substrate `MultiSignature` setup.

The important distinction is that transaction signatures, consensus signatures,
authority public keys, and account state do not all carry the same data.

## Constants

Quip's H3 suite is `sr25519 + ML-DSA-44`.

| Item | Size |
|---|---:|
| Classical sr25519 public key | 32 bytes |
| Classical ed25519 public key | 32 bytes |
| Classical sr25519/ed25519 signature | 64 bytes |
| Classical ECDSA signature | 65 bytes |
| Hybrid public key | 1344 bytes |
| Hybrid signature | 2484 bytes |
| Hybrid transaction signature envelope | 3828 bytes |

The hybrid transaction envelope is:

```text
HybridTxSignature {
  public: [u8; 1344],
  signature: [u8; 2484],
}
```

It SCALE-encodes as fixed-size fields, so the encoded envelope is:

```text
1344 + 2484 = 3828 bytes
```

The runtime uses this envelope as its transaction signature type:

```text
Signature = HybridTxSignature
```

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

Quip's transaction signature field is the full hybrid envelope:

```text
3828 bytes
```

So the per-signed-extrinsic delta versus classical sr25519/ed25519 is:

```text
3828 - 65 = 3763 bytes
```

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

| Component | Classical sr25519/ed25519 | Quip hybrid |
|---|---:|---:|
| Address | 33 bytes | 33 bytes |
| Signature field | 65 bytes | 3828 bytes |
| Total | 98 bytes | 3861 bytes |
| Delta |  | +3763 bytes |

The delta is still 3763 bytes because the address side stays compact.

## Archive and Bandwidth Impact

Extrinsic signatures live in block bodies, not ordinary account state. The main
impact is therefore block-body size, archive database size, RPC response size,
and network bandwidth.

With 6-second blocks:

```text
blocks_per_day = 24 * 60 * 60 / 6 = 14400
extra_per_signed_extrinsic = 3763 bytes
```

For an average of one signed extrinsic per block:

```text
3763 * 14400 = 54,187,200 bytes/day
               = 51.7 MiB/day
               = 18.4 GiB/year
```

Examples:

| Average signed extrinsics per block | Extra per day | Extra per year |
|---:|---:|---:|
| 1 | 51.7 MiB | 18.4 GiB |
| 5 | 258.4 MiB | 92.1 GiB |
| 10 | 516.8 MiB | 184.2 GiB |
| 25 | 1.26 GiB | 460.5 GiB |

These figures only cover the signature-field delta. They do not include
database indexing overhead, compression, pruning policy, RocksDB behavior, RPC
JSON expansion, or any application payload changes.

## Fee Impact

The current runtime config uses:

```text
LengthToFee = IdentityFee<Balance>
```

So the transaction length delta directly adds about:

```text
3763 fee units
```

per signed extrinsic before weight fees, tips, fee multipliers, or any pallet
specific dispatch weight.

If the chain wants classical-sized user fees while retaining hybrid
transactions, `LengthToFee` or the broader fee model needs to account for this
larger fixed authentication cost.

## Account State Impact

Ordinary account state does not grow by 1312 bytes per account.

Quip derives:

```text
AccountId = blake2b_256("quip-account-v1" || full_h3_public_key_bytes)
```

The account id stored in balances, system account storage, nonces, events, and
addresses remains 32 bytes. The full hybrid public key is carried in the signed
transaction envelope so the runtime can verify the signature and derive the
claimed `AccountId`.

The practical result:

| Area | Growth from hybrid tx signatures |
|---|---:|
| `System::Account` key size | none |
| Balance account ids | none |
| Signed block body | +3763 bytes per signed extrinsic |
| Transaction pool memory | +3763 bytes per signed extrinsic |
| RPC block/extrinsic payloads | +3763 bytes per signed extrinsic before JSON expansion |

## Consensus and Session Key Impact

Consensus uses the hybrid Substrate application-crypto wrappers, not the
transaction envelope.

For public keys:

```text
classical public key = 32 bytes
hybrid public key = 1344 bytes
delta = 1312 bytes
```

The runtime session keys contain both BABE and GRANDPA keys:

```text
SessionKeys {
  babe,
  grandpa,
}
```

So each validator session key pair is approximately:

| Item | Classical | Hybrid | Delta |
|---|---:|---:|---:|
| BABE public key | 32 bytes | 1344 bytes | +1312 bytes |
| GRANDPA public key | 32 bytes | 1344 bytes | +1312 bytes |
| Combined session keys | 64 bytes | 2688 bytes | +2624 bytes |

This affects session key storage and authority lists. Exact storage overhead
also includes SCALE container overhead and pallet-specific storage layout, but
the key bytes dominate.

For consensus signatures:

| Item | Classical | Hybrid | Delta |
|---|---:|---:|---:|
| BABE/GRANDPA seal signature | 64 bytes | 2484 bytes | +2420 bytes |

BABE VRF pre-digests are a separate case. The hybrid H3 VRF proof keeps the
classical sr25519 VRF proof material and adds the ML-DSA-44 binding signature.

The classical sr25519 VRF proof material is:

```text
pre_output: 32 bytes
proof: 64 bytes
total: 96 bytes
```

The hybrid VRF proof is approximately:

```text
sr25519_vrf_signature: 96 bytes
pq_binding_signature: 2420 bytes
total: 2516 bytes
delta: 2420 bytes
```

This chain is configured with:

```text
AllowedSlots::PrimaryAndSecondaryPlainSlots
```

Primary BABE pre-digests carry VRF proof material. Secondary-plain pre-digests
do not. Every authored block still carries a BABE seal signature.

## Summary

The high-level cost profile is:

| Scope | Incremental cost |
|---|---:|
| Signed transaction signature field | +3763 bytes |
| Average 1 signed tx per 6s block | +51.7 MiB/day, +18.4 GiB/year |
| Authority public key | +1312 bytes |
| BABE + GRANDPA session keys per validator | +2624 bytes |
| BABE/GRANDPA seal signature | +2420 bytes |
| BABE primary VRF proof | +2420 bytes |
| Ordinary account id/state key | no growth; still 32 bytes |

The main operational impact is not account-state bloat. It is block-body,
archive, RPC, transaction-pool, network, and fee impact from carrying the full
hybrid transaction authentication envelope on every signed extrinsic.
