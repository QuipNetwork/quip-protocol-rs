# Falcon Hybrid Signature Implementation Plan

## Goal

Add a smaller-footprint hybrid transaction signature option:

```text
sr25519 + Falcon-512
```

The working suite name is `sr25519_fndsa512`. It should conform to the same
interfaces as the current `sr25519_mldsa44` suite so most transaction,
runtime, signer, and client code can select the backing suite through Cargo
features and type aliases rather than through broad plumbing.

A network reset is acceptable, so this plan does not include an account
migration or dual-signature transition path.

## Related Context

- Size comparison: `docs/hybrid-signature-storage-impact.md`
- Existing crypto-core split: `docs/hybrid-crypto-dedup-plan.md`
- SDK path during development: `../polkadot-sdk`
- Current pure crypto crate: `../polkadot-sdk/quip/primitives/crypto-core`
- Current Substrate wrapper crate: `../polkadot-sdk/quip/primitives/crypto`

## Target Size

Current transaction envelope:

```text
sr25519_mldsa44 = public 1344 bytes + signature 2484 bytes = 3828 bytes
```

Falcon transaction envelope:

```text
sr25519_fndsa512 = public 929 bytes + signature 730 bytes = 1659 bytes
```

The Falcon option saves 2169 bytes per signed transaction envelope and reduces
the delta versus classical `MultiSignature` from 3763 bytes to 1594 bytes.

## Interface Shape

Both suites must expose the same Rust surface:

```rust
pub type Public = ...;
pub type Signature = ...;
pub type Pair = ...;
pub const CRYPTO_ID: CryptoTypeId = ...;
```

The pure core suite must implement:

```rust
quip_crypto_primitives_core::HybridSignatureScheme
```

The Substrate wrapper must work through:

```rust
quip_crypto_primitives::substrate::signature::{
    Public,
    Signature,
    Pair,
    SubstrateSignatureScheme,
}
```

This is viable because the shared wrapper is already const-parameterized by
public-key and signature length. The current 2484-byte signature has a
metadata workaround because of large array metadata; the 730-byte Falcon
signature should fit the generic metadata path.

## Feature Selection

Use mutually exclusive features in both transaction crypto crates:

```text
tx-mldsa44    # default/current
tx-fndsa512   # smaller reset-network option
```

Example boundary alias in `quip-transaction-crypto`:

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

`quip-transaction-crypto-core` needs the same selection for pure core suites:

```rust
#[cfg(feature = "tx-fndsa512")]
use quip_crypto_primitives_core::suite::sr25519_fndsa512 as tx_suite;

#[cfg(all(feature = "tx-mldsa44", not(feature = "tx-fndsa512")))]
use quip_crypto_primitives_core::suite::sr25519_mldsa44 as tx_suite;
```

Then the public constants remain aliases:

```rust
pub const HYBRID_PUBLIC_LEN: usize = tx_suite::HYBRID_PK_LEN;
pub const HYBRID_SIGNATURE_LEN: usize = tx_suite::HYBRID_SIG_LEN;
pub const HYBRID_SECRET_LEN: usize = tx_suite::HYBRID_SK_LEN;
```

## Phase 1: SDK Core

Work in `../polkadot-sdk/quip/primitives/crypto-core`.

1. Add `fn-dsa` dependencies to `crypto-core/Cargo.toml`.
   - Prefer depending on the split crates only if that materially reduces the
     signer/runtime footprint.
   - Consider `no_avx2` for binary size if verification performance remains
     acceptable.
2. Add `src/pq/fndsa512.rs`.
   - Constants:
     - `PUBLIC_KEY_LEN = 897`
     - `SIGN_KEY_LEN = 1281`
     - `SIGNATURE_LEN = 666`
   - Decide secret storage after checking the API:
     - If a verifying key can be derived from the signing key, store only the
       1281-byte signing key.
     - Otherwise store `sign_key || verifying_key` so `public_key_from_secret`
       stays cheap and deterministic.
   - Use `FN_DSA_LOGN_512`, `DOMAIN_NONE`, and `HASH_ID_RAW`.
   - Sign the already domain-separated `msg_prime`; do not add a second Quip
     domain wrapper inside the Falcon backend.
3. Extend `src/pq/mod.rs`.
   - Add `pub mod fndsa512`.
   - Add marker type `FnDsa512`.
   - Implement `FixedPqSignatureAlgorithm` for `FnDsa512`.
4. Deterministic behavior.
   - Key generation from the hybrid 32-byte PQ seed must be stable.
   - If `fn-dsa` exposes only RNG-based keygen/signing, build a small
     deterministic `CryptoRngCore` from existing hash/RNG patterns in the
     crate.
   - `sign_deterministic(secret, msg_prime, nonce)` must incorporate `nonce`
     into the Falcon signing RNG or nonce source so repeated consensus-style
     deterministic signing is reproducible.
5. Validation.
   - `validate_public_key` must reject wrong lengths and non-canonical keys.
   - `signature_from_bytes` should reject wrong lengths. If `fn-dsa` exposes
     signature canonicality checks independent of verification, use them.

## Phase 2: SDK Suites

Work in `../polkadot-sdk/quip/primitives/crypto-core/src/suite`.

1. Add `sr25519_fndsa512.rs`.
   - Mirror `sr25519_mldsa44.rs`.
   - Use `Classical = Sr25519`.
   - Use `Pq = FnDsa512`.
   - Use a new label:

     ```text
     hybrid-sr25519-fndsa512-v1\0
     ```

   - Public key layout: `sr25519_pk || fndsa512_pk`.
   - Secret key layout: `sr25519_sk || fndsa512_sk`.
   - Signature layout: `sr25519_sig || fndsa512_sig`.
2. Export the suite from `suite/mod.rs` and `crypto-core/src/lib.rs`.
3. Optional later: add `ed25519_fndsa512.rs` for GRANDPA.
   - This is not required for a transaction-only Falcon switch.
   - If consensus footprint is also targeted, add it in the same SDK pass.

## Phase 3: SDK Substrate Wrappers

Work in `../polkadot-sdk/quip/primitives/crypto/src/substrate`.

1. Add `sr25519_fndsa512.rs`.
   - Mirror the non-VRF portions of `sr25519_mldsa44.rs`.
   - Reuse the shared `signature.rs` wrapper.
   - Assign a new `CryptoTypeId`, for example `h3f5`.
2. Export it from `substrate/mod.rs`.
3. Add app-crypto wrapper tests.
   - `Public` and `Signature` round-trip to suite types.
   - `Pair::sign` and `Pair::verify` match suite verification.
   - `app_crypto!` can wrap the new types.
4. Optional consensus work.
   - If BABE moves to Falcon, port the hybrid VRF binding from
     `sr25519_mldsa44.rs` and replace the ML-DSA-44 binding signature with
     Falcon-512.
   - If GRANDPA moves to Falcon, add `ed25519_fndsa512.rs` and a new
     `CryptoTypeId`, for example `h1f5`.

## Phase 4: Protocol Transaction Crates

Work in `quip-protocol-rs`.

1. `crates/transaction-crypto-core`
   - Add `tx-mldsa44` and `tx-fndsa512` features.
   - Default to `tx-mldsa44` until the runtime intentionally flips.
   - Select the pure suite through a private alias module.
   - Keep public helper names stable:
     - `HYBRID_PUBLIC_LEN`
     - `HYBRID_SIGNATURE_LEN`
     - `HYBRID_SECRET_LEN`
     - `HybridTxSignatureBytes`
     - `public_key_from_seed`
     - `sign_payload_from_seed`
     - `sign_payload_from_secret`
   - Ensure `HybridTxSignatureBytes::verify` calls the selected suite.
2. `crates/transaction-crypto`
   - Add matching features and forward them to `transaction-crypto-core`.
   - Select the Substrate wrapper through a private alias module.
   - Keep `HybridPublic`, `HybridSignatureBytes`, `HybridPair`,
     `HybridTxPublic`, and `HybridTxSignature` names stable.
3. Runtime feature propagation.
   - Add the selected feature to `runtime/Cargo.toml` dependency features for
     `quip-transaction-crypto`.
   - Bump `spec_version`.
   - Bump `transaction_version` because the signed extrinsic signature field
     SCALE shape changes.
4. Genesis and dev keys.
   - Since a reset is acceptable, regenerate any funded/dev transaction account
     ids after flipping the feature.
   - Current account ids derive from full public bytes:

     ```text
     blake2b_256("quip-account-v1" || full_hybrid_public_key_bytes)
     ```

     The Falcon public key bytes produce different account ids.

## Phase 5: Signers And Bindings

1. WASM signer: `crates/transaction-crypto-wasm`
   - Propagate the selected `tx-*` feature to `transaction-crypto-core`.
   - Keep exported JS function names stable.
   - Update comments that explicitly say H3 or ML-DSA-44.
2. JS wrapper: `js/quip-signer`
   - No large structural change should be required because fee-estimation fake
     signature length is already read from metadata.
   - Update comments that hardcode 1344, 2484, or 3828.
3. Python binding: `crates/transaction-crypto-py`
   - Propagate or document the selected feature.
   - Update docstrings and tests that hardcode 1344-byte public keys.
4. CLI/examples/scripts
   - Transaction-key examples should derive the selected transaction public key.
   - Consensus key insertion only changes if BABE/GRANDPA are also moved.

## Phase 6: Fixtures And Tests

Add protocol-critical golden vectors for both current and Falcon suites where
useful.

Required Falcon vectors:

- `seed -> public_key`
- `(seed, message) -> signature envelope`
- `public_key -> account_id`
- BIP39 phrase and optional password to seed parity

Recommended test gates:

```bash
cargo test -p quip-crypto-primitives-core
cargo test -p quip-crypto-primitives
cargo test -p quip-transaction-crypto-core --features tx-fndsa512
cargo test -p quip-transaction-crypto --features tx-fndsa512
cargo test -p quip-protocol-runtime
make wasm-signer
```

Also verify:

- A Falcon-signed payload verifies in `quip-transaction-crypto-core`.
- A Falcon `HybridTxSignature` verifies through `sp_runtime::traits::Verify`.
- A full signed extrinsic using the Falcon envelope passes runtime checks.
- Metadata reports the new `ExtrinsicSignature` encoded length.
- `js/quip-signer` fake-signature patch sizes the fake signature from metadata.

## Open Implementation Questions

Resolve these before coding the SDK backend:

1. Can `fn-dsa` derive a verifying key from an encoded signing key?
   - If yes, `fndsa512::SECRET_KEY_LEN = 1281`.
   - If no, store `sign_key || verifying_key`, making the hybrid PQ secret
     component 2178 bytes.
2. Does `fn-dsa` expose deterministic keygen from seed directly?
   - If no, implement deterministic RNG from the 32-byte PQ component seed.
3. Does `fn-dsa` expose deterministic signing or nonce injection?
   - If no, deterministic signing must use a deterministic RNG derived from
     `secret || nonce || msg_prime`.
4. Are all required `fn-dsa` crates `no_std` under the features we need?
   - The runtime and browser signer depend on `no_std` compatibility.
5. Does `fn-dsa` verification-only dependency splitting materially reduce WASM
   or runtime size?
   - If yes, wire split crates instead of the top-level crate where practical.

## Risks And Mitigations

| Risk | Mitigation |
|---|---|
| `fn-dsa` is pre-1.0 and may change encodings | Pin the crate version and keep golden vectors checked in |
| accidental double domain separation | Sign only Quip's existing `msg_prime` with `HASH_ID_RAW` / no extra Quip domain in the Falcon backend |
| feature mismatch between runtime and signer | Propagate one `tx-*` feature through all transaction crypto crates and test envelope parity |
| account ids change | Network reset is accepted; regenerate genesis/funded accounts |
| consensus scope creep | Land transaction-only first; port BABE/GRANDPA only if explicitly needed |
| WASM size growth | Compare `make wasm-signer` output before and after; consider `fn-dsa` split crates and `no_avx2` |

## Out Of Scope

- Non-reset migration of existing account ids.
- A dual-signature runtime enum accepting both ML-DSA-44 and Falcon envelopes.
- Changing `ACCOUNT_ID_DOMAIN`.
- Changing Substrate's >256-byte `SignedPayload` hashing rule.
- Consensus Falcon wrappers unless explicitly selected after the transaction
  path is working.
