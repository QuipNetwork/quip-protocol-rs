# Substrate Integration Research

## Status

This document summarizes the hybrid signature and Substrate integration work across:

- `quip-protocol-rs` local head: `d62d85a3c1e9` (`v0.2` branch, `v0.2.1-rc10-10-gd62d85a`)
- `polkadot-sdk` local head: `4330574c320b` (`v0.2` branch)
- `polkadot-sdk` comparison base: `origin/ru/tag/polkadot-stable2603` at `2e4dd0bc2236`
- SDK review anchor: [QuipNetwork/polkadot-sdk#3](https://github.com/QuipNetwork/polkadot-sdk/pull/3)

The source audit treats `polkadot-sdk v0.2` compared with `origin/ru/tag/polkadot-stable2603` as the SDK integration delta. The local SDK history also includes a merge commit for wasm-compatible signing, so the sections below cover both consensus integration and application signing surfaces.

No test suite was run as part of creating this research note. The testing section lists the source-level test coverage found during the audit.

## Executive Summary

Quip's v0.2 integration replaces the normal Substrate signing assumptions in three places:

1. User transaction signatures use a hybrid H3 scheme: `sr25519 + ML-DSA-44`.
2. BABE authority keys and BABE VRF proofs use the same H3 scheme, with a hybrid VRF wrapper that binds the classical sr25519 VRF output to an ML-DSA-44 signature.
3. GRANDPA authority signatures use a hybrid H1 scheme: `ed25519 + ML-DSA-44`.

The implementation is split deliberately:

- `polkadot-sdk/quip/primitives/crypto-core` contains the dependency-light, `no_std`, Substrate-independent hybrid crypto core.
- `polkadot-sdk/quip/primitives/crypto` adapts the core into Substrate `Pair`, `Public`, `Signature`, app-crypto, and BABE VRF types.
- `quip-protocol-rs/crates/transaction-crypto-core` exposes a smaller transaction-signing core for WASM and Python consumers.
- `quip-protocol-rs/crates/transaction-crypto` connects that transaction core to runtime traits such as `Verify` and `IdentifyAccount`.
- `quip-protocol-rs/crates/transaction-crypto-wasm`, `js/quip-signer`, and `crates/transaction-crypto-py` provide browser/Polkadot-js and Python integration surfaces.

The broad result is that Substrate runtime, node consensus, keystore, CLI, browser signing, and Python signing can all work with the same hybrid envelope and account derivation rules.

## Patch Map

The SDK diff from `origin/ru/tag/polkadot-stable2603` to `v0.2` touches 39 files. The material areas are:

- New hybrid crypto crates:
  - `quip/primitives/crypto-core`
  - `quip/primitives/crypto`
- BABE integration:
  - `substrate/primitives/consensus/babe`
  - `substrate/client/consensus/babe`
  - `substrate/frame/babe`
- GRANDPA integration:
  - `substrate/primitives/consensus/grandpa`
- Keystore and host interfaces:
  - `substrate/primitives/keystore`
  - `substrate/client/keystore`
  - `substrate/primitives/io`
- CLI support:
  - `substrate/client/cli/src/commands/insert_key.rs`
- Compatibility adjustments:
  - `polkadot/node/primitives/src/approval/mod.rs`
  - `cumulus/test/relay-sproof-builder/src/lib.rs`

The local SDK commit sequence shows the work landing in this order:

- BABE primitives and integration
- GRANDPA integration and generic callsite fixes
- Quip crypto primitives added to the SDK
- Type information support for large hybrid public/signature types
- CLI support for hybrid key insertion
- Keystore support for public keys too large for filename-based storage
- Wasm-compatible signing merge

On the protocol repo side, the important integration points are:

- Root `Cargo.toml` pins Substrate dependencies to `https://github.com/QuipNetwork/polkadot-sdk.git`, branch `v0.2`.
- `runtime/src/lib.rs` switches the runtime signature type to `HybridTxSignature`.
- `runtime/src/genesis_config_presets.rs` derives and wires hybrid transaction, BABE, and GRANDPA keys.
- `node/src/service.rs` keeps standard BABE and GRANDPA service wiring, but it now runs over patched SDK primitives.
- `node/src/insert_hybrid_key.rs` adds an operator-friendly hybrid session-key insertion command.
- `js/quip-signer` and `crates/transaction-crypto-py` expose app-facing signing APIs.

## Hybrid Signature Schemes

Two hybrid schemes are used:

| Name | Classical component | PQ component | Main use | Public bytes | Signature bytes |
| --- | --- | --- | --- | ---: | ---: |
| H1 / `h144` | ed25519 | ML-DSA-44 | GRANDPA authority signatures | 1344 | 2484 |
| H3 / `h344` | sr25519 | ML-DSA-44 | User transactions, BABE authority signatures, BABE VRF binding | 1344 | 2484 |

Both schemes use a 32-byte master seed. The SDK crypto core expands that seed into classical and post-quantum material with HKDF-SHA256 using:

- salt: `hybrid-sig`
- info: `classical` and `pq`

Messages are domain framed before signing:

```text
M' = version || label || context_length || context || message
```

The scheme labels distinguish H1 and H3:

- `hybrid-ed25519-mldsa44-v1\0`
- `hybrid-sr25519-mldsa44-v1\0`

The SDK `Pair` wrapper stores only the 32-byte master seed plus cached public key, then expands the full hybrid secret when signing is needed. This avoids making the Substrate keystore own a permanent 2624-byte secret representation.

## User Transaction Signing

User transactions use H3 (`sr25519 + ML-DSA-44`) through `HybridTxSignature`.

The signature envelope carries:

- full hybrid public key: 1344 bytes
- full hybrid signature: 2484 bytes

The runtime account ID is not the raw public key. It is:

```text
blake2_256("quip-account-v1" || hybrid_public_key_bytes)
```

This is implemented in `crates/transaction-crypto-core` and mirrored in the runtime-facing `crates/transaction-crypto` crate. Runtime verification checks both:

1. The envelope public key hashes to the claimed account ID.
2. The hybrid signature verifies over the signed payload bytes.

This gives the runtime a normal 32-byte `AccountId` while keeping full hybrid public-key material available inside the signature envelope.

### Runtime Wiring

`runtime/src/lib.rs` sets:

- `Signature = HybridTxSignature`
- `AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId`
- `Address = MultiAddress<AccountId, ()>`
- `UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, TxExtension>`

The runtime version comments record that changing the signed extrinsic wire format from `MultiSignature` to the hybrid envelope required transaction-version bumps. This is consensus relevant because existing signed extrinsics are no longer wire-compatible with the new signature type.

### Payload Rule

Substrate signing uses `SignedPayload::using_encoded`: payloads longer than 256 bytes are signed as `blake2_256(payload)`, while shorter payloads are signed directly.

The raw WASM and Python signing functions sign exactly the bytes they are given. That keeps the core bindings small and language-neutral, but it means callers must apply the `>256` Substrate rule themselves unless they are using a helper that already does it.

The TypeScript `js/quip-signer` package does apply this rule in `messageToSign`.

## Polkadot-js and Browser Signing

The browser-facing path has three layers:

- `crates/transaction-crypto-wasm`: wasm-bindgen wrapper over the transaction crypto core.
- `js/quip-transaction-crypto-wasm`: generated JS/WASM package copied from `wasm-pack`.
- `js/quip-signer`: Polkadot-js-compatible signer package.

The WASM API is intentionally hex-based:

- `publicFromSeed(seedHex)`
- `accountIdFromPublic(publicHex)`
- `seedFromMnemonic(secretUri)`
- `signPayloadFromSeed(seedHex, payloadHex)`
- `verifyEnvelope(payloadHex, envelopeHex, accountIdHex)`

The Polkadot-js signer implements `Signer.signRaw`. It expects the Polkadot-js API to convert normal payloads to raw signing bytes, then it:

1. Applies the Substrate `>256` payload rule.
2. Looks up the local secret by account ID.
3. Calls the WASM signer.
4. Returns the hybrid signature envelope as the `SignerResult.signature`.

There is also a compatibility patch:

- `patchExtrinsicSignFake()` overrides Polkadot-js fake-signature sizing.

This is needed because the hybrid envelope is about 3828 bytes, while upstream Polkadot-js fee-estimation paths assume much smaller fixed fake signatures. Without that patch, dry-run fee estimation can encode an unrealistically small signature.

The current browser integration is suitable for app-level development and injected signer experiments. Production browser extension work still needs careful key-storage and UX design.

## Python Signing

`crates/transaction-crypto-py` exposes PyO3 bindings over the same transaction crypto core.

The public Python API includes:

- `public_from_seed`
- `account_id_from_public`
- `seed_from_mnemonic`
- `sign_payload_from_seed`
- `verify_envelope`
- `HybridSigner.from_seed`
- `HybridSigner.from_mnemonic`
- `HybridSigner.public_key`
- `HybridSigner.account_id`
- `HybridSigner.sign`

The bindings release the GIL around CPU-heavy public-key derivation and signing. They also use `Zeroizing` for sensitive seed material.

The package documentation states that prebuilt abi3 wheels are available for Linux x86_64/aarch64 on CPython >= 3.9, with macOS and Windows building from source when installed from sdist.

As with the WASM API, Python signs exact bytes. Substrate callers must apply the `SignedPayload::using_encoded` payload rule before calling the raw signer.

## BABE Integration

BABE is moved from sr25519 app-crypto to the H3 hybrid suite:

- SDK crypto wrapper: `quip_crypto_primitives::substrate::sr25519_mldsa44`
- crypto ID: `h344`
- app key type: `babe`
- authority public size: 1344 bytes
- seal signature size: 2484 bytes

The SDK preserves familiar BABE type names where possible:

- `AuthorityId`
- `AuthorityPair`
- `AuthoritySignature`
- `VrfInput`
- `VrfOutput`
- `VrfSignature`

### Hybrid VRF

BABE also needs a VRF. The H3 implementation keeps the classical sr25519 VRF transcript shape, then binds the result to the PQ key:

1. Build the normal BABE sr25519 transcript from randomness, slot, and epoch.
2. Produce an sr25519 VRF output/proof.
3. Build a binding message from the BABE input and sr25519 pre-output.
4. Sign that binding message with the ML-DSA-44 key.
5. Define the hybrid VRF output as a hash over the sr25519 pre-output and PQ signature.

Verification checks both the sr25519 VRF proof and the ML-DSA-44 binding signature. BABE threshold and randomness consumers use `make_vrf_bytes` over the verified hybrid output rather than calling schnorrkel directly.

### Client and Runtime Changes

The BABE authoring path now asks the keystore for a hybrid VRF signature through:

- key type: `babe`
- crypto ID: H3 / `h344`
- input: `BabeVrfSignData { randomness, slot, epoch }`

The verification path decodes and checks the hybrid VRF proof, then computes BABE score bytes through the hybrid `make_vrf_bytes` helper.

`pallet-babe` finalization also uses the verified hybrid VRF bytes when updating randomness.

Compatibility changes were needed where Polkadot and Cumulus code previously assumed raw sr25519 BABE VRF pre-outputs. The SDK patch adjusts approval randomness and test relay sproof building to work with the new BABE VRF output type.

## GRANDPA Integration

GRANDPA is moved from ed25519 app-crypto to the H1 hybrid suite:

- SDK crypto wrapper: `quip_crypto_primitives::substrate::ed25519_mldsa44`
- crypto ID: `h144`
- app key type: `gran`
- authority public size: 1344 bytes
- authority signature size: 2484 bytes

The GRANDPA primitive crate keeps the normal public API shape:

- `AuthorityId`
- `AuthorityPair`
- `AuthoritySignature`

The main implementation change is signing. Instead of calling an ed25519-specific keystore method, GRANDPA now calls the generic `sign_with` path using the app key type and crypto ID. Verification remains authority-public-key driven through the Substrate signature traits.

## Keystore, Host Functions, and CLI

Hybrid keys do not fit well into Substrate assumptions that are convenient for 32-byte public keys. The SDK patch addresses this at three levels.

### Generic Crypto Host Functions

`sp_keystore` and `sp_io` add generic crypto methods that take both key type and crypto ID:

- list public keys
- generate new key
- sign
- BABE VRF sign

This lets consensus and session-key code route to H1/H3 without using sr25519-only or ed25519-only host functions.

### Long Public-Key Persistence

The local keystore previously encoded public keys into filenames. A 1344-byte hybrid public key is too large for that.

The SDK patch keeps legacy behavior for short public keys and introduces a new envelope for long keys:

- filename suffix: `blake2_256(public_key)`
- file body: JSON containing the full public key and secret URI

This preserves compatibility with existing short-key stores while allowing hybrid keys to be recovered and enumerated.

### Operator Key Insertion

The SDK CLI accepts:

- `hybrid-babe-h344`
- `hybrid-grandpa-h144`

The protocol repo also adds a focused `insert-hybrid-key` command that maps the scheme to the expected key type:

- BABE H3/H344 -> `babe`
- GRANDPA H1/H144 -> `gran`

That command reduces the chance of inserting a valid hybrid key under the wrong session key type.

## Runtime, Session, and Genesis

The runtime session key bundle contains:

- `babe: Babe`
- `grandpa: Grandpa`

Genesis construction uses three key roles:

- user transaction account: H3 transaction key
- BABE authority key: H3 session key
- GRANDPA authority key: H1 session key

For development presets, keys are derived from well-known seeds. For public testnet presets, the genesis builder imports validator public keys from configured hex files or literals.

The session genesis config maps each validator account to its BABE and GRANDPA session keys. BABE and GRANDPA authorities are populated through `pallet-session` rather than double-initializing the consensus pallets directly.

The runtime currently uses `SessionManager = ()`, so runtime-driven validator rotation is not implemented yet. Session APIs still exist for node tooling, explorers, and future session-key flows.

## Node Service Integration

The node service keeps the standard BABE and GRANDPA control flow:

- BABE block import
- BABE import queue
- BABE authoring
- GRANDPA block import
- GRANDPA voter

The important point is that the service code can remain mostly conventional because the SDK primitives, keystore, and consensus crates now present hybrid-compatible versions of the same expected Substrate interfaces.

## Testing Evidence Found

Source-level tests and fixtures found during the audit include:

- SDK crypto-core tests for:
  - H1/H3 key sizes
  - public/secret/signature byte roundtrips
  - deterministic and hedged signing
  - domain/context separation
- SDK Substrate-wrapper tests for:
  - `Pair`, `Public`, and `Signature` behavior
  - app-crypto compatibility
  - BABE VRF transcript compatibility
  - hybrid VRF verification
- Transaction crypto tests for:
  - SCALE envelope compatibility
  - account ID derivation
  - mnemonic and secret URI derivation parity with Substrate seed handling
  - wrong account/message/public/signature rejection
- Runtime tests for:
  - successful hybrid signed extrinsic checking
  - rejection when the account does not match the envelope public key
- WASM tests for:
  - sign/verify roundtrip
  - mnemonic seed derivation
  - invalid input handling
- Python tests for:
  - function API roundtrips
  - class API behavior
  - malformed envelope handling
  - parity with checked-in golden vectors

The current source also includes planning notes under `docs/polkadotjs/` for Polkadot-js validation and wasm signing work.

## Risks and Open Questions

- The raw WASM and Python APIs sign exact bytes. Substrate clients must consistently apply the `>256` payload hashing rule before calling them.
- Polkadot-js fee estimation currently depends on a `signFake` monkey patch. This should be monitored against Polkadot-js upgrades.
- Browser extension production work is not complete. Key storage, import/export UX, account selection, locking, and threat model need a separate pass.
- The large signature envelope increases extrinsic size. Fees, block limits, transaction pool behavior, and UX around fee estimates should be validated with realistic payloads.
- Hybrid BABE digests and GRANDPA messages increase consensus data sizes. Multi-validator soak testing should measure bandwidth and import latency.
- Runtime equivocation reporting is disabled in the current config. That may be acceptable for the current stage, but it should be tracked before production readiness.
- Session rotation is not implemented in-runtime because `SessionManager = ()`. Operator workflows can insert keys, but full validator lifecycle design is still future work.
- The SDK comparison base is `origin/ru/tag/polkadot-stable2603`; release notes should avoid comparing this patch stack against a different upstream Polkadot tag.
- The protocol repo depends on the SDK `v0.2` branch. For reproducible releases, consider pinning exact SDK revisions or documenting the branch/tag invariant in the release checklist.

## Suggested Next Steps

1. Run the full local test matrix for both repos against the audited heads.
2. Add generated JSON golden fixtures shared by Rust, WASM, TypeScript, and Python.
3. Perform a manual Polkadot-js Apps transaction test using the injected Quip signer.
4. Run a multi-validator dev/testnet with hybrid BABE and GRANDPA keys inserted through the operator command.
5. Measure extrinsic, digest, and finality-message size impacts under realistic block production.
6. Decide whether the release process should pin SDK dependencies to an exact commit instead of a mutable branch.
7. Expand operator docs for hybrid key insertion, session-key registration, and recovery.
