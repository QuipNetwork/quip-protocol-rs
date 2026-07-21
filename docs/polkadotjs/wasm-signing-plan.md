# WASM Transaction Signing Plan

This document captures the implementation plan for browser-compatible Quip
transaction signing so Quip accounts can be used from Polkadot.js Apps.

The goal is ordinary signed extrinsic submission from Apps. This is separate
from validator/session key management: BABE and GRANDPA hybrid authority keys
remain node-keystore managed via `author_rotateKeys` and `session.setKeys`.

Current implementation decisions:

- Keep the WASM signer and supporting browser code in this repository where
  practical.
- Let Apps default injected Quip accounts to `sr25519` when no account `type`
  is specified; signing is still delegated to the injected Quip signer.
- Defer metadata registration support until a concrete Apps flow requires it.
- Use a key-storage model similar to the Polkadot.js extension for now.
- Keep browser-WASM signing independent of `quip-crypto-primitives`.
  Validation showed that crate pulls `sp-io`/`sp-core`, which pulls
  `secp256k1-sys`; that dependency path is not browser-WASM clean in this
  toolchain.

## Current State

The branch contains the Rust-side foundation:

- `crates/transaction-crypto-core` is a byte-oriented, runtime-free crate for
  account derivation, H3 payload signing, and signature envelope encoding. It
  uses lower-level crypto crates directly and deliberately avoids `sp_core`,
  `sp_io`, and `quip-crypto-primitives`.
- `crates/transaction-crypto` adapts those byte helpers into runtime traits:
  `HybridTxSignature`, `HybridTxPublic`, `IdentifyAccount`, and `Verify`.
- `crates/transaction-crypto-wasm` exposes the byte-level helpers through
  `wasm-bindgen` using hex-string inputs and outputs.
- `js/quip-signer` provides a TypeScript `Signer`, dev seed provider, and
  `window.injectedWeb3.quip` helper for Apps/extension integration.
- `runtime/src/lib.rs` sets `Signature = HybridTxSignature` and derives
  `AccountId` from the signature verifier's signer type.
- `node/src/benchmarking.rs` shows the expected signing payload shape: build a
  `SignedPayload`, sign its SCALE-encoded bytes, and place the resulting
  `{ public, signature }` hybrid envelope into the extrinsic signature field.

The important runtime contract is already in place:

```text
AccountId = blake2b_256("quip-account-v1" || full_h3_public_key_bytes)
Signature = SCALE(HybridTxSignature { public, signature })
Verification =
  1. derive AccountId from embedded public key
  2. compare it with the claimed signer
  3. verify H3 signature over the SCALE-encoded transaction payload
```

## Apps Integration Model

The local Polkadot.js Apps checkout is available at `../apps`.

Relevant Apps behavior:

- `packages/react-api/src/Api.tsx` creates the main `ApiPromise` with a shared
  `ApiSigner`, `types`, and `typesBundle`.
- `packages/react-api/src/Api.tsx` loads injected accounts through
  `web3Accounts()` and defaults missing account `type` values to `sr25519`.
- `packages/react-signer/src/TxSigned.tsx` uses `web3FromSource(source)` for
  injected accounts and then passes `injected.signer` into `signAndSend`.
- `packages/react-signer/src/signers/AccountSigner.ts` shows the local keyring
  baseline: Apps creates an `ExtrinsicPayload` from the JSON payload and calls
  `.sign(pair)`.

For Quip, the browser path should use an injected signer rather than making
Apps' built-in keyring understand H3. The injected signer must return the
already correctly encoded hybrid envelope as the `signature` field in
`SignerResult`.

## Implementation Phases

### 1. Pin Wire Fixtures

Rust parity fixtures are currently test-driven rather than stored as a JSON
fixture file. The core fixture is the deterministic `quip-signer-fixture`
payload used to compare the byte-level core envelope against the runtime
`HybridTxSignature` encoding.

A JSON fixture file is still useful before wiring automated Apps tests.

Minimum fixture set:

- dev seed or test-only seed
- H3 public bytes
- derived 32-byte account id
- SS58 address for the derived account id
- representative `SignerPayloadJSON`
- SCALE-encoded signing payload bytes
- raw H3 signature bytes
- SCALE-encoded `HybridTxSignature` envelope bytes
- full signed extrinsic hex

The fixture should use a low-impact call such as `system.remark`.

### 2. Add Rust Parity Tests

Implemented. Tests prove the runtime envelope and the byte-level core envelope
are identical on the wire:

- `HybridTxSignatureBytes::encode_envelope()` matches
  `HybridTxSignature::encode()`.
- `account_id_from_public_bytes()` matches `account_id_from_public()`.
- a full signed test extrinsic validates through runtime transaction checking.

These tests are the guardrail for the browser package. A browser signature that
is cryptographically valid but SCALE-encoded differently must fail before it
reaches Apps.

### 3. Add a WASM Package

Implemented:

```text
crates/transaction-crypto-wasm
```

Exported functions:

```text
accountIdFromPublic(publicHex) -> accountIdHex
signPayloadFromSeed(seedHex, payloadHex) -> envelopeHex
verifyEnvelope(payloadHex, envelopeHex, accountIdHex) -> bool
publicFromSeed(seedHex) -> publicHex
seedFromMnemonic(secretUri) -> seedHex
```

`seedFromMnemonic` derives the 32-byte master seed from a limited secret URI
(English BIP39 phrase with optional `///password`, or a `0x` seed hex), matching
substrate's `Pair::from_phrase`. Derivation junctions are rejected. Rust parity
is enforced by `mnemonic_seed_matches_substrate_from_phrase` in
`crates/transaction-crypto`.

`public_from_seed` and raw seed signing are acceptable for development
fixtures, but a production signer should not expose long-lived raw seeds to page
JavaScript.

Build target:

```text
wasm32-unknown-unknown
```

The repository toolchain currently pins `wasm32v1-none` for the runtime. The
browser package may need a separate documented setup step for
`wasm32-unknown-unknown` if `wasm-bindgen` is used.

### 4. Add a TypeScript Signer Wrapper

Implemented as source package:

```text
js/quip-signer
```

It wraps the WASM exports structurally and implements the polkadot-js `Signer`
interface.

Expected behavior for `signPayload(payload)`:

1. Read `payload.payload`.
2. Convert the hex payload to bytes.
3. Sign the exact bytes with H3.
4. Return `SignerResult` with:

```ts
{
  id,
  signature: envelopeHex
}
```

The returned `signature` must be the SCALE-encoded `HybridTxSignature` envelope,
with no `MultiSignature` variant byte.

### 5. Implement Browser Injection

Partially implemented in `js/quip-signer`.

Current helper surface:

```ts
window.injectedWeb3.quip = {
  version,
  enable: async (origin) => ({
    accounts,
    signer
  })
}
```

Account behavior:

- Return Quip SS58 addresses derived from H3 public bytes.
- Set `meta.source = "quip"`.
- Set a clear display name.
- Omit the account `type` initially and allow Apps to default it to `sr25519`.
  This is acceptable because transaction signing is delegated to
  `injected.signer`, not Apps' local keyring.

Metadata behavior:

- Leave `metadata.get()` and `metadata.provide()` out of the first pass unless
  Apps blocks a supported transaction flow without them.
- Track metadata registration as follow-up work.

Security behavior:

- Keep private key material in the extension or background context.
- Do not expose raw seeds to the page.
- Treat any seed-based page-level helper as dev-only.
- Use the Polkadot.js extension's key-storage and unlock model as the initial
  reference design.

### 6. Validate in Apps

Use the local Apps checkout at `../apps` for manual and automated validation.

Acceptance path:

1. Run a local Quip dev node.
2. Run Apps from `../apps`.
3. Connect Apps to `ws://localhost:9944`.
4. Confirm the injected Quip account appears.
5. Submit `system.remark` or a small balance transfer from the injected account.
6. Confirm the transaction is included.
7. Confirm a tampered signature or mismatched account is rejected as
   `InvalidTransaction::BadProof`.

If Apps fails before calling the injected signer, check account type filtering
and metadata/type registration first. If Apps calls the signer but the node
rejects the transaction, compare the returned `signature` against the pinned
Rust fixture.

## Test Matrix

Rust:

```bash
cargo test -p quip-transaction-crypto-core -p quip-transaction-crypto -p quip-transaction-crypto-wasm
cargo test -p quip-protocol-runtime hybrid_signed_extrinsic_checks_successfully
```

WASM:

```bash
cargo check -p quip-transaction-crypto-wasm --target wasm32-unknown-unknown
```

The generated browser bindings under `js/quip-transaction-crypto-wasm/` are
git-ignored. Regenerate them (requires `wasm-pack`) with:

```bash
make wasm-signer
```

TypeScript, once package dependencies are installed:

```bash
cd js/quip-signer
yarn typecheck
```

Apps:

```bash
cd ../apps
yarn install
QUIP_DEV_SIGNER=1 yarn start
```

The local Apps integration lives in `../apps/packages/apps/src/initQuipSigner.ts`
and is opt-in. It can be enabled with any of:

- `QUIP_DEV_SIGNER=1` at build/start time
- `?quipSigner=1` in the Apps URL
- `localStorage.setItem('quip:devSigner', '1')`

When enabled, Apps loads `js/quip-signer` and the generated
`js/quip-transaction-crypto-wasm` package from this repository, injects a
`quip` source before `web3Enable('polkadot-js/apps')`, and exposes the funded
dev accounts `Quip Alice`, `Quip Bob`, and `Quip Alice Stash`.

It also publishes `globalThis.quipSigner.importMnemonic(name, mnemonic)` and
adds a **From Quip mnemonic** button to the Accounts page (only when the dev
signer is active). The modal derives the account with `seedFromMnemonic`,
registers the seed with the injected signer, and calls
`keyring.addExternal(address, { source: 'quip', isInjected: true })` so the
account appears immediately and signs through the injected signer. The signer
keys seeds by account id (not the SS58 address), so it is independent of the
chain's address prefix.

Manual Apps verification remains required because the critical integration
point is injected account discovery and `signPayload` wiring through the signer
modal.

## Runtime Versioning

No runtime bump is needed for client-only WASM or Apps changes.

Bump `spec_version` if runtime metadata, signed extensions, account types, or
signature type metadata change.

Bump `transaction_version` if signed extrinsic bytes change. That includes any
change to the `HybridTxSignature` SCALE shape, signed extension order, or
signed payload fields.

## Remaining Work

- Add a generated JSON fixture that can be loaded by both Rust and TypeScript
  tests.
- Typecheck `js/quip-signer` with installed JS dependencies.
- Manually validate transaction submission from `../apps`.
- Wire `js/quip-signer` into an actual browser extension.
- Add metadata registration only if Apps blocks a supported transaction flow.
