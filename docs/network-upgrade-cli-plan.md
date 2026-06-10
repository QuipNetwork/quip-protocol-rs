# Network Upgrade CLI Plan

## Goal

Create a Rust CLI tool for submitting runtime upgrades to a Quip network. The
tool signs a sudo-wrapped runtime upgrade extrinsic with a Quip hybrid
transaction key and submits it to a node over RPC.

## Crate Layout

Add a new workspace crate:

```text
crates/tools
```

Package name:

```text
quip-tools
```

Binary target:

```text
quip-network-upgrade
```

Suggested structure:

```text
crates/tools/Cargo.toml
crates/tools/src/lib.rs
crates/tools/src/bin/quip-network-upgrade.rs
```

Use `src/lib.rs` for reusable pieces:

- signer input resolution
- Wasm loading and hashing
- signed extrinsic construction
- RPC helpers

Keep the binary file mostly as argument parsing plus orchestration.

## CLI Interface

Required arguments:

```bash
quip-network-upgrade \
  --rpc ws://127.0.0.1:9944 \
  --wasm ./path/to/runtime.wasm \
  --suri "<secret phrase or SURI>"
```

Signer input should support exactly one of:

```text
--suri <secret phrase or SURI>
--suri-file <path>
--suri-env <ENV_VAR_NAME>
```

Other flags:

```text
--dry-run
--yes
--wait-finalized
```

`--dry-run` builds and prints the transaction details but does not submit.
`--yes` is required for real submission.

## Signing

Reuse the existing Quip transaction signing scheme:

- `quip_transaction_crypto::HybridPair`
- `quip_transaction_crypto::HybridTxSignature`
- `quip_transaction_crypto::account_id_from_public`

Do not use stock sr25519 signing. The runtime uses the Quip hybrid signature
envelope.

Use the signing pattern from `node/src/benchmarking.rs` as the reference:

- Build the runtime `TxExtension`.
- Build `SignedPayload`.
- Sign the encoded payload with `HybridTxSignature::sign`.
- Construct `runtime::UncheckedExtrinsic::new_signed`.

## Upgrade Call

Read the Wasm file from `--wasm` and construct:

```text
RuntimeCall::System(frame_system::Call::set_code { code: wasm_bytes })
```

Wrap it in sudo:

```text
RuntimeCall::Sudo(...)
```

Prefer `sudo_unchecked_weight` with an explicit conservative weight if that
fits the current runtime call type cleanly. Otherwise use the normal `sudo`
call if it compiles and works with the current metadata.

The signer must be the sudo account configured on the target chain.

## RPC Flow

Fetch chain context from the target node:

- genesis hash
- best block hash
- best block number
- signer nonce via `system_accountNextIndex`

Use this context to build a mortal signed extrinsic:

- era period derived from runtime `BlockHashCount`
- current best block as era phase
- current runtime `spec_version`
- current runtime `transaction_version`
- genesis hash
- best hash
- nonce

Submit the SCALE-encoded extrinsic through:

```text
author_submitExtrinsic
```

Print the returned transaction hash.

If `--wait-finalized` is passed, wait until the extrinsic is finalized and
print the finalized block hash.

## Safety Output

Before submission, print:

- signer account SS58
- RPC URL
- Wasm path
- Wasm byte length
- Wasm hash
- account nonce
- best block number and hash
- call summary: `sudo(system.set_code)`

For real submission:

- refuse to submit unless `--yes` is provided
- never print the secret/SURI

## Tests

Add unit tests for:

- Wasm loading rejects missing files.
- Wasm loading rejects empty files.
- signer input resolution accepts direct, file, and env sources.
- signer input resolution rejects multiple signer sources.
- signed extrinsic construction is deterministic for fixed inputs.
- upgrade call encodes as `sudo(system.set_code)`.
- dry-run does not call `author_submitExtrinsic`.

## Documentation

Add:

```text
docs/network-upgrade-cli.md
```

Document:

- dev-chain usage
- testnet operator usage
- how to pass signer material safely
- how to locate the runtime Wasm artifact
- that the signer must be the sudo account

## Non-Goals

- Do not implement multisig or governance flows in this tool.
- Do not add node-side RPC endpoints.
- Do not replace the existing node CLI.
- Do not support stock Substrate sr25519 transaction signing.
