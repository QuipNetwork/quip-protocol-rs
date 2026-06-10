# Network Upgrade CLI

`quip-network-upgrade` submits a sudo-wrapped `system.set_code` extrinsic with
the Quip hybrid transaction signer.

## Build

```bash
cargo build -p quip-tools --bin quip-network-upgrade
```

The binary is available at:

```text
target/debug/quip-network-upgrade
```

Use `--release` when running operational upgrades.

## Dev Chain Example

Start a local dev node, then inspect the upgrade transaction:

```bash
./target/debug/quip-network-upgrade \
  --rpc ws://127.0.0.1:9944 \
  --wasm ./target/release/wbuild/quip-protocol-runtime/quip_protocol_runtime.compact.compressed.wasm \
  --suri "//Alice" \
  --dry-run
```

Submit the transaction:

```bash
./target/debug/quip-network-upgrade \
  --rpc ws://127.0.0.1:9944 \
  --wasm ./target/release/wbuild/quip-protocol-runtime/quip_protocol_runtime.compact.compressed.wasm \
  --suri "//Alice" \
  --yes \
  --wait-finalized
```

The signer must be the sudo account configured on the target chain. The tool
checks this before submitting (along with the chain's `spec_version`) and
aborts if either preflight check fails; in `--dry-run` mode the checks only
print warnings.

Because the signed payload embeds the tool's compiled `spec_version`
(`CheckSpecVersion`), the binary must be built from the source revision
matching the **currently live** runtime — while `--wasm` points at the **new**
runtime blob built from the upgraded source.

## Signer Material

Pass exactly one signer source:

```text
--suri <secret phrase or SURI>
--suri-file <path>
--suri-env <ENV_VAR_NAME>
```

Prefer `--suri-file` or `--suri-env` for shared testnets so the secret does not
appear directly in shell history. The tool never prints the signer secret.

## Runtime Wasm

For a production runtime blob, build with the release profile and runtime
release feature set used by operators:

```bash
cargo build --release --features on-chain-release-build
```

The expected artifact path is usually:

```text
target/release/wbuild/quip-protocol-runtime/quip_protocol_runtime.compact.compressed.wasm
```

## Output

Before submission the tool prints:

- signer account
- RPC URL
- Wasm path, byte length, and hash
- nonce
- best block number and hash
- call summary
- encoded extrinsic length and hash

For real submissions, `--yes` is required. `--dry-run` builds and prints the
transaction without calling `author_submitExtrinsic`; it does not validate the
transaction against the chain beyond the preflight checks above, and it
conflicts with `--wait-finalized`.

## Verifying the Upgrade

Without `--wait-finalized`, a zero exit only means the transaction was
accepted into the node's pool — inclusion and dispatch success are not
confirmed, and the tool says so.

With `--wait-finalized`, the tool polls until the extrinsic appears in a
finalized block, then verifies the upgrade actually happened:

- fails on a `system.ExtrinsicFailed` event for the extrinsic
- fails if `sudo.Sudid` reports the inner `system.set_code` errored
  (e.g. the new runtime does not increase `spec_version`)
- prints the old and new on-chain `spec_version`

Use `--wait-finalized` for real upgrades; only its success output proves the
chain is running the new code.
