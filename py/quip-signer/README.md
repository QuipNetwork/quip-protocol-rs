# quip-signer (Python)

CPython bindings for Quip's hybrid (H3 = `sr25519 + ML-DSA-44`) transaction
signer. A thin PyO3 wrapper over `quip-transaction-crypto-core` — the same
`sp`-free engine the browser WASM signer is built from — so the Python signer,
the browser signer, and the runtime verifier are byte-identical.

## Install

The package is distributed by vendoring `quip-protocol-rs` as a git submodule
(the same model the browser signer uses), then building the extension locally
with [maturin](https://www.maturin.rs/). The build drops the git-ignored
extension into `py/quip-signer/quip_signer/`.

```bash
# from your downstream repo, with quip-protocol-rs pinned as a submodule:
make -C quip-protocol-rs py-signer        # builds the wheel + extension

# then either install the wheel...
pip install quip-protocol-rs/target/wheels/quip_signer-*.whl
# ...or, for an editable/dev install:
pip install -e quip-protocol-rs/crates/transaction-crypto-py
# ...or add the staging dir to PYTHONPATH after `make py-signer-develop`:
export PYTHONPATH="quip-protocol-rs/py/quip-signer:$PYTHONPATH"
```

The submodule pin must be pushed to origin to be shareable (same as the WASM
signer flow).

## Usage

```python
import quip_signer

# from a BIP39 phrase (or a 0x-prefixed 64-hex seed)
signer = quip_signer.HybridSigner.from_mnemonic(
    "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
)
public = signer.public_key        # 1344 bytes
account = signer.account_id       # 32 bytes
envelope = signer.sign(b"payload bytes")   # SCALE-encoded HybridTxSignature

assert quip_signer.verify_envelope(b"payload bytes", envelope, account)

# free functions mirror the core byte API:
seed = quip_signer.seed_from_mnemonic("0x" + "07" * 32)
pub = quip_signer.public_from_seed(seed)
acct = quip_signer.account_id_from_public(pub)
env = quip_signer.sign_payload_from_seed(seed, b"hello")
```

Invalid input (bad seed length, malformed envelope, derivation junctions in a
URI, …) raises `quip_signer.QuipSignerError`.

## Building / testing in-repo

```bash
make py-signer-develop   # maturin develop into a local venv
make py-signer           # release wheel + size report
```
