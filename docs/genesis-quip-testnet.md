# quip-testnet Genesis Manifest

Public material for the three bootnode operators pinned into the
`quip-testnet` genesis preset (introduced in v0.2.0). The full BABE / GRANDPA
public bytes live as `include_str!`-loaded hex blobs under
`runtime/src/genesis_quip_testnet/`. This file is the human-readable index.

## Operators

### Operator 1

- **multiaddr**: `/dns4/bootnode-1.testnet.quip.network/tcp/30333/p2p/12D3KooWBdhB4xGX6hfFsNufqQsG99kekiH9kJhLSiui3RgatnpE`
- **peer-id**: `12D3KooWBdhB4xGX6hfFsNufqQsG99kekiH9kJhLSiui3RgatnpE`
- **tx_account_ss58**: `5GZMoWFMoNGLZKT1tduLMQQQC7dBQo4MHkYqriCdDATXqaYi`
- **tx_account_hex**: `0xc6cb8a79a71b11347a7ce0d983104278c0682dc70b7f90be9afd92ab54f1404b`
- **role**: holds initial sudo for v0.2.0 (replace with multisig in a later release)

### Operator 2

- **multiaddr**: `/dns4/bootnode-2.testnet.quip.network/tcp/30333/p2p/12D3KooWPJAHo45AA94u3fYS3tXvyKouZnWihQnXWPHAzikXLfPW`
- **peer-id**: `12D3KooWPJAHo45AA94u3fYS3tXvyKouZnWihQnXWPHAzikXLfPW`
- **tx_account_ss58**: `5FUFx3HLMXCAes5RrGDV2KEPxHwPyDu8LpmarD2iwcqQm48c`
- **tx_account_hex**: `0x96ab60c5a90f6b18566155d2187fae8f52e3cd43627fb4a40d5c89f3a512bb5b`

### Operator 3

- **multiaddr**: `/dns4/bootnode-3.testnet.quip.network/tcp/30333/p2p/12D3KooWM6n7wYvett975UnLYXrvnBGqLk2DLJoCRoFxgXTkptWe`
- **peer-id**: `12D3KooWM6n7wYvett975UnLYXrvnBGqLk2DLJoCRoFxgXTkptWe`
- **tx_account_ss58**: `5HgizfVW1rciPqPafkipfytynovFC3d8N1WFr8ffVF9Gjtte`
- **tx_account_hex**: `0xf8a5d50a6b32c3784b1e9fd9811e57b63524e5ec0defaafc289304bf99061db7`

## Verifying

To independently confirm the genesis preset matches this manifest:

```bash
cargo build --release -p quip-network-node
./target/release/quip-network-node export-chain-spec --chain quip-testnet \
    | jq '.bootNodes, .properties'
```

Expected output: three `/dns4/bootnode-N.testnet.quip.network/.../p2p/12D3KooW…`
multiaddrs (matching the peer-ids above) and `tokenSymbol=tQUIP`,
`tokenDecimals=12`, `ss58Format=42`.

To compare the runtime-derived authority public bytes against the hex blobs:

```bash
cargo test -p quip-protocol-runtime --lib genesis_config_presets::tests
```

The `quip_testnet_operator_1_account_is_pinned` test asserts that
`tx_account_from_hex("c6cb8a79…")` round-trips to the same bytes, catching
silent regressions in either the hex parsing or the account-id derivation.

## Updating

To add or rotate an operator, follow [`docs/testnet-keys.md`](testnet-keys.md):
the helper script produces the `public-bundle.txt` and the coordinator
commits the matching `*.hex` files plus a manifest entry here. Bumping the
`quip_testnet` genesis requires re-exporting `quip-testnet.json` and
republishing it in `nodes.quip.network`.
