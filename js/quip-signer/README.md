# @quip-network/quip-signer

TypeScript wrapper for Quip browser transaction signing.

The package expects a WASM module built from
`crates/transaction-crypto-wasm`. The wrapper keeps the WASM API structural so
the generated module can be imported directly or passed through extension
background/page boundaries.

## Development Usage

```ts
import * as wasm from 'quip-transaction-crypto-wasm';
import { DevSeedProvider, QuipSigner, injectQuip } from '@quip-network/quip-signer';

const { accounts, provider } = await DevSeedProvider.fromSeeds(wasm, [
  {
    name: 'Alice',
    seedHex: '0x0707070707070707070707070707070707070707070707070707070707070707'
  }
]);

injectQuip({
  accounts,
  signer: new QuipSigner(provider)
});
```

`DevSeedProvider` is for fixtures and local smoke tests only. A production
extension should keep private key material in extension-controlled storage and
only expose the injected accounts plus the signer.

## Mnemonic Import

`DevSeedProvider.fromMnemonics` derives master seeds from BIP39 phrases using
the WASM module, matching substrate's `Pair::from_phrase`, so imported accounts
resolve to the same addresses the runtime recognizes:

```ts
const { accounts, provider } = await DevSeedProvider.fromMnemonics(wasm, [
  {
    name: 'Alice',
    mnemonic: 'bottom drive obey lake curtain smoke basket hold race lonely fit walk'
  }
]);
```

Each `mnemonic` may be an English BIP39 phrase, optionally followed by
`///<password>`, or a `0x`-prefixed 64-digit hex seed. Derivation junctions
(`//hard`, `/soft`) are intentionally not supported and are rejected.

The underlying `wasm.seedFromMnemonic(secretUri)` export returns the master seed
hex, which can also be passed to `publicFromSeed` / `signPayloadFromSeed`.

## Signer Contract

`QuipSigner` implements `signRaw` (not `signPayload`): polkadot-js hands
`signRaw` the fully SCALE-encoded `ExtrinsicPayload` bytes via `toRaw()`, so the
signer needs no metadata-aware registry. The signer reproduces substrate's
`SignedPayload::using_encoded` rule (blake2-256 the payload when it exceeds 256
bytes, otherwise sign verbatim), signs with H3, and returns:

```ts
{
  id,
  signature
}
```

`signature` is the SCALE-encoded `HybridTxSignature { public, signature }`
envelope expected by the Quip runtime. It is not a `MultiSignature` variant.
