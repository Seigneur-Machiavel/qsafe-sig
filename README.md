# qsafe-sig 🔐

> Hybrid Ed25519 + MAYO signatures — quantum-migration-ready, single master key

A signing library that combines a classical Ed25519 signature with a post-quantum MAYO signature into a single hybrid output. One key, one `sign()`, one `verify()` — both algorithms run in parallel and both must pass.

Designed for systems that need to start hedging against quantum threats today, without dropping classical security in the process.

Built on top of [`@pinkparrot/qsafe-mayo-wasm`](https://github.com/Seigneur-Machiavel/qsafe-mayo-wasm) and [`@noble/curves`](https://github.com/paulmillr/noble-curves).

## Links

- **NPM:** [qsafe-sig] (https://www.npmjs.com/package/@pinkparrot/qsafe-sig)
- **Browser bundle:** [unpkg.com/@pinkparrot/qsafe-sig/dist/qsafe-sig.min.js](https://unpkg.com/@pinkparrot/qsafe-mayo-wasm/dist/mayo.browser.min.js)
- **MAYO-WASM:** https://github.com/Seigneur-Machiavel/qsafe-mayo-wasm
- **MAYO spec:** [pqmayo.org](https://pqmayo.org)

## Install

```sh
npm install qsafe-sig
```

## Quickstart

```js
import { QsafeSigner } from 'qsafe-sig';

// One-time setup: generate a random master seed (keep it secret)
const masterSeed = QsafeSigner.generateMasterKey(); // 32-byte Uint8Array

// Create a signer and derive a keypair from the seed
const signer = await QsafeSigner.create();
const { publicKey, secretKey } = signer.loadMasterKey(masterSeed);

// Sign
const message   = new TextEncoder().encode('hello world');
const signature = signer.sign(message);

// Verify (use createFull() for backward-compatible multi-version verification)
const verifier = await QsafeSigner.createFull();
const valid    = await verifier.verify(message, signature, publicKey);
console.log(valid); // true
```

## How it works

Each `sign()` call produces a single `Uint8Array` containing:

```
[ header (3B) | ed25519 signature (64B) | MAYO signature (variant-dependent) ]
```

The header encodes the protocol version and MAYO variant so `verify()` always knows what it's reading — no out-of-band metadata needed.

Both keys are derived from the same master seed via **HKDF-SHA256**, using separate info tags (`qsafe-ed25519` / `qsafe-mayo`). One seed → two independent keys → one hybrid keypair.

`verify()` runs Ed25519 first (pure JS, fast), and only hits WASM if that passes. Both must succeed for the signature to be valid.

## API

### `QsafeSigner.create(variant?, version?)` → `Promise<QsafeSigner>`

Creates a signer instance ready for both signing and verifying.

- `variant`: `'mayo1'` (default) or `'mayo2'`
- `version`: protocol version string. Default: `'<CURRENT_VERSION>'`

### `QsafeSigner.createFull(versions?)` → `Promise<QsafeSigner>`

Creates a verifier with **all known variants pre-loaded** — useful for validators that need to accept signatures from multiple versions or variants. Calling `loadMasterKey()` or `sign()` on this instance will throw.

- `versions`: array of version strings. Default: all known versions (`['1']`)

### `QsafeSigner.generateMasterKey(size?)` → `Uint8Array`

Generates a cryptographically random master seed.

- `size`: `16`, `24`, or `32` bytes. Default: `32`

### `QsafeSigner.checkFormat(signature)` → `boolean`

Fast structural check: validates the header and byte length. **Does not perform any cryptographic verification** — use as a pre-filter before `verify()`.

### `signer.loadMasterKey(masterSeed)` → `{ publicKey, secretKey }`

Derives and loads a keypair from the master seed. Must be called before `sign()`.

- `masterSeed`: `Uint8Array` of 16, 24, or 32 bytes
- Returns `{ publicKey: Uint8Array, secretKey: Uint8Array }`

The same instance can sign many messages after a single `loadMasterKey()` call.

### `signer.sign(message)` → `Uint8Array`

Signs a message. Requires a prior `loadMasterKey()` call.

### `signer.verify(message, signature, publicKey)` → `Promise<boolean>`

Verifies a hybrid signature. Lazy-loads the required WASM variant on first call, then caches it. Works across all registered protocol versions.

## Variants

| Variant | Public key | Signature | Secret key seed |
|---------|-----------|-----------|-----------------|
| mayo1   | 1420 B    | 454 B     | 24 B            |
| mayo2   | 4912 B    | 186 B     | 24 B            |

`mayo1` is the default — larger signature, smaller public key.  
`mayo2` flips the tradeoff: smaller signature, larger public key. Pick based on your storage/bandwidth constraints.

## Performance

Measured on a single run of `test.mjs` (Node.js, 256-byte and 128 KB messages):

| Operation      | mayo1    | mayo2    |
|----------------|----------|----------|
| Key generation | ~9.5 ms  | ~5.5 ms  |
| Sign           | ~13 ms   | ~9.5 ms  |
| Verify         | ~8.6 ms  | ~9.4 ms  |

WASM variants are loaded once and cached — subsequent `verify()` calls on a `createFull()` instance skip the load cost entirely.

## Protocol versioning

The 3-byte header encodes `version (u16 BE) + variant_id (u8)`. This means `verify()` is always backward-compatible: old signatures can be verified by a new verifier without any configuration, as long as the corresponding version entry is still registered in `constants.mjs`.

Old version entries are **never removed** — only new ones are added.

## Running the tests

```sh
node test.mjs
```

Each variant runs 100 sign/verify cycles and checks: keypair determinism, seed isolation, sign/verify roundtrip, wrong-key rejection, tampered signature/message rejection, and `checkFormat` behavior.

## License

GPL-3.0 — see [LICENSE](./LICENSE).

Depends on [`@pinkparrot/qsafe-mayo-wasm`](https://github.com/Seigneur-Machiavel/qsafe-mayo-wasm) (Apache-2.0) and [`@noble/curves`](https://github.com/paulmillr/noble-curves) / [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (MIT).