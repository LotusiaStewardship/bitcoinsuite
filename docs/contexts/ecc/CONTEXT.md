# Context: bitcoinsuite-ecc-secp256k1

## Boundary

**Inside**: Concrete implementation of the `Ecc` trait using the `secp256k1_abc` C library.

**Outside**: Core `Ecc` trait definition (`PubKey`, `SecKey`, error types are in `bitcoinsuite-core`). Signature verification and validation consumers.

## Dependencies

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-core` | Runtime | Ecc trait, PubKey, SecKey, ByteArray, Bytes, EccError, VerifySignatureError |
| `secp256k1_abc` | Runtime | C library binding for secp256k1 (with recovery support) |

## Module Structure

```
src/
└── lib.rs             EccSecp256k1 struct implementing Ecc trait
                        - pubkey_from_array, seckey_from_array
                        - sign (ECDSA DER), schnorr_sign
                        - verify, schnorr_verify
                        - derive_pubkey, serialize_pubkey_uncompressed
                        - normalize_sig (low-s normalization)
                        - sign_recoverable, recover_sig
```

## Key Invariants

1. **Small wrapper** — The crate is intentionally thin: just enough code to bridge the `Ecc` trait to `secp256k1_abc`. No business logic.
2. **`secp256k1_abc` is a specific fork** — Uses the `secp256k1_abc` crate (not mainstream `rust-secp256k1` or `libsecp256k1`). This fork includes Schnorr (BCH adaptation) and recovery support.
3. **`expect()` for infallible conversions** — `SecretKey::from_slice(&seckey).expect("Invalid secret key")` — These conversions are verified by the `seckey_from_array()` call first, so they should never fail.
4. **All `Ecc` trait methods implemented** — No `unimplemented!()` stubs (unlike `DummyEcc`).

## Key Contracts

| Contract | Type | Description |
|---|---|---|
| `EccSecp256k1` | struct implementing `Ecc` | The concrete ECC backend |
| `EccSecp256k1::new()` | constructor | Creates a new `Secp256k1<All>` context |
