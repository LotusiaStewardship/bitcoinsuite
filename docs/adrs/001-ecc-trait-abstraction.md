# ADR 001: ECC Trait Abstraction with Multiple Backends

**Date**: 2026-05-22 (inferred from codebase)

## Context

Bitcoin Suite needs to perform elliptic curve cryptography (ECDSA signing, Schnorr signing, key derivation, signature recovery) across multiple crates. The `secp256k1` curve is used by Bitcoin Cash, eCash, Lotus, and Ergon networks. Different environments may need different implementations: production uses the `secp256k1` C library, but tests need a no-op backend to avoid linking issues in CI or on resource-constrained systems.

The core crate (`bitcoinsuite-core`) defines the ECC interface, but should not depend on any specific C library. The concrete implementation lives in a separate crate.

## Decision

Define an `Ecc` trait in `bitcoinsuite-core/src/ecc/mod.rs` with all ECC operations as trait methods:

- `pubkey_from_array`, `seckey_from_array`
- `sign`, `schnorr_sign`
- `verify`, `schnorr_verify`
- `derive_pubkey`, `serialize_pubkey_uncompressed`
- `normalize_sig`, `sign_recoverable`, `recover_sig`

Provide two implementations:
- `EccSecp256k1` (in `bitcoinsuite-ecc-secp256k1`) — real implementation wrapping `secp256k1_abc` (a fork/version of the rust-secp256k1 library with recovery support)
- `DummyEcc` (in `bitcoinsuite-core`) — test double that returns zeros for all operations and `unimplemented!()` for verification

The `Ecc` trait, key types (`PubKey`, `SecKey`), and error types (`EccError`, `VerifySignatureError`) are all defined in `bitcoinsuite-core`. The implementation crate imports only these types.

## Considered Options

1. **Direct dependency on secp256k1 in core** — Simpler but couples core to a specific C library and makes CI harder for crates that don't need crypto.
2. **Feature-gated secp256k1 in core** — Complex feature flag management, still has C build dependency.
3. **Trait + separate impl crate (chosen)** — Clean separation, testability, no C build for crates that don't need real crypto.

## Consequences

**Positive**:
- `bitcoinsuite-core` has zero C build dependencies
- Tests can use `DummyEcc` for pure logic tests without linking secp256k1
- Backend can be swapped (e.g., for WASM or different secp256k1 versions)
- Clear trait boundary documented by `Ecc` interface

**Negative**:
- All ECC operations go through dynamic dispatch or generic parameterization
- Two crates to maintain instead of one
- `DummyEcc` verification methods are `unimplemented!()` — tests that need real verification must use the real backend
