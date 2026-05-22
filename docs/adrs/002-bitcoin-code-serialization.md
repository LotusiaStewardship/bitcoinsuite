# ADR 002: Custom `BitcoinCode` Trait for Bitcoin Wire Serialization

**Date**: 2026-05-22 (inferred from codebase)

## Context

Bitcoin Suite works with Bitcoin wire-format data: transactions, blocks, scripts, and other protocol-level structures. The existing Rust ecosystem has competing approaches:
- `serde` with custom `Serializer`/`Deserializer` implementations
- `bitcoin` crate's `consensus` encoding
- Manual `encode`/`decode` functions per type

The project needs a serialization approach that:
- Matches Bitcoin wire format exactly (little-endian integers, compact-size-prefixed vectors, etc.)
- Is simple and trait-based
- Avoids adding heavy dependencies like a full consensus library
- Works for all core types (Tx, Block, Script, etc.)

## Decision

Define a custom `BitcoinCode` trait in `bitcoinsuite-core/src/bitcoin_code.rs`:

```rust
pub trait BitcoinCode: Sized {
    fn ser_to(&self, bytes: &mut BytesMut);
    fn deser(data: &mut Bytes) -> Result<Self>;
    fn ser(&self) -> Bytes { /* default: allocate, ser_to, freeze */ }
}
```

Types implement this trait directly rather than using serde's derive. The `ser_to`/`deser` methods operate on `BytesMut`/`Bytes` to avoid unnecessary allocations and support partial reads (important for parsing block data from streams).

## Considered Options

1. **serde Serialize/Deserialize** — Powerful but serde's data model doesn't map cleanly to Bitcoin wire format (compact sizes, specific integer encodings). Would need a custom `serde::Serializer` which is complex.
2. **bitcoin crate's consensus encoding** — Heavy dependency with its own type system, would conflict with the project's custom types.
3. **Manual encode/decode functions** — Works but no trait to constrain the pattern, harder to write generic code.
4. **Custom `BitcoinCode` trait (chosen)** — Simple, explicit, no external dependencies, works with existing error types.

## Consequences

**Positive**:
- No dependency on serde's data model for binary encoding (serde is used separately for JSON/config)
- `ser_to`/`deser` on mutable references enables zero-copy slicing and streaming reads
- `BitcoinCode` is implementable for any type, not just structs (e.g., `i32`, `u64`, `ByteArray<N>`)
- Clear, minimal trait with only two required methods

**Negative**:
- Duplication: some types have both `BitcoinCode` impls and `serde` derives (for different use cases)
- Manual implementation required for each type (no derive macro)
- Third-party types can't implement `BitcoinCode` without a newtype wrapper
