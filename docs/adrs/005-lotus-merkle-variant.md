# ADR 005: Lotus-Specific Merkle Tree Implementation

**Date**: 2026-05-22 (inferred from codebase)

## Context

Bitcoin Suite supports multiple Bitcoin-family blockchains (BCH, XEC, XPI/Lotus, XRG). The Lotus (XPI) blockchain uses a modified merkle tree compared to standard Bitcoin:

1. **Merkle leaf computation**: `SHA256d(txid || lotus_txid)` instead of Bitcoin's `SHA256d(raw_tx)`. Lotus defines `lotus_txid` as an additional 32-byte identifier computed from the transaction data.
2. **Odd-leaf handling**: When the number of leaves is odd, Bitcoin duplicates the last leaf (`SHA256d(last || last)`). Lotus pads with a 32-byte zero hash (`SHA256d(last || 0x0000...0000)`).

The merkle tree functions are used across multiple contexts:
- Block building (in `bitcoinsuite-core`)
- Block header hashing (in `bitcoinsuite-core`, `bitcoinsuite-bitcoind-stratum`)
- Stratum mining (in `bitcoinsuite-bitcoind-stratum`)

## Decision

Add a `MerkleMode` enum to the merkle tree implementation:

```rust
pub enum MerkleMode {
    Bitcoin,  // duplicate last leaf for odd counts
    Lotus,    // pad with zero hash for odd counts
}
```

The `get_merkle_root()` and `get_merkle_root_and_height()` functions accept a `MerkleMode` parameter. Lotus leaf computation is handled separately via `lotus_merkle_leaf(tx: &Tx) -> Sha256d`, which computes `SHA256d(txid || lotus_txid)`.

## Considered Options

1. **Separate merkle functions per chain** — Duplicates code, harder to maintain.
2. **Detection via Network enum** — Ties merkle logic to network config, which may not always be available.
3. **MerkleMode enum (chosen)** — Clean separation of concern, no network dependency, testable in isolation.

## Consequences

**Positive**:
- Single merkle implementation for all chains
- `MerkleMode` can be passed independently of network config
- Clear, documented difference between Bitcoin and Lotus modes
- Lotus leaf computation is separate and explicit

**Negative**:
- Callers must know which mode to use (documented in calling code via `bitcoinsuite-core/src/block.rs` and `bitcoinsuite-bitcoind-stratum/src/lib.rs`)
- `lotus_merkle_leaf()` depends on transaction hash computation, which has its own complexity
