# ADR 006: Stratum V1 with Lotus Extensions

**Date**: 2026-05-22 (inferred from codebase)

## Context

The bitcoind-stratum crate implements Stratum V1 mining protocol primitives for Lotus (XPI). Standard Stratum V1 uses Bitcoin's block header format (80 bytes, 4 fields: version, prev_block, merkle_root, timestamp, bits, nonce). Lotus's block header differs significantly:

- Lotus header: `prev_block (32) | bits (4) | timestamp (8) | reserved (2) | nonce (8) | version (1) | size (8) | height (4) | epoch_hash (32) | merkle_root (32)` = 131 bytes
- Lotus uses `primitive_types::U256` for difficulty calculations instead of f64
- Lotus has a `target_to_difficulty` conversion that can overflow with large difficulty values (fixed in commit `ae00819`)

## Decision

Create a `bitcoinsuite-bitcoind-stratum` crate that provides:

- **`lotus_merkle_leaf(tx)`**: Computes `SHA256d(txid || lotus_txid)` for the Lotus merkle tree.
- **`build_coinbase(height, coinbase_tag, extra_nonce)`**: Builds a Lotus-format coinbase transaction with proper merkle leaf.
- **`build_header(height, prev_block, merkle_root, timestamp, bits, nonce, epoch_hash)`**: Builds a Lotus `LotusHeader` from Stratum job parameters.
- **`lotus_template_to_header(template, coinbase)`**: Converts a NNG mining template to a `LotusHeader` that can be hashed.
- **`target_to_difficulty(target_hex)`**: Converts a hex target to `U256` difficulty value (with overflow-safe math).
- **`merkle_branch_to_root(merkle_branches, leaf)`**: Reconstructs the merkle root from branch hashes (BCH/Lotus compatible).
- **Stratum V1 message types**: `StratumJob` with Lotus-specific fields (merkle_branches, coinbase1/2, prev_hash_stratum, etc.).

Error handling uses a dedicated `StratumError` enum (not `bitcoinsuite_error::ErrorMeta`) for simplicity — this crate is a mining protocol library that doesn't need the full error metadata pipeline.

## Considered Options

1. **Extend stratum into bitcoind-nng** — Mixes transport (NNG), data (flatbuffers), and protocol (stratum) layers. Too coupled.
2. **Extend stratum into core** — Core should remain blockchain-agnostic. Stratum V1 is a mining protocol, not a blockchain primitive.
3. **Standalone stratum crate (chosen)** — Clean separation of concerns: stratum is a mining protocol layer that depends on core types but is independent of transport.

## Consequences

**Positive**:
- Stratum V1 logic is isolated from transport (NNG) and core blockchain types
- Can be reused with any mining pool (not just bitcoind-nng templates)
- Lotus-specific header construction and difficulty calculation are centralized in one crate
- `target_to_difficulty` overflow fix prevents panic on large difficulty values

**Negative**:
- `StratumError` duplicates the error handling pattern instead of using `ErrorMeta` (inconsistency in the project)
- Lotus header fields (epoch_hash, size, height, reserved) are specific to Lotus; not relevant for BCH/XEC mining
- The crate only has unit tests; no integration tests against a real stratum server
