# Context: bitcoinsuite-bitcoind-stratum

## Boundary

**Inside**: Stratum V1 mining protocol primitives for Lotus: merkle leaf computation, coinbase building, Lotus header construction, difficulty calculation, stratum job types.

**Outside**: NNG transport, core blockchain types, actual pool communication.

## Dependencies

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-core` | Runtime | LotusHeader, Tx, Sha256d, Bytes, BitcoinCode, Hashed |
| `primitive-types` | Runtime | U256 for difficulty arithmetic |
| `thiserror` | Runtime | Error derive |
| `hex` | Runtime | Hex encoding/decoding |

## Module Structure

```
src/
└── lib.rs             All code in a single file:
                        - lotus_merkle_leaf()
                        - build_coinbase()
                        - build_header()
                        - lotus_template_to_header()
                        - target_to_difficulty()
                        - merkle_branch_to_root()
                        - StratumError
                        - StratumJob struct
                        - test module with 7 tests
```

## Key Invariants

1. **Lotus-specific merkle leaf** — `lotus_merkle_leaf(tx)` computes `SHA256d(txid || lotus_txid)` instead of standard Bitcoin's `SHA256d(raw_tx)`.
2. **No ErrorMeta derive** — Unlike most crates, `StratumError` uses plain `thiserror::Error` without `ErrorMeta`. (Design inconsistency noted.)
3. **Difficulty uses U256** — Uses `primitive_types::U256` for target/difficulty conversion, not f64 (which caused overflow in earlier versions).
4. **Deprecated pool difficulty** — The `pool_difficulty` parameter is deprecated and always returns `network_difficulty` for backward compatibility.
5. **Lotus header is 131 bytes** — Different from Bitcoin's 80-byte header. Key difference: merkle_root comes after epoch_hash.

## Key Contracts

| Contract | Type | Description |
|---|---|---|
| `lotus_merkle_leaf(tx: &Tx) -> Sha256d` | fn | Compute Lotus merkle leaf hash |
| `build_coinbase(height, tag, extra_nonce) -> Tx` | fn | Build Lotus coinbase transaction |
| `build_header(height, prev_block, merkle_root, timestamp, bits, nonce, epoch_hash) -> LotusHeader` | fn | Build Lotus block header from params |
| `lotus_template_to_header(template, coinbase) -> (LotusHeader, Sha256d)` | fn | Convert NNG mining template to header + coinbase txid |
| `target_to_difficulty(target_hex) -> U256` | fn | Convert hex target to difficulty |
| `merkle_branch_to_root(branches, leaf) -> Sha256d` | fn | Reconstruct merkle root from branches |
| `StratumError` | enum | `InvalidInput`, `HexError`, `SerializationError` |
| `StratumJob` | struct | Job ID, prev hash, coinbase1/2, merkle branches, nbits, ntime, version, network height |
