# Context: bitcoinsuite-slp (+ slpv2)

## Boundary

**Inside**: SLP token protocol parsing, validation, and building. SLPv2 OP_RETURN script building.

**Outside**: Core blockchain types, block/tx broadcasting, wallet logic, indexer logic.

## Dependencies

### bitcoinsuite-slp

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-core` | Runtime | Bytes, Sha256d, Script, Tx, BitcoinCode, Hashed, ecc types |
| `hex` | Runtime | Hex encoding |
| `thiserror` | Runtime | Error derive |

### bitcoinsuite-slpv2

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-core` | Runtime | Bytes, Script, op_return builder |
| `hex` | Runtime | Hex encoding |

## Module Structure

```
bitcoinsuite-slp/src/
├── lib.rs           Re-exports all public types
├── build.rs         Build SLP OP_RETURN scripts (GENESIS, MINT, SEND)
├── consts.rs        SLP protocol constants (token IDs, version bytes)
├── error.rs         SlpError enum
├── interface.rs     SlpInterface trait (parse + validate)
├── parse.rs         OP_RETURN parsing → SlpParseData
├── rich_tx.rs       RichTx — transaction with SLP and non-SLP outputs
├── rich_utxo.rs     RichUtxo — UTXO with parsed SLP data
├── slp_amount.rs    SlpAmount — SLP token amount type
├── slp_tx.rs        SlpTxData, SlpTxType, SlpTokenType, SlpToken
├── slp_utxo.rs      SlpUtxo — UTXO with SLP token info
├── token_id.rs      TokenId type (newtype around Sha256d)
├── validate.rs      SLP transaction validation (main logic ~1461 lines)
└── value.rs         Token value handling

bitcoinsuite-slpv2/src/
├── lib.rs           Re-exports
├── build.rs         Build SLPv2 OP_RETURN scripts (burn, mint, send)
├── structs.rs       SLPv2 data structures
└── token_id.rs      SLPv2 token ID types
```

## Key Invariants

1. **Validation happens in `validate_slp_tx()`** — This is the core function (~1461 lines) that validates all SLP transactions. It takes `SlpParseData` and spent outputs, returns `SlpValidTxData`.
2. **Three token types** — `Fungible (0x01)`, `NFT1Group (0x81)`, `NFT1Child (0x41)`.
3. **Four transaction types** — `GENESIS`, `MINT`, `SEND`, `BURN` (burn is a Lotus extension).
4. **Token IDs are SHA256d of GENESIS txid** — `TokenId` is a newtype around `Sha256d`.
5. **SLPv2 is a separate crate** — SLPv2 uses the SLPv1 token model but with different OP_RETURN format (separated because it's less stable/experimental).
6. **Validation checks token type consistency** — Input UTXOs must all have the same `token_id` and `token_type` for a given SEND/MINT.

## Key Contracts

| Contract | Type | Description |
|---|---|---|
| `validate_slp_tx(parse_data, spent_outputs) -> SlpValidTxData` | fn | Main validation logic |
| `SlpToken` | enum: `Fungible`, `NFT1Group`, `NFT1Child` | SLP token type |
| `SlpTxType` | enum: `GENESIS`, `MINT`, `SEND`, `BURN` | SLP transaction type |
| `SlpTxData` | struct: tx_type, token_id, amounts, etc. | Parsed SLP transaction data |
| `SlpParseData` | struct: output_tokens, burn_info | Intermediate parsing result |
| `SlpValidTxData` | struct: slp_tx_data, slp_burns | Validated transaction data |
| `SlpAmount` | u64 newtype with display/parse | Token amount (decimal-aware) |
| `TokenId` | Sha256d newtype | Token identifier |
| `SlpError` | enum: InvalidOpReturn, InvalidTokenType, InvalidSpentOutputs, etc. | Validation errors |
