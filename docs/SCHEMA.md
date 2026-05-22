# Bitcoin Suite — Data Schema Reference

This project has no traditional database. Data formats are defined by serialization schemas and wire protocols.

---

## FlatBuffer Schema (`nng_interface.fbs`)

**Location**: `bitcoinsuite-bitcoind-nng/flatbuffers/nng_interface.fbs`

Used for NNG RPC request/response and PubSub messages between bitcoind-nng and the node.

### RPC Messages

| RPC Method | Request | Response | Description |
|---|---|---|---|
| `GetBlock` | `BlockIdentifier` (Height u64 / Hash [u8;32]) | `GetBlockResponse` { header raw, metadata, txs, file_num, data_pos, undo_pos } | Fetch a full block |
| `GetBlockRange` | `GetBlockRangeRequest` (start_height, end_height) | `GetBlockRangeResponse` { blocks } | Fetch a range of blocks |
| `GetBlockSlice` | `GetBlockSliceRequest` (block_id, offset, limit) | `GetBlockSliceResponse` { data } | Fetch a slice of a block file |
| `GetUndoSlice` | `GetUndoSliceRequest` (block_id, offset, limit) | `GetUndoSliceResponse` { data } | Fetch a slice of an undo file |
| `GetMempool` | `GetMempoolRequest` | `GetMempoolResponse` { txs, txs_by_hash } | Fetch mempool contents |
| `GetMiningTemplate` | `GetMiningTemplateRequest` (coinbase_tx) | `GetMiningTemplateResponse` { version, prev_hash, target, curtime, mintime, maxtime, coinbase_value, coinbase_tx, transactions, coinbase1, coinbase2, merkle_branches, prev_hash_stratum, nbits_stratum, ntime_stratum } | Mining template for Stratum |

### PubSub Topics

| Topic | Message | Description |
|---|---|---|
| `BlockConnected` | `BlockConnected` (height, hash, prev_hash, n_bits, timestamp) | A block was connected to the chain |
| `BlockDisconnected` | `BlockDisconnected` (height, hash, prev_hash, n_bits, timestamp) | A block was disconnected from the chain |
| `UpdatedBlockTip` | `UpdatedBlockTip` (height, hash, prev_hash, n_bits, timestamp, branch_work) | Chain tip changed |
| `TransactionAddedToMempool` | `TransactionAddedToMempool` (txid [u8;32], raw bytes) | New tx in mempool |
| `TransactionRemovedFromMempool` | `TransactionRemovedFromMempool` (txid [u8;32]) | Tx removed from mempool |
| `ChainStateFlushed` | `ChainStateFlushed` | Chain state flushed to disk |
| `MiningWorkChanged` | `MiningWorkChanged` (mining_state bytes) | Mining work parameters changed |

### NNG Wire Format

- **Transport**: TCP via NNG (Req0/Rep0 for RPC, Sub0/Pub0 for pubsub)
- **Serialization**: FlatBuffers binary format (self-describing, zero-copy)
- **Framing**: NNG message framing (length-prefixed)

---

## Protobuf Schema (`chronik.proto`)

**Location**: `bitcoinsuite-chronik-client/proto/chronik.proto`

Used for Chronik HTTP REST and WebSocket API. Compiled to Rust via `prost` and to TypeScript via `ts-proto`.

### Key Messages

| Message | Fields | Description |
|---|---|---|
| `Tx` | `txid`, `version`, `inputs[]`, `outputs[]`, `lock_time`, `block`, `time_first_seen`, `size`, `is_coinbase` | Transaction |
| `TxInput` | `prev_out`, `script`, `sequence_no`, `script_type`, `script_payload`, `p2tr_inner_spk`, `sighash_type`, `schnorr_sig`, `spent_coins` | Transaction input with parsed details |
| `TxOutput` | `value`, `script`, `script_type`, `script_payload`, `p2tr_inner_spk`, `spent_by`, `slp_token`, `slpv2_data` | Transaction output with parsed details |
| `Block` | `height`, `hash`, `prev_hash`, `timestamp`, `block_size`, `num_txs`, `num_inputs`, `num_outputs`, `sunken_outputs`, `confirming_tx_count`, `confirming_input_count`, `confirming_output_count`, `connect_height` | Block info |
| `ScriptUtxo` | `outpoint`, `block_height`, `is_coinbase`, `value`, `script`, `script_type`, `script_payload`, `p2tr_inner_spk`, `slp_meta`, `slpv2_data`, `first_seen`, `is_spent` | UTXO at a script |
| `Token` | `token_id`, `amount`, `is_minted_by_burn`, `block_height` | SLP token info |
| `SlpMeta` | `token_id`, `token_type`, `num_zero_value_outputs` | SLP metadata |
| `Error` | `status_code`, `error_msg`, `type`, `slp_error`, `tx_id`, `outpoint` | Error response |

### HTTP Endpoints

| Method | Path | Response |
|---|---|---|
| GET | `/v1/chronik/` | `Block` (genesis info) |
| GET | `/v1/chronik/block/:heightOrHash` | `Block` |
| GET | `/v1/chronik/tx/:txid` | `Tx` |
| GET | `/v1/chronik/script/:script_type/:script_payload` | `ScriptHistory` |
| GET | `/v1/chronik/script/:script_type/:script_payload/:page` | `ScriptHistory` |
| GET | `/v1/chronik/plugin/:plugin_name/:payload` | Plugin-specific response |
| POST | `/v1/chronik/plugin/:plugin_name` | Plugin-specific response |
| WS | `/v1/chronik/ws` | PubSub over WebSocket |

---

## SLP Token Data Model

### SLP Token Types (`bitcoinsuite-slp`)

| Token Type | Value | Description |
|---|---|---|
| `Fungible` | `0x01` | Simple Ledger Protocol — fungible tokens (GENESIS, SEND, MINT) |
| `NFT1Group` | `0x81` | NFT1 Group parent token |
| `NFT1Child` | `0x41` | NFT1 Child (minted by burning from a Group) |

### SLP Transaction Types

| Tx Type | OP_RETURN Format | Actions |
|---|---|---|
| `GENESIS` | `SLP\x00\x01 GENESIS token_type|token_ticker|token_name|token_document_url|token_document_hash|decimals|mint_baton_vout|initial_mint_quantity` | Create a new token |
| `MINT` | `SLP\x00\x01 MINT token_id|mint_baton_vout|mint_quantity` | Mint more tokens (requires baton UTXO) |
| `SEND` | `SLP\x00\x01 SEND token_id|amount1|amount2|...` | Transfer tokens to outputs |
| `BURN` | `SLP\x00\x01 BURN token_id|amount1|amount2|...` | Burn tokens (Lotus-specific extension) |

### SLP Validation

Order of validation in `validate_slp_tx()`:
1. Parse OP_RETURN output → `SlpParseData`
2. Verify input tokens match spent outputs (token_id, token_type)
3. Calculate burn amounts per output
4. Verify SEND amounts sum correctly (GENESIS/MINT validation of input tokens)
5. Produce `SlpValidTxData` with burn information

### SLPv2 (`bitcoinsuite-slpv2`)

| Function | Purpose |
|---|---|
| `build_slpv2_burn_script()` | Build OP_RETURN for burning SLPv1 tokens via SLPv2 |
| `build_slpv2_mint_script()` | Build OP_RETURN for minting tokens via SLPv2 |
| `build_slpv2_send_script()` | Build OP_RETURN for sending tokens via SLPv2 |

---

## Bitcoin Wire Format (BitcoinCode Serialization)

All on-chain types implement the `BitcoinCode` trait with `ser_to()` / `deser()` for Bitcoin wire format encoding:

| Type | Wire Format | Notes |
|---|---|---|
| `Bytes` | CompactSize-prefixed | Variable-length byte array |
| `ByteArray<N>` | Fixed N bytes | Fixed-length byte sequence |
| `i32` / `u32` / `i64` / `u64` | Signed/unsigned little-endian | Bitcoin integer encoding |
| `i128` | Signed little-endian | For high-precision arithmetic |
| `VarInt` | CompactSize | Bitcoin variable-length integer |
| `Sha256d` | 32 bytes | Double SHA-256 hash (internal byte order) |
| `Script` | CompactSize-prefixed bytecode | Bitcoin script |

---

## Coinbase Identity Encoding

**Location**: `bitcoinsuite-bitcoind-nng/src/coinbase_identity.rs`

The coinbase identity is an extra field in mining template requests that identifies the miner/pool. Format:
- Encode the identity string as UTF-8 bytes
- Pad to a fixed length with zeros
- Include in the template request payload

### Encoding Variants

| Format | Description |
|---|---|
| `IdentityFormat::Raw` | Raw bytes, no encoding |
| `IdentityFormat::Hex` | Hex-encoded string |
| `IdentityFormat::B64` | Base64-encoded string |
