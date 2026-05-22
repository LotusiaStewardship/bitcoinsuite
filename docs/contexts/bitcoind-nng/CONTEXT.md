# Context: bitcoinsuite-bitcoind-nng

## Boundary

**Inside**: NNG-based RPC and PubSub interface for bitcoind, flatbuffer schema binding, mining template retrieval, coinbase identity encoding.

**Outside**: Core types, bitcoind node management, SLP token types, stratum protocol.

## Dependencies

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-error` | Runtime | ErrorMeta, Result |
| `bitcoinsuite-core` | Runtime | Sha256d, Coin types |
| `bitcoinsuite-slp` | Runtime | SLP token types |
| `bitcoinsuite-bitcoind` | Runtime | Bitcoind types |
| `bitcoinsuite-test-utils` | Dev | Test infrastructure |
| `nng` | Runtime | NNG transport layer |
| `flatbuffers` | Runtime | Flatbuffer schema interpretation |
| `thiserror` | Runtime | Error derive |
| `tokio` | Runtime | Async pubsub listener |
| `serde` / `serde_json` | Runtime | JSON serialization |

## Module Structure

```
src/
├── lib.rs                 Re-exports key types
├── coinbase_identity.rs   Coinbase identity encoding (Raw, Hex, B64 formats)
├── field.rs               OptionExt trait for flatbuffer field extraction with errors
├── map_from_fbs.rs        Flatbuffer → Rust struct mapping utilities
├── nng_interface_generated.rs  Generated flatbuffer types (include! of flatc output)
├── pub_interface.rs       PubInterface — NNG pubsub client
├── rpc_interface.rs       RpcInterface — NNG RPC client
└── structs.rs             Rust structs for all flatbuffer messages
```

## Key Invariants

1. **Flatbuffer verifier limits are relaxed** — `max_tables: 0xffff_ffff` is set to allow complex messages with many tables. This is a safety vs compatibility trade-off.
2. **RPC is mutex-serialized** — NNG Req0 protocol requires serialized requests (one response per request). The `Mutex<()>` in `RpcInterface` enforces this.
3. **PubSub buffer is 1024 messages** — Configured via `RecvBufferSize` to reduce overflow risk during block bursts or reorgs.
4. **Topics are string-based** — Subscription topics (`"block_connected"`, `"mining_work_changed"`, etc.) are simple C-strings. The flatbuffer type is inferred from the topic.
5. **Coinbase identity is optional** — The coinbase_identity field is not required; mining templates work without it.

## Key Contracts

| Contract | Type | Description |
|---|---|---|
| `RpcInterface` | struct with `open(url)`, `get_block()`, `get_block_range()`, `get_block_slice()`, `get_undo_slice()`, `get_mempool()`, `get_mining_template()` | NNG RPC client |
| `PubInterface` | struct with `open(url)`, `subscribe()`, `unsubscribe()`, `recv_async()` | NNG PubSub client |
| `structs::Block` | Block with header, metadata, txs, file positions | Block data from RPC |
| `structs::BlockIdentifier` | enum: `Height(u64)` / `Hash(Sha256d)` | Block lookup key |
| `structs::MiningTemplate` | Version, prev_hash, target, coinbase tx, transactions, stratum fields | Mining job template |
| `structs::Message` | enum: `BlockConnected`, `BlockDisconnected`, `UpdatedBlockTip`, `TransactionAddedToMempool`, `TransactionRemovedFromMempool`, `ChainStateFlushed`, `MiningWorkChanged` | PubSub event messages |
| `RpcInterfaceError` | `RpcError { error_code, message }` | RPC error type |
| `PubInterfaceError` | `InvalidPubMessage`, `NoMessageReceived` | PubSub error type |
| `FlatbufferFieldError` / `OptionExt` | `MissingField(name)` for flatbuffer field access | Safe field extraction |
| `CoinbaseIdentity` | struct with format variants and encoding | Miner identity in templates |
