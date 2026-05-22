# Context: bitcoinsuite-bitcoind

## Boundary

**Inside**: Bitcoind node lifecycle management, JSON-RPC client, CLI helpers.

**Outside**: Core blockchain types, error infrastructure, NNG interface, test utilities.

## Dependencies

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-core` | Runtime | Network types, Sha256d |
| `bitcoinsuite-error` | Runtime | ErrorMeta, Result, WrapErr |
| `thiserror` | Runtime | Error derive |
| `serde` (derive) | Runtime | Config deserialization |
| `hex` | Runtime | Hex encoding for RPC parameters |
| `reqwest` | Runtime | HTTP client for JSON-RPC |
| `json` | Runtime | JSON value manipulation |
| `tempdir` | Runtime | Temporary directories for bitcoind datadir |
| `rev_buf_reader` | Runtime | Read bitcoind debug.log in reverse |
| `bitcoinsuite-test-utils` | Runtime (dev) | Binary discovery, port picking |
| `tokio` | Dev | Async test support |

## Module Structure

```
src/
├── lib.rs             Re-exports: cli, error, instance, rpc_client
├── cli.rs             BitcoinCli — command-line interface wrapper (runs bitcoin-cli)
├── error.rs           BitcoindError enum (all #[critical()])
├── instance.rs        BitcoindConf, BitcoindInstance, BitcoindChain
├── rpc_client.rs      BitcoindRpcClient, BitcoindRpcClientConf
└── test_instance.rs   Test helpers for bitcoind instance lifecycle
```

## Key Invariants

1. **All errors are `#[critical()]`** — Bitcoind errors are always critical because they indicate infrastructure failure (binary not found, process died, network error).
2. **Port picking via `bitcoinsuite-test-utils::pick_ports`** — Test instances use dynamically allocated ports to avoid conflicts.
3. **Data directory is a tempdir** — Each bitcoind instance gets its own temporary directory that is cleaned up on drop.
4. **Non-blocking ready check** — `wait_for_ready()` polls bitcoind until it responds, with configurable timeout.
5. **Conf files generated with `Net` awareness** — Configuration lines differ per network (regtest=1, testnet=1, etc.).

## Key Contracts

| Contract | Type | Description |
|---|---|---|
| `BitcoindInstance` | struct with `setup()`, `wait_for_ready()`, `cmd()`, `cmd_json()`, `cmd_string()` | Full bitcoind lifecycle |
| `BitcoindConf` | struct: path, args, ports, timeout | Bitcoind configuration |
| `BitcoindChain` | enum: `XEC`, `BCH`, `XPI` | Chain flavor (determines args) |
| `BitcoindRpcClient` | struct with `cmd_text()`, `cmd_json()`, `new()` | JSON-RPC client |
| `BitcoindRpcClientConf` | struct: url, rpc_user, rpc_pass | RPC client configuration |
| `BitcoindError` | enum: `TestInstance`, `Client`, `JsonRpc`, `BitcoindExited`, `Timeout` | Error types |
| `extract_error_meta()` | fn `(&Report) -> Option<&dyn ErrorMeta>` | ErrorMeta extraction for bitcoind errors |
