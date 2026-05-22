# Context: bitcoinsuite-test-utils (+ test-utils-blockchain)

## Boundary

**Inside**: Test infrastructure: binary discovery, port allocation, HTTP server, blockchain setup helpers.

**Outside**: Core types, bitcoind management, specific test cases.

## Dependencies

### bitcoinsuite-test-utils

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-error` | Runtime | Error types |
| `thiserror` | Runtime | Error derive |
| `serde` (derive) | Runtime | Serialization for test data |

### bitcoinsuite-test-utils-blockchain

| Dependency | Type | Purpose |
|---|---|---|
| `bitcoinsuite-bitcoind` | Runtime | BitcoindConf, BitcoindInstance |
| `bitcoinsuite-core` | Runtime | Network, OutPoint, Script, TxInput, etc. |
| `bitcoinsuite-error` | Runtime | Result type |
| `bitcoinsuite-test-utils` | Runtime | bin_folder for binary discovery |

## Module Structure

```
bitcoinsuite-test-utils/src/
├── lib.rs           Re-exports modules
├── bin_folder.rs    BITCOINSUITE_BIN_DIR env var → path
├── error.rs         UtilError
├── pick_ports.rs    Dynamic port allocation (OS-assigned ports)
└── serve.rs         Simple HTTP file server for test data

bitcoinsuite-test-utils-blockchain/src/
├── lib.rs           setup_xec_chain(), setup_bch_chain(), setup_bitcoind_coins()
└── mock_slp_node.rs Mock SLP node for testing
```

## Key Invariants

1. **`BITCOINSUITE_BIN_DIR` env var is required** — Tests that need bitcoind binaries must have this set. `Makefile.toml` sets it to `downloads/`.
2. **Ports are dynamically allocated** — `pick_ports()` uses OS-assigned ports to avoid conflicts. Does NOT return the same port twice (tracks allocations internally).
3. **Chain setup functions generate real blocks** — `setup_xec_chain()` and `setup_bch_chain()` start a real bitcoind instance, generate blocks to fund UTXOs, and return the UTXO set.
4. **`bin_folder()` panics without env var** — This is intentional: no fallback default for binary path.

## Key Contracts

| Contract | Type | Description |
|---|---|---|
| `bin_folder() -> PathBuf` | fn | Returns binary directory from env var |
| `pick_ports(n) -> Vec<u16>` | fn | Allocate n OS ports |
| `setup_xec_chain(num_utxos, redeem_script) -> (BitcoindInstance, Vec<(OutPoint, i64)>)` | fn | Full XEC chain setup |
| `setup_bch_chain(num_utxos, redeem_script) -> (BitcoindInstance, Vec<(OutPoint, i64)>)` | fn | Full BCH chain setup |
| `setup_bitcoind_coins(bitcoind, network, num_utxos, address, script_hex) -> Result<Vec<(OutPoint, i64)>>` | fn | Generate funded UTXOs |
