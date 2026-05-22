# Bitcoin Suite — Bounded Context Map

## Dependency Flow

```
                        ┌──────────────────────┐
                        │   bitcoinsuite-error  │◄────── (foundation: ErrorMeta trait, eyre re-export)
                        │   error-derive        │
                        │   error-warp          │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                   ┌───►│   bitcoinsuite-core   │◄── (foundation: BitcoinCode, Ecc, Hashed, core types)
                   │    └──┬───┬───┬───┬───┬───┘
                   │       │   │   │   │   │
                   │       │   │   │   │   └──────────────────┐
                   │       │   │   │   └──────────┐           │
                   │       │   │   └──────┐       │           │
                   │       │   └──┐       │       │           │
                   ▼       ▼      ▼       ▼       ▼           ▼
        ┌────────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌────────────┐
        │bitcoinsuite│ │bcoin-│ │bcoin-│ │bcoin-│ │bitcoinsuite│
        │-ecc-       │ │suite-│ │suite-│ │suite-│ │-chronik-   │
        │secp256k1   │ │slp   │ │bit-  │ │test- │ │client (Rust)│
        └────────────┘ │      │ │coind │ │utils │ └────────────┘
                       │      │ └──┬───┘ └──┬───┘        │
                       │      │    │        │            │
                  ┌────┘      │    │        │            │
                  ▼           ▼    ▼        ▼            ▼
           ┌──────────┐ ┌────────┐ ┌──────────┐  ┌──────────────┐
           │bitcoinsui│ │bitcoin-│ │bitcoinsui│  │chronik-client│
           │te-slpv2  │ │suite-  │ │te-test-  │  │(TypeScript)  │
           └──────────┘ │bitcoin │ │utils-    │  └──────────────┘
                        │d-nng   │ │blockchain│
                        └───┬────┘ └──────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │bitcoinsuite- │
                     │bitcoind-     │
                     │stratum       │
                     └──────────────┘
```

**Key**: Arrows point in dependency direction. A → B means "A depends on B".

## Context Summary

| # | Context | Crate(s) | Module Path | Dependencies (Cargo) | Key Contracts |
|---|---|---|---|---|---|
| 1 | **Error** | `bitcoinsuite-error`, `-error-derive`, `-error-warp` | `bitcoinsuite-error/src/` | `eyre`, `stable-eyre`, `thiserror` | `ErrorMeta` trait, `ErrorSeverity`, `report_to_details()`, `install()` |
| 2 | **Core** | `bitcoinsuite-core` | `bitcoinsuite-core/src/` | `bitcoinsuite-error` (via `thiserror`) | `BitcoinCode` trait, `Ecc` trait, `Hashed` trait, `Bytes`, `Sha256d`, `Network`, `Script`, `Tx`, `Block` |
| 3 | **ECC** | `bitcoinsuite-ecc-secp256k1` | `bitcoinsuite-ecc-secp256k1/src/` | `bitcoinsuite-core` (Ecc trait types) | `EccSecp256k1` (impl of `Ecc`), `DummyEcc` |
| 4 | **SLP** | `bitcoinsuite-slp`, `bitcoinsuite-slpv2` | `bitcoinsuite-slp/src/`, `bitcoinsuite-slpv2/src/` | `bitcoinsuite-core` | `SlpToken`, `SlpValidTxData`, `validate_slp_tx()`, `SlpTxType`, `TokenId` |
| 5 | **Bitcoind** | `bitcoinsuite-bitcoind` | `bitcoinsuite-bitcoind/src/` | `bitcoinsuite-core`, `bitcoinsuite-error`, `bitcoinsuite-test-utils` | `BitcoindInstance`, `BitcoindRpcClient`, `BitcoindConf`, `BitcoindChain` |
| 6 | **NNG** | `bitcoinsuite-bitcoind-nng` | `bitcoinsuite-bitcoind-nng/src/` | `bitcoinsuite-core`, `bitcoinsuite-error`, `bitcoinsuite-bitcoind`, `bitcoinsuite-slp` | `RpcInterface`, `PubInterface`, flatbuffer-generated types |
| 7 | **Stratum** | `bitcoinsuite-bitcoind-stratum` | `bitcoinsuite-bitcoind-stratum/src/` | `bitcoinsuite-core`, `primitive-types` | `lotus_merkle_leaf()`, `build_coinbase()`, `target_to_difficulty()`, `StratumError` |
| 8 | **Chronik Client (Rust)** | `bitcoinsuite-chronik-client` | `bitcoinsuite-chronik-client/src/` | `bitcoinsuite-core`, `bitcoinsuite-error`, `reqwest`, `prost` | `ChronikClient`, `ScriptType`, protobuf-generated types |
| 9 | **Chronik Client (TS)** | `chronik-client` | `chronik-client/` | `axios`, `ws`, `protobufjs` | `ChronikClient` (JS class), WS subscription API |
| 10 | **Test Utils** | `bitcoinsuite-test-utils`, `bitcoinsuite-test-utils-blockchain` | `bitcoinsuite-test-utils/src/`, `bitcoinsuite-test-utils-blockchain/src/` | `bitcoinsuite-bitcoind`, `bitcoinsuite-core`, `bitcoinsuite-error` | `bin_folder()`, `pick_ports()`, `setup_xec_chain()`, `setup_bch_chain()` |

## Shared Kernel

Types and structs that cross context boundaries (defined in `bitcoinsuite-core`, used by most downstream contexts):

| Type | Defined In | Used By | Notes |
|---|---|---|---|
| `Sha256d` | `bitcoinsuite-core/src/hash.rs` | All contexts | SHA256 double-hash, 32-byte array with `Hashed` trait |
| `Bytes` / `BytesMut` | `bitcoinsuite-core/src/bytes.rs`, `bytes_mut.rs` | All contexts | Wrapper around `bytes::Bytes` with hex, split, serde |
| `BitcoinCode` trait | `bitcoinsuite-core/src/bitcoin_code.rs` | Core, SLP, Bitcoind, Stratum | Binary ser/deser trait (not serde) |
| `Hashed` trait | `bitcoinsuite-core/src/hash.rs` | Core, Merkle | Hash computation abstraction (SHA256d via `digest` crate, SHA1, RIPEMD160) |
| `Ecc` trait | `bitcoinsuite-core/src/ecc/mod.rs` | Core, ECC, Sign | ECDSA + Schnorr + key derivation |
| `Network` / `Net` | `bitcoinsuite-core/src/network.rs` | All contexts | BCH, XEC, XPI, XRG × Mainnet/Regtest/Testnet |
| `Script` | `bitcoinsuite-core/src/script.rs` | All contexts | Bitcoin script bytecode, script variant parsing |
| `Tx` / `UnhashedTx` / `TxInput` / `TxOutput` | `bitcoinsuite-core/src/tx.rs` | Core, SLP, Bitcoind, NNG, Stratum | Transaction types with BitcoinCode ser/deser |
| `Block` / `BitcoinHeader` / `LotusHeader` | `bitcoinsuite-core/src/block.rs` | Core, NNG, Stratum | Block types with BitcoinCode ser/deser |
| `ErrorMeta` trait | `bitcoinsuite-error/src/lib.rs` | All contexts except test-utils-blockchain | Severity + error code + tags |
| `Result<T>` | `bitcoinsuite-error` re-export of `eyre::Result` | All contexts | Standard error type |
| `SlpToken` / `TokenId` | `bitcoinsuite-slp/src/` | SLP, NNG, Chronik | SLP token types |

## Cross-Cutting Concerns

| Concern | Primary Owner | Secondary Owners |
|---|---|---|
| Error handling pipeline | `bitcoinsuite-error` | All contexts (consumers) |
| Binary serialization format | `bitcoinsuite-core` (BitcoinCode) | NNG (flatbuffers), Chronik (protobuf) |
| ECC operations | `bitcoinsuite-core` (Ecc trait) | `bitcoinsuite-ecc-secp256k1` (impl), `bitcoinsuite-core/src/sign/` (consumer) |
| SLP token validation | `bitcoinsuite-slp` | Chronik client (Rust), NNG |
| Mining protocol | `bitcoinsuite-bitcoind-nng` (templates) + `bitcoinsuite-bitcoind-stratum` (primitives) | `bitcoinsuite-core` (Lotus types) |
| Test infrastructure | `bitcoinsuite-test-utils` | `bitcoinsuite-test-utils-blockchain`, integration tests |
| Build system | Cargo workspace | `Makefile.toml` (cargo-make), `build.rs` for proto/flatbuffers |
