# Context: bitcoinsuite-core

## Boundary

**Inside**: Core Bitcoin/blockchain primitives: types, serialization, hashing, ECC trait, script parsing, merkle trees, network definitions, transaction building and signing.

**Outside**: ECC implementation (`DummyEcc` lives here, but real impl is in `bitcoinsuite-ecc-secp256k1`). Node management, indexers, mining protocols, test utilities.

## Dependencies

| Dependency | Type | Purpose |
|---|---|---|
| `thiserror` | Runtime | Error derive |
| `bytes` | Runtime | Byte buffer management (with serde feature) |
| `hex` / `hex-literal` | Runtime | Hex encoding/decoding |
| `regex` | Runtime | CashAddress pattern matching |
| `digest` / `sha-1` / `ripemd` / `sha2` | Runtime | Hash computation (SHA1, RIPEMD160, SHA256, SHA256d) |
| `serde` | Runtime | JSON serialization for config and network types |
| `bs58` | Runtime | Base58Check address encoding |
| `secrecy` | Runtime | Secret key zeroing on drop |
| `once_cell` | Runtime | Lazy statics |
| `serde_json` / `bincode` | Dev | Test serialization roundtrips |
| `tokio` | Dev | Async test support |
| `bitcoinsuite-bitcoind` | Dev | Integration test helpers |
| `bitcoinsuite-test-utils` | Dev | Test infrastructure |
| `bitcoinsuite-test-utils-blockchain` | Dev | Chain setup in tests |

## Module Structure

```
src/
├── address/           CashAddress + LotusAddress encoding (mod.rs + cashaddress.rs + lotusaddress.rs)
├── ecc/               Ecc trait + PubKey/SecKey types + DummyEcc (mod.rs + pubkey.rs + seckey.rs)
├── sign/              Transaction signing infrastructure (mod.rs + error.rs + sign_data.rs + signatory.rs + tx_builder.rs + unsigned_tx.rs)
├── lib.rs             Re-exports all public types
├── bitcoin_code.rs    BitcoinCode trait — ser/deser for wire format
├── block.rs           BitcoinHeader, LotusHeader, BitcoinBlock, LotusBlock types
├── build_block.rs     Coinbase and block building helpers
├── byte_array.rs      Fixed-size byte array type
├── bytes.rs           Bytes wrapper (immutable)
├── bytes_mut.rs       BytesMut wrapper (mutable)
├── compression.rs     Amount/height compression (Bitcoin Core compatible)
├── encoding.rs        CompactSize (VarInt) reader/writer
├── error.rs           BitcoinSuiteError enum
├── hash.rs            Hashed trait, Sha256d, Sha1, ShaRmd160, Sha256 types
├── merkle.rs          Merkle tree with MerkleMode (Bitcoin/Lotus)
├── network.rs         Network (BCH/XEC/XPI/XRG) and Net (Mainnet/Regtest/Testnet)
├── op.rs              Op enum for script operations
├── opcode.rs          Bitcoin script opcode constants
├── script.rs          Script type, ScriptVariant, script parsing
├── sequence.rs        SequenceNo type
├── sighashtype.rs     SigHashType enum
├── tx.rs              Tx, UnhashedTx, TxInput, TxOutput, OutPoint types
└── utxo.rs            Coin, Utxo, TxUtxo types
```

## Key Invariants

1. **No C build dependencies** — `bitcoinsuite-core` must compile without any native library (unlike ECC impl crates).
2. **BitcoinCode over serde for wire format** — All types implement `BitcoinCode` for binary serialization. `serde` is used only for config/JSON, not for wire format.
3. **Hashed trait for hash types** — `Sha256d`, `Sha1`, `ShaRmd160`, `Sha256` all implement `Hashed` which provides `digest()`, `as_slice()`, `from_array()`.
4. **Ecc trait is abstract** — No concrete ECC implementation in core. `DummyEcc` is provided for testing only.
5. **Network enum is closed** — Adding a new blockchain network requires changing the `Network` enum in `network.rs` and updating all match arms.
6. **Bytes wrapping bytes crate** — `Bytes` wraps `bytes::Bytes` with serde support, hex output, and split operations. Not the same as `bitcoin::util::misc::serialize`.
7. **taproot module** — `calculate_tap_tweak()` performs BIP-340 tagged hash for TapTweak computation. Pure SHA256, no ECC context needed.
8. **Ecc::tweak_pubkey()** — New method on `Ecc` trait: adds a 32-byte scalar to a public key in place. Used for Taproot tweak derivation.
9. **LotusAddressType::TaprootCommitment = 2** — New address type byte for P2TR addresses in the LotusAddress format. Payload is a 33-byte commitment (not the full script).

## Key Contracts

| Contract | Type | Description |
|---|---|---|
| `BitcoinCode` trait | `ser_to(&self, &mut BytesMut)` / `deser(&mut Bytes) -> Result<Self>` | Bitcoin wire format serialization |
| `Ecc` trait | Methods for signing, verification, key derivation | Abstract elliptic curve operations |
| `Hashed` trait | `digest(BytesMut) -> Self`, `as_slice()`, `from_array()` | Hash computation interface |
| `Network` enum | `BCH`, `XEC`, `XPI`, `XRG` + `dust_amount()`, `coin_decimals()`, `block_spacing()` | Supported blockchain networks |
| `Net` enum | `Mainnet`, `Regtest`, `Testnet` with `Default::default() = Mainnet` | Network type |
| `taproot` module | `calculate_tap_tweak(pubkey, merkle_root) -> [u8; 32]` | BIP-340 tagged hash for TapTweak computation |
| `LotusAddress` | `from_taproot_commitment()`, `from_script()`, `commitment()` | P2TR address support with type byte 2 |
| `MerkleMode` enum | `Bitcoin`, `Lotus` | Merkle tree odd-leaf handling |
| `Sha256d` | 32-byte type implementing `Hashed`, `BitcoinCode`, serde | Double SHA-256 hash |
| `Script` | Bytecode + `ScriptVariant` enum | Bitcoin script parsing and classification. `ScriptVariant::P2TR(PubKey, Option<[u8;32]>)` for Taproot scripts. |
| `Tx` / `UnhashedTx` | Wire-format transaction with hash caching | Transaction representation |
