# Plan: P2TR (Pay-To-Taproot) Implementation

**Goal**: Mirror the TypeScript P2TR implementation from `xpi-ts` into the Rust `bitcoinsuite` workspace, enabling Taproot address generation, key-tweaking, script-tree building, control blocks, spend verification, and transaction signing for Lotus-family blockchains (XPI, XRG, BCH, XEC).

**Reference implementation**: `~/Documents/Code/lotusia/xpi-ts/lib/bitcore/script/taproot.ts` (882 lines)

## Current State

### Already in bitcoinsuite-core
| Feature | Location | Status |
|---|---|---|
| P2TR script construction | `script.rs:151` `Script::p2tr()` | ✓ Done |
| P2TR script parsing | `script.rs:236` `parse_variant()` → `ScriptVariant::P2TR` | ✓ Done |
| `OP_SCRIPTTYPE` opcode | `opcode.rs:29` | ✓ Done |
| Schnorr sign/verify | `ecc/mod.rs` trait methods `schnorr_sign`/`schnorr_verify` | ✓ Done |
| Schnorr ECC impl | `bitcoinsuite-ecc-secp256k1` via `secp256k1_abc` | ✓ Done |
| SigHash types (BIP143) | `sighashtype.rs` | ✓ Done |
| Transaction signing infra | `sign/` module (Signatory trait, TxBuilder, UnsignedTx) | ✓ Done |

### NOT yet implemented (scope of this plan)
- Taproot tagged hashes (`TapTweak`, `TapLeaf`, `TapBranch`)
- Key tweaking (`tweakPublicKey`, `tweakPrivateKey`) — ECC point addition with scalar
- Taproot script tree (Merkle tree of scripts with paths)
- Control block construction and verification
- Taproot commitment verification (key path + script path)
- P2TR address encoding (CashAddress version byte)
- P2TR Signatory (key-path and script-path signing)
- SIGHASH_LOTUS flag for Taproot key-path spends
- ECC trait: `tweak_pubkey` method for public key tweaking

---

## Phases

### Phase 1: Foundation — Tagged Hashes + Key Tweaking

**Crates**: `bitcoinsuite-core`, `bitcoinsuite-ecc-secp256k1`

Add the two primitive operations that all Taproot computation rests on:

1. **Tagged hashes** — BIP340-style `SHA256(SHA256(tag) || SHA256(tag) || data)`
   - New module: `bitcoinsuite-core/src/taproot/hash.rs`
   - Functions: `tagged_hash(tag: &str, data: &[u8]) -> [u8; 32]`
   - Constants: `TAPROOT_TAG_TAPTWEAK`, `TAPROOT_TAG_TAPLEAF`, `TAPROOT_TAG_TAPBRANCH`
   - Convenience: `tap_tweak_hash(internal_pubkey, merkle_root)` -> `[u8; 32]`
   - Convenience: `tap_leaf_hash(script, leaf_version)` -> `[u8; 32]`
   - Convenience: `tap_branch_hash(left, right)` -> `[u8; 32]` (lexicographic ordering)

2. **ECC trait: key tweaking**
   - Add `fn tweak_pubkey(&self, pubkey: &PubKey, tweak: &[u8; 32]) -> Result<PubKey, EccError>` to `Ecc` trait
   - Implement in `EccSecp256k1`: `pubkey_point + tweak_scalar * G`
   - Implement stub in `DummyEcc`
   - Add `fn tweak_seckey(&self, seckey: &SecKey, tweak: &[u8; 32]) -> Result<SecKey, EccError>` to `Ecc` trait
   - This mirrors `PublicKey.addScalar()` in xpi-ts

3. **Taproot module scaffold**
   - New module: `bitcoinsuite-core/src/taproot/mod.rs`
   - Re-exports from hash submodule
   - Constants from xpi-ts: `TAPROOT_LEAF_MASK`, `TAPROOT_LEAF_TAPSCRIPT`, `TAPROOT_CONTROL_BASE_SIZE`, `TAPROOT_CONTROL_NODE_SIZE`, `TAPROOT_CONTROL_MAX_NODE_COUNT`, `TAPROOT_CONTROL_MAX_SIZE`

**Verification**: Unit tests for tagged hashes (test vectors from xpi-ts or lotusd), key tweaking round-trip test.

---

### Phase 2: Taproot Tree + Commitment

**Crates**: `bitcoinsuite-core`

Build on Phase 1 to implement the Taproot Merkle tree and commitment computation:

1. **Tree types**
   - `TapLeafNode { script, leaf_version }` 
   - `TapBranchNode { left, right }`
   - `TapNode = Leaf | Branch`
   - `TapLeaf { script, leaf_version, leaf_hash, merkle_path }`
   - `TapTreeBuildResult { merkle_root, leaves }`

2. **Tree construction**: `build_tap_tree(tree: &TapNode) -> TapTreeBuildResult`
   - Recursive: leaf → hash; branch → `tap_branch_hash(left, right)`
   - Merkle paths accumulated during recursion

3. **Control block**: `create_control_block(internal_pubkey, leaf_index, tree) -> Vec<u8>`
   - Format: `[control_byte][32-byte x-coord][merkle_path...]`
   - Parity bit from pubkey prefix (0x02=even, 0x03=odd)

4. **Commitment verification**: `verify_taproot_commitment(control_block, commitment_pubkey, script) -> (tapleaf_hash, success)`
   - Walk merkle path, reconstruct root, check tweak matches commitment

5. **High-level builders**:
   - `build_key_path_taproot(internal_pubkey) -> (Script, PubKey)` — key-path only (no scripts)
   - `build_script_path_taproot(internal_pubkey, tree, state?) -> (Script, PubKey, merkle_root, leaves)`

**Verification**: Unit tests with known test vectors.

---

### Phase 3: Address Encoding

**Crates**: `bitcoinsuite-core`

Enable P2TR address representation in CashAddress format:

1. **`AddressType::P2TR` variant**
   - Add `P2TR = 16` (or whatever the Lotus/coin-specific version byte is) to `AddressType` enum
   - The version byte used in CashAddress payload encoding

2. **`CashAddress` P2TR support**
   - `CashAddress::from_pubkey(prefix, pubkey: &PubKey)` — create P2TR address from commitment pubkey
   - `CashAddress::to_script()` — handle `AddressType::P2TR` → `Script::p2tr(...)`
   - `_from_cash_addr()` — handle P2TR version byte → `AddressType::P2TR`
   - `_to_cash_addr()` — handle `AddressType::P2TR` version byte

3. **`LotusAddress` P2TR support**
   - LotusAddress already wraps a `Script`, so it should just work with P2TR scripts

**Note**: The version byte for P2TR in CashAddress needs to match the Lotus specification. Check the lotusd reference or xpi-ts for the exact value.

**Verification**: Address round-trip tests (encode → decode → encode).

---

### Phase 4: SIGHASH_LOTUS + Taproot Signing

**Crates**: `bitcoinsuite-core`

Enable Taproot-aware transaction signing:

1. **SIGHASH_LOTUS flag**
   - Add `SigHashTypeVariant::Lotus` variant (or extend the u32 encoding)
   - `TAPROOT_SIGHASH_TYPE = SIGHASH_ALL | SIGHASH_LOTUS` (0x41 | 0x?? — check lotusd)
   - The Lotus sighash differs from BIP143 in how the preimage is constructed for Taproot

2. **`P2TRKeyPathSignatory`** — implements `Signatory`
   - Signs with Schnorr + SIGHASH_LOTUS
   - Uses tweaked private key (internal key + tweak)
   - Input script remains empty for key-path (witness-based in Bitcoin, but Lotus embeds in scriptSig)
   
3. **`P2TRScriptPathSignatory`** — implements `Signatory`
   - Includes control block and revealed script in the scriptSig
   - Stack-based execution of the revealed script

4. **Sighash preimage for Taproot** (if different from BIP143)
   - Check xpi-ts/lotusd for exact Taproot sighash format
   - May need new `SigHashTypeVariant::Taproot` variant

**Verification**: Sign and verify test transactions against xpi-ts reference output.

---

### Phase 5: Spend Verification

**Crates**: `bitcoinsuite-core`

Implement full Taproot spend verification (key-path and script-path):

1. **`verify_taproot_spend(script_pubkey, stack, flags) -> TaprootVerifyResult`**
   - Key-path: single Schnorr signature on stack → verify against commitment pubkey
   - Script-path: script + control block on stack → verify merkle proof → execute revealed script
   - Annex detection, state push, control block validation
   - Matches `verifyTaprootSpend()` in xpi-ts `taproot.ts:748`

2. **Flag constants**: `SCRIPT_DISABLE_TAPROOT_SIGHASH_LOTUS`, `SCRIPT_TAPROOT_KEY_SPEND_PATH`

**Verification**: Test with known-good and known-bad control blocks and signatures.

---

### Phase 6: Stratum Integration (if needed)

**Crates**: `bitcoinsuite-bitcoind-stratum`

Check if `build_stratum_header` or mining template logic needs P2TR awareness (coinbase output scripts, block template construction). This is likely minimal — P2TR outputs in coinbase are just script bytecode.

---

## Documentation Updates

Per `docs/CONSTITUTION.md` §1 decision matrix:

- [ ] `docs/contexts/core/CONTEXT.md` — Add `src/taproot/` module, update module structure
- [ ] `docs/contexts/ecc/CONTEXT.md` — Add `tweak_pubkey`/`tweak_seckey` trait methods
- [ ] `docs/contexts/bitcoind-stratum/CONTEXT.md` — If Phase 6 changes are made
- [ ] `docs/CONTEXT_MAP.md` — Add taproot module dependency flow
- [ ] `docs/adrs/007-p2tr-taproot.md` — New ADR (this is hard to reverse, surprising without context, and involves real trade-offs around the SIGHASH_LOTUS design and 33-byte pubkeys vs BIP340's x-only keys)

## Affected Crates Summary

| Crate | Phase | Changes |
|---|---|---|
| `bitcoinsuite-core` | 1-5 | New `taproot/` module, ECC trait additions, AddressType, CashAddress, SigHashType, Signatory impls |
| `bitcoinsuite-ecc-secp256k1` | 1 | `tweak_pubkey`/`tweak_seckey` impl, DummyEcc stub |
| `bitcoinsuite-bitcoind-stratum` | 6 | P2TR awareness (optional, minimal) |

## Key Design Decisions (ADR-eligible)

1. **33-byte pubkeys vs x-only**: Lotus uses compressed 33-byte pubkeys (not x-only 32-byte), with parity encoded in control block first bit. This diverges from BIP341.
2. **SIGHASH_LOTUS for key-path**: Requires a custom sighash type, not standard BIP143.
3. **State in P2TR output**: Lotus P2TR can carry a 32-byte state commitment, making the output 69 bytes (vs 36 for key-path only).
4. **ECC trait extension**: Adding key tweaking to the `Ecc` trait affects all implementors (currently `EccSecp256k1` and `DummyEcc`).
