//! DEV-355 interoperability: `LotusAddress` must accept and generate the
//! XAddress form used by lotusd v12 (`XAddress::Parse`/`Encode`) and xpi-ts
//! (`Address.toXAddress`): type byte 0 carries the full scriptPubKey
//! (25-byte P2PKH, 23-byte P2SH), type byte 2 the 33-byte taproot
//! commitment. The library's historical bare-hash type-0 payload stays
//! parseable, but is no longer generated.

use bitcoinsuite_core::{
    ecc::Ecc, Hashed, LotusAddress, Net, Script, ScriptVariant, ShaRmd160, LOTUS_PREFIX,
};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;

/// Node-valid regtest P2PKH address, taken from the DEV-336 regtest harness
/// (validateaddress-verified against lotusd v12). The type-0 payload is the
/// full 25-byte P2PKH scriptPubKey of hash160(pubkey(seckey = [1; 32])).
const REGTEST_NODE_P2PKH: &str = "lotusR16PSJLqasHgB8GqFFzCqpJGH3Bpgh399zfuDxUJcn";
/// The same hash160 in the legacy bare-hash type-0 form this library used to
/// emit; lotusd v12 rejects it, but stored addresses must keep parsing.
const REGTEST_LEGACY_P2PKH: &str = "lotusR1C6Rc3w25VHud3dLDamutaqfKWqhoAJgYu";
/// Mainnet node/xpi-ts P2PKH addresses, taken from the stratum pool's
/// config/session tests (mining identity payout and worker authorization).
const MAINNET_NODE_P2PKH_POOL: &str = "lotus_16PSJNRge55cpi1srcnK6A3YXuTZKpzrUir3ZBwTD";
const MAINNET_NODE_P2PKH_WORKER: &str = "lotus_16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyW61iGi";

fn node_p2pkh_script() -> Script {
    let ecc = EccSecp256k1::default();
    let seckey = ecc.seckey_from_array([1; 32]).unwrap();
    let pubkey = ecc.derive_pubkey(&seckey);
    let pubkey_hash = ShaRmd160::digest(pubkey.array().into());
    Script::p2pkh(&pubkey_hash)
}

/// The known node-valid regtest P2PKH address parses to the expected P2PKH
/// script, and both generating constructors round-trip to the same string.
#[test]
fn test_node_valid_regtest_p2pkh_vector() -> Result<(), Box<dyn std::error::Error>> {
    let expected_script = node_p2pkh_script();

    let parsed: LotusAddress = REGTEST_NODE_P2PKH.parse()?;
    assert_eq!(parsed.net(), Net::Regtest);
    assert_eq!(parsed.script(), expected_script);

    for generated in [
        LotusAddress::from_hash(LOTUS_PREFIX, Net::Regtest, parsed.hash().unwrap()),
        LotusAddress::from_script(LOTUS_PREFIX, Net::Regtest, &expected_script)?,
    ] {
        assert_eq!(generated.as_str(), REGTEST_NODE_P2PKH);
        let reparsed: LotusAddress = generated.as_str().parse()?;
        assert_eq!(reparsed.script(), expected_script);
    }
    Ok(())
}

/// A P2SH script generates a full-script address whose exact script
/// round-trips through parse.
#[test]
fn test_p2sh_full_script_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let p2sh_hash = ShaRmd160::from_hex("260617ebf668c9102f71ce24aba97fcaaf9c666a")?;
    let p2sh_script = Script::p2sh(&p2sh_hash);

    let addr = LotusAddress::from_script(LOTUS_PREFIX, Net::Regtest, &p2sh_script)?;
    assert_eq!(addr.net(), Net::Regtest);
    assert_eq!(addr.hash(), Some(p2sh_hash.clone()));

    let parsed: LotusAddress = addr.as_str().parse()?;
    assert_eq!(parsed.script(), p2sh_script);
    match parsed.script().parse_variant() {
        ScriptVariant::P2SH(hash) => assert_eq!(hash, p2sh_hash),
        other => panic!("expected P2SH variant, got {other:?}"),
    }
    Ok(())
}

/// The legacy bare-hash type-0 form still parses and resolves to the P2PKH
/// script of the hash (backward compatibility with stored addresses), while
/// generation now produces the node form for the same hash.
#[test]
fn test_legacy_bare_hash_still_parses() -> Result<(), Box<dyn std::error::Error>> {
    let expected_script = node_p2pkh_script();
    let hash = match expected_script.parse_variant() {
        ScriptVariant::P2PKH(hash) => hash,
        other => panic!("expected P2PKH variant, got {other:?}"),
    };

    let legacy = LotusAddress::from_hash_legacy(LOTUS_PREFIX, Net::Regtest, hash.clone());
    assert_eq!(legacy.as_str(), REGTEST_LEGACY_P2PKH);

    let parsed: LotusAddress = REGTEST_LEGACY_P2PKH.parse()?;
    assert_eq!(parsed.net(), Net::Regtest);
    assert_eq!(parsed.hash(), Some(hash.clone()));
    assert_eq!(parsed.script(), expected_script);

    // Generation has moved to the node form
    assert_ne!(
        legacy.as_str(),
        LotusAddress::from_hash(LOTUS_PREFIX, Net::Regtest, hash).as_str()
    );
    Ok(())
}

/// The mainnet addresses used by the stratum pool (payout identity and
/// worker authorization) parse as full-script P2PKH and regenerate exactly.
#[test]
fn test_pool_mainnet_p2pkh_vectors() -> Result<(), Box<dyn std::error::Error>> {
    for address in [MAINNET_NODE_P2PKH_POOL, MAINNET_NODE_P2PKH_WORKER] {
        let parsed: LotusAddress = address.parse()?;
        assert_eq!(parsed.net(), Net::Mainnet);
        match parsed.script().parse_variant() {
            ScriptVariant::P2PKH(hash) => assert_eq!(parsed.hash(), Some(hash)),
            other => panic!("expected P2PKH variant for {address}, got {other:?}"),
        }
        let regen = LotusAddress::from_script(LOTUS_PREFIX, Net::Mainnet, &parsed.script())?;
        assert_eq!(regen.as_str(), address);
    }
    Ok(())
}
