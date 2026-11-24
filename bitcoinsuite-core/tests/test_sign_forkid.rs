//! P2PKH signing at CHAIN_FORK_ID with the real secp256k1 implementation.
//!
//! The signature is only valid over the sighash that carries the fork value
//! in its BIP143 preimage, and the sighash byte appended to the scriptSig
//! stays 0x41 (the low byte) — lotusd applies its own CHAIN_FORK_ID inside
//! SignatureHash when replay protection is active.

use bitcoinsuite_core::{
    ecc::Ecc, Hashed, OutPoint, P2PKHSignatory, Script, SequenceNo, Sha256d, ShaRmd160,
    SigHashType, SignData, SignField, Signatory, TxInput, TxOutput, UnhashedTx, UnsignedTx,
    CHAIN_FORK_ID,
};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;

#[test]
fn test_p2pkh_signatory_fork_id() -> Result<(), Box<dyn std::error::Error>> {
    let ecc = EccSecp256k1::default();
    let seckey = ecc.seckey_from_array([1; 32])?;
    let pubkey = ecc.derive_pubkey(&seckey);
    let p2pkh_script = Script::p2pkh(&ShaRmd160::digest(pubkey.array().into()));

    let tx = UnhashedTx {
        version: 1,
        inputs: vec![TxInput {
            prev_out: OutPoint::default(),
            script: Script::default(),
            sequence: SequenceNo::finalized(),
            sign_data: Some(SignData::new(vec![
                SignField::Value(12345),
                SignField::OutputScript(p2pkh_script),
            ])),
        }],
        outputs: vec![TxOutput::default()],
        lock_time: 0,
    };

    let sig_hash_type = SigHashType::ALL_BIP143.with_fork_value(CHAIN_FORK_ID);
    let signatory = P2PKHSignatory {
        seckey: seckey.clone(),
        pubkey,
        sig_hash_type,
    };
    let mut unsigned_tx = UnsignedTx::new_dummy(tx.clone());
    signatory.sign_input(&ecc, unsigned_tx.input_at(0))?;
    let input = &unsigned_tx.tx().inputs[0];
    let (pubkey_from_script, sig) = input.script.parse_p2pkh_spend().unwrap();
    // Schnorr sig is 64 bytes + 1 sighash type byte, low byte only
    assert_eq!(sig.len(), 65);
    assert_eq!(sig[64], 0x41);
    assert_eq!(pubkey_from_script.as_ref(), pubkey.as_slice());

    // Sighashes for the same (dummy-hashed) transaction
    let mut verify_tx = UnsignedTx::new_dummy(tx);
    let input = verify_tx.input_at(0);
    let sighash_fork_id = Sha256d::digest(input.sighash_preimage(sig_hash_type, None)?.bytes);
    let sighash_fork_0 =
        Sha256d::digest(input.sighash_preimage(SigHashType::ALL_BIP143, None)?.bytes);
    let sig_core: bitcoinsuite_core::Bytes = sig[..64].to_vec().into();

    // Valid over the fork-value sighash
    ecc.schnorr_verify(&pubkey, sighash_fork_id.byte_array().clone(), &sig_core)?;
    // Invalid over the fork-0 sighash
    match ecc.schnorr_verify(&pubkey, sighash_fork_0.byte_array().clone(), &sig_core) {
        Err(bitcoinsuite_core::ecc::VerifySignatureError::IncorrectSignature) => {}
        result => panic!("Unexpected: {result:?}"),
    }
    Ok(())
}
