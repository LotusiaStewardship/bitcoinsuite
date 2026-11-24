use crate::{
    ecc::{Ecc, PubKey, SecKey},
    taproot::tap_tweak_hash,
    BytesMut, Hashed, Result, Script, Sha256d, SigHashType, SignError, UnsignedTxInput,
};

use crate::sign::Signatory;

/// Signatory for P2TR key-path spending (Taproot).
///
/// Signs with Schnorr + SIGHASH_LOTUS. Uses the tweaked private key
/// (internal_key + TapTweak hash mod n).
///
/// NOTE: SIGHASH_LOTUS is not yet implemented in this crate —
/// [`crate::UnsignedTxInput::sighash_preimage`] only implements the Bip143
/// variant, so [`Signatory::sign_input`] currently returns
/// [`SignError::InvalidSigHashType`] for the default
/// [`SigHashType::ALL_LOTUS`]. SIGHASH_LOTUS signing is owned by DEV-354.
pub struct P2TRKeyPathSignatory {
    pub seckey: SecKey,
    pub internal_pubkey: PubKey,
    pub sig_hash_type: SigHashType,
}

impl P2TRKeyPathSignatory {
    /// Create a new P2TR key-path signatory.
    pub fn new(seckey: SecKey, internal_pubkey: PubKey) -> Self {
        P2TRKeyPathSignatory {
            seckey,
            internal_pubkey,
            sig_hash_type: SigHashType::ALL_LOTUS,
        }
    }
}

impl Signatory for P2TRKeyPathSignatory {
    fn sign_input<'tx>(&self, ecc: &dyn Ecc, mut input: UnsignedTxInput<'tx>) -> Result<()> {
        // Tweak the private key: tweak = tagged_hash("TapTweak", internal_pubkey || zeros)
        let merkle_root = [0u8; 32];
        let tweak = tap_tweak_hash(&self.internal_pubkey, &merkle_root);
        let tweaked_seckey = ecc
            .tweak_seckey(&self.seckey, &tweak)
            .map_err(|_| SignError::InvalidSigHashType(self.sig_hash_type))?;

        // Compute sighash preimage
        let preimage = input.sighash_preimage(self.sig_hash_type, None)?;
        let sighash = Sha256d::digest(preimage.bytes).byte_array().clone();

        // Sign with Schnorr
        let sig = ecc.schnorr_sign(&tweaked_seckey, sighash);

        // Append sighash type byte after signature
        let mut sig_flagged = BytesMut::new();
        sig_flagged.put_bytes(sig);
        sig_flagged.put_slice(&[self.sig_hash_type.to_u32() as u8]);

        *input.input_script_mut() = Script::from_slice(sig_flagged.freeze().as_ref());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ecc::{DummyEcc, PubKey, SecKey},
        BitcoinSuiteError, OutPoint, P2TRKeyPathSignatory, Script, SequenceNo, SigHashType,
        SignData, SignError, SignField, Signatory, TxInput, TxOutput, UnhashedTx, UnsignedTx,
    };

    /// Pins the current P2TR gap: the default sighash type ALL_LOTUS
    /// (SIGHASH_ALL | SIGHASH_LOTUS) has no preimage implementation in this
    /// crate yet, so key-path signing fails with InvalidSigHashType.
    /// SIGHASH_LOTUS support is owned by DEV-354.
    #[test]
    fn test_p2tr_signatory_sighash_lotus_unimplemented() {
        let seckey = SecKey::new_unchecked([1; 32]);
        let internal_pubkey = PubKey::new_unchecked([2; 33]);
        let signatory = P2TRKeyPathSignatory::new(seckey, internal_pubkey);

        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint::default(),
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![SignField::Value(12345)])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let mut unsigned_tx = UnsignedTx::new(tx);
        match signatory.sign_input(&DummyEcc, unsigned_tx.input_at(0)) {
            Err(BitcoinSuiteError::Sign(SignError::InvalidSigHashType(sighash_type))) => {
                assert_eq!(sighash_type, SigHashType::ALL_LOTUS);
            }
            result => panic!("Unexpected: {result:?}"),
        }
    }
}
