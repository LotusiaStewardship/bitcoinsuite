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
