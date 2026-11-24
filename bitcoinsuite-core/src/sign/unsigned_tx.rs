use crate::{
    BitcoinCode, BitcoinSuiteError, Bytes, BytesMut, Hashed, Script, Sha256d, SigHashType,
    SigHashTypeInputs, SigHashTypeOutputs, SigHashTypeVariant, SignData, SignError, UnhashedTx,
};

use crate::sign::error::Result;

pub struct UnsignedTx {
    prevouts_hash: Sha256d,
    sequences_hash: Sha256d,
    outputs_hash: Sha256d,
    tx: UnhashedTx,
}

pub struct UnsignedTxInput<'tx> {
    idx: usize,
    unsigned_tx: &'tx mut UnsignedTx,
}

#[derive(Debug, Clone)]
pub struct SighashPreimage {
    pub bytes: Bytes,
    pub script_code: Script,
    pub redeem_script: Script,
}

impl UnsignedTx {
    pub fn new(tx: UnhashedTx) -> Self {
        UnsignedTx {
            prevouts_hash: calc_prevouts_hash(&tx),
            sequences_hash: calc_sequences_hash(&tx),
            outputs_hash: calc_outputs_hash(&tx),
            tx,
        }
    }

    pub fn new_dummy(tx: UnhashedTx) -> Self {
        UnsignedTx {
            prevouts_hash: Sha256d::default(),
            sequences_hash: Sha256d::default(),
            outputs_hash: Sha256d::default(),
            tx,
        }
    }

    pub fn tx(&self) -> &UnhashedTx {
        &self.tx
    }

    pub fn into_tx(self) -> UnhashedTx {
        self.tx
    }

    pub fn input_at(&mut self, input_idx: usize) -> UnsignedTxInput<'_> {
        UnsignedTxInput {
            idx: input_idx,
            unsigned_tx: self,
        }
    }
}

impl<'tx> UnsignedTxInput<'tx> {
    pub fn input_script_mut(&mut self) -> &mut Script {
        &mut self.unsigned_tx.tx.inputs[self.idx].script
    }

    pub fn input_sign_data_mut(&mut self) -> &mut Option<SignData> {
        &mut self.unsigned_tx.tx.inputs[self.idx].sign_data
    }

    pub fn unsigned_tx(&self) -> &UnsignedTx {
        self.unsigned_tx
    }

    pub fn input_idx(&self) -> usize {
        self.idx
    }

    pub fn sighash_preimage(
        &self,
        sig_hash_type: SigHashType,
        codesep_idx: Option<usize>,
    ) -> Result<SighashPreimage> {
        if sig_hash_type.variant != SigHashTypeVariant::Bip143 {
            return Err(SignError::InvalidSigHashType(sig_hash_type));
        }
        let tx = &self.unsigned_tx.tx;
        let input = &tx.inputs[self.idx];
        let sign_data = match &input.sign_data {
            Some(sign_data) => sign_data,
            None => return Err(SignError::NoSignData),
        };
        let redeem_script = sign_data.find_script_code()?;
        let script_code = redeem_script
            .cut_out_codesep(codesep_idx)
            .map_err(|err| match err {
                BitcoinSuiteError::Bytes(_) => SignError::InvalidScriptEncoding,
                BitcoinSuiteError::CodesepNotFound(idx) => SignError::CodesepNotFound(idx),
                _ => unreachable!(),
            })?;
        let mut preimage = BytesMut::new();
        preimage.put_bytes(tx.version.ser());
        preimage.put_byte_array(if sig_hash_type.input_type == SigHashTypeInputs::Fixed {
            self.unsigned_tx.prevouts_hash.byte_array().clone()
        } else {
            [0; 32].into()
        });
        preimage.put_byte_array(
            if sig_hash_type.input_type == SigHashTypeInputs::Fixed
                && sig_hash_type.output_type == SigHashTypeOutputs::All
            {
                self.unsigned_tx.sequences_hash.byte_array().clone()
            } else {
                [0; 32].into()
            },
        );
        preimage.put_bytes(input.prev_out.ser());
        preimage.put_bytes(script_code.ser());
        preimage.put_bytes(sign_data.find_value()?.ser());
        preimage.put_bytes(input.sequence.ser());
        preimage.put_byte_array(match sig_hash_type.output_type {
            SigHashTypeOutputs::All => self.unsigned_tx.outputs_hash.byte_array().clone(),
            SigHashTypeOutputs::Single if self.idx < tx.outputs.len() => {
                Sha256d::digest(tx.outputs[self.idx].ser())
                    .byte_array()
                    .clone()
            }
            _ => [0; 32].into(),
        });
        preimage.put_bytes(tx.lock_time.ser());
        preimage.put_bytes(sig_hash_type.to_u32().ser());
        Ok(SighashPreimage {
            bytes: preimage.freeze(),
            script_code,
            redeem_script,
        })
    }
}

fn calc_prevouts_hash(tx: &UnhashedTx) -> Sha256d {
    let mut hashes = BytesMut::new();
    for input in &tx.inputs {
        hashes.put_bytes(input.prev_out.ser());
    }
    Sha256d::digest(hashes.freeze())
}

fn calc_sequences_hash(tx: &UnhashedTx) -> Sha256d {
    let mut hashes = BytesMut::new();
    for input in &tx.inputs {
        hashes.put_bytes(input.sequence.ser());
    }
    Sha256d::digest(hashes.freeze())
}

fn calc_outputs_hash(tx: &UnhashedTx) -> Sha256d {
    let mut hashes = BytesMut::new();
    for output in &tx.outputs {
        hashes.put_bytes(output.ser());
    }
    Sha256d::digest(hashes.freeze())
}

#[cfg(test)]
mod tests {
    use crate::{
        Hashed, OutPoint, Script, SequenceNo, Sha256d, SigHashType, SignData, SignError, SignField,
        TxInput, TxOutput, UnhashedTx, UnsignedTx,
    };

    #[test]
    fn test_unsigned_tx_ctor() -> Result<(), Box<dyn std::error::Error>> {
        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint::default(),
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(12345),
                    SignField::RedeemScript(Script::from_slice(&[0x51])),
                ])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let unsigned_tx = UnsignedTx::new(tx);
        assert_eq!(
            unsigned_tx.prevouts_hash,
            Sha256d::from_hex_be(
                "e15426c0d1fbb5b78943c8425a9232fdfc1670d77f987707292a77ec6dce5aca"
            )?
        );
        assert_eq!(
            unsigned_tx.sequences_hash,
            Sha256d::from_hex_be(
                "445066705e799022b7095f7ceca255149f43acfc47e7f59e551f7bce2930b13b"
            )?
        );
        assert_eq!(
            unsigned_tx.outputs_hash,
            Sha256d::from_hex_be(
                "f9adfde059810f37b3d0686d67f6b29034e0c669537df7e59b40c14a0508b9ed"
            )?
        );
        Ok(())
    }

    #[test]
    fn test_sighash_preimage() -> Result<(), Box<dyn std::error::Error>> {
        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint {
                    txid: Sha256d::new([0xae; 32]),
                    out_idx: 0x12345678,
                },
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(12345),
                    SignField::RedeemScript(Script::from_slice(&[0x51])),
                ])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let mut unsigned_tx = UnsignedTx::new(tx);
        let input = unsigned_tx.input_at(0);
        {
            let preimage = input.sighash_preimage(SigHashType::ALL_BIP143, None)?.bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::NONE_BIP143, None)?
                .bytes;
            println!("{}", preimage.hex());
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                0000000000000000000000000000000000000000000000000000000000000000\
                00000000\
                42000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::SINGLE_BIP143, None)?
                .bytes;
            println!("{}", preimage.hex());
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                43000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::ALL_BIP143_ANYONECANPAY, None)?
                .bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                c1000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::NONE_BIP143_ANYONECANPAY, None)?
                .bytes;
            println!("{}", preimage.hex());
            assert_eq!(
                preimage.hex(),
                "01000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                0000000000000000000000000000000000000000000000000000000000000000\
                00000000\
                c2000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::SINGLE_BIP143_ANYONECANPAY, None)?
                .bytes;
            println!("{}", preimage.hex());
            assert_eq!(
                preimage.hex(),
                "01000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                0000000000000000000000000000000000000000000000000000000000000000\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                c3000000"
            );
        }

        Ok(())
    }

    #[test]
    fn test_sighash_preimage_codesep() -> Result<(), Box<dyn std::error::Error>> {
        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint {
                    txid: Sha256d::new([0xae; 32]),
                    out_idx: 0x12345678,
                },
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(12345),
                    SignField::RedeemScript(Script::from_slice(&[0x51, 0xab, 0xac, 0xab, 0x87])),
                ])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let mut unsigned_tx = UnsignedTx::new(tx);
        let input = unsigned_tx.input_at(0);
        {
            let preimage = input.sighash_preimage(SigHashType::ALL_BIP143, None)?.bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0551abacab87\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::ALL_BIP143, Some(0))?
                .bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                03acab87\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
        }
        {
            let preimage = input
                .sighash_preimage(SigHashType::ALL_BIP143, Some(1))?
                .bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0187\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
        }
        {
            match input.sighash_preimage(SigHashType::ALL_BIP143, Some(2)) {
                Err(SignError::CodesepNotFound(2)) => {}
                result => panic!("Unexpected: {result:?}"),
            }
        }
        Ok(())
    }

    /// Golden vectors for the fork value in the BIP143 preimage.
    ///
    /// Generated with lotusd's Python reference `SignatureHashForkId`
    /// (lotusd/test/functional/test_framework/script.py) for exactly the
    /// fixed transaction from `test_sighash_preimage` above (version 1,
    /// one input with prevout txid ae*32 / n 0x12345678, sequence
    /// 0xffffffff, script_code 0x51, amount 12345, one empty output of
    /// value 0, lock time 0), once at fork value 0 and once at
    /// CHAIN_FORK_ID (0x4c4f54, hashtype 0x4c4f5441).
    ///
    /// Generator snippet (run with the lotusd checkout):
    /// ```text
    /// import sys
    /// sys.path.insert(0, "<lotusd>/test/functional")
    /// from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, hash256
    /// from test_framework.script import CScript, CScriptOp, SignatureHashForkId
    ///
    /// tx = CTransaction()
    /// tx.nVersion = 1
    /// tx.vin = [CTxIn(outpoint=COutPoint(hash=int.from_bytes(b"\xae" * 32, "little"),
    ///                                    n=0x12345678),
    ///                 scriptSig=CScript(), nSequence=0xFFFFFFFF)]
    /// tx.vout = [CTxOut(nValue=0, scriptPubKey=CScript())]
    /// tx.nLockTime = 0
    /// script_code = CScript([CScriptOp(0x51)])
    /// for hashtype in (0x41, 0x4C4F5441):
    ///     sighash = SignatureHashForkId(script_code, tx, 0, hashtype, 12345)
    ///     print(f"{hashtype:#x} sighash={sighash.hex()}")
    /// ```
    #[test]
    fn test_sighash_preimage_fork_id_golden() -> Result<(), Box<dyn std::error::Error>> {
        use crate::CHAIN_FORK_ID;

        let tx = UnhashedTx {
            version: 1,
            inputs: vec![TxInput {
                prev_out: OutPoint {
                    txid: Sha256d::new([0xae; 32]),
                    out_idx: 0x12345678,
                },
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::Value(12345),
                    SignField::RedeemScript(Script::from_slice(&[0x51])),
                ])),
            }],
            outputs: vec![TxOutput::default()],
            lock_time: 0,
        };
        let mut unsigned_tx = UnsignedTx::new(tx);
        let input = unsigned_tx.input_at(0);

        // Fork value 0: byte-for-byte the preimage from test_sighash_preimage
        {
            let preimage = input.sighash_preimage(SigHashType::ALL_BIP143, None)?.bytes;
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41000000"
            );
            assert_eq!(
                Sha256d::digest(preimage).as_slice(),
                &hex::decode("a4140b14d52e977545274a1fbace142391c4227e5ca3cf3e1b3d4ed58eae5c51")?,
            );
        }

        // CHAIN_FORK_ID: only the trailing 4 sighash-type bytes differ
        // (0x4c4f5441 serialized little-endian: 41 54 4f 4c)
        let sighash_type = SigHashType::ALL_BIP143.with_fork_value(CHAIN_FORK_ID);
        {
            let preimage = input.sighash_preimage(sighash_type, None)?.bytes;
            assert_eq!(&preimage[preimage.len() - 4..], &[0x41, 0x54, 0x4f, 0x4c]);
            assert_eq!(
                preimage.hex(),
                "01000000\
                2c084ff03a1103581b512a25262f9a7d7e17565de0d4a4bb5d45cabb9b1f2ffb\
                3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044\
                aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae78563412\
                0151\
                3930000000000000\
                ffffffff\
                edb908054ac1409be5f77d5369c6e03490b2f6676d68d0b3370f8159e0fdadf9\
                00000000\
                41544f4c"
            );
            assert_eq!(
                Sha256d::digest(preimage).as_slice(),
                &hex::decode("dee2f4bfa867e5c3494126942c9bff1b543567e5d0192a4a9902f8bca3805fe6")?,
            );
        }

        Ok(())
    }
}
