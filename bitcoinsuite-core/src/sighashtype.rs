use std::fmt::Display;

/// The Lotus chain's fork id, committed to every signature while replay
/// protection is active (`CHAIN_FORK_ID` in `lotusd/src/script/sighashtype.h`).
///
/// This is a chain identity, not an epoch marker: a signature made for this
/// value is invalid on any chain using a different fork id, and a signature
/// made for another chain is invalid here. It occupies the 24-bit
/// [`SigHashType::fork_value`] field, so it must fit in 24 bits and must not
/// be zero. Do not change this value without a coordinated hard fork.
pub const CHAIN_FORK_ID: u32 = 0x4c_4f_54; // "LOT"

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SigHashType {
    pub variant: SigHashTypeVariant,
    pub input_type: SigHashTypeInputs,
    pub output_type: SigHashTypeOutputs,
    /// 24-bit fork value committed to the signature (bits 8..=31 of the
    /// serialized 32-bit sighash type). 0 before replay protection
    /// activation. Set it with [`SigHashType::with_fork_value`].
    pub fork_value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigHashTypeInputs {
    Fixed,
    AnyoneCanPay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigHashTypeOutputs {
    All,
    None,
    Single,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigHashTypeVariant {
    Legacy,
    Bip143,
    /// SIGHASH_LOTUS (0x60) — required for Taproot key-path spending in Lotus chains.
    Lotus,
}

impl SigHashType {
    /// Taproot key-path sighash type: SIGHASH_ALL | SIGHASH_LOTUS (0x61)
    pub const ALL_LOTUS: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Lotus,
        input_type: SigHashTypeInputs::Fixed,
        output_type: SigHashTypeOutputs::All,
        fork_value: 0,
    };
    pub const ALL_BIP143: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        output_type: SigHashTypeOutputs::All,
        fork_value: 0,
    };
    pub const NONE_BIP143: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        output_type: SigHashTypeOutputs::None,
        fork_value: 0,
    };
    pub const SINGLE_BIP143: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::Fixed,
        output_type: SigHashTypeOutputs::Single,
        fork_value: 0,
    };
    pub const ALL_BIP143_ANYONECANPAY: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::AnyoneCanPay,
        output_type: SigHashTypeOutputs::All,
        fork_value: 0,
    };
    pub const NONE_BIP143_ANYONECANPAY: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::AnyoneCanPay,
        output_type: SigHashTypeOutputs::None,
        fork_value: 0,
    };
    pub const SINGLE_BIP143_ANYONECANPAY: SigHashType = SigHashType {
        variant: SigHashTypeVariant::Bip143,
        input_type: SigHashTypeInputs::AnyoneCanPay,
        output_type: SigHashTypeOutputs::Single,
        fork_value: 0,
    };

    /// Set the 24-bit fork value committed to the signature (e.g.
    /// [`CHAIN_FORK_ID`] on Lotus chains while replay protection is active).
    ///
    /// Panics when `fork_value` does not fit in 24 bits.
    pub const fn with_fork_value(self, fork_value: u32) -> Self {
        assert!(fork_value <= 0x00ff_ffff, "fork value must fit in 24 bits");
        SigHashType {
            variant: self.variant,
            input_type: self.input_type,
            output_type: self.output_type,
            fork_value,
        }
    }

    /// Serialize to the full 32-bit sighash type: fork value in bits
    /// 8..=31, low byte carrying input/output/variant flags.
    pub fn to_u32(&self) -> u32 {
        ((self.fork_value & 0x00ff_ffff) << 8)
            | self.input_type.to_u32()
            | self.output_type.to_u32()
            | self.variant.to_u32()
    }

    /// Parse the full 32-bit sighash type, extracting the 24-bit fork value
    /// from bits 8..=31. Returns `None` when the low byte does not encode a
    /// valid input/output/variant combination.
    pub fn from_u32(flags: u32) -> Option<SigHashType> {
        let low_byte = flags & 0xff;
        let fork_value = flags >> 8;
        let variant = match low_byte & 0x7c {
            0 => SigHashTypeVariant::Legacy,
            0x40 => SigHashTypeVariant::Bip143,
            0x60 => SigHashTypeVariant::Lotus,
            _ => return None,
        };
        let input_type = match low_byte & 0x80 {
            0 => SigHashTypeInputs::Fixed,
            _ => SigHashTypeInputs::AnyoneCanPay,
        };
        let output_type = match low_byte & 0x03 {
            0 => return None,
            1 => SigHashTypeOutputs::All,
            2 => SigHashTypeOutputs::None,
            3 => SigHashTypeOutputs::Single,
            _ => unreachable!(),
        };
        Some(SigHashType {
            variant,
            input_type,
            output_type,
            fork_value,
        })
    }
}

impl SigHashTypeInputs {
    pub fn to_u32(&self) -> u32 {
        match self {
            SigHashTypeInputs::Fixed => 0x00,
            SigHashTypeInputs::AnyoneCanPay => 0x80,
        }
    }
}

impl SigHashTypeOutputs {
    pub fn to_u32(&self) -> u32 {
        match self {
            SigHashTypeOutputs::All => 1,
            SigHashTypeOutputs::None => 2,
            SigHashTypeOutputs::Single => 3,
        }
    }
}

impl SigHashTypeVariant {
    pub fn to_u32(&self) -> u32 {
        match self {
            SigHashTypeVariant::Legacy => 0x00,
            SigHashTypeVariant::Bip143 => 0x40,
            SigHashTypeVariant::Lotus => 0x60,
        }
    }
}

impl Display for SigHashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.output_type {
            SigHashTypeOutputs::All => write!(f, "ALL")?,
            SigHashTypeOutputs::None => write!(f, "NONE")?,
            SigHashTypeOutputs::Single => write!(f, "SINGLE")?,
        }
        if let SigHashTypeVariant::Bip143 = self.variant {
            write!(f, "|FORKID")?;
        }
        if let SigHashTypeVariant::Lotus = self.variant {
            write!(f, "|LOTUS")?;
        }
        if let SigHashTypeInputs::AnyoneCanPay = self.input_type {
            write!(f, "|ANYONECANPAY")?;
        }
        if self.fork_value != 0 {
            write!(f, "|CHAINID:0x{:x}", self.fork_value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{SigHashType, SigHashTypeInputs, SigHashTypeOutputs, SigHashTypeVariant};

    #[test]
    fn test_sighash_display() {
        assert_eq!(SigHashType::ALL_BIP143.to_string(), "ALL|FORKID");
        assert_eq!(SigHashType::NONE_BIP143.to_string(), "NONE|FORKID");
        assert_eq!(SigHashType::SINGLE_BIP143.to_string(), "SINGLE|FORKID");
        assert_eq!(
            SigHashType::ALL_BIP143_ANYONECANPAY.to_string(),
            "ALL|FORKID|ANYONECANPAY"
        );
        assert_eq!(
            SigHashType::NONE_BIP143_ANYONECANPAY.to_string(),
            "NONE|FORKID|ANYONECANPAY"
        );
        assert_eq!(
            SigHashType::SINGLE_BIP143_ANYONECANPAY.to_string(),
            "SINGLE|FORKID|ANYONECANPAY"
        );
        assert_eq!(
            SigHashType::ALL_BIP143.with_fork_value(0).to_string(),
            "ALL|FORKID"
        );
        assert_eq!(
            SigHashType::ALL_BIP143
                .with_fork_value(crate::CHAIN_FORK_ID)
                .to_string(),
            "ALL|FORKID|CHAINID:0x4c4f54"
        );
        assert_eq!(
            SigHashType::ALL_BIP143.with_fork_value(0xdead).to_string(),
            "ALL|FORKID|CHAINID:0xdead"
        );
    }

    #[test]
    fn test_sighash_to_u32() {
        assert_eq!(SigHashType::ALL_BIP143.to_u32(), 0x41);
        assert_eq!(SigHashType::NONE_BIP143.to_u32(), 0x42);
        assert_eq!(SigHashType::SINGLE_BIP143.to_u32(), 0x43);
        assert_eq!(SigHashType::ALL_BIP143_ANYONECANPAY.to_u32(), 0xc1);
        assert_eq!(SigHashType::NONE_BIP143_ANYONECANPAY.to_u32(), 0xc2);
        assert_eq!(SigHashType::SINGLE_BIP143_ANYONECANPAY.to_u32(), 0xc3);
    }

    #[test]
    fn test_sighash_from_u32() {
        assert_eq!(
            SigHashType::from_u32(0xdead_0041),
            // fork value occupies bits 8..=31, matching lotusd's
            // SigHashType::getForkValue() (sigHash >> 8)
            Some(SigHashType::ALL_BIP143.with_fork_value(0xdead_00))
        );
        assert_eq!(SigHashType::from_u32(0x21), None);
        assert_eq!(SigHashType::from_u32(0x11), None);
        assert_eq!(SigHashType::from_u32(0x00), None);
        assert_eq!(SigHashType::from_u32(0x40), None);
        assert_eq!(SigHashType::from_u32(0x41), Some(SigHashType::ALL_BIP143));
        assert_eq!(SigHashType::from_u32(0x42), Some(SigHashType::NONE_BIP143));
        assert_eq!(
            SigHashType::from_u32(0x43),
            Some(SigHashType::SINGLE_BIP143),
        );
        assert_eq!(
            SigHashType::from_u32(0xc1),
            Some(SigHashType::ALL_BIP143_ANYONECANPAY),
        );
        assert_eq!(
            SigHashType::from_u32(0xc2),
            Some(SigHashType::NONE_BIP143_ANYONECANPAY),
        );
        assert_eq!(
            SigHashType::from_u32(0xc3),
            Some(SigHashType::SINGLE_BIP143_ANYONECANPAY),
        );
        {
            use SigHashTypeInputs::*;
            use SigHashTypeOutputs::*;
            for (sighash, input_type, output_type) in [
                (0x01, Fixed, All),
                (0x02, Fixed, None),
                (0x03, Fixed, Single),
                (0x81, AnyoneCanPay, All),
                (0x82, AnyoneCanPay, None),
                (0x83, AnyoneCanPay, Single),
            ] {
                assert_eq!(
                    SigHashType::from_u32(sighash),
                    Some(SigHashType {
                        variant: SigHashTypeVariant::Legacy,
                        input_type,
                        output_type,
                        fork_value: 0,
                    }),
                );
            }
        }
    }
}
