use std::fmt::Debug;

use crate::{Hashed, Sha256d};
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;

pub const SECKEY_LENGTH: usize = 32;

#[derive(Clone)]
pub struct SecKey(Secret<[u8; SECKEY_LENGTH]>);

#[derive(Debug, Error)]
pub enum SecKeyParseError {
    #[error("invalid hex private key")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("invalid WIF private key")]
    InvalidWif,
}

impl SecKey {
    pub fn new_unchecked(seckey: [u8; SECKEY_LENGTH]) -> SecKey {
        SecKey(Secret::new(seckey))
    }

    pub fn from_hex_or_wif(key: &str) -> Result<SecKey, SecKeyParseError> {
        if key.len() == 64 {
            let bytes = hex::decode(key)?;
            let mut seckey = [0u8; SECKEY_LENGTH];
            seckey.copy_from_slice(&bytes);
            return Ok(SecKey::new_unchecked(seckey));
        }

        let decoded = bs58::decode(key)
            .into_vec()
            .map_err(|_| SecKeyParseError::InvalidWif)?;
        if decoded.len() != 37 && decoded.len() != 38 {
            return Err(SecKeyParseError::InvalidWif);
        }
        let (payload, checksum) = decoded.split_at(decoded.len() - 4);
        let checksum_hash = Sha256d::digest(payload.to_vec().into());
        let expected_checksum = &checksum_hash.as_slice()[..4];
        if checksum != expected_checksum {
            return Err(SecKeyParseError::InvalidWif);
        }

        // Validate WIF version byte: 0x80 for mainnet, 0xef for testnet
        if payload[0] != 0x80 && payload[0] != 0xef {
            return Err(SecKeyParseError::InvalidWif);
        }

        if payload.len() < 33 {
            return Err(SecKeyParseError::InvalidWif);
        }
        let key_bytes = if payload.len() == 34 {
            if payload[33] != 0x01 {
                return Err(SecKeyParseError::InvalidWif);
            }
            &payload[1..33]
        } else {
            &payload[1..33]
        };

        let mut seckey = [0u8; SECKEY_LENGTH];
        seckey.copy_from_slice(key_bytes);
        Ok(SecKey::new_unchecked(seckey))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl Debug for SecKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecKey([SECRET])")
    }
}

impl Default for SecKey {
    fn default() -> Self {
        SecKey(Secret::new([0; SECKEY_LENGTH]))
    }
}

#[cfg(test)]
mod tests {
    use super::SecKey;

    #[test]
    fn test_as_slice() {
        let seckey = SecKey::new_unchecked([1; 32]);
        assert_eq!(seckey.as_slice(), &[1; 32]);
    }

    #[test]
    fn test_format_debug_doesnt_leak() {
        let seckey = SecKey::new_unchecked([1; 32]);
        assert_eq!(format!("{seckey:?}"), "SecKey([SECRET])");
    }

    #[test]
    fn test_from_hex() {
        let hex_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let seckey = SecKey::from_hex_or_wif(hex_key).unwrap();
        assert_eq!(seckey.as_slice(), &[0xaa; 32]);
    }

    #[test]
    fn test_from_testnet_wif() {
        // Testnet WIF: cPymiBZp9Ak8aVAmrnh8TL8E4yoibD61KE7weuhXNbaMsJt2murF
        let wif = "cPymiBZp9Ak8aVAmrnh8TL8E4yoibD61KE7weuhXNbaMsJt2murF";
        let seckey = SecKey::from_hex_or_wif(wif).unwrap();
        // The key should parse successfully
        assert!(!seckey.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_invalid_wif_format() {
        // Invalid WIF (not base58)
        let invalid_wif = "invalid_wif_string";
        assert!(SecKey::from_hex_or_wif(invalid_wif).is_err());
    }
}
