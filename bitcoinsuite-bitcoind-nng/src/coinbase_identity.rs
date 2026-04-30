use std::fmt;

pub const MAX_IDENTITY_BYTES_FOR_DEFAULT_EXTRANONCE: usize = 88;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoinbaseIdentityError {
    IdentityTooLong { len: usize, max: usize },
}

impl fmt::Display for CoinbaseIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityTooLong { len, max } => {
                write!(f, "coinbase identity is too long: {len} bytes > max {max}")
            }
        }
    }
}

impl std::error::Error for CoinbaseIdentityError {}

/// Encode operator identity to raw UTF-8 bytes for lotusd's coinbase_identity field.
///
/// The default limit targets stratum's fixed 4-byte extranonce1 + 4-byte
/// extranonce2 split, keeping coinbase scriptSig within the 100-byte consensus
/// bound even in the 2-byte pushdata-encoding case.
pub fn encode_coinbase_identity_utf8(identity: &str) -> Result<Vec<u8>, CoinbaseIdentityError> {
    let bytes = identity.as_bytes().to_vec();
    if bytes.len() > MAX_IDENTITY_BYTES_FOR_DEFAULT_EXTRANONCE {
        return Err(CoinbaseIdentityError::IdentityTooLong {
            len: bytes.len(),
            max: MAX_IDENTITY_BYTES_FOR_DEFAULT_EXTRANONCE,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_identity() {
        let encoded = encode_coinbase_identity_utf8("").unwrap();
        assert!(encoded.is_empty());
    }

    #[test]
    fn ascii_identity() {
        let encoded = encode_coinbase_identity_utf8("LotusiaPool").unwrap();
        assert_eq!(encoded, b"LotusiaPool");
    }

    #[test]
    fn non_ascii_identity() {
        let encoded = encode_coinbase_identity_utf8("莲花").unwrap();
        assert_eq!(encoded, "莲花".as_bytes());
    }

    #[test]
    fn oversized_identity_rejected() {
        let identity = "a".repeat(MAX_IDENTITY_BYTES_FOR_DEFAULT_EXTRANONCE + 1);
        let err = encode_coinbase_identity_utf8(&identity).unwrap_err();
        assert_eq!(
            err,
            CoinbaseIdentityError::IdentityTooLong {
                len: MAX_IDENTITY_BYTES_FOR_DEFAULT_EXTRANONCE + 1,
                max: MAX_IDENTITY_BYTES_FOR_DEFAULT_EXTRANONCE,
            }
        );
    }
}
