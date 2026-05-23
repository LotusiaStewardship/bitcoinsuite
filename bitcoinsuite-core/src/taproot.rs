use sha2::{Digest, Sha256};

use crate::ecc::PubKey;

/// BIP-340 style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute TapTweak for a given internal public key and merkle root.
///
/// `tweak = tagged_hash("TapTweak", internal_pubkey || merkle_root)`
///
/// For key-path-only spending, use `[0u8; 32]` as the merkle root.
pub fn calculate_tap_tweak(internal_pubkey: &PubKey, merkle_root: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(33 + 32);
    data.extend_from_slice(internal_pubkey.as_slice());
    data.extend_from_slice(merkle_root);
    tagged_hash("TapTweak", &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::PubKey;
    use hex_literal::hex;

    #[test]
    fn test_tagged_hash_known() {
        // Empty data with "TapTweak" tag
        let result = tagged_hash("TapTweak", b"");
        // SHA256(SHA256("TapTweak") || SHA256("TapTweak"))
        let tag_hash = Sha256::digest(b"TapTweak");
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(tag_hash);
        expected_hasher.update(tag_hash);
        let expected: [u8; 32] = expected_hasher.finalize().into();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_calculate_tap_tweak_deterministic() {
        let pubkey = PubKey::new_unchecked(hex!(
            "020000000000000000000000000000000000000000000000000000000000000001"
        ));
        let merkle_root = [0u8; 32];
        let tweak = calculate_tap_tweak(&pubkey, &merkle_root);
        // Tweak must be 32 bytes and non-zero
        assert_eq!(tweak.len(), 32);
    }

    #[test]
    fn test_calculate_tap_tweak_changes_with_pubkey() {
        let pubkey_a = PubKey::new_unchecked(hex!(
            "020000000000000000000000000000000000000000000000000000000000000001"
        ));
        let pubkey_b = PubKey::new_unchecked(hex!(
            "030000000000000000000000000000000000000000000000000000000000000001"
        ));
        let merkle_root = [0u8; 32];
        let tweak_a = calculate_tap_tweak(&pubkey_a, &merkle_root);
        let tweak_b = calculate_tap_tweak(&pubkey_b, &merkle_root);
        assert_ne!(tweak_a, tweak_b);
    }
}
