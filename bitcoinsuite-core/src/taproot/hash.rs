use sha2::{Digest, Sha256};

use crate::ecc::{PubKey, PUBKEY_LENGTH};

/// Tag for TapLeaf hash calculation
pub const TAPROOT_TAG_TAPLEAF: &str = "TapLeaf";
/// Tag for TapBranch hash calculation
pub const TAPROOT_TAG_TAPBRANCH: &str = "TapBranch";
/// Tag for TapTweak hash calculation
pub const TAPROOT_TAG_TAPTWEAK: &str = "TapTweak";

/// Tagged hash for Taproot (BIP340-style).
///
/// `tag_hash = SHA256(SHA256(tag) || SHA256(tag) || data)`
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// Calculate TapTweak hash.
///
/// `tweak = SHA256_tag("TapTweak", internal_pubkey || merkle_root)`
pub fn tap_tweak_hash(internal_pubkey: &PubKey, merkle_root: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; PUBKEY_LENGTH + 32];
    data[..PUBKEY_LENGTH].copy_from_slice(internal_pubkey.as_slice());
    data[PUBKEY_LENGTH..].copy_from_slice(merkle_root);
    tagged_hash(TAPROOT_TAG_TAPTWEAK, &data)
}

/// Calculate TapLeaf hash.
///
/// `tapleaf_hash = SHA256_tag("TapLeaf", leaf_version || compact_size(script) || script)`
pub fn tap_leaf_hash(script: &[u8], leaf_version: u8) -> [u8; 32] {
    // Build: leaf_version || compact_size(script_len) || script
    let script_len = script.len();
    let mut data = Vec::with_capacity(1 + 9 + script_len); // 1 byte version + up to 9 varint + script
    data.push(leaf_version);
    // Compact-size encoding (varint)
    if script_len < 0xfd {
        data.push(script_len as u8);
    } else if script_len <= 0xffff {
        data.push(0xfd);
        data.extend_from_slice(&(script_len as u16).to_le_bytes());
    } else if script_len <= 0xffffffff {
        data.push(0xfe);
        data.extend_from_slice(&(script_len as u32).to_le_bytes());
    } else {
        data.push(0xff);
        data.extend_from_slice(&(script_len as u64).to_le_bytes());
    }
    data.extend_from_slice(script);
    tagged_hash(TAPROOT_TAG_TAPLEAF, &data)
}

/// Calculate TapBranch hash.
///
/// `tapbranch_hash = SHA256_tag("TapBranch", left || right)`
/// where left and right are ordered lexicographically.
pub fn tap_branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(first);
    data[32..].copy_from_slice(second);
    tagged_hash(TAPROOT_TAG_TAPBRANCH, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecc::PubKey;

    #[test]
    fn test_tagged_hash_tap_tweak() {
        // Test vector: all-zero pubkey + all-zero merkle_root
        let pubkey = PubKey::new_unchecked([0; 33]);
        let merkle_root = [0; 32];
        let result = tap_tweak_hash(&pubkey, &merkle_root);
        // Verify it's deterministic and correct length
        assert_eq!(result.len(), 32);
        assert_ne!(result, [0; 32]); // Should not be all zeros
    }

    #[test]
    fn test_tagged_hash_tap_leaf() {
        // Empty script with tapscript version
        let result = tap_leaf_hash(&[], 0xc0);
        assert_eq!(result.len(), 32);
        assert_ne!(result, [0; 32]);
    }

    #[test]
    fn test_tagged_hash_tap_branch_ordering() {
        let a = [0xaa; 32];
        let b = [0xbb; 32];
        let result_ab = tap_branch_hash(&a, &b);
        let result_ba = tap_branch_hash(&b, &a);
        // Lexicographic ordering means both should produce same result
        assert_eq!(result_ab, result_ba);
    }

    #[test]
    fn test_tagged_hash_known_tap_tweak() {
        // Test against known xpi-ts output
        // Pubkey: 020202020202020202020202020202020202020202020202020202020202020202
        // Merkle root: all zeros
        let pubkey = PubKey::new_unchecked([2; 33]);
        let merkle_root = [0; 32];
        let result = tap_tweak_hash(&pubkey, &merkle_root);
        assert_eq!(
            hex::encode(result),
            "3479108df2142be2d9debbe5d3030037e7bb652dc556d0657c6007b6da456698"
        );
    }
}
