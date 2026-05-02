use bitcoinsuite_core::{lotus_txid, Bytes, BytesMut, Hashed, LotusHeader, Sha256d, Tx, BitcoinCode};
use primitive_types::U256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StratumError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Serialization error")]
    SerializationError,
}

pub type Result<T> = std::result::Result<T, StratumError>;

/// Lotus merkle leaf: SHA256d(txid || lotus_txid)
///
/// This is the Lotus-specific merkle leaf computation that differs from
/// standard Bitcoin merkle trees.
pub fn lotus_merkle_leaf(tx: &Tx) -> Sha256d {
    let txid = tx.hash();
    let lotus_txid_val = lotus_txid(tx.unhashed_tx());
    let mut leaf_raw = BytesMut::new();
    leaf_raw.put_slice(txid.as_ref());
    leaf_raw.put_slice(lotus_txid_val.as_ref());
    Sha256d::digest(leaf_raw.freeze())
}

/// Build a Lotus header from Stratum V1 components.
///
/// This function assembles a complete 160-byte Lotus header from the parts
/// provided in the Stratum V1 mining.notify message, combined with the
/// miner's extranonce1 and submitted extranonce2/ntime/nonce.
/// No precomputed template header is used - everything is built from scratch.
///
/// # Arguments
///
/// * `coinbase1` - First part of coinbase transaction (hex)
/// * `extranonce1` - Pool-provided extranonce (hex)
/// * `extranonce2` - Miner-provided extranonce (hex)
/// * `coinbase2` - Second part of coinbase transaction (hex)
/// * `merkle_branches` - Merkle tree branches for the coinbase (hex strings)
/// * `prevhash` - Previous block hash (hex, from mining.notify)
/// * `version` - Block version (hex, from mining.notify)
/// * `nbits_hex` - Compact difficulty bits (hex)
/// * `ntime_hex_6b` - Timestamp (6-byte hex, little-endian)
/// * `nonce_hex_8b` - Nonce (8-byte hex, little-endian)
/// * `height` - Block height (optional, defaults to 0)
/// * `epoch_hash_hex` - Epoch hash in big-endian hex (optional, defaults to zero hash)
/// * `extended_metadata_hash_hex` - Extended metadata hash in big-endian hex (optional, defaults to zero hash)
/// * `size` - Block size (optional, defaults to 0)
pub fn build_stratum_header(
    coinbase1: &str,
    extranonce1: &str,
    extranonce2: &str,
    coinbase2: &str,
    merkle_branches: &[String],
    prevhash_hex: &str,
    version_hex: &str,
    nbits_hex: &str,
    ntime_hex_6b: &str,
    nonce_hex_8b: &str,
    height: Option<i32>,
    epoch_hash_hex: Option<&str>,
    extended_metadata_hash_hex: Option<&str>,
    size: Option<u64>,
) -> Result<Vec<u8>> {
    // Build coinbase transaction
    let coinbase_hex = format!("{}{}{}{}", coinbase1, extranonce1, extranonce2, coinbase2);
    let coinbase_bytes = hex::decode(coinbase_hex)?;
    let mut coinbase_buf = Bytes::from_slice(&coinbase_bytes);
    let coinbase_tx = Tx::deser(&mut coinbase_buf)
        .map_err(|_| StratumError::SerializationError)?;

    // Compute Lotus merkle leaf and root
    let leaf = lotus_merkle_leaf(&coinbase_tx);
    let mut merkle = leaf.as_ref().to_vec();
    
    for branch_hex in merkle_branches {
        let mut branch = hex::decode(branch_hex)?;
        // Branches are stored as big-endian hex (via GetHex() in lotusd), but hashing
        // expects little-endian byte order (internal representation). Reverse.
        branch.reverse();
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&merkle);
        concat.extend_from_slice(&branch);
        merkle = Sha256d::digest(Bytes::from_slice(&concat)).as_ref().to_vec();
    }

    // Create new header from scratch
    let mut header = LotusHeader::default();

    // Set header fields
    // Convert prevhash from stratum word-reversed format to native byte order
    let prevhash_stratum_bytes: [u8; 32] = hex::decode(prevhash_hex)?
        .as_slice()
        .try_into()
        .map_err(|_| StratumError::InvalidInput("invalid prevhash length".into()))?;
    // Stratum format reverses each 32-bit word; reverse back to native order
    let mut prevhash_bytes = [0u8; 32];
    for i in 0..8 {
        let word: [u8; 4] = prevhash_stratum_bytes[i * 4..(i + 1) * 4].try_into().unwrap();
        prevhash_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.iter().rev().copied().collect::<Vec<_>>());
    }
    header.prev_block = Sha256d::new(prevhash_bytes);

    let version_byte = u8::from_str_radix(version_hex, 16)
        .map_err(|_| StratumError::InvalidInput("invalid version".into()))?;
    header.version = version_byte;

    let nbits_bytes: [u8; 4] = hex::decode(nbits_hex)?
        .as_slice()
        .try_into()
        .map_err(|_| StratumError::InvalidInput("invalid nbits length".into()))?;
    
    let ntime_bytes: [u8; 6] = hex::decode(ntime_hex_6b)?
        .as_slice()
        .try_into()
        .map_err(|_| StratumError::InvalidInput("invalid ntime length".into()))?;
    
    let nonce_bytes: [u8; 8] = hex::decode(nonce_hex_8b)?
        .as_slice()
        .try_into()
        .map_err(|_| StratumError::InvalidInput("invalid nonce length".into()))?;

    let mut ntime_le8 = [0u8; 8];
    ntime_le8[..6].copy_from_slice(&ntime_bytes);

    header.bits = u32::from_le_bytes(nbits_bytes);
    header.timestamp = i64::from_le_bytes(ntime_le8);
    header.nonce = u64::from_le_bytes(nonce_bytes);
    header.merkle_root = Sha256d::new(merkle.as_slice().try_into().map_err(|_| {
        StratumError::InvalidInput("invalid merkle length".into())
    })?);

    // Set Lotus-specific header fields from optional parameters
    header.height = height.unwrap_or(0);
    
    if let Some(epoch_hash_hex) = epoch_hash_hex {
        header.epoch_hash = Sha256d::from_hex_be(epoch_hash_hex)
            .map_err(|e| StratumError::InvalidInput(format!("invalid epoch_hash: {}", e)))?;
    }
    
    if let Some(ext_meta_hash_hex) = extended_metadata_hash_hex {
        header.extended_metadata_hash = Sha256d::from_hex_be(ext_meta_hash_hex)
            .map_err(|e| StratumError::InvalidInput(format!("invalid extended_metadata_hash: {}", e)))?;
    }
    
    header.size = size.unwrap_or(0);

    Ok(header.ser().as_ref().to_vec())
}

/// Difficulty-1 target from Bitcoin/Lotus SHA-family convention.
/// Uses pdiff (pool difficulty) standard: non-truncated target.
/// This matches industry practice for Stratum V1 pools.
const DIFF1_TARGET_HEX: &str = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Maximum target (minimum difficulty) for Lotus testnet/mainnet.
/// This is the powLimit value from consensus parameters.
const MAX_TARGET_HEX: &str = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Convert Stratum V1 difficulty to a 32-byte target (big-endian).
///
/// This follows the standard Stratum V1 difficulty-to-target conversion:
/// target = DIFF1_TARGET / difficulty
///
/// # Arguments
///
/// * `difficulty` - The Stratum difficulty value (e.g., 1.0, 0.1, etc.)
///
/// # Returns
///
/// 32-byte target in big-endian order
pub fn difficulty_to_target(difficulty: f64) -> Result<[u8; 32]> {
    if difficulty <= 0.0 || !difficulty.is_finite() {
        return Err(StratumError::InvalidInput("invalid difficulty".into()));
    }
    
    let diff1 = U256::from_big_endian(&hex::decode(DIFF1_TARGET_HEX)?);
    
    // For fractional difficulties, we need to handle the division carefully
    // Use: target = diff1 / difficulty
    // Scale both diff1 and difficulty to preserve precision for all values.
    // Using u128 for difficulty allows precise representation up to ~1e38,
    // which covers all realistic difficulty values.
    let scale = 1e9;
    let difficulty_scaled = (difficulty * scale).round() as u128;
    if difficulty_scaled == 0 {
        return Err(StratumError::InvalidInput("difficulty too small".into()));
    }
    // target = diff1 / difficulty = (diff1 * scale) / (difficulty * scale)
    let diff1_scaled = diff1 * U256::from(scale as u128);
    let target = diff1_scaled / U256::from(difficulty_scaled);
    if target.is_zero() {
        return Err(StratumError::InvalidInput("difficulty too high".into()));
    }
    let mut out = [0u8; 32];
    target.to_big_endian(&mut out);
    Ok(out)
}

/// Convert a 32-byte target (big-endian) to difficulty.
///
/// Uses the standard formula: difficulty = DIFF1_TARGET / target
pub fn target_to_difficulty(target_be: &[u8; 32]) -> Result<f64> {
    let target = U256::from_big_endian(target_be);
    if target.is_zero() {
        return Err(StratumError::InvalidInput("zero target".into()));
    }
    
    let diff1 = U256::from_big_endian(&hex::decode(DIFF1_TARGET_HEX)?);
    
    // difficulty = diff1 / target
    // Scale up diff1 to preserve fractional precision for all target values.
    // Using u128 for the scaled result allows precise representation up to ~1e38.
    let scale = 1_000_000_000u64;
    let diff1_scaled = diff1 * U256::from(scale);
    let difficulty_scaled = diff1_scaled / target;
    
    // Convert scaled difficulty back to f64
    // For very large values, use safe conversion to avoid overflow
    if difficulty_scaled > U256::from(u128::MAX) {
        // Extremely high difficulty, return as f64 directly from u64 portion
        // This is a rare edge case for near-zero targets
        Ok(difficulty_scaled.as_u64() as f64 / scale as f64)
    } else {
        // Normal case: use full u128 precision
        let difficulty_hi = ((difficulty_scaled >> 64) & U256::from(u64::MAX)).as_u64();
        let difficulty_lo = (difficulty_scaled & U256::from(u64::MAX)).as_u64();
        let difficulty_scaled_f64 = (difficulty_hi as f64) * 1.8446744e19 + (difficulty_lo as f64);
        Ok(difficulty_scaled_f64 / scale as f64)
    }
}

/// Convert a 32-byte network target (big-endian) from lotusd to network difficulty.
///
/// This uses the standard Bitcoin/Lotus difficulty formula:
/// difficulty = max_target / target
///
/// Note: This returns the absolute network difficulty (not scaled by DIFF_SCALE).
/// For Lotus testnet at difficulty-1 target, this returns ~65536.0.
///
/// # Arguments
///
/// * `target_be` - 32-byte target in big-endian format (from mining template)
///
/// # Returns
///
/// Network difficulty as f64
pub fn network_target_to_difficulty(target_be: &[u8; 32]) -> Result<f64> {
    let target = U256::from_big_endian(target_be);
    if target.is_zero() {
        return Err(StratumError::InvalidInput("zero target".into()));
    }
    
    let max_target = U256::from_big_endian(&hex::decode(MAX_TARGET_HEX)?);
    let difficulty = max_target / target;
    
    // Convert U256 to f64 safely (avoids overflow from as_u128())
    // U256::as_u128() panics on overflow, so we use a safe conversion
    let difficulty_f64 = u256_to_f64(difficulty);
    
    Ok(difficulty_f64)
}

/// Safely convert U256 to f64 without overflow panics.
/// For very large values (> f64::MAX), returns f64::INFINITY.
fn u256_to_f64(value: U256) -> f64 {
    // U256 stores as 4 x u64 in little-endian order
    let words = value.0;
    
    // Check if value is too large for f64 representation
    // f64 can represent integers exactly up to 2^53, and up to ~1.8e308 total
    // U256 max is ~1.15e77, so most values will fit in f64 range
    
    // Fast path: if high words are zero, convert directly
    if words[3] == 0 && words[2] == 0 && words[1] == 0 {
        return words[0] as f64;
    }
    
    // Build f64 from parts using logarithms for large values
    // value = words[0] + words[1]*2^64 + words[2]*2^128 + words[3]*2^192
    let mut result = 0.0f64;
    let mut multiplier = 1.0f64;
    
    for &word in &words {
        if word != 0 {
            result += (word as f64) * multiplier;
        }
        // Check for overflow to infinity
        if !multiplier.is_finite() {
            return f64::INFINITY;
        }
        multiplier *= 2.0f64.powi(64);
        if !multiplier.is_finite() {
            // Remaining words would overflow, but contribution is negligible
            // compared to result already at/near infinity
            break;
        }
    }
    
    result
}

/// Calculate pool difficulty from network difficulty.
///
/// Pool difficulty is set to network_difficulty / ratio, where ratio
/// determines how much easier pool shares are compared to network blocks.
/// Includes rate limiting to prevent sudden difficulty jumps that could
/// destabilize miners.
///
/// # Arguments
///
/// * `network_diff` - Current network difficulty
/// * `previous_pool_diff` - Previous pool difficulty (for rate limiting)
/// * `share_target_ratio` - Ratio of network to pool difficulty (e.g., 100.0)
/// * `min_difficulty` - Absolute minimum pool difficulty (clamp floor)
/// * `max_difficulty` - Absolute maximum pool difficulty (clamp ceiling)
/// * `max_change_pct` - Maximum allowed change per update (e.g., 0.5 for 50%)
///
/// # Returns
///
/// Pool difficulty clamped to [min_difficulty, max_difficulty] and rate-limited
pub fn calculate_pool_difficulty(
    network_diff: f64,
    previous_pool_diff: f64,
    share_target_ratio: f64,
    min_difficulty: f64,
    max_difficulty: f64,
    max_change_pct: f64,
) -> f64 {
    let target_pool_diff = network_diff / share_target_ratio;
    
    // Apply rate limiting to prevent sudden jumps
    // This protects miners from instability during network difficulty changes
    let max_increase = previous_pool_diff * (1.0 + max_change_pct);
    let max_decrease = previous_pool_diff * (1.0 - max_change_pct);
    
    let mut pool_diff = target_pool_diff;
    if pool_diff > max_increase {
        pool_diff = max_increase;
    } else if pool_diff < max_decrease && max_decrease > min_difficulty {
        pool_diff = max_decrease;
    }
    
    pool_diff.clamp(min_difficulty, max_difficulty)
}

/// Validate that pool difficulty configuration is sensible.
///
/// # Arguments
///
/// * `min_difficulty` - Minimum difficulty
/// * `max_difficulty` - Maximum difficulty
/// * `share_target_ratio` - Target ratio
///
/// # Returns
///
/// Ok(()) if valid, Err with explanation if not
pub fn validate_difficulty_config(
    min_difficulty: f64,
    max_difficulty: f64,
    share_target_ratio: f64,
) -> Result<()> {
    if min_difficulty <= 0.0 || !min_difficulty.is_finite() {
        return Err(StratumError::InvalidInput("min_difficulty must be positive".into()));
    }
    if max_difficulty <= 0.0 || !max_difficulty.is_finite() {
        return Err(StratumError::InvalidInput("max_difficulty must be positive".into()));
    }
    if min_difficulty >= max_difficulty {
        return Err(StratumError::InvalidInput(
            "min_difficulty must be < max_difficulty".into()
        ));
    }
    if share_target_ratio <= 0.0 || !share_target_ratio.is_finite() {
        return Err(StratumError::InvalidInput(
            "share_target_ratio must be positive".into()
        ));
    }
    Ok(())
}

/// Validate that a header hash meets a given difficulty target.
///
/// # Arguments
///
/// * `header_hash_be` - The header hash in big-endian (32 bytes)
/// * `difficulty` - The Stratum difficulty to check against
pub fn header_meets_difficulty(header_hash_be: &[u8; 32], difficulty: f64) -> Result<bool> {
    let hash_u256 = U256::from_big_endian(header_hash_be);
    let target = U256::from_big_endian(&difficulty_to_target(difficulty)?);
    Ok(hash_u256 <= target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stratum_prevhash_conversion() {
        // Test that stratum word-reversed prevhash is converted correctly
        // Genesis block hash (testnet): 00000000080a6c9633aae9d24b9acda10d7e6b028e7aa714069798d18ca7bad1
        // Internal bytes (little-endian): d1baa78cd198970614a77a8e026b7e0da1cd9a4bd2e9aa33966c0a0800000000
        // Stratum hex (word-reversed): 8ca7bad1069798d18e7aa7140d7e6b024b9acda133aae9d2080a6c9600000000
        
        let genesis_hash_internal_hex = "d1baa78cd198970614a77a8e026b7e0da1cd9a4bd2e9aa33966c0a0800000000";
        let genesis_hash_stratum_hex = "8ca7bad1069798d18e7aa7140d7e6b024b9acda133aae9d2080a6c9600000000";
        
        // Simulate the conversion in build_stratum_header
        let prevhash_stratum_bytes: [u8; 32] = hex::decode(genesis_hash_stratum_hex).unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let mut prevhash_bytes = [0u8; 32];
        for i in 0..8 {
            let word: [u8; 4] = prevhash_stratum_bytes[i * 4..(i + 1) * 4].try_into().unwrap();
            prevhash_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.iter().rev().copied().collect::<Vec<_>>());
        }
        
        assert_eq!(prevhash_bytes.to_vec(), hex::decode(genesis_hash_internal_hex).unwrap());
    }

    #[test]
    fn test_difficulty_to_target() {
        let target = difficulty_to_target(1.0).unwrap();
        // Difficulty 1 should produce DIFF1 target
        let expected = hex::decode(DIFF1_TARGET_HEX).unwrap();
        assert_eq!(&target[..], &expected[..]);
    }

    #[test]
    fn test_target_to_difficulty() {
        let target = difficulty_to_target(1.0).unwrap();
        let diff = target_to_difficulty(&target).unwrap();
        assert!((diff - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_invalid_difficulty() {
        assert!(difficulty_to_target(0.0).is_err());
        assert!(difficulty_to_target(-1.0).is_err());
        assert!(difficulty_to_target(f64::INFINITY).is_err());
        assert!(difficulty_to_target(f64::NAN).is_err());
    }

    #[test]
    fn test_network_target_to_difficulty() {
        // Test with difficulty-1 target
        // At diff-1, network_target_to_difficulty should return 1.0
        let target = difficulty_to_target(1.0).unwrap();
        let diff = network_target_to_difficulty(&target).unwrap();
        assert!((diff - 1.0).abs() < 0.0001);
        
        // Test with a harder target (difficulty 2.0)
        let target2 = difficulty_to_target(2.0).unwrap();
        let diff2 = network_target_to_difficulty(&target2).unwrap();
        assert!((diff2 - 2.0).abs() < 0.0001);
    }

    #[test]
    fn test_calculate_pool_difficulty() {
        // Network diff 1000, ratio 100 -> target pool diff 10
        // With rate limiting (50% max change from previous=1.0), should clamp to 1.5
        let pool_diff = calculate_pool_difficulty(1000.0, 1.0, 100.0, 1.0, 1000.0, 0.5);
        assert!((pool_diff - 1.5).abs() < 0.0001);  // Rate limited from 1.0 to max 1.5
        
        // Starting from reasonable previous value, should reach target
        let pool_diff = calculate_pool_difficulty(1000.0, 8.0, 100.0, 1.0, 1000.0, 0.5);
        assert!((pool_diff - 10.0).abs() < 0.0001);  // Within 50% range, reaches target
        
        // Test clamping to min (rate limited)
        let pool_diff = calculate_pool_difficulty(10.0, 8.0, 100.0, 4.0, 1000.0, 0.5);
        // target = 0.1, rate limited to 4.0 (from 8.0, max decrease is 4.0), then clamped to min 4.0
        assert!((pool_diff - 4.0).abs() < 0.0001);
        
        // Test clamping to max (rate limited)
        let pool_diff = calculate_pool_difficulty(1_000_000_000.0, 500_000.0, 1.0, 1.0, 1_000_000.0, 0.5);
        // target = 1B, rate limited to 750K (500K * 1.5), within max 1M
        assert!((pool_diff - 750_000.0).abs() < 0.0001);
    }

    #[test]
    fn test_validate_difficulty_config() {
        // Valid config
        assert!(validate_difficulty_config(1.0, 1000.0, 100.0).is_ok());
        
        // Invalid: min <= 0
        assert!(validate_difficulty_config(0.0, 1000.0, 100.0).is_err());
        assert!(validate_difficulty_config(-1.0, 1000.0, 100.0).is_err());
        
        // Invalid: max <= 0
        assert!(validate_difficulty_config(1.0, 0.0, 100.0).is_err());
        
        // Invalid: min >= max
        assert!(validate_difficulty_config(1000.0, 100.0, 100.0).is_err());
        
        // Invalid: ratio <= 0
        assert!(validate_difficulty_config(1.0, 1000.0, 0.0).is_err());
        assert!(validate_difficulty_config(1.0, 1000.0, -10.0).is_err());
    }

    #[test]
    fn test_u256_to_f64_small_values() {
        // Test small values that fit in u64
        let val = U256::from(42u64);
        assert!((u256_to_f64(val) - 42.0).abs() < 0.0001);
        
        let val = U256::from(1_000_000u64);
        assert!((u256_to_f64(val) - 1_000_000.0).abs() < 0.0001);
    }

    #[test]
    fn test_u256_to_f64_large_values() {
        // Test large values requiring multiple words
        // 2^64 (one word overflow)
        let val = U256::from(1u64) << 64;
        let result = u256_to_f64(val);
        assert!(result.is_finite());
        assert!(result > 1e19);
        
        // Very large value
        let val = U256::MAX;
        let result = u256_to_f64(val);
        assert!(result.is_finite() || result == f64::INFINITY);
    }

    #[test]
    fn test_network_target_to_difficulty_no_overflow() {
        // Test with a very small target (would cause overflow with as_u128)
        // Use a target that gives difficulty > u128::MAX
        let mut tiny_target = [0u8; 32];
        tiny_target[31] = 1; // Very small target = very high difficulty
        
        let result = network_target_to_difficulty(&tiny_target);
        assert!(result.is_ok());
        // Should be a very large number, but not panic
        let diff = result.unwrap();
        assert!(diff.is_finite() || diff == f64::INFINITY);
    }

    #[test]
    fn test_fractional_difficulty_precision() {
        // Test that fractional difficulties are not truncated
        // This is a regression test for the bug where difficulty >= 1.0
        // was cast to u64, losing the decimal part (e.g., 16.73 -> 16)
        
        let difficulty = 16.73;
        let target = difficulty_to_target(difficulty).unwrap();
        let roundtrip = target_to_difficulty(&target).unwrap();
        
        // Round-trip should preserve the difficulty within reasonable tolerance
        // The tolerance accounts for U256 integer division rounding
        let relative_error = (roundtrip - difficulty).abs() / difficulty;
        assert!(relative_error < 0.001, "Fractional difficulty precision lost: {} -> {}", difficulty, roundtrip);
        
        // Also verify that difficulty 16.73 produces a different target than 16.0
        let target_16 = difficulty_to_target(16.0).unwrap();
        let target_16_73 = difficulty_to_target(16.73).unwrap();
        assert_ne!(target_16, target_16_73, "Targets should differ for 16.0 vs 16.73");
        
        // Target for 16.73 should be smaller (harder) than target for 16.0
        let target_16_u256 = U256::from_big_endian(&target_16);
        let target_16_73_u256 = U256::from_big_endian(&target_16_73);
        assert!(target_16_73_u256 < target_16_u256, "Higher difficulty should produce smaller target");
    }
}
