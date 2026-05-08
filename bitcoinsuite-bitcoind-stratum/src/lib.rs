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

/// Validate that vardiff minimum floor configuration is sensible.
///
/// # Arguments
///
/// * `vardiff_min_floor` - Absolute minimum difficulty floor (e.g., 0.001)
///
/// # Returns
///
/// Ok(()) if valid, Err with explanation if not
pub fn validate_vardiff_floor(vardiff_min_floor: f64) -> Result<()> {
    if vardiff_min_floor <= 0.0 || !vardiff_min_floor.is_finite() {
        return Err(StratumError::InvalidInput(
            "vardiff_min_floor must be positive".into()
        ));
    }
    Ok(())
}

/// Validate that pool difficulty configuration is sensible.
///
/// DEPRECATED: min_difficulty and max_difficulty are no longer used.
/// Use `validate_vardiff_floor()` instead.
#[deprecated(
    since = "0.2.0",
    note = "Use validate_vardiff_floor() instead. min_difficulty/max_difficulty are no longer used."
)]
pub fn validate_difficulty_config(
    _min_difficulty: f64,
    _max_difficulty: f64,
) -> Result<()> {
    Ok(())  // No-op for backward compatibility
}

/// Calculate pool difficulty from network difficulty.
///
/// DEPRECATED: This function is no longer used in network-aware difficulty mode.
/// Pool difficulty now equals network difficulty directly.
#[deprecated(
    since = "0.2.0",
    note = "Pool difficulty now equals network difficulty. Use network_diff() directly."
)]
pub fn calculate_pool_difficulty(
    network_diff: f64,
    _previous_pool_diff: f64,
    _min_difficulty: f64,
    _max_difficulty: f64,
) -> f64 {
    network_diff  // Return network diff directly for backward compatibility
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
    fn test_validate_vardiff_floor() {
        // Valid floor
        assert!(validate_vardiff_floor(0.001).is_ok());
        assert!(validate_vardiff_floor(1.0).is_ok());
        assert!(validate_vardiff_floor(0.5).is_ok());
        
        // Invalid floors
        assert!(validate_vardiff_floor(0.0).is_err());
        assert!(validate_vardiff_floor(-1.0).is_err());
        assert!(validate_vardiff_floor(f64::INFINITY).is_err());
        assert!(validate_vardiff_floor(f64::NAN).is_err());
    }

    #[test]
    fn test_calculate_pool_difficulty_with_network_target() {
        // Network target: 000000000389f600000000000000000000000000000000000000000000000000
        let network_target_hex = "000000000389f600000000000000000000000000000000000000000000000000";
        let network_target_bytes = hex::decode(network_target_hex).unwrap();
        let network_target: [u8; 32] = network_target_bytes.as_slice().try_into().unwrap();
        
        // Convert network target to difficulty
        let network_diff = target_to_difficulty(&network_target).unwrap();
        
        // Calculate pool difficulty with min=0.1, max=1.0
        #[allow(deprecated)]
        let pool_diff = calculate_pool_difficulty(network_diff, 0.0, 0.1, 1.0);
        
        // Deprecated function now returns network_diff directly
        println!("Network target: {}", network_target_hex);
        println!("Network difficulty: {}", network_diff);
        println!("Pool difficulty (deprecated, returns network_diff): {}", pool_diff);
        
        // Verify pool difficulty equals network_diff (deprecated behavior)
        assert!((pool_diff - network_diff).abs() < 0.0001, "Pool difficulty should equal network_diff in deprecated mode, got {}", pool_diff);
    }
}
