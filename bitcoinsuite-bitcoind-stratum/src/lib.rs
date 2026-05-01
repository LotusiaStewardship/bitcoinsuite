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
        let branch = hex::decode(branch_hex)?;
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

    Ok(header.ser().as_ref().to_vec())
}

/// Difficulty-1 target from Bitcoin/Lotus SHA-family convention.
const DIFF1_TARGET_HEX: &str = "00000000ffff0000000000000000000000000000000000000000000000000000";
const DIFF_SCALE: u128 = 100_000_000;

/// Maximum target (minimum difficulty) for Lotus testnet/mainnet.
/// This is the powLimit value from consensus parameters.
const MAX_TARGET_HEX: &str = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Convert Stratum V1 difficulty to a 32-byte target (big-endian).
///
/// This follows the standard Stratum V1 difficulty-to-target conversion:
/// target = (DIFF1_TARGET * DIFF_SCALE) / (difficulty * DIFF_SCALE)
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
    
    let scaled = (difficulty * DIFF_SCALE as f64).round() as u128;
    if scaled == 0 {
        return Err(StratumError::InvalidInput("invalid difficulty scale".into()));
    }
    
    let scaled_u = U256::from(scaled);
    let diff1 = U256::from_big_endian(&hex::decode(DIFF1_TARGET_HEX)?);
    let scaled_diff1 = diff1 * U256::from(DIFF_SCALE);
    let mut target = scaled_diff1 / scaled_u;
    
    if target.is_zero() {
        target = U256::one();
    }
    
    let mut out = [0u8; 32];
    target.to_big_endian(&mut out);
    Ok(out)
}

/// Convert a 32-byte target (big-endian) to difficulty.
pub fn target_to_difficulty(target_be: &[u8; 32]) -> Result<f64> {
    let target = U256::from_big_endian(target_be);
    if target.is_zero() {
        return Err(StratumError::InvalidInput("zero target".into()));
    }
    
    let diff1 = U256::from_big_endian(&hex::decode(DIFF1_TARGET_HEX)?);
    let scaled_diff1 = diff1 * U256::from(DIFF_SCALE);
    let difficulty = scaled_diff1 / target;
    
    Ok(difficulty.as_u128() as f64 / DIFF_SCALE as f64)
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
    
    // Return raw ratio as f64 (no DIFF_SCALE division)
    Ok(difficulty.as_u128() as f64)
}

/// Calculate pool difficulty from network difficulty.
///
/// Pool difficulty is set to network_difficulty / ratio, where ratio
/// determines how much easier pool shares are compared to network blocks.
///
/// # Arguments
///
/// * `network_diff` - Current network difficulty
/// * `share_target_ratio` - Ratio of network to pool difficulty (e.g., 100.0)
/// * `min_difficulty` - Absolute minimum pool difficulty (clamp floor)
/// * `max_difficulty` - Absolute maximum pool difficulty (clamp ceiling)
///
/// # Returns
///
/// Pool difficulty clamped to [min_difficulty, max_difficulty]
pub fn calculate_pool_difficulty(
    network_diff: f64,
    share_target_ratio: f64,
    min_difficulty: f64,
    max_difficulty: f64,
) -> f64 {
    let pool_diff = network_diff / share_target_ratio;
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
        // Network diff 1000, ratio 100 -> pool diff 10
        let pool_diff = calculate_pool_difficulty(1000.0, 100.0, 1.0, 1000.0);
        assert!((pool_diff - 10.0).abs() < 0.0001);
        
        // Test clamping to min
        let pool_diff = calculate_pool_difficulty(10.0, 100.0, 4.0, 1000.0);
        assert!((pool_diff - 4.0).abs() < 0.0001); // 0.1 clamped to 4.0
        
        // Test clamping to max
        let pool_diff = calculate_pool_difficulty(1_000_000_000.0, 1.0, 1.0, 1_000_000.0);
        assert!((pool_diff - 1_000_000.0).abs() < 0.0001);
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
}
