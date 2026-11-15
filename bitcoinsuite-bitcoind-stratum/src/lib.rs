use bitcoinsuite_core::{
    lotus_txid, BitcoinCode, Bytes, BytesMut, Hashed, LotusHeader, Sha256d, Tx,
};
use primitive_types::{U256, U512};
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
    let coinbase_tx = Tx::deser(&mut coinbase_buf).map_err(|_| StratumError::SerializationError)?;

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
        merkle = Sha256d::digest(Bytes::from_slice(&concat))
            .as_ref()
            .to_vec();
    }

    // Create new header from scratch
    let mut header = LotusHeader::default();

    // Set header fields
    // Decode LE-hex prevhash bytes directly into native byte order.
    // Lotus uses little-endian uint256 internally, so the raw hex bytes are
    // already in the correct order for Sha256d.
    let prevhash_bytes: [u8; 32] = hex::decode(prevhash_hex)?
        .as_slice()
        .try_into()
        .map_err(|_| StratumError::InvalidInput("invalid prevhash length".into()))?;
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
    header.merkle_root = Sha256d::new(
        merkle
            .as_slice()
            .try_into()
            .map_err(|_| StratumError::InvalidInput("invalid merkle length".into()))?,
    );

    // Set Lotus-specific header fields from optional parameters
    header.height = height.unwrap_or(0);

    if let Some(epoch_hash_hex) = epoch_hash_hex {
        header.epoch_hash = Sha256d::from_hex_be(epoch_hash_hex)
            .map_err(|e| StratumError::InvalidInput(format!("invalid epoch_hash: {}", e)))?;
    }

    if let Some(ext_meta_hash_hex) = extended_metadata_hash_hex {
        header.extended_metadata_hash = Sha256d::from_hex_be(ext_meta_hash_hex).map_err(|e| {
            StratumError::InvalidInput(format!("invalid extended_metadata_hash: {}", e))
        })?;
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
/// target = floor(DIFF1_TARGET / difficulty)
///
/// The division is exact for every positive finite difficulty: the f64 is
/// split into its integer mantissa and binary exponent and the quotient is
/// computed on 512 bits. Targets above 2^256 - 1 (difficulty below about
/// 2.3e-10) saturate at 2^256 - 1.
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

    let diff1 = U512::from(U256::from_big_endian(&hex::decode(DIFF1_TARGET_HEX)?));

    // difficulty = mantissa * 2^exponent, with an integer mantissa < 2^53.
    let bits = difficulty.to_bits();
    let biased_exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    let (mantissa, exponent) = if biased_exponent == 0 {
        (fraction, -1074) // subnormal
    } else {
        (fraction | (1u64 << 52), biased_exponent - 1075)
    };

    // target = diff1 / difficulty = diff1 * 2^-exponent / mantissa
    let target = if exponent >= 0 {
        // diff1 < 2^224 and mantissa >= 1: any shift past 224 gives 0.
        if exponent > 224 {
            U512::zero()
        } else {
            diff1 / (U512::from(mantissa) << exponent as usize)
        }
    } else {
        let shift = (-exponent) as usize;
        // diff1 << shift must fit in 512 bits; beyond that the target
        // saturates anyway (diff1 << 288 / 2^53 > 2^256).
        if shift > 288 {
            U512::MAX
        } else {
            (diff1 << shift) / U512::from(mantissa)
        }
    };

    let max_target = U512::from(U256::MAX);
    let target = if target > max_target {
        U256::MAX
    } else {
        let mut wide = [0u8; 64];
        target.to_big_endian(&mut wide);
        U256::from_big_endian(&wide[32..])
    };
    if target.is_zero() {
        return Err(StratumError::InvalidInput("difficulty too high".into()));
    }
    let mut out = [0u8; 32];
    target.to_big_endian(&mut out);
    Ok(out)
}

/// Convert a 32-byte target (big-endian) to difficulty.
///
/// Uses the standard formula: difficulty = DIFF1_TARGET / target, computed
/// in f64 (relative error below 1e-15 for every non-zero target).
pub fn target_to_difficulty(target_be: &[u8; 32]) -> Result<f64> {
    let target = U256::from_big_endian(target_be);
    if target.is_zero() {
        return Err(StratumError::InvalidInput("zero target".into()));
    }

    let diff1 = U256::from_big_endian(&hex::decode(DIFF1_TARGET_HEX)?);
    Ok(u256_to_f64(diff1) / u256_to_f64(target))
}

/// Nearest f64 of a U256 (each 64-bit limb is added at its weight).
fn u256_to_f64(value: U256) -> f64 {
    value.0.iter().rev().fold(0f64, |acc, &limb| {
        acc * 18_446_744_073_709_551_616.0 + limb as f64
    })
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
            "vardiff_min_floor must be positive".into(),
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
pub fn validate_difficulty_config(_min_difficulty: f64, _max_difficulty: f64) -> Result<()> {
    Ok(()) // No-op for backward compatibility
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
    network_diff // Return network diff directly for backward compatibility
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
        println!(
            "Pool difficulty (deprecated, returns network_diff): {}",
            pool_diff
        );

        // Verify pool difficulty equals network_diff (deprecated behavior)
        assert!(
            (pool_diff - network_diff).abs() < 0.0001,
            "Pool difficulty should equal network_diff in deprecated mode, got {}",
            pool_diff
        );
    }

    fn diff1() -> U256 {
        U256::from_big_endian(&hex::decode(DIFF1_TARGET_HEX).unwrap())
    }

    fn target(difficulty: f64) -> U256 {
        U256::from_big_endian(&difficulty_to_target(difficulty).unwrap())
    }

    fn be(value: U256) -> [u8; 32] {
        let mut out = [0u8; 32];
        value.to_big_endian(&mut out);
        out
    }

    #[test]
    fn test_difficulty_one_is_diff1() {
        assert_eq!(target(1.0), diff1());
        assert_eq!(target_to_difficulty(&be(diff1())).unwrap(), 1.0);
    }

    #[test]
    fn test_difficulty_to_target_is_exact() {
        for d in [3u64, 7, 1000, 123_456_789, 1 << 40] {
            assert_eq!(target(d as f64), diff1() / U256::from(d));
        }
        assert_eq!(target(0.5), diff1() * 2);
        assert_eq!(target(0.25), diff1() * 4);
        assert_eq!(target(1024.0), diff1() / 1024);
    }

    #[test]
    fn test_regtest_target_round_trip() {
        // Regtest powLimit (nBits 0x207fffff): 0x7fffff << 232. Its
        // difficulty is about 4.66e-10; a 1e9 fixed-point conversion
        // returned 0 here and refused every difficulty below 5e-10.
        let regtest = U256::from(0x7f_ffffu64) << 232;
        let d = target_to_difficulty(&be(regtest)).unwrap();
        assert!(d > 4.65e-10 && d < 4.67e-10, "{d}");
        let back = target(d);
        let diff = if back > regtest {
            back - regtest
        } else {
            regtest - back
        };
        assert!(diff < regtest >> 40, "{back} vs {regtest}");
        // Low difficulties are accepted; the target saturates at 2^256 - 1.
        assert!(!target(3e-10).is_zero());
        assert_eq!(target(1e-12), U256::MAX);
        assert_eq!(target(f64::MIN_POSITIVE), U256::MAX);
        assert_eq!(target(5e-324), U256::MAX);
        assert_eq!(
            target_to_difficulty(&[0xff; 32]).unwrap(),
            1.0 / 4294967296.0
        );
    }

    #[test]
    fn test_difficulty_round_trip_and_monotonic() {
        let mut d = 1e-9;
        let mut previous = U256::MAX;
        while d < 1e15 {
            let t = target(d);
            assert!(t <= previous, "not monotonic at {d}");
            previous = t;
            let back = target_to_difficulty(&be(t)).unwrap();
            assert!(((back - d) / d).abs() < 1e-12, "{d} -> {back}");
            d *= 3.7;
        }
    }

    #[test]
    fn test_difficulty_refusals() {
        for d in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(difficulty_to_target(d).is_err(), "{d}");
        }
        assert!(difficulty_to_target(1e80).is_err());
        assert!(difficulty_to_target(f64::MAX).is_err());
        assert!(target_to_difficulty(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_header_meets_difficulty_boundary() {
        let t = target(1.0);
        assert!(header_meets_difficulty(&be(t), 1.0).unwrap());
        assert!(!header_meets_difficulty(&be(t + 1), 1.0).unwrap());
        // Every hash meets a difficulty whose target saturates.
        assert!(header_meets_difficulty(&[0xff; 32], 1e-12).unwrap());
    }
}
