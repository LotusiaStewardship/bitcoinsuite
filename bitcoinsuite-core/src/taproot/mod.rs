mod hash;
mod tree;

pub use hash::*;
pub use tree::*;

// Leaf version constants
/// Mask for extracting leaf version from control block first byte (clears parity bit)
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// Default leaf version for tapscript (0xc0)
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

// Control block sizing
/// Base size of control block: 1 byte control + 32 bytes internal pubkey X-coordinate
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// Size of each Merkle path node in control block
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// Maximum number of Merkle path nodes allowed in control block
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
/// Maximum control block size: base + max nodes (33 + 32 * 128 = 4129 bytes)
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

// Script sizing
/// P2TR script intro size: OP_SCRIPTTYPE + OP_1 + push_33 (3 bytes)
pub const TAPROOT_INTRO_SIZE: usize = 3;
/// P2TR output without state: intro (3) + pubkey (33) = 36 bytes
pub const TAPROOT_SIZE_WITHOUT_STATE: usize = TAPROOT_INTRO_SIZE + crate::ecc::PUBKEY_LENGTH;
/// State push byte + 32-byte state
pub const TAPROOT_STATE_SIZE: usize = 33;

// Annex tag
/// Annex tag byte for Taproot witness stack (0x50)
pub const TAPROOT_ANNEX_TAG: u8 = 0x50;

// Sighash flags
pub const SCRIPT_DISABLE_TAPROOT_SIGHASH_LOTUS: u32 = 1 << 22;
pub const SCRIPT_TAPROOT_KEY_SPEND_PATH: u32 = 1 << 23;

use crate::ecc::{Ecc, EccError, PubKey};
use crate::Script;

/// Build a key-path-only Taproot output (no script tree).
///
/// Returns the P2TR output script and the tweaked commitment public key.
pub fn build_key_path_taproot(
    ecc: &dyn Ecc,
    internal_pubkey: &PubKey,
) -> Result<(Script, PubKey), EccError> {
    let merkle_root = [0u8; 32];
    let tweak = tap_tweak_hash(internal_pubkey, &merkle_root);
    let commitment = ecc.tweak_pubkey(internal_pubkey, &tweak)?;
    let script = Script::p2tr(&commitment, None);
    Ok((script, commitment))
}

/// Build a script-path Taproot output.
///
/// Returns the P2TR output script, commitment pubkey, merkle root, and leaf list.
pub fn build_script_path_taproot(
    ecc: &dyn Ecc,
    internal_pubkey: &PubKey,
    tree: &TapNode,
    state: Option<[u8; 32]>,
) -> Result<(Script, PubKey, [u8; 32], Vec<TapLeaf>), EccError> {
    let tree_info = build_tap_tree(tree);
    let tweak = tap_tweak_hash(internal_pubkey, &tree_info.merkle_root);
    let commitment = ecc.tweak_pubkey(internal_pubkey, &tweak)?;
    let script = Script::p2tr(&commitment, state);
    Ok((script, commitment, tree_info.merkle_root, tree_info.leaves))
}

/// Tweak a private key for Taproot spending.
///
/// `tweaked_privkey = (internal_privkey + tweak) mod n`
pub fn tweak_private_key(
    ecc: &dyn Ecc,
    internal_seckey: &crate::ecc::SecKey,
    merkle_root: &[u8; 32],
) -> Result<crate::ecc::SecKey, EccError> {
    let internal_pubkey = ecc.derive_pubkey(internal_seckey);
    let tweak = tap_tweak_hash(&internal_pubkey, merkle_root);
    ecc.tweak_seckey(internal_seckey, &tweak)
}
