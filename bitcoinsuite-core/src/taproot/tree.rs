use crate::{
    ecc::{Ecc, PubKey, PUBKEY_LENGTH},
    taproot::{
        hash::{tap_branch_hash, tap_leaf_hash, tap_tweak_hash},
        TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_MAX_NODE_COUNT, TAPROOT_CONTROL_MAX_SIZE,
        TAPROOT_CONTROL_NODE_SIZE, TAPROOT_LEAF_MASK,
    },
    Script,
};

/// A leaf node in the Taproot script tree.
#[derive(Debug, Clone)]
pub struct TapLeafNode {
    pub script: Script,
    pub leaf_version: u8,
}

/// A branch node in the Taproot script tree.
#[derive(Debug, Clone)]
pub struct TapBranchNode {
    pub left: TapNode,
    pub right: TapNode,
}

/// A node in the Taproot script tree.
#[derive(Debug, Clone)]
pub enum TapNode {
    Leaf(TapLeafNode),
    Branch(Box<TapBranchNode>),
}

/// An individual leaf with its computed hash and Merkle path.
#[derive(Debug, Clone)]
pub struct TapLeaf {
    pub script: Script,
    pub leaf_version: u8,
    pub leaf_hash: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
}

/// Result of building a Taproot tree.
#[derive(Debug, Clone)]
pub struct TapTreeBuildResult {
    pub merkle_root: [u8; 32],
    pub leaves: Vec<TapLeaf>,
}

/// Build a Taproot script tree from a root node.
///
/// Returns the Merkle root and all leaves with their Merkle paths.
pub fn build_tap_tree(tree: &TapNode) -> TapTreeBuildResult {
    match tree {
        TapNode::Leaf(leaf) => {
            let script_bytes = leaf.script.bytecode();
            let leaf_hash = tap_leaf_hash(script_bytes, leaf.leaf_version);
            TapTreeBuildResult {
                merkle_root: leaf_hash,
                leaves: vec![TapLeaf {
                    script: leaf.script.clone(),
                    leaf_version: leaf.leaf_version,
                    leaf_hash,
                    merkle_path: vec![],
                }],
            }
        }
        TapNode::Branch(branch) => {
            let left_result = build_tap_tree(&branch.left);
            let right_result = build_tap_tree(&branch.right);
            let branch_hash = tap_branch_hash(&left_result.merkle_root, &right_result.merkle_root);

            // Add the right merkle root to left leaves' paths
            let left_leaves: Vec<TapLeaf> = left_result
                .leaves
                .into_iter()
                .map(|mut leaf| {
                    leaf.merkle_path.push(right_result.merkle_root);
                    leaf
                })
                .collect();

            // Add the left merkle root to right leaves' paths
            let right_leaves: Vec<TapLeaf> = right_result
                .leaves
                .into_iter()
                .map(|mut leaf| {
                    leaf.merkle_path.push(left_result.merkle_root);
                    leaf
                })
                .collect();

            TapTreeBuildResult {
                merkle_root: branch_hash,
                leaves: [left_leaves, right_leaves].concat(),
            }
        }
    }
}

/// Create a Taproot control block.
///
/// Format: `[control_byte][32-byte x-coord][merkle_path...]`
/// The control byte encodes: `(leaf_version & 0xFE) | parity_bit`
/// where parity_bit is 0 for even Y (prefix 0x02), 1 for odd Y (prefix 0x03).
pub fn create_control_block(
    internal_pubkey: &PubKey,
    leaf_index: usize,
    tree: &TapNode,
) -> Result<Vec<u8>, &'static str> {
    let tree_result = build_tap_tree(tree);

    if leaf_index >= tree_result.leaves.len() {
        return Err("Invalid leaf index");
    }

    let leaf = &tree_result.leaves[leaf_index];
    let pubkey_bytes = internal_pubkey.as_slice();

    // Parity bit from pubkey prefix: 0x02 = even, 0x03 = odd
    let parity = if pubkey_bytes[0] == 0x03 { 1u8 } else { 0u8 };
    let control_byte = (leaf.leaf_version & TAPROOT_LEAF_MASK) | parity;

    let mut result = Vec::with_capacity(
        TAPROOT_CONTROL_BASE_SIZE + leaf.merkle_path.len() * TAPROOT_CONTROL_NODE_SIZE,
    );
    result.push(control_byte);
    // Next 32 bytes: X-coordinate only (skip the 1-byte prefix)
    result.extend_from_slice(&pubkey_bytes[1..PUBKEY_LENGTH]);

    // Merkle path
    for node in &leaf.merkle_path {
        result.extend_from_slice(node);
    }

    Ok(result)
}

/// Result of verifying a Taproot commitment.
#[derive(Debug)]
pub struct TaprootCommitmentResult {
    pub tapleaf_hash: [u8; 32],
    pub success: bool,
}

/// Verify that a script is committed to in a Taproot output via a control block.
///
/// Returns the computed tapleaf hash and whether verification succeeded.
pub fn verify_taproot_commitment(
    ecc: &dyn Ecc,
    control_block: &[u8],
    commitment_pubkey: &[u8; PUBKEY_LENGTH],
    script: &Script,
) -> TaprootCommitmentResult {
    let zero_hash = [0u8; 32];

    // Validate control block size
    if control_block.len() < TAPROOT_CONTROL_BASE_SIZE
        || control_block.len() > TAPROOT_CONTROL_MAX_SIZE
    {
        return TaprootCommitmentResult {
            tapleaf_hash: zero_hash,
            success: false,
        };
    }

    let size_remainder =
        (control_block.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE;
    if size_remainder != 0 {
        return TaprootCommitmentResult {
            tapleaf_hash: zero_hash,
            success: false,
        };
    }

    let path_len = (control_block.len() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    if path_len > TAPROOT_CONTROL_MAX_NODE_COUNT {
        return TaprootCommitmentResult {
            tapleaf_hash: zero_hash,
            success: false,
        };
    }

    // Calculate leaf hash
    let leaf_version = control_block[0] & TAPROOT_LEAF_MASK;
    let leaf_hash = tap_leaf_hash(script.bytecode(), leaf_version);
    let mut merkle_hash = leaf_hash;

    // Process merkle path nodes
    for i in 0..path_len {
        let node_offset = TAPROOT_CONTROL_BASE_SIZE + i * TAPROOT_CONTROL_NODE_SIZE;
        let node: &[u8; 32] = control_block[node_offset..node_offset + TAPROOT_CONTROL_NODE_SIZE]
            .try_into()
            .unwrap();
        merkle_hash = tap_branch_hash(&merkle_hash, node);
    }

    // Extract internal pubkey from control block (32-byte x-coord + parity bit)
    let parity = control_block[0] & 0x01;
    let prefix = if parity == 1 { 0x03u8 } else { 0x02u8 };

    let mut pubkey_bytes = [0u8; PUBKEY_LENGTH];
    pubkey_bytes[0] = prefix;
    pubkey_bytes[1..].copy_from_slice(&control_block[1..TAPROOT_CONTROL_BASE_SIZE]);

    // Verify: internal_pubkey + tweak*G == commitment
    let tweak_hash = tap_tweak_hash(&PubKey::new_unchecked(pubkey_bytes), &merkle_hash);

    let success = match ecc.tweak_pubkey(&PubKey::new_unchecked(pubkey_bytes), &tweak_hash) {
        Ok(tweaked) => tweaked.as_slice() == commitment_pubkey.as_ref(),
        Err(_) => false,
    };

    TaprootCommitmentResult {
        tapleaf_hash: leaf_hash,
        success,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Script, ecc::PubKey, taproot::TAPROOT_LEAF_TAPSCRIPT};

    #[test]
    fn test_build_tap_tree_single_leaf() {
        let leaf = TapNode::Leaf(TapLeafNode {
            script: Script::from_slice(&[0x51]), // OP_1
            leaf_version: TAPROOT_LEAF_TAPSCRIPT,
        });
        let result = build_tap_tree(&leaf);
        assert_eq!(result.leaves.len(), 1);
        assert_eq!(result.leaves[0].merkle_path.len(), 0);
        assert_eq!(result.leaves[0].leaf_version, TAPROOT_LEAF_TAPSCRIPT);
    }

    #[test]
    fn test_build_tap_tree_two_leaves() {
        let left = TapNode::Leaf(TapLeafNode {
            script: Script::from_slice(&[0x51]),
            leaf_version: TAPROOT_LEAF_TAPSCRIPT,
        });
        let right = TapNode::Leaf(TapLeafNode {
            script: Script::from_slice(&[0x52]),
            leaf_version: TAPROOT_LEAF_TAPSCRIPT,
        });
        let branch = TapNode::Branch(Box::new(TapBranchNode {
            left,
            right,
        }));
        let result = build_tap_tree(&branch);
        assert_eq!(result.leaves.len(), 2);
        // Each leaf should have one merkle path entry (the other sibling)
        assert_eq!(result.leaves[0].merkle_path.len(), 1);
        assert_eq!(result.leaves[1].merkle_path.len(), 1);
    }

    #[test]
    fn test_create_control_block() {
        let leaf = TapNode::Leaf(TapLeafNode {
            script: Script::from_slice(&[0x51]),
            leaf_version: TAPROOT_LEAF_TAPSCRIPT,
        });
        let pubkey = PubKey::new_unchecked([0x02u8; PUBKEY_LENGTH]);
        let control_block = create_control_block(&pubkey, 0, &leaf).unwrap();
        // Base size (33) + 0 merkle path nodes = 33 bytes
        assert_eq!(control_block.len(), TAPROOT_CONTROL_BASE_SIZE);
        // Control byte: leaf_version (0xc0) & 0xFE = 0xc0 | parity (0 for 0x02 prefix) = 0xc0
        assert_eq!(control_block[0], 0xc0);
        // Next 32 bytes: x-coordinate (all 0x02 except first byte which was prefix)
        assert_eq!(&control_block[1..], &[0x02u8; 32]);
    }

    #[test]
    fn test_create_control_block_odd_parity() {
        let leaf = TapNode::Leaf(TapLeafNode {
            script: Script::from_slice(&[0x51]),
            leaf_version: TAPROOT_LEAF_TAPSCRIPT,
        });
        let pubkey = PubKey::new_unchecked([0x03u8; PUBKEY_LENGTH]);
        let control_block = create_control_block(&pubkey, 0, &leaf).unwrap();
        // parity bit set: 0xc0 | 0x01 = 0xc1
        assert_eq!(control_block[0], 0xc1);
    }
}
