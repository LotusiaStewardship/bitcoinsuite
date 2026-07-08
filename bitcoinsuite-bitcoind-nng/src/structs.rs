use bitcoinsuite_core::{Coin, Sha256d};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub txid: Sha256d,
    pub raw: Vec<u8>,
    pub spent_coins: Option<Vec<Coin>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub raw: Vec<u8>,
    pub hash: Sha256d,
    pub prev_hash: Sha256d,
    pub n_bits: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub metadata: Vec<BlockMetadata>,
    pub txs: Vec<BlockTx>,
    pub file_num: u32,
    pub data_pos: u32,
    pub undo_pos: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTx {
    pub tx: Tx,
    pub data_pos: u32,
    pub undo_pos: u32,
    pub undo_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolTx {
    pub tx: Tx,
    pub time: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMetadata {
    pub field_id: u32,
    pub field_value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockIdentifier {
    Height(i32),
    Hash(Sha256d),
}

/// Reason code for MiningWorkChanged events.
///
/// Indicates WHY the mining template was invalidated.
/// From lotusd's MiningWorkChangeReason flatbuffer enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MiningWorkChangedReason {
    /// New block connected at tip — template invalid due to prevhash change.
    NewTip,
    /// Chain reorganization — template invalid due to chain switch.
    Reorg,
    /// Mempool changed (tx added/removed) — template invalid due to merkle root / size change.
    MempoolRefresh,
    /// Manual invalidation (e.g., RPC call).
    ManualInvalidation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningWorkChanged {
    /// Why the mining work was invalidated.
    pub reason: MiningWorkChangedReason,
    /// Hash of the current chain tip block (big-endian hex).
    pub block_hash: Sha256d,
    /// Height of the current chain tip.
    pub height: i32,
    /// Unix timestamp when the event was emitted.
    pub node_time: i64,
    /// Monotonically increasing epoch counter from lotusd.
    /// Used to detect missed events (gaps > 1) and for observability.
    pub template_epoch: u64,
}

pub enum Message {
    UpdatedBlockTip(UpdatedBlockTip),
    TransactionAddedToMempool(TransactionAddedToMempool),
    TransactionRemovedFromMempool(TransactionRemovedFromMempool),
    BlockConnected(BlockConnected),
    BlockDisconnected(BlockDisconnected),
    ChainStateFlushed(ChainStateFlushed),
    MiningWorkChanged(MiningWorkChanged),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatedBlockTip {
    pub block_hash: Sha256d,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionAddedToMempool {
    pub mempool_tx: MempoolTx,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRemovedFromMempool {
    pub txid: Sha256d,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockConnected {
    pub block: Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDisconnected {
    pub block: Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainStateFlushed {
    pub block_hash: Sha256d,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mining_work_changed_reason_debug() {
        assert_eq!(format!("{:?}", MiningWorkChangedReason::NewTip), "NewTip");
        assert_eq!(format!("{:?}", MiningWorkChangedReason::Reorg), "Reorg");
        assert_eq!(
            format!("{:?}", MiningWorkChangedReason::MempoolRefresh),
            "MempoolRefresh"
        );
        assert_eq!(
            format!("{:?}", MiningWorkChangedReason::ManualInvalidation),
            "ManualInvalidation"
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningTemplateTx {
    pub raw: Vec<u8>,
    pub txid: Sha256d,
    pub fee: i64,
    pub sigops: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningTemplate {
    pub template_id: u64,
    pub block: Vec<u8>,
    pub header: Vec<u8>,
    pub previous_block_hash: Sha256d,
    pub height: i32,
    pub version: u32,
    pub bits: u32,
    pub target: Sha256d,
    pub curtime: u64,
    pub mintime: u64,
    pub maxtime: u64,
    pub coinbase_value: u64,
    pub coinbase_tx: Vec<u8>,
    pub transactions: Vec<MiningTemplateTx>,
    pub coinbase1: String,
    pub coinbase2: String,
    pub merkle_branches: Vec<String>,
    pub prev_hash_stratum: String,
    pub nbits_stratum: String,
    pub ntime_stratum: String,
}
