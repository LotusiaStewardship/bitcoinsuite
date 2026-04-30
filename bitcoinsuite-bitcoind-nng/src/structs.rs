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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    UpdatedBlockTip(UpdatedBlockTip),
    TransactionAddedToMempool(TransactionAddedToMempool),
    TransactionRemovedFromMempool(TransactionRemovedFromMempool),
    BlockConnected(BlockConnected),
    BlockDisconnected(BlockDisconnected),
    ChainStateFlushed(ChainStateFlushed),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiningSubmitResult {
    Accepted,
    Duplicate,
    DuplicateInvalid,
    DuplicateInconclusive,
    Inconclusive,
    Rejected,
    DeserializationError,
    InvalidBlock,
    InvalidCoinbase,
    InvalidPrevBlock,
    Unknown(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitMinedBlockResult {
    pub result: MiningSubmitResult,
    pub accepted: bool,
    pub reject_reason: String,
    pub block_hash: Sha256d,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateMinedBlockProposalResult {
    pub result: MiningSubmitResult,
    pub valid: bool,
    pub reject_reason: String,
}

