use std::sync::Mutex;

use bitcoinsuite_core::Hashed;
use bitcoinsuite_error::{ErrorMeta, Result};
use flatbuffers::VerifierOptions;
use nng::{Message, Protocol, Socket};
use thiserror::Error;

use crate::{
    field::OptionExt,
    nng_interface_generated::nng_interface::{
        BlockHash, BlockHashArgs, BlockHeight, BlockHeightArgs, BlockIdentifier,
        GetBlockRangeRequest, GetBlockRangeRequestArgs, GetBlockRangeResponse, GetBlockRequest,
        GetBlockRequestArgs, GetBlockResponse, GetBlockSliceRequest, GetBlockSliceRequestArgs,
        GetBlockSliceResponse, GetMempoolRequest, GetMempoolRequestArgs, GetMempoolResponse,
        GetMiningTemplateRequest, GetMiningTemplateRequestArgs, GetMiningTemplateResponse,
        GetUndoSliceRequest, GetUndoSliceRequestArgs, GetUndoSliceResponse, Hash, RpcCall,
        RpcCallArgs, RpcRequest, RpcResult, SendRawTransactionRequest,
        SendRawTransactionRequestArgs, SendRawTransactionResponse, SubmitMinedBlockRequest,
        SubmitMinedBlockRequestArgs, SubmitMinedBlockResponse,
        ValidateMinedBlockProposalRequest, ValidateMinedBlockProposalRequestArgs,
        ValidateMinedBlockProposalResponse,
    },
    structs,
};

pub struct RpcInterface {
    sock: Socket,
    mutex: Mutex<()>,
    fbb_opts: VerifierOptions,
}

#[derive(Error, Debug, ErrorMeta)]
pub enum RpcInterfaceError {
    #[critical()]
    #[error("RPC error ({error_code}): {message}")]
    RpcError { error_code: i32, message: String },
}

use self::RpcInterfaceError::*;

impl RpcInterface {
    pub fn open(url: &str) -> Result<Self> {
        let sock = Socket::new(Protocol::Req0)?;
        sock.dial(url)?;
        Ok(RpcInterface {
            sock,
            mutex: Mutex::new(()),
            fbb_opts: VerifierOptions {
                max_tables: 0xffff_ffff,
                ..Default::default()
            },
        })
    }

    pub fn get_block(&self, block_id: structs::BlockIdentifier) -> Result<structs::Block> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let request = match block_id {
            structs::BlockIdentifier::Height(height) => {
                let block_height = BlockHeight::create(&mut fbb, &BlockHeightArgs { height });
                GetBlockRequest::create(
                    &mut fbb,
                    &GetBlockRequestArgs {
                        block_id_type: BlockIdentifier::Height,
                        block_id: Some(block_height.as_union_value()),
                    },
                )
            }
            structs::BlockIdentifier::Hash(blockhash) => {
                let block_hash = BlockHash::create(
                    &mut fbb,
                    &BlockHashArgs {
                        hash: Some(&Hash(blockhash.byte_array().array())),
                    },
                );
                GetBlockRequest::create(
                    &mut fbb,
                    &GetBlockRequestArgs {
                        block_id_type: BlockIdentifier::Hash,
                        block_id: Some(block_hash.as_union_value()),
                    },
                )
            }
        };
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::GetBlockRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root_with_opts::<GetBlockResponse>(
            &self.fbb_opts,
            self.handle_msg(&msg)?,
        )?;
        let block = response.block().field("GetBlockResponse.block")?;
        structs::Block::from_fbs(block)
    }

    pub fn get_block_range(
        &self,
        start_height: i32,
        num_blocks: u32,
    ) -> Result<Vec<structs::Block>> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let request = GetBlockRangeRequest::create(
            &mut fbb,
            &GetBlockRangeRequestArgs {
                start_height,
                num_blocks,
            },
        );
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::GetBlockRangeRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root_with_opts::<GetBlockRangeResponse>(
            &self.fbb_opts,
            self.handle_msg(&msg)?,
        )?;
        response
            .blocks()
            .field("GetBlockRangeResponse.blocks")?
            .into_iter()
            .map(structs::Block::from_fbs)
            .collect::<Result<Vec<_>>>()
    }

    pub fn get_block_slice(&self, file_num: u32, data_pos: u32, num_bytes: u32) -> Result<Vec<u8>> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let request = GetBlockSliceRequest::create(
            &mut fbb,
            &GetBlockSliceRequestArgs {
                file_num,
                data_pos,
                num_bytes,
            },
        );
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::GetBlockSliceRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root_with_opts::<GetBlockSliceResponse>(
            &self.fbb_opts,
            self.handle_msg(&msg)?,
        )?;
        Ok(response
            .data()
            .field("GetBlockSliceResponse.data")?
            .bytes()
            .to_vec())
    }

    pub fn get_undo_slice(&self, file_num: u32, undo_pos: u32, num_bytes: u32) -> Result<Vec<u8>> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let request = GetUndoSliceRequest::create(
            &mut fbb,
            &GetUndoSliceRequestArgs {
                file_num,
                undo_pos,
                num_bytes,
            },
        );
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::GetUndoSliceRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root_with_opts::<GetUndoSliceResponse>(
            &self.fbb_opts,
            self.handle_msg(&msg)?,
        )?;
        Ok(response
            .data()
            .field("GetUndoSliceResponse.data")?
            .bytes()
            .to_vec())
    }

    pub fn get_mempool(&self) -> Result<Vec<structs::MempoolTx>> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(1024);
        let request = GetMempoolRequest::create(&mut fbb, &GetMempoolRequestArgs {});
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::GetMempoolRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root::<GetMempoolResponse>(self.handle_msg(&msg)?)?;
        response
            .txs()
            .field("txs")?
            .into_iter()
            .map(structs::MempoolTx::from_fbs)
            .collect::<Result<_>>()
    }

    pub fn get_mining_template(
        &self,
        coinbase_script: Option<&[u8]>,
        extranonce1_size: u32,
        extranonce2_size: u32,
        include_transactions: bool,
    ) -> Result<structs::MiningTemplate> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(2048);
        let coinbase_script_offset = coinbase_script.map(|s| fbb.create_vector(s));
        let request = GetMiningTemplateRequest::create(
            &mut fbb,
            &GetMiningTemplateRequestArgs {
                coinbase_script: coinbase_script_offset,
                extranonce1_size,
                extranonce2_size,
                include_transactions,
            },
        );
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::GetMiningTemplateRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root_with_opts::<GetMiningTemplateResponse>(
            &self.fbb_opts,
            self.handle_msg(&msg)?,
        )?;
        Ok(structs::MiningTemplate {
            template_id: response.template_id(),
            block: response
                .block()
                .field("GetMiningTemplateResponse.block")?
                .bytes()
                .to_vec(),
            header: response
                .header()
                .field("GetMiningTemplateResponse.header")?
                .bytes()
                .to_vec(),
            previous_block_hash: bitcoinsuite_core::Sha256d::new(
                response
                    .previous_block_hash()
                    .field("GetMiningTemplateResponse.previous_block_hash")?
                    .hash()
                    .field("GetMiningTemplateResponse.previous_block_hash.hash")?
                    .0,
            ),
            height: response.height(),
            version: response.version(),
            bits: response.bits(),
            target: bitcoinsuite_core::Sha256d::new(
                response
                    .target()
                    .field("GetMiningTemplateResponse.target")?
                    .0,
            ),
            curtime: response.curtime(),
            mintime: response.mintime(),
            maxtime: response.maxtime(),
            coinbase_value: response.coinbase_value(),
            coinbase_tx: response
                .coinbase_tx()
                .field("GetMiningTemplateResponse.coinbase_tx")?
                .bytes()
                .to_vec(),
            transactions: response
                .transactions()
                .map(|txs| {
                    txs.iter()
                        .map(|tx| {
                            Ok(structs::MiningTemplateTx {
                                raw: tx.raw().field("MiningTemplateTx.raw")?.bytes().to_vec(),
                                txid: bitcoinsuite_core::Sha256d::new(
                                    tx.txid()
                                        .field("MiningTemplateTx.txid")?
                                        .hash()
                                        .field("MiningTemplateTx.txid.hash")?
                                        .0,
                                ),
                                fee: tx.fee(),
                                sigops: tx.sigops(),
                            })
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default(),
            coinbase1: response
                .coinbase1()
                .field("GetMiningTemplateResponse.coinbase1")?
                .to_string(),
            coinbase2: response
                .coinbase2()
                .field("GetMiningTemplateResponse.coinbase2")?
                .to_string(),
            merkle_branches: response
                .merkle_branches()
                .map(|b| b.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default(),
            prev_hash_stratum: response
                .prev_hash_stratum()
                .field("GetMiningTemplateResponse.prev_hash_stratum")?
                .to_string(),
            nbits_stratum: response
                .nbits_stratum()
                .field("GetMiningTemplateResponse.nbits_stratum")?
                .to_string(),
            ntime_stratum: response
                .ntime_stratum()
                .field("GetMiningTemplateResponse.ntime_stratum")?
                .to_string(),
        })
    }

    pub fn submit_mined_block(&self, block: &[u8]) -> Result<structs::SubmitMinedBlockResult> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(block.len() + 128);
        let block_vec = fbb.create_vector(block);
        let request = SubmitMinedBlockRequest::create(
            &mut fbb,
            &SubmitMinedBlockRequestArgs {
                block: Some(block_vec),
            },
        );
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::SubmitMinedBlockRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root_with_opts::<SubmitMinedBlockResponse>(
            &self.fbb_opts,
            self.handle_msg(&msg)?,
        )?;
        Ok(structs::SubmitMinedBlockResult {
            result: map_submit_result(response.result()),
            accepted: response.accepted(),
            reject_reason: response
                .reject_reason()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            block_hash: bitcoinsuite_core::Sha256d::new(
                response
                    .block_hash()
                    .field("SubmitMinedBlockResponse.block_hash")?
                    .hash()
                    .field("SubmitMinedBlockResponse.block_hash.hash")?
                    .0,
            ),
        })
    }

    pub fn validate_mined_block_proposal(
        &self,
        block: &[u8],
    ) -> Result<structs::ValidateMinedBlockProposalResult> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(block.len() + 128);
        let block_vec = fbb.create_vector(block);
        let request = ValidateMinedBlockProposalRequest::create(
            &mut fbb,
            &ValidateMinedBlockProposalRequestArgs {
                block: Some(block_vec),
            },
        );
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::ValidateMinedBlockProposalRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root_with_opts::<ValidateMinedBlockProposalResponse>(
            &self.fbb_opts,
            self.handle_msg(&msg)?,
        )?;
        Ok(structs::ValidateMinedBlockProposalResult {
            result: map_submit_result(response.result()),
            valid: response.valid(),
            reject_reason: response
                .reject_reason()
                .map(|s| s.to_string())
                .unwrap_or_default(),
        })
    }

    pub fn send_raw_transaction(
        &self,
        raw_tx: &[u8],
        max_fee_rate: u64,
        relay: bool,
        wait_callback: bool,
    ) -> Result<structs::SendRawTransactionSubmitResult> {
        let mut fbb = flatbuffers::FlatBufferBuilder::with_capacity(raw_tx.len() + 128);
        let raw_tx_vec = fbb.create_vector(raw_tx);
        let request = SendRawTransactionRequest::create(
            &mut fbb,
            &SendRawTransactionRequestArgs {
                raw_tx: Some(raw_tx_vec),
                max_fee_rate,
                relay,
                wait_callback,
            },
        );
        let rpc_call = RpcCall::create(
            &mut fbb,
            &RpcCallArgs {
                rpc_type: RpcRequest::SendRawTransactionRequest,
                rpc: Some(request.as_union_value()),
            },
        );
        fbb.finish(rpc_call, None);
        let msg = self.tranceive(&fbb)?;
        let response = flatbuffers::root_with_opts::<SendRawTransactionResponse>(
            &self.fbb_opts,
            self.handle_msg(&msg)?,
        )?;
        Ok(structs::SendRawTransactionSubmitResult {
            result: map_send_raw_tx_result(response.result()),
            accepted: response.accepted(),
            reject_reason: response
                .reject_reason()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            txid: bitcoinsuite_core::Sha256d::new(
                response
                    .txid()
                    .field("SendRawTransactionResponse.txid")?
                    .hash()
                    .field("SendRawTransactionResponse.txid.hash")?
                    .0,
            ),
        })
    }

    fn tranceive(&self, fbb: &flatbuffers::FlatBufferBuilder) -> Result<Message> {
        self.tranceive_raw(fbb.finished_data())
    }

    /// Send pre-encoded RpcCall bytes and return raw response message.
    pub fn tranceive_raw(&self, payload: &[u8]) -> Result<Message> {
        let _guard = self.mutex.lock().expect("Acquire mutex failed");
        self.sock.send(payload).map_err(|(_, err)| err)?;
        let resp = self.sock.recv()?;
        Ok(resp)
    }

    /// Forward-compatible escape hatch for callers using newer schemas than
    /// this crate currently models.
    pub fn call_raw(&self, rpc_call_payload: &[u8]) -> Result<Vec<u8>> {
        let msg = self.tranceive_raw(rpc_call_payload)?;
        Ok(self.handle_msg(&msg)?.to_vec())
    }

    fn handle_msg<'a>(&self, msg: &'a Message) -> Result<&'a [u8]> {
        let result = flatbuffers::root_with_opts::<RpcResult>(&self.fbb_opts, &msg[..])?;
        if result.is_success() {
            Ok(result.data().field("data")?.bytes())
        } else {
            Err(RpcError {
                error_code: result.error_code(),
                message: result.error_msg().field("error_msg")?.to_string(),
            }
            .into())
        }
    }
}

fn map_send_raw_tx_result(
    v: crate::nng_interface_generated::nng_interface::SendRawTransactionResult,
) -> structs::SendRawTransactionResult {
    use crate::nng_interface_generated::nng_interface::SendRawTransactionResult as Fbs;
    match v {
        Fbs::ACCEPTED => structs::SendRawTransactionResult::Accepted,
        Fbs::ALREADY_IN_CHAIN => structs::SendRawTransactionResult::AlreadyInChain,
        Fbs::MEMPOOL_REJECTED => structs::SendRawTransactionResult::MempoolRejected,
        Fbs::MEMPOOL_ERROR => structs::SendRawTransactionResult::MempoolError,
        Fbs::MAX_FEE_EXCEEDED => structs::SendRawTransactionResult::MaxFeeExceeded,
        Fbs::DESERIALIZATION_ERROR => structs::SendRawTransactionResult::DeserializationError,
        _ => structs::SendRawTransactionResult::Unknown(v.0),
    }
}

fn map_submit_result(
    v: crate::nng_interface_generated::nng_interface::MiningSubmitResult,
) -> structs::MiningSubmitResult {
    use crate::nng_interface_generated::nng_interface::MiningSubmitResult as Fbs;
    match v {
        Fbs::ACCEPTED => structs::MiningSubmitResult::Accepted,
        Fbs::DUPLICATE => structs::MiningSubmitResult::Duplicate,
        Fbs::DUPLICATE_INVALID => structs::MiningSubmitResult::DuplicateInvalid,
        Fbs::DUPLICATE_INCONCLUSIVE => structs::MiningSubmitResult::DuplicateInconclusive,
        Fbs::INCONCLUSIVE => structs::MiningSubmitResult::Inconclusive,
        Fbs::REJECTED => structs::MiningSubmitResult::Rejected,
        Fbs::DESERIALIZATION_ERROR => structs::MiningSubmitResult::DeserializationError,
        Fbs::INVALID_BLOCK => structs::MiningSubmitResult::InvalidBlock,
        Fbs::INVALID_COINBASE => structs::MiningSubmitResult::InvalidCoinbase,
        Fbs::INVALID_PREV_BLOCK => structs::MiningSubmitResult::InvalidPrevBlock,
        _ => structs::MiningSubmitResult::Unknown(v.0),
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, str::FromStr};

    use bitcoinsuite_bitcoind::instance::{BitcoindChain, BitcoindConf, BitcoindInstance};
    use bitcoinsuite_core::{Hashed, Sha256d};
    use bitcoinsuite_error::Result;
    use bitcoinsuite_test_utils::bin_folder;
    use tempdir::TempDir;

    use crate::{BlockIdentifier, RpcInterface};

    #[test]
    fn test_rpc() -> Result<()> {
        bitcoinsuite_error::install()?;
        let ipc_dir = TempDir::new("ipc_rpc_dir")?;
        let rpc_url = format!(
            "ipc://{}",
            ipc_dir.path().join("rpc.pipe").to_string_lossy()
        );
        let rpc_arg = format!("-nngrpc={rpc_url}");
        let conf = BitcoindConf::from_chain_regtest(
            bin_folder(),
            BitcoindChain::XPI,
            vec![OsString::from_str(&rpc_arg)?],
        )?;
        let mut instance = BitcoindInstance::setup(conf)?;
        instance.wait_for_ready()?;
        let rpc = RpcInterface::open(&rpc_url)?;
        test_get_block(&mut instance, &rpc)?;
        instance.cleanup()?;
        Ok(())
    }

    fn test_get_block(instance: &mut BitcoindInstance, rpc: &RpcInterface) -> Result<()> {
        assert!(rpc.get_mempool()?.is_empty());
        let genesis_block_hash = instance.cmd_string("getblockhash", &["0"])?;
        let genesis_block_header =
            instance.cmd_string("getblockheader", &[&genesis_block_hash, "false"])?;
        let json_block = instance.cmd_json("getblock", &[&genesis_block_hash, "2"])?;
        let block = rpc.get_block(BlockIdentifier::Height(0))?;
        assert_eq!(hex::encode(&block.header.raw), genesis_block_header);
        assert_eq!(block.header.hash.to_hex_be(), genesis_block_hash);
        assert_eq!(block.header.prev_hash.as_slice(), [0; 32]);
        assert_eq!(
            format!("{:08x}", block.header.n_bits),
            json_block["bits"].as_str().unwrap()
        );
        assert_eq!(block.header.timestamp, json_block["time"].as_u64().unwrap());
        assert_eq!(block.metadata, vec![]);
        assert_eq!(block.txs.len(), 1);
        assert_eq!(
            hex::encode(&block.txs[0].tx.raw),
            json_block["tx"][0]["hex"]
        );
        assert_eq!(block.txs[0].tx.spent_coins, None);
        assert_eq!(
            block.txs[0].tx.txid.to_hex_be(),
            json_block["tx"][0]["txid"]
        );
        let block_from_hash = rpc.get_block(BlockIdentifier::Hash(Sha256d::from_hex_be(
            &genesis_block_hash,
        )?))?;
        assert_eq!(block, block_from_hash);
        Ok(())
    }
}
