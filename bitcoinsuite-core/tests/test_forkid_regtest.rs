//! DEV-336 regtest acceptance: sign a real spend at CHAIN_FORK_ID and see a
//! regtest node (replay protection active from genesis) accept it, while the
//! identical spend signed at fork value 0 is rejected.
//!
//! This test is `#[ignore]`d so it never runs in the default `cargo test`.
//! Run it with the prebuilt lotusd:
//!
//! ```sh
//! CC=gcc-13 cargo +1.99.0 test -p bitcoinsuite-core \
//!     --test test_forkid_regtest -- --ignored --nocapture
//! ```
//!
//! Env overrides:
//! - `LOTUSD_BIN`: lotusd binary (default: the sibling `../lotusd` checkout)
//! - `DEV336_RPC_PORT`: RPC port base (default: 38300 + pid % 2000)

use bitcoinsuite_core::{
    ecc::{Ecc, PubKey, SecKey},
    BitcoinCode, Hashed, LotusAddress, Net, OutPoint, P2PKHSignatory, Script, SequenceNo, Sha256,
    Sha256d, ShaRmd160, SigHashType, SignData, SignField, TxBuilder, TxBuilderInput,
    TxBuilderOutput, TxInput, TxOutput, CHAIN_FORK_ID,
};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const RPC_USER: &str = "dev336";
const RPC_PASSWORD: &str = "dev336-regtest-password";
/// Default relative to the workspace root; override with `LOTUSD_BIN`.
const DEFAULT_LOTUSD_BIN: &str = "../lotusd/build-clang/src/lotusd";
const FEE_SATS: i64 = 1_000;

/// Locate the lotusd binary: `LOTUSD_BIN`, then the sibling checkout from the
/// workspace root or the crate root.
fn lotusd_bin() -> String {
    if let Ok(path) = std::env::var("LOTUSD_BIN") {
        return path;
    }
    for candidate in [DEFAULT_LOTUSD_BIN, "../../lotusd/build-clang/src/lotusd"] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    panic!("lotusd not found; set LOTUSD_BIN or build the sibling ../lotusd checkout");
}

/// Kills the node and removes the temp datadir even when assertions fail.
struct NodeGuard {
    child: Child,
    datadir: PathBuf,
}

impl Drop for NodeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

fn base58_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = input.iter().take_while(|&&byte| byte == 0).count();
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 138 / 100 + 1);
    for &byte in &input[zeros..] {
        let mut carry = byte as u32;
        for digit in digits.iter_mut() {
            let value = (*digit as u32) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits.iter().rev() {
        out.push(ALPHABET[*digit as usize] as char);
    }
    out
}

/// Encode a regtest P2PKH address in the format lotusd v12's
/// `XAddress::Parse` accepts (src/addresses/xaddress.cpp): base58 over
/// `[type byte 0] ++ payload ++ checksum`, with the payload being the full
/// scriptPubKey and checksum = SHA256("lotus" ++ 'R' ++ type ++ payload)[..4].
///
/// Kept as an independent cross-check of `LotusAddress::from_script`
/// (DEV-355): the library must generate exactly this string.
fn lotusd_regtest_p2pkh_address(script: &Script) -> String {
    // Raw script bytes (bytecode), NOT ser() which prefixes a compact-size
    // length; the XAddress payload is the scriptPubKey itself.
    let payload = script.bytecode();
    let mut checksum_preimage = Vec::new();
    checksum_preimage.extend_from_slice(b"lotus");
    checksum_preimage.push(b'R');
    checksum_preimage.push(0); // AddressType SCRIPT_PUB_KEY
    checksum_preimage.extend_from_slice(payload.as_ref());
    let check = Sha256::digest(checksum_preimage.into());

    let mut data = Vec::new();
    data.push(0); // AddressType SCRIPT_PUB_KEY
    data.extend_from_slice(payload.as_ref());
    data.extend_from_slice(&check.as_slice()[..4]);
    format!("lotusR{}", base58_encode(&data))
}

fn rpc(port: u16, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({
        "jsonrpc": "1.0",
        "id": "dev336",
        "method": method,
        "params": params,
    })
    .to_string();
    let auth = base64(format!("{RPC_USER}:{RPC_PASSWORD}").as_bytes());
    let request = format!(
        "POST / HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Authorization: Basic {auth}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|err| format!("RPC {method}: connect failed: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|err| format!("RPC {method}: set_read_timeout: {err}"))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("RPC {method}: write failed: {err}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|err| format!("RPC {method}: read failed: {err}"))?;
    let text = String::from_utf8(raw).map_err(|err| format!("RPC {method}: non-utf8: {err}"))?;
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| format!("RPC {method}: no HTTP body in {text:?}"))?;
    let value: Value =
        serde_json::from_str(body).map_err(|err| format!("RPC {method}: bad json: {err}"))?;
    if let Some(error) = value.get("error") {
        if !error.is_null() {
            return Err(format!("RPC {method} error: {error}"));
        }
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| format!("RPC {method}: missing result"))
}

fn build_spend(
    outpoint: OutPoint,
    value_sat: i64,
    p2pkh_script: &Script,
    seckey: &SecKey,
    pubkey: PubKey,
    sig_hash_type: SigHashType,
) -> TxBuilder {
    let mut tx_builder = TxBuilder {
        version: 1,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    tx_builder.inputs.push(TxBuilderInput::new(
        TxInput {
            prev_out: outpoint,
            script: Script::default(),
            sequence: SequenceNo::finalized(),
            sign_data: Some(SignData::new(vec![
                SignField::Value(value_sat),
                SignField::OutputScript(p2pkh_script.clone()),
            ])),
        },
        Box::new(P2PKHSignatory {
            seckey: seckey.clone(),
            pubkey,
            sig_hash_type,
        }),
    ));
    tx_builder.outputs.push(TxBuilderOutput::Fixed(TxOutput {
        value: value_sat - FEE_SATS,
        script: p2pkh_script.clone(),
    }));
    tx_builder
}

#[test]
#[ignore]
fn test_forkid_regtest_acceptance() -> Result<(), Box<dyn std::error::Error>> {
    let lotusd_bin = lotusd_bin();
    let rpc_port: u16 = std::env::var("DEV336_RPC_PORT")
        .ok()
        .and_then(|port| port.parse().ok())
        .unwrap_or(38300 + (std::process::id() % 2000) as u16);
    let p2p_port = rpc_port + 1;
    let datadir = std::env::temp_dir().join(format!("dev336-regtest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir);
    std::fs::create_dir_all(&datadir)?;

    let child = Command::new(&lotusd_bin)
        .args([
            "-regtest",
            &format!("-datadir={}", datadir.display()),
            // Replay protection active from genesis: every sighash commits
            // to CHAIN_FORK_ID.
            "-replayprotectionactivationtime=0",
            "-server",
            &format!("-rpcuser={RPC_USER}"),
            &format!("-rpcpassword={RPC_PASSWORD}"),
            &format!("-rpcport={rpc_port}"),
            &format!("-port={p2p_port}"),
            "-nolisten",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let _node = NodeGuard {
        child,
        datadir: datadir.clone(),
    };

    // Wait for the RPC interface
    let start = Instant::now();
    loop {
        match rpc(rpc_port, "getblockcount", json!([])) {
            Ok(height) => {
                println!(
                    "node up ({}): blockcount {}",
                    start.elapsed().as_secs(),
                    height
                );
                break;
            }
            Err(_) if start.elapsed() < Duration::from_secs(120) => {
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(err) => panic!("node RPC did not come up within 120s: {err}"),
        }
    }

    // P2PKH address derived from a known sec key. The script comes from the
    // library; the address string is generated with
    // `LotusAddress::from_script`, which since DEV-355 emits lotusd v12's
    // XAddress P2PKH encoding (full scriptPubKey payload). The manual
    // encoder above stays as an independent cross-check.
    let ecc = EccSecp256k1::default();
    let seckey = ecc.seckey_from_array([1; 32])?;
    let pubkey = ecc.derive_pubkey(&seckey);
    let pubkey_hash = ShaRmd160::digest(pubkey.array().into());
    let p2pkh_script = Script::p2pkh(&pubkey_hash);
    let address = LotusAddress::from_script("lotus", Net::Regtest, &p2pkh_script)?
        .as_str()
        .to_string();
    assert_eq!(
        address,
        lotusd_regtest_p2pkh_address(&p2pkh_script),
        "library address must match the manual XAddress encoder"
    );
    assert!(
        address.starts_with("lotusR"),
        "unexpected regtest address {address}"
    );
    println!("funded address: {address}");
    let validated = rpc(rpc_port, "validateaddress", json!([&address]))?;
    assert_eq!(
        validated["isvalid"].as_bool(),
        Some(true),
        "node rejected generated address: {validated}"
    );

    // Mine 101 blocks: block 1's coinbase reaches maturity (100 confs)
    let generated = rpc(
        rpc_port,
        "generatetoaddress",
        json!([101, address.as_str()]),
    )?;
    assert_eq!(generated.as_array().map(Vec::len), Some(101));

    // Fetch block 1 and its coinbase, finding the first non-OP_RETURN
    // spendable vout (the stratum pool's accounting/service.rs pattern)
    let block1_hash = rpc(rpc_port, "getblockhash", json!([1]))?
        .as_str()
        .unwrap()
        .to_string();
    let block = rpc(rpc_port, "getblock", json!([block1_hash, 2]))?;
    let coinbase = &block["tx"][0];
    let coinbase_txid = coinbase["txid"].as_str().unwrap().to_string();
    let vouts = coinbase["vout"]
        .as_array()
        .ok_or("coinbase has no vout array")?;
    let (vout_idx, value_sat, script_hex) = vouts
        .iter()
        .enumerate()
        .find(|(_idx, vout)| {
            vout["scriptPubKey"]["type"].as_str() != Some("nulldata")
                && vout["value"].as_f64().unwrap_or(0.0) > 0.0
        })
        .map(|(idx, vout)| {
            (
                idx as u32,
                // lotusd's LOTUS unit has 6 decimals (amount.h:
                // LOTUS = 1'000'000 * SATOSHI); the RPC `value` field is in
                // LOTUS units, so satoshis = value * 1e6.
                (vout["value"].as_f64().unwrap() * 1e6).round() as i64,
                vout["scriptPubKey"]["hex"].as_str().unwrap().to_string(),
            )
        })
        .ok_or("no spendable coinbase vout")?;
    assert_eq!(
        script_hex,
        p2pkh_script.bytecode().hex(),
        "coinbase vout must pay to our P2PKH script"
    );
    println!(
        "coinbase outpoint: {}:{} ({} sats)",
        coinbase_txid, vout_idx, value_sat
    );
    let outpoint = OutPoint {
        txid: Sha256d::from_hex_be(&coinbase_txid)?,
        out_idx: vout_idx,
    };

    // 1) Fork-0 signature must be rejected (submit before the fork-id spend,
    //    so the signature check runs with nothing else in the mempool)
    let signed_fork_0 = build_spend(
        outpoint.clone(),
        value_sat,
        &p2pkh_script,
        &seckey,
        pubkey,
        SigHashType::ALL_BIP143,
    )
    .sign(&ecc, 1000, 546)?;
    let fork_0_rejection = match rpc(
        rpc_port,
        "sendrawtransaction",
        json!([signed_fork_0.ser().hex()]),
    ) {
        Ok(result) => panic!("fork-0 spend unexpectedly accepted: {result}"),
        Err(err) => err,
    };
    println!("fork-0 rejection: {fork_0_rejection}");

    // 2) CHAIN_FORK_ID signature must be accepted
    let signed_fork_id = build_spend(
        outpoint,
        value_sat,
        &p2pkh_script,
        &seckey,
        pubkey,
        SigHashType::ALL_BIP143.with_fork_value(CHAIN_FORK_ID),
    )
    .sign(&ecc, 1000, 546)?;
    let txid = rpc(
        rpc_port,
        "sendrawtransaction",
        json!([signed_fork_id.ser().hex()]),
    )?;
    println!("accepted txid: {txid}");
    let mempool = rpc(rpc_port, "getrawmempool", json!([]))?;
    assert!(
        mempool
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.as_str() == Some(txid.as_str().unwrap())),
        "accepted txid not in mempool"
    );

    Ok(())
}
