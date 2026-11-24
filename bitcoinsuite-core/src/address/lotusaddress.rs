use std::{fmt::Display, str::FromStr};
use thiserror::Error;

use crate::ecc::{PubKey, PUBKEY_LENGTH};
use crate::{BytesMut, Hashed, Net, Script, Sha256, ShaRmd160};

pub const LOTUS_ADDRESS_CHECKSUM_LEN: usize = 4;
pub const LOTUS_PREFIX: &str = "lotus";

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct LotusAddress {
    prefix: String,
    net: Net,
    lotus_addr: String,
    payload: LotusAddressPayload,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum LotusAddressPayload {
    /// Type byte 0, legacy bare 20-byte HASH160 payload. The historical
    /// format of this library; kept parseable for stored addresses, but
    /// lotusd v12's `XAddress::Parse` and xpi-ts reject it for P2PKH/P2SH.
    Hash(ShaRmd160),
    /// Type byte 0, full scriptPubKey payload: 25-byte P2PKH or 23-byte P2SH,
    /// matching lotusd v12 `XAddress::Encode` and xpi-ts `toXAddress`.
    Script(Script),
    /// Type byte 2: 33-byte Taproot commitment pubkey (xpi-ts P2TR format)
    Taproot(PubKey),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum LotusAddressType {
    Hash = 0,
    TaprootCommitment = 2,
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum LotusAddressError {
    #[error("Missing prefix")]
    MissingPrefix,
    #[error("Missing checksum")]
    MissingChecksum,
    #[error("Missing net character")]
    MissingNetChar,
    #[error("Unsupported net {0}")]
    UnsupportedNet(char),
    #[error("Invalid base58")]
    InvalidBase58(bs58::decode::Error),
    #[error("Missing base58")]
    MissingBase58,
    #[error("Missing payload")]
    MissingPayload,
    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(u8),
    #[error("Invalid checksum, expected {expected} but got {actual}")]
    InvalidChecksum { expected: String, actual: String },
    #[error("Invalid type-0 payload length: expected 20 (legacy bare hash), 23 (P2SH script) or 25 (P2PKH script), got {0}")]
    InvalidHashPayloadLength(usize),
    #[error("Invalid Taproot payload length: expected {PUBKEY_LENGTH}, got {0}")]
    InvalidTaprootPayloadLength(usize),
}

use self::LotusAddressError::*;

impl LotusAddress {
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
    pub fn net(&self) -> Net {
        self.net
    }
    pub fn as_str(&self) -> &str {
        &self.lotus_addr
    }

    /// Output script for this address. For a legacy bare-hash payload this is
    /// the P2PKH script of the hash; for a full-script payload it is the
    /// exact script that was encoded (lotusd/xpi-ts interoperability).
    pub fn script(&self) -> Script {
        match &self.payload {
            LotusAddressPayload::Hash(hash) => Script::p2pkh(hash),
            LotusAddressPayload::Script(script) => script.clone(),
            LotusAddressPayload::Taproot(pubkey) => Script::p2tr(pubkey, None),
        }
    }

    /// HASH160 for P2PKH/P2SH payloads: stored directly for legacy bare-hash
    /// payloads, extracted from the script for full-script payloads. `None`
    /// for taproot addresses.
    pub fn hash(&self) -> Option<ShaRmd160> {
        match &self.payload {
            LotusAddressPayload::Hash(hash) => Some(hash.clone()),
            LotusAddressPayload::Script(script) => match script.parse_variant() {
                crate::ScriptVariant::P2PKH(hash) | crate::ScriptVariant::P2SH(hash) => Some(hash),
                _ => None,
            },
            LotusAddressPayload::Taproot(_) => None,
        }
    }

    pub fn taproot_pubkey(&self) -> Option<&PubKey> {
        match &self.payload {
            LotusAddressPayload::Taproot(pk) => Some(pk),
            _ => None,
        }
    }

    /// Create a P2PKH address from HASH160, emitting the node/xpi-ts
    /// full-script form: type byte 0 with the 25-byte P2PKH scriptPubKey as
    /// payload, the only P2PKH form lotusd v12's `XAddress::Parse` and
    /// xpi-ts accept.
    pub fn from_hash(prefix: &str, net: Net, hash: ShaRmd160) -> Self {
        encode_payload(
            prefix,
            net,
            LotusAddressPayload::Script(Script::p2pkh(&hash)),
        )
    }

    /// Legacy form: bare 20-byte HASH160 payload (type byte 0). Kept for
    /// reading back stored addresses; lotusd v12 and xpi-ts reject it, so
    /// new code should use [LotusAddress::from_hash].
    pub fn from_hash_legacy(prefix: &str, net: Net, hash: ShaRmd160) -> Self {
        encode_payload(prefix, net, LotusAddressPayload::Hash(hash))
    }

    // ponytail: compatibility — stratum-server-nng tests pass full scripts.
    // Deprecated: use from_script() for new code.
    #[deprecated(note = "use from_script()")]
    pub fn new(prefix: &str, net: Net, script: Script) -> Self {
        Self::from_script(prefix, net, &script).expect("P2PKH/P2SH/P2TR scripts only")
    }

    /// Create from Taproot commitment pubkey (type byte 2, xpi-ts format).
    pub fn from_taproot(prefix: &str, net: Net, pubkey: &PubKey) -> Self {
        encode_payload(prefix, net, LotusAddressPayload::Taproot(pubkey.clone()))
    }

    /// Create from a Script, emitting the node/xpi-ts form: P2PKH/P2SH
    /// scripts become a full-scriptPubKey payload (type byte 0), taproot a
    /// 33-byte commitment (type byte 2).
    pub fn from_script(prefix: &str, net: Net, script: &Script) -> Result<Self, LotusAddressError> {
        match script.parse_variant() {
            crate::ScriptVariant::P2PKH(_) | crate::ScriptVariant::P2SH(_) => Ok(encode_payload(
                prefix,
                net,
                LotusAddressPayload::Script(script.clone()),
            )),
            crate::ScriptVariant::P2TR(pubkey, _) => Ok(Self::from_taproot(prefix, net, &pubkey)),
            _ => Err(InvalidPayloadType(0)),
        }
    }
}

fn encode_payload(prefix: &str, net: Net, payload: LotusAddressPayload) -> LotusAddress {
    let addr_type = match &payload {
        LotusAddressPayload::Hash(_) | LotusAddressPayload::Script(_) => LotusAddressType::Hash,
        LotusAddressPayload::Taproot(_) => LotusAddressType::TaprootCommitment,
    };
    let payload_bytes: &[u8] = match &payload {
        LotusAddressPayload::Hash(hash) => hash.as_slice(),
        LotusAddressPayload::Script(script) => script.bytecode().as_ref(),
        LotusAddressPayload::Taproot(pubkey) => pubkey.as_slice(),
    };

    let mut lotus_addr = prefix.to_string();
    let net_char = match net {
        Net::Mainnet => '_',
        Net::Regtest => 'R',
        Net::Testnet => 'T',
    };
    lotus_addr.push(net_char);

    let checksum = calc_checksum(prefix, net_char, addr_type, payload_bytes);

    let mut data = BytesMut::new();
    data.put_slice(&[addr_type as u8]);
    data.put_slice(payload_bytes);
    data.put_slice(&checksum);
    lotus_addr.push_str(&bs58::encode(data.as_slice()).into_string());

    LotusAddress {
        prefix: prefix.to_string(),
        net,
        lotus_addr,
        payload,
    }
}

impl FromStr for LotusAddress {
    type Err = LotusAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix = s
            .chars()
            .take_while(|&c| (c.is_ascii_alphabetic() && c.is_lowercase()) || c.is_ascii_digit())
            .collect::<String>();
        if prefix.is_empty() {
            return Err(MissingPrefix);
        }

        let net_char = s.chars().nth(prefix.len()).ok_or(MissingNetChar)?;
        let net = match net_char {
            '_' => Net::Mainnet,
            'R' => Net::Regtest,
            'T' => Net::Testnet,
            _ => return Err(UnsupportedNet(net_char)),
        };

        let data_b58 = &s[prefix.len() + 1..];
        let data = bs58::decode(data_b58).into_vec().map_err(InvalidBase58)?;
        let payload_type_byte = *data.first().ok_or(MissingBase58)?;
        let checksum_end = data
            .len()
            .checked_sub(LOTUS_ADDRESS_CHECKSUM_LEN)
            .ok_or(MissingChecksum)?;
        let payload = data.get(1..checksum_end).ok_or(MissingChecksum)?;
        if payload.is_empty() {
            return Err(MissingPayload);
        }

        let expected_checksum = &data[data.len() - LOTUS_ADDRESS_CHECKSUM_LEN..];

        let addr_type = match payload_type_byte {
            0 => LotusAddressType::Hash,
            2 => LotusAddressType::TaprootCommitment,
            x => return Err(InvalidPayloadType(x)),
        };

        let actual_checksum = calc_checksum(&prefix, net_char, addr_type, payload);
        if expected_checksum != actual_checksum {
            return Err(InvalidChecksum {
                expected: hex::encode(expected_checksum),
                actual: hex::encode(actual_checksum),
            });
        }

        // Validate payload length after checksum check (short inputs fail checksum first)
        match addr_type {
            LotusAddressType::TaprootCommitment if payload.len() != PUBKEY_LENGTH => {
                return Err(InvalidTaprootPayloadLength(payload.len()))
            }
            _ => {}
        }

        let payload_enum = match addr_type {
            LotusAddressType::Hash => match payload.len() {
                // Legacy bare HASH160 (historical format of this library)
                20 => LotusAddressPayload::Hash(ShaRmd160::new(payload.try_into().unwrap())),
                // Full scriptPubKey: 25-byte P2PKH or 23-byte P2SH, matching
                // lotusd v12 XAddress::Parse and xpi-ts toXAddress
                23 | 25 => LotusAddressPayload::Script(Script::from_slice(payload)),
                len => return Err(InvalidHashPayloadLength(len)),
            },
            LotusAddressType::TaprootCommitment => {
                LotusAddressPayload::Taproot(PubKey::new_unchecked(payload.try_into().unwrap()))
            }
        };

        Ok(LotusAddress {
            prefix,
            net,
            lotus_addr: s.to_string(),
            payload: payload_enum,
        })
    }
}

impl Display for LotusAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.lotus_addr.fmt(f)
    }
}

fn calc_checksum(
    prefix: &str,
    net_char: char,
    addr_type: LotusAddressType,
    payload: &[u8],
) -> [u8; 4] {
    let mut preimage = BytesMut::new();
    preimage.put_slice(prefix.as_bytes());
    preimage.put_slice(&[net_char as u8, addr_type as u8]);
    preimage.put_slice(payload);
    let hash = Sha256::digest(preimage.freeze());
    hash.as_slice()[..LOTUS_ADDRESS_CHECKSUM_LEN]
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use crate::ecc::{PubKey, PUBKEY_LENGTH};
    use crate::{Hashed, LotusAddress, LotusAddressError, Net, ShaRmd160, LOTUS_PREFIX};

    const MAINNET_P2PKH: &str = "lotus_1HWH7ZdGdFJfbGUZwdg3aCQL1xgQk67Mw5";
    const REGTEST_P2PKH: &str = "lotusR1HWH7ZdGdFJfbGUZwdg3aCQL1xgQgrAbks";
    const TESTNET_P2PKH: &str = "lotusT1HWH7ZdGdFJfbGUZwdg3aCQL1xgQmMVjU9";
    const MAINNET_P2SH: &str = "lotus_14U3yfq9YupnAjRVtKQGo5MKX8digk5uVZ";
    const REGTEST_P2SH: &str = "lotusR14U3yfq9YupnAjRVtKQGo5MKX8difdLFws";
    /// Node-valid regtest P2PKH address (lotusd v12 `XAddress::Encode`: the
    /// type-0 payload is the full scriptPubKey), taken from the DEV-336
    /// regtest harness. The script is
    /// `OP_DUP OP_HASH160 <hash160(pubkey(seckey=[1;32]))> OP_EQUALVERIFY OP_CHECKSIG`.
    const REGTEST_NODE_P2PKH: &str = "lotusR16PSJLqasHgB8GqFFzCqpJGH3Bpgh399zfuDxUJcn";

    /// Build a LotusAddress string from raw parts with a valid checksum
    /// (test helper for malformed-payload cases).
    fn raw_address(prefix: &str, net_char: char, addr_type: u8, payload: &[u8]) -> String {
        use crate::{BytesMut, Sha256};
        let mut preimage = BytesMut::new();
        preimage.put_slice(prefix.as_bytes());
        preimage.put_slice(&[net_char as u8, addr_type]);
        preimage.put_slice(payload);
        let checksum = Sha256::digest(preimage.freeze());

        let mut data = BytesMut::new();
        data.put_slice(&[addr_type]);
        data.put_slice(payload);
        data.put_slice(&checksum.as_slice()[..4]);
        format!(
            "{prefix}{net_char}{}",
            bs58::encode(data.as_slice()).into_string()
        )
    }

    fn test_hash() -> ShaRmd160 {
        ShaRmd160::from_hex("b50b86a893d80c9e2ee72b199612374b7b4c1cd8").unwrap()
    }

    fn p2sh_hash() -> ShaRmd160 {
        ShaRmd160::from_hex("260617ebf668c9102f71ce24aba97fcaaf9c666a").unwrap()
    }

    #[test]
    fn decode_lotus_address() -> Result<(), Box<dyn std::error::Error>> {
        let addr: LotusAddress = MAINNET_P2PKH.parse()?;
        assert_eq!(addr.prefix(), "lotus");
        assert_eq!(addr.net(), Net::Mainnet);
        assert_eq!(addr.hash(), Some(test_hash()));
        assert_eq!(addr.as_str(), MAINNET_P2PKH);

        let addr: LotusAddress = REGTEST_P2PKH.parse()?;
        assert_eq!(addr.net(), Net::Regtest);
        assert_eq!(addr.hash(), Some(test_hash()));

        let addr: LotusAddress = MAINNET_P2SH.parse()?;
        assert_eq!(addr.net(), Net::Mainnet);
        assert_eq!(addr.hash(), Some(p2sh_hash()));

        let addr: LotusAddress = REGTEST_P2SH.parse()?;
        assert_eq!(addr.net(), Net::Regtest);
        assert_eq!(addr.hash(), Some(p2sh_hash()));

        // Error cases
        assert_eq!(
            "A".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingPrefix
        );
        assert_eq!(
            "lotus".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingNetChar
        );
        assert_eq!(
            "lotusP".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::UnsupportedNet('P')
        );
        assert_eq!(
            "lotus_".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingBase58
        );
        assert_eq!(
            "lotus_0".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::InvalidBase58(bs58::decode::Error::InvalidCharacter {
                character: '0',
                index: 0
            })
        );
        assert_eq!(
            "lotus_1".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingChecksum
        );
        assert_eq!(
            "lotus_1111".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingChecksum
        );
        assert_eq!(
            "lotus_11111".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::MissingPayload
        );
        assert_eq!(
            "lotus_111111".parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::InvalidChecksum {
                expected: "00000000".to_string(),
                actual: "66276ef9".to_string()
            }
        );
        Ok(())
    }

    #[test]
    fn encode_lotus_address() -> Result<(), Box<dyn std::error::Error>> {
        use crate::Script;
        let hash = test_hash();
        let p2sh_hash = p2sh_hash();

        // from_hash emits the node/xpi-ts full-script P2PKH form
        let addr = LotusAddress::from_hash(LOTUS_PREFIX, Net::Mainnet, hash.clone());
        assert_eq!(addr.hash(), Some(hash.clone()));
        assert_eq!(addr.script(), Script::p2pkh(&hash));
        assert!(addr.as_str().starts_with("lotus_"));
        let reparsed: LotusAddress = addr.as_str().parse()?;
        assert_eq!(reparsed.script(), Script::p2pkh(&hash));

        let addr = LotusAddress::from_hash(LOTUS_PREFIX, Net::Regtest, hash.clone());
        assert!(addr.as_str().starts_with("lotusR"));

        let addr = LotusAddress::from_hash(LOTUS_PREFIX, Net::Testnet, hash.clone());
        assert!(addr.as_str().starts_with("lotusT"));

        // from_hash_legacy keeps emitting the historical bare-hash form
        let addr = LotusAddress::from_hash_legacy(LOTUS_PREFIX, Net::Mainnet, hash.clone());
        assert_eq!(addr.as_str(), MAINNET_P2PKH);

        let addr = LotusAddress::from_hash_legacy(LOTUS_PREFIX, Net::Regtest, hash.clone());
        assert_eq!(addr.as_str(), REGTEST_P2PKH);

        let addr = LotusAddress::from_hash_legacy(LOTUS_PREFIX, Net::Mainnet, p2sh_hash.clone());
        assert_eq!(addr.as_str(), MAINNET_P2SH);

        let addr = LotusAddress::from_hash_legacy(LOTUS_PREFIX, Net::Regtest, p2sh_hash.clone());
        assert_eq!(addr.as_str(), REGTEST_P2SH);

        // Round-trip from encoded string
        let parsed: LotusAddress = TESTNET_P2PKH.parse()?;
        assert_eq!(parsed.net(), Net::Testnet);
        assert_eq!(parsed.hash(), Some(hash));
        Ok(())
    }

    #[test]
    fn test_taproot_address_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let pubkey = PubKey::new_unchecked([0x02; PUBKEY_LENGTH]);
        let address = LotusAddress::from_taproot(LOTUS_PREFIX, Net::Mainnet, &pubkey);
        assert_eq!(address.prefix(), "lotus");
        assert_eq!(address.net(), Net::Mainnet);
        assert_eq!(
            address.taproot_pubkey().unwrap().as_slice(),
            pubkey.as_slice()
        );

        let parsed: LotusAddress = address.as_str().parse()?;
        assert_eq!(
            parsed.taproot_pubkey().unwrap().as_slice(),
            pubkey.as_slice()
        );
        assert_eq!(parsed.as_str(), address.as_str());
        Ok(())
    }

    #[test]
    fn test_from_taproot_script() -> Result<(), Box<dyn std::error::Error>> {
        use crate::Script;
        let pubkey = PubKey::new_unchecked([0x03; PUBKEY_LENGTH]);
        let p2tr_script = Script::p2tr(&pubkey, None);
        let address = LotusAddress::from_script(LOTUS_PREFIX, Net::Mainnet, &p2tr_script)?;
        assert_eq!(address.taproot_pubkey().unwrap(), &pubkey);

        let parsed: LotusAddress = address.as_str().parse()?;
        assert_eq!(parsed.script(), p2tr_script);
        Ok(())
    }

    /// The node/xpi-ts P2PKH form carries the full 25-byte scriptPubKey as
    /// the type-0 payload; it must parse and yield the exact script.
    #[test]
    fn test_parse_full_script_p2pkh_payload() -> Result<(), Box<dyn std::error::Error>> {
        use crate::Script;
        let addr: LotusAddress = REGTEST_NODE_P2PKH.parse()?;
        assert_eq!(addr.prefix(), "lotus");
        assert_eq!(addr.net(), Net::Regtest);
        // hash160 extracted from the script payload
        assert_eq!(
            addr.hash(),
            Some(ShaRmd160::from_hex(
                "79b000887626b294a914501a4cd226b58b235983"
            )?)
        );
        assert_eq!(
            addr.script(),
            Script::from_hex("76a91479b000887626b294a914501a4cd226b58b23598388ac")?
        );
        Ok(())
    }

    /// Type-0 payloads of any other length are rejected, even with a valid
    /// checksum.
    #[test]
    fn test_parse_rejects_unexpected_type0_lengths() {
        // 21 bytes: neither a bare hash nor a known scriptPubKey
        let addr_str = raw_address("lotus", 'R', 0, &[0x51; 21]);
        assert_eq!(
            addr_str.parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::InvalidHashPayloadLength(21)
        );
        // 24 bytes: between P2SH (23) and P2PKH (25)
        let addr_str = raw_address("lotus", 'R', 0, &[0x51; 24]);
        assert_eq!(
            addr_str.parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::InvalidHashPayloadLength(24)
        );
        // 19 bytes: one short of a bare hash
        let addr_str = raw_address("lotus", 'R', 0, &[0x51; 19]);
        assert_eq!(
            addr_str.parse::<LotusAddress>().unwrap_err(),
            LotusAddressError::InvalidHashPayloadLength(19)
        );
    }
}
