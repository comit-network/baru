use bitcoin_hashes::{sha256, Hash, HashEngine};
use secp256k1_zkp::SECP256K1;

pub struct Message {
    /// Price of bitcoin in whole USD.
    btc_price: WitnessStackInteger,
    /// UNIX timestamp.
    timestamp: WitnessStackInteger,
}

impl Message {
    pub fn new(btc_price: u64, timestamp: u64) -> Self {
        Self {
            btc_price: WitnessStackInteger(btc_price),
            timestamp: WitnessStackInteger(timestamp),
        }
    }

    /// Serialize price as bytes.
    pub fn price_to_bytes(&self) -> Vec<u8> {
        self.btc_price.serialize()
    }

    /// Serialize timestamp as bytes.
    pub fn timestamp_to_bytes(&self) -> Vec<u8> {
        self.timestamp.serialize()
    }

    pub fn message_hash(&self) -> secp256k1_zkp::Message {
        let mut sha256d = sha256::Hash::engine();
        sha256d.input(&self.price_to_bytes());
        sha256d.input(&self.timestamp_to_bytes());
        let message_hash = sha256::Hash::from_engine(sha256d);

        secp256k1_zkp::Message::from_slice(&message_hash).unwrap()
    }

    pub fn sign(&self, key: &secp256k1_zkp::SecretKey) -> secp256k1_zkp::Signature {
        let hashed_msg = self.message_hash();

        SECP256K1.sign(&hashed_msg, key)
    }
}

struct WitnessStackInteger(u64);

impl WitnessStackInteger {
    /// Serialize an integer so that it can be included in a Bitcoin witness stack.
    ///
    /// Said format is a little-endian byte encoding without trailing 0-bytes.
    fn serialize(&self) -> Vec<u8> {
        // to save a reverse operation, we first encode it as big-endian
        let bytes = self.0.to_be_bytes().to_vec();
        let mut bytes = bytes
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect::<Vec<_>>();
        bytes.reverse();

        bytes
    }
}
