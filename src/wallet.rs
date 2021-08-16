use crate::coin_selection;
use crate::coin_selection::coin_select;
use crate::estimate_transaction_size::estimate_virtual_size;
use crate::input::Input;
use crate::swap::sign_with_key;
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bip32::{ExtendedPrivateKey, Prefix};
use elements::bitcoin::secp256k1::{PublicKey, SECP256K1};
use elements::bitcoin::Amount;
use elements::hashes::{hash160, Hash};
use elements::script::Builder;
use elements::secp256k1_zkp::{rand, Message, SecretKey};
use elements::sighash::SigHashCache;
use elements::{
    confidential, opcodes, Address, AddressParams, AssetId, OutPoint, SigHashType, Transaction,
    TxIn, TxOut, TxOutSecrets,
};
use hkdf::Hkdf;
use itertools::Itertools;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::iter;
use std::str::FromStr;

#[async_trait(?Send)]
pub trait GetUtxos {
    async fn get_utxos(&self, address: Address) -> Result<Vec<(OutPoint, TxOut)>>;
}

/// Derive the encryption key from the wallet's password and a salt.
///
/// # Choice of salt
///
/// The salt of HKDF can be public or secret and while it can operate without a salt, it is better to pass a salt value [0].
///
/// # Choice of ikm
///
/// The user's password is our input key material. The stronger the password, the better the resulting encryption key.
///
/// # Choice of info
///
/// HKDF can operate without `info`, however, it is useful to "tag" the derived key with its usage.
/// In our case, we use the encryption key to encrypt the secret key and as such, tag it with `b"ENCRYPTION_KEY"`.
///
/// [0]: https://tools.ietf.org/html/rfc5869#section-3.1
fn derive_encryption_key(salt: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Result<[u8; 32]> {
    let h = Hkdf::<Sha256>::new(Some(salt.as_ref()), password.as_ref());
    let mut enc_key = [0u8; 32];
    h.expand(b"ENCRYPTION_KEY", &mut enc_key)
        .context("failed to derive encryption key")?;

    Ok(enc_key)
}

#[derive(Debug, PartialEq)]
pub struct Wallet {
    name: String,
    encryption_key: Option<([u8; 32])>,
    xprv: ExtendedPrivateKey<SecretKey>,
    sk_salt: [u8; 32],
    chain: Chain,
    utxo_cache: Vec<(OutPoint, TxOut)>,
}

const SECRET_KEY_ENCRYPTION_NONCE: &[u8; 12] = b"SECRET_KEY!!";

impl Wallet {
    pub async fn sync(&mut self, client: &impl GetUtxos) -> Result<()> {
        self.utxo_cache = client.get_utxos(self.address()).await?;
        Ok(())
    }

    pub fn new_from_seed(name: String, seed: impl AsRef<[u8]>, chain: Chain) -> Result<Self> {
        let sk_salt = thread_rng().gen::<[u8; 32]>();

        let xprv = ExtendedPrivateKey::new(seed)?;

        Ok(Self {
            name,
            encryption_key: None,
            xprv,
            sk_salt,
            chain,
            utxo_cache: vec![],
        })
    }

    #[deprecated(note = "Use Self::new_from_seed instead", since = "0.4.0")]
    pub fn initialize_new(
        name: String,
        password: String,
        root_xprv: ExtendedPrivateKey<SecretKey>,
        chain: Chain,
    ) -> Result<Self> {
        let sk_salt = thread_rng().gen::<[u8; 32]>();

        let encryption_key = derive_encryption_key(&sk_salt, &password)?;

        Ok(Self {
            name,
            encryption_key: Some(encryption_key),
            sk_salt,
            chain,
            xprv: root_xprv,
            utxo_cache: vec![],
        })
    }

    #[deprecated(note = "Use EncryptedWallet::decrypt instead", since = "0.4.0")]
    pub fn initialize_existing(
        name: String,
        password: String,
        xprv_ciphertext: String,
        chain: Chain,
    ) -> Result<Self> {
        let mut parts = xprv_ciphertext.split('$');

        let salt = parts.next().context("no salt in cipher text")?;
        let xprv = parts.next().context("no secret key in cipher text")?;

        let mut sk_salt = [0u8; 32];
        hex::decode_to_slice(salt, &mut sk_salt).context("failed to decode salt as hex")?;

        let encryption_key = derive_encryption_key(&sk_salt, &password)?;

        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&encryption_key));
        let nonce = GenericArray::from_slice(SECRET_KEY_ENCRYPTION_NONCE);
        let xprv = cipher
            .decrypt(
                nonce,
                hex::decode(xprv)
                    .context("failed to decode xpk as hex")?
                    .as_slice(),
            )
            .context("failed to decrypt secret key")?;

        let xprv = String::from_utf8(xprv)?;
        let root_xprv = ExtendedPrivateKey::from_str(xprv.as_str())?;

        Ok(Self {
            name,
            encryption_key: Some(encryption_key),
            xprv: root_xprv,
            sk_salt,
            chain,
            utxo_cache: vec![],
        })
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(SECP256K1, &self.secret_key())
    }

    pub fn get_address(&self) -> Address {
        Address::p2wpkh(
            &elements::bitcoin::PublicKey {
                compressed: false,
                key: self.get_public_key(),
            },
            Some(PublicKey::from_secret_key(
                SECP256K1,
                &self.blinding_secret_key(),
            )),
            self.chain.into(),
        )
    }

    /// Encrypts the extended private key with the encryption key.
    ///
    /// # Choice of nonce
    ///
    /// We store the extended private key on disk and as such have to use a constant nonce, otherwise we would not be able to decrypt it again.
    /// The encryption only happens once and as such, there is conceptually only one message and we are not "reusing" the nonce which would be insecure.
    #[deprecated(note = "Use Self::encrypt instead", since = "0.4.0")]
    pub fn encrypted_xprv_key(&self) -> Result<Vec<u8>> {
        let encryption_key = self.encryption_key.context("the wallet was initialised using Self::new_from_seed that is incompatible with this deprecated function")?;
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&encryption_key));
        let xprv = &self.xprv.to_string(Prefix::XPRV);
        let enc_sk = cipher
            .encrypt(
                GenericArray::from_slice(SECRET_KEY_ENCRYPTION_NONCE),
                xprv.as_bytes(),
            )
            .context("failed to encrypt secret key")?;

        Ok(enc_sk)
    }

    /// Encrypt the wallet using a password.
    /// The Utxo cache is dropped.
    /// The password is salted using a randomly generated salt. The salt is stored in the EncryptedWallet type.
    /// The EncryptedWallet can be converted back to a Wallet using the EncryptedWallet::decrypt method.
    pub fn encrypt(&self, password: impl AsRef<[u8]>) -> Result<EncryptedWallet> {
        let encryption_key = derive_encryption_key(self.sk_salt, password)?;
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(encryption_key.as_ref()));
        let xprv = &self.xprv.to_string(Prefix::XPRV);
        let encrypted_xprv = cipher
            .encrypt(
                GenericArray::from_slice(SECRET_KEY_ENCRYPTION_NONCE),
                xprv.as_bytes(),
            )
            .context("failed to encrypt secret key")?;
        Ok(EncryptedWallet {
            name: self.name.clone(),
            encrypted_xprv,
            sk_salt: self.sk_salt,
            chain: self.chain,
        })
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    #[deprecated(note = "Use Self::encrypt instead", since = "0.4.0")]
    pub fn sk_salt(&self) -> [u8; 32] {
        self.sk_salt
    }

    pub fn address(&self) -> Address {
        Address::p2wpkh(
            &elements::bitcoin::PublicKey {
                compressed: false,
                key: self.get_public_key(),
            },
            Some(self.blinding_public_key()),
            self.chain.into(),
        )
    }

    fn blinding_public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(SECP256K1, &self.blinding_secret_key())
    }

    /// Derive the blinding key.
    ///
    /// # Choice of salt
    ///
    /// We choose to not add a salt because the ikm is already a randomly-generated, secret value with decent entropy.
    ///
    /// # Choice of ikm
    ///
    /// We derive the blinding key from the secret key to avoid having to store two secret values on disk.
    ///
    /// # Choice of info
    ///
    /// We choose to tag the derived key with `b"BLINDING_KEY"` in case we ever want to derive something else from the secret key.
    pub fn blinding_secret_key(&self) -> SecretKey {
        let h = Hkdf::<sha2::Sha256>::new(None, self.secret_key().as_ref());

        let mut bk = [0u8; 32];
        h.expand(b"BLINDING_KEY", &mut bk)
            .expect("output length aligns with sha256");

        SecretKey::from_slice(bk.as_ref()).expect("always a valid secret key")
    }

    pub fn secret_key(&self) -> SecretKey {
        // TODO: derive key according to some derivation path
        let secret_key = self.xprv.to_bytes();
        SecretKey::from_slice(&secret_key).unwrap()
    }

    pub fn compute_balances(&self) -> Vec<BalanceEntry> {
        let txouts = self.utxo_cache.clone();

        let grouped_txouts = txouts
            .iter()
            .filter_map(|(_, txout)| match txout {
                TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: confidential::Value::Explicit(value),
                    ..
                } => Some((*asset, *value)),
                txout => match txout.unblind(SECP256K1, self.blinding_secret_key()) {
                    Ok(unblinded_txout) => Some((unblinded_txout.asset, unblinded_txout.value)),
                    Err(e) => {
                        log::warn!("failed to unblind txout: {}", e);
                        None
                    }
                },
            })
            .into_group_map();

        grouped_txouts
            .into_iter()
            .map(|(asset, utxos)| {
                let total_sum = utxos.into_iter().sum();
                BalanceEntry {
                    asset,
                    value: total_sum,
                }
            })
            .collect()
    }

    pub fn sign(&self, mut transaction: Transaction) -> Transaction {
        let mut cache = SigHashCache::new(&transaction);

        let witnesses = transaction
            .clone()
            .input
            .iter()
            .enumerate()
            .filter_map(|(index, input)| {
                self.utxo_cache
                    .iter()
                    .find(|(utxo, _)| *utxo == input.previous_output)
                    .map(|(_, txout)| (index, txout))
            })
            .map(|(index, output)| {
                let script_witness = sign_with_key(
                    SECP256K1,
                    &mut cache,
                    index,
                    &self.secret_key(),
                    output.value,
                );

                (index, script_witness)
            })
            .collect::<Vec<_>>();

        for (index, witness) in witnesses {
            transaction.input[index].witness.script_witness = witness
        }

        transaction
    }

    pub fn coin_selection(
        &self,
        amount: Amount,
        asset: AssetId,
        fee_rate: f32,
        fee_offset: Amount,
    ) -> Result<Vec<Input>> {
        let utxos = self
            .utxo_cache
            .iter()
            .filter_map(|(utxo, txout)| {
                let unblinded_txout = match txout.unblind(SECP256K1, self.blinding_secret_key()) {
                    Ok(txout) => txout,
                    Err(_) => {
                        log::warn!("could not unblind utxo {}, ignoring", utxo);
                        return None;
                    }
                };
                let candidate_asset = unblinded_txout.asset;

                if candidate_asset == asset {
                    Some((
                        coin_selection::Utxo {
                            outpoint: *utxo,
                            value: unblinded_txout.value,
                            script_pubkey: txout.script_pubkey.clone(),
                            asset: candidate_asset,
                        },
                        txout,
                    ))
                } else {
                    log::debug!(
                        "utxo {} with asset id {} is not the target asset, ignoring",
                        utxo,
                        candidate_asset
                    );
                    None
                }
            })
            .collect::<Vec<_>>();

        let output = coin_select(
            utxos.iter().map(|(utxo, _)| utxo).cloned().collect(),
            amount,
            fee_rate,
            fee_offset,
        )?;
        let selection = output
            .coins
            .iter()
            .map(|coin| {
                let original_txout = utxos
                    .iter()
                    .find_map(|(utxo, txout)| (utxo.outpoint == coin.outpoint).then(|| *txout))
                    .expect("same source of utxos");

                Input {
                    txin: coin.outpoint,
                    original_txout: original_txout.clone(),
                    blinding_key: self.blinding_secret_key(),
                }
            })
            .collect();
        Ok(selection)
    }

    pub fn find_our_input_indices_in_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<Vec<(AssetId, u64)>> {
        transaction
            .input
            .iter()
            .filter_map(|txin| {
                self.utxo_cache
                    .iter()
                    .map(|(utxo, txout)| {
                        let is_ours = *utxo == txin.previous_output;
                        if !is_ours {
                            return Ok(None);
                        }

                        Ok(match txout {
                            TxOut {
                                asset: confidential::Asset::Explicit(asset),
                                value: confidential::Value::Explicit(value),
                                ..
                            } => Some((*asset, *value)),
                            txout => {
                                let unblinded =
                                    txout.unblind(SECP256K1, self.blinding_secret_key())?;
                                Some((unblinded.asset, unblinded.value))
                            }
                        })
                    })
                    .find_map(|res| res.transpose())
            })
            .collect::<Result<Vec<_>>>()
    }

    pub fn find_our_ouput_indices_in_transaction(
        &self,
        transaction: &Transaction,
    ) -> Vec<(AssetId, u64)> {
        transaction
            .output
            .iter()
            .filter_map(|txout| match txout {
                TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: confidential::Value::Explicit(value),
                    script_pubkey,
                    ..
                } if script_pubkey == &self.address().script_pubkey() => Some((*asset, *value)),
                TxOut {
                    asset: confidential::Asset::Explicit(_),
                    value: confidential::Value::Explicit(_),
                    ..
                } => {
                    log::debug!(
                        "ignoring explicit outputs that do not pay to our address, including fees"
                    );
                    None
                }
                txout => match txout.unblind(SECP256K1, self.blinding_secret_key()) {
                    Ok(unblinded) => Some((unblinded.asset, unblinded.value)),
                    _ => None,
                },
            })
            .collect()
    }

    pub fn withdraw_everything_to_transaction(
        &self,
        address: Address,
        btc_asset_id: AssetId,
        fee_rate: f32,
    ) -> Result<Transaction> {
        if !address.is_blinded() {
            bail!("can only withdraw to blinded addresses")
        }

        let utxos = self
            .utxo_cache
            .clone()
            .into_iter()
            .filter_map(|(utxos, txout)| {
                match txout.unblind(SECP256K1, self.blinding_secret_key()) {
                    Ok(unblinded_txout) => Some((utxos, txout, unblinded_txout)),
                    Err(_) => {
                        log::warn!("could not unblind utxo: {:?}, {:?}", utxos, txout);
                        None
                    }
                }
            })
            .collect::<Vec<_>>();

        let prevout_values = utxos
            .iter()
            .map(|(outpoint, confidential, _)| (outpoint, confidential.value))
            .collect::<HashMap<_, _>>();

        let estimated_virtual_size =
            estimate_virtual_size(prevout_values.len() as u64, utxos.len() as u64);

        let fee = (estimated_virtual_size as f32 * fee_rate) as u64;

        let txout_inputs = utxos
            .iter()
            .map(|(_, txout, secrets)| (txout.asset, secrets))
            .collect::<Vec<_>>();

        let txouts_grouped_by_asset = utxos
            .iter()
            .map(|(utxo, _, unblinded)| (unblinded.asset, (utxo, unblinded)))
            .into_group_map()
            .into_iter()
            .map(|(asset, txouts)| {
                // calculate the total amount we want to spend for this asset
                // if this is the native asset, subtract the fee
                let total_input = txouts.iter().map(|(_, txout)| txout.value).sum::<u64>();
                let to_spend = if asset == btc_asset_id {
                    log::debug!(
                        "{} is the native asset, subtracting a fee of {} from it",
                        asset,
                        fee
                    );

                    total_input - fee
                } else {
                    total_input
                };

                log::debug!(
                    "found {} UTXOs for asset {} worth {} in total",
                    txouts.len(),
                    asset,
                    total_input
                );

                (asset, to_spend)
            })
            .collect::<Vec<_>>();

        // build transaction from grouped txouts
        let mut transaction = match txouts_grouped_by_asset.as_slice() {
            [] => bail!("no balances in wallet"),
            [(asset, _)] if *asset != btc_asset_id => {
                bail!("cannot spend from wallet without native asset L-BTC because we cannot pay a fee",)
            }
            // handle last group separately because we need to create it is as the `last_confidential` output
            [other @ .., (last_asset, to_spend_last_txout)] => {
                // first, build all "non-last" outputs
                let other_txouts = other
                    .iter()
                    .map(|(asset, to_spend)| {
                        let (txout, abf, vbf) = TxOut::new_not_last_confidential(
                            &mut thread_rng(),
                            SECP256K1,
                            *to_spend,
                            address.clone(),
                            *asset,
                            txout_inputs
                                .iter()
                                .map(|(asset, secrets)| (*asset, Some(*secrets)))
                                .collect::<Vec<_>>()
                                .as_slice(),
                        )?;

                        log::debug!(
                            "constructed non-last confidential output for asset {} with value {}",
                            asset,
                            to_spend
                        );

                        Ok((txout, asset, *to_spend, abf, vbf))
                    })
                    .collect::<Result<Vec<_>>>()?;

                // second, make the last one, depending on the previous ones
                let last_txout = {
                    let other_outputs = other_txouts
                        .iter()
                        .map(|(_, asset, value, abf, vbf)| {
                            TxOutSecrets::new(**asset, *abf, *value, *vbf)
                        })
                        .collect::<Vec<_>>();

                    let (txout, _, _) = TxOut::new_last_confidential(
                        &mut thread_rng(),
                        SECP256K1,
                        *to_spend_last_txout,
                        address,
                        *last_asset,
                        txout_inputs.as_slice(),
                        other_outputs.iter().collect::<Vec<_>>().as_ref(),
                    )
                    .context("failed to make confidential txout")?;

                    log::debug!(
                        "constructed last confidential output for asset {} with value {}",
                        last_asset,
                        to_spend_last_txout
                    );

                    txout
                };

                let txins = utxos
                    .iter()
                    .map(|(utxo, _, _)| TxIn {
                        previous_output: *utxo,
                        is_pegin: false,
                        has_issuance: false,
                        script_sig: Default::default(),
                        sequence: 0,
                        asset_issuance: Default::default(),
                        witness: Default::default(),
                    })
                    .collect::<Vec<_>>();
                let txouts = other_txouts
                    .iter()
                    .map(|(txout, _, _, _, _)| txout)
                    .chain(iter::once(&last_txout))
                    .chain(iter::once(&TxOut::new_fee(fee, btc_asset_id)))
                    .cloned()
                    .collect::<Vec<_>>();

                Transaction {
                    version: 2,
                    lock_time: 0,
                    input: txins,
                    output: txouts,
                }
            }
        };

        let tx_clone = transaction.clone();
        let mut cache = SigHashCache::new(&tx_clone);

        for (index, input) in transaction.input.iter_mut().enumerate() {
            input.witness.script_witness = {
                let hash = hash160::Hash::hash(&self.get_public_key().serialize());
                let script = Builder::new()
                    .push_opcode(opcodes::all::OP_DUP)
                    .push_opcode(opcodes::all::OP_HASH160)
                    .push_slice(&hash.into_inner())
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_CHECKSIG)
                    .into_script();

                let sighash = cache.segwitv0_sighash(
                    index,
                    &script,
                    prevout_values[&input.previous_output],
                    SigHashType::All,
                );

                let sig = SECP256K1.sign(&Message::from(sighash), &self.secret_key());

                let mut serialized_signature = sig.serialize_der().to_vec();
                serialized_signature.push(SigHashType::All as u8);

                vec![
                    serialized_signature,
                    self.get_public_key().serialize().to_vec(),
                ]
            }
        }

        Ok(transaction)
    }
}

/// A single balance entry as returned by [`get_balances`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct BalanceEntry {
    pub asset: AssetId,
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Chain {
    Elements,
    Liquid,
}

impl From<Chain> for &AddressParams {
    fn from(from: Chain) -> Self {
        match from {
            Chain::Elements => &AddressParams::ELEMENTS,
            Chain::Liquid => &AddressParams::LIQUID,
        }
    }
}

impl FromStr for Chain {
    type Err = WrongChain;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lowercase = s.to_ascii_lowercase();
        match lowercase.as_str() {
            "elements" => Ok(Chain::Elements),
            "liquid" => Ok(Chain::Liquid),
            _ => Err(WrongChain(lowercase)),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Unsupported chain: {0}")]
pub struct WrongChain(String);

/// An Wallet with an encrypted xprv. This format should be used when you want to persist the wallet and recover it for later use.
/// # Example
/// ```
/// let wallet = baru::Wallet::new_from_seed("wallet-1".to_string(), &[1u8; 32], baru::Chain::Elements).unwrap();
///
/// let password = "123";
///
/// let encrypted = wallet.encrypt(password).unwrap();
/// let decrypted = encrypted.decrypt(password).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedWallet {
    name: String,
    encrypted_xprv: Vec<u8>,
    sk_salt: [u8; 32],
    chain: Chain,
}

impl EncryptedWallet {
    /// Decrypt the wallet using a password.
    /// Since the Utxo cache was dropped when the Wallet was encrypted, Wallet::sync needs to be called to refresh the cache.
    pub fn decrypt(self, password: impl AsRef<[u8]>) -> Result<Wallet> {
        let encryption_key = derive_encryption_key(self.sk_salt, password)?;
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&encryption_key));
        let nonce = GenericArray::from_slice(SECRET_KEY_ENCRYPTION_NONCE);
        let xprv = cipher
            .decrypt(nonce, self.encrypted_xprv.as_slice())
            .context("failed to decrypt secret key")?;

        let xprv = String::from_utf8(xprv)?;
        let xprv = ExtendedPrivateKey::from_str(xprv.as_str())?;

        Ok(Wallet {
            name: self.name,
            encryption_key: None,
            xprv,
            sk_salt: self.sk_salt,
            chain: self.chain,
            utxo_cache: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_wallet_rountdtrip() {
        let wallet =
            Wallet::new_from_seed("wallet-1".to_string(), &[1u8; 32], Chain::Elements).unwrap();

        let password = "123";

        let encrypted = wallet.encrypt(password).unwrap();
        let decrypted = encrypted.decrypt(password).unwrap();

        assert_eq!(wallet, decrypted)
    }

    #[test]
    fn serde_roundtrip_encrypted_wallet() {
        let wallet =
            Wallet::new_from_seed("wallet-1".to_string(), &[1u8; 32], Chain::Elements).unwrap();

        let password = "123";
        let encrypted = wallet.encrypt(password).unwrap();

        let ser = serde_json::to_string(&encrypted).unwrap();
        println!("{}", &ser);
        let deser = serde_json::from_str::<EncryptedWallet>(&ser).unwrap();

        assert_eq!(deser, encrypted)
    }

    #[test]
    fn deser_json_snapshot() {
        let json = r#"
        {
            "name":"wallet-1",
            "encrypted_xprv":[201,19,224,118,17,221,153,30,172,177,140,161,205,33,157,38,144,44,132,112,3,213,198,8,194,238,83,251,181,232,248,148,152,112,96,213,102,15,131,230,117,8,110,240,39,210,52,77,222,4,43,95,178,34,47,16,174,96,222,74,35,48,154,24,163,208,142,197,33,92,83,51,197,35,30,30,116,24,18,233,65,167,28,232,108,249,138,176,6,194,88,103,38,228,81,141,13,242,98,210,129,171,74,241,10,133,206,68,84,196,9,98,152,253,49,161,197,241,28,196,19,116,121,118,210,89,123],"sk_salt":[252,148,200,216,216,187,198,93,6,180,163,211,127,82,181,102,194,68,220,1,71,161,83,9,80,130,27,191,126,135,80,183],
            "chain":"Elements"
        }
        "#;

        serde_json::from_str::<EncryptedWallet>(json).unwrap();
    }
}
