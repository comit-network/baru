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
use sha2::Sha256;
use std::collections::HashMap;
use std::iter;
use std::str::FromStr;

#[async_trait(?Send)]
pub trait GetUtxos {
    async fn get_utxos(&self, address: Address) -> Result<Vec<(OutPoint, TxOut)>>;
}

#[derive(Debug)]
pub struct Wallet {
    name: String,
    encryption_key: [u8; 32],
    secret_key: SecretKey,
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

    pub fn initialize_new(
        name: String,
        password: String,
        root_xprv: ExtendedPrivateKey<SecretKey>,
        chain: Chain,
    ) -> Result<Self> {
        let sk_salt = thread_rng().gen::<[u8; 32]>();

        let encryption_key = Self::derive_encryption_key(&password, &sk_salt)?;

        // TODO: derive key according to some derivation path
        let secret_key = root_xprv.to_bytes();

        Ok(Self {
            name,
            encryption_key,
            sk_salt,
            chain,
            secret_key: SecretKey::from_slice(&secret_key)?,
            xprv: root_xprv,
            utxo_cache: vec![],
        })
    }

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

        let encryption_key = Self::derive_encryption_key(&password, &sk_salt)?;

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

        // TODO: derive key according to some derivation path
        let secret_key = root_xprv.to_bytes();

        Ok(Self {
            name,
            encryption_key,
            secret_key: SecretKey::from_slice(&secret_key)?,
            xprv: root_xprv,
            sk_salt,
            chain,
            utxo_cache: vec![],
        })
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(SECP256K1, &self.secret_key)
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
    pub fn encrypted_xprv_key(&self) -> Result<Vec<u8>> {
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&self.encryption_key));
        let xprv = &self.xprv.to_string(Prefix::XPRV);
        let enc_sk = cipher
            .encrypt(
                GenericArray::from_slice(SECRET_KEY_ENCRYPTION_NONCE),
                xprv.as_bytes(),
            )
            .context("failed to encrypt secret key")?;

        Ok(enc_sk)
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
    fn derive_encryption_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let h = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
        let mut enc_key = [0u8; 32];
        h.expand(b"ENCRYPTION_KEY", &mut enc_key)
            .context("failed to derive encryption key")?;

        Ok(enc_key)
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

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
        let h = Hkdf::<sha2::Sha256>::new(None, self.secret_key.as_ref());

        let mut bk = [0u8; 32];
        h.expand(b"BLINDING_KEY", &mut bk)
            .expect("output length aligns with sha256");

        SecretKey::from_slice(bk.as_ref()).expect("always a valid secret key")
    }

    pub fn secret_key(&self) -> SecretKey {
        self.secret_key
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

#[derive(Debug, Clone, Copy, PartialEq)]
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
