extern crate link_cplusplus;

use anyhow::{Context, Result};
use baru::input::Input;
use elements::bitcoin::util::psbt::serialize::Serialize;
use elements::bitcoin::{Amount, Network, PrivateKey, PublicKey};
use elements::confidential::{Asset, AssetBlindingFactor, ValueBlindingFactor};
use elements::hashes::Hash;
use elements::secp256k1_zkp::{SecretKey, SECP256K1};
use elements::sighash::SigHashCache;
use elements::{
    Address, AddressParams, AssetId, OutPoint, SigHashType, Transaction, TxOut, TxOutSecrets, Txid,
};
use rand::{thread_rng, CryptoRng, RngCore};

#[derive(Default, Clone)]
pub struct Wallet {
    pub utxos: Vec<(Input, SecretKey, PublicKey)>,
}

impl Wallet {
    pub fn coin_select(&mut self, amount: Amount, asset: AssetId) -> Result<Vec<Input>> {
        let mut rng = thread_rng();

        let (sk, pk) = make_keypair(&mut rng);
        let (blinding_sk, blinding_pk) = make_keypair(&mut rng);
        let address = Address::p2wpkh(&pk, Some(blinding_pk.key), &AddressParams::LIQUID);

        let spent_utxo_secrets = {
            let abf = AssetBlindingFactor::new(&mut rng);
            let vbf = ValueBlindingFactor::new(&mut rng);
            let secrets = TxOutSecrets::new(asset, abf, amount.as_sat(), vbf);
            let asset = Asset::new_confidential(SECP256K1, asset, abf);

            [(asset, secrets)]
        };

        let (original_txout, _, _) = TxOut::new_last_confidential(
            &mut rng,
            SECP256K1,
            amount.as_sat() + 10_000,
            address,
            asset,
            spent_utxo_secrets
                .iter()
                .map(|(asset, secrets)| (*asset, secrets))
                .collect::<Vec<_>>()
                .as_slice(),
            &[],
        )?;

        let txid = {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);

            Txid::from_slice(&bytes)
        }?;

        let input = Input {
            txin: { OutPoint { txid, vout: 0 } },
            original_txout,
            blinding_key: blinding_sk,
        };

        self.utxos.push((input.clone(), sk, pk));

        Ok(vec![input])
    }

    pub fn sign_inputs(&self, tx: Transaction) -> Transaction {
        let mut tx_to_sign = tx;
        // first try to find out which utxos we know
        let known_inputs = tx_to_sign.clone().input.into_iter().filter_map(|txin| {
            if let Some((input, sk, pk)) = self.utxos.iter().find(
                |(
                    Input {
                        txin: OutPoint { txid, .. },
                        ..
                    },
                    _,
                    _,
                )| *txid == txin.previous_output.txid,
            ) {
                Some((txin, input.original_txout.value, sk, pk))
            } else {
                None
            }
        });

        known_inputs.into_iter().for_each(|(txin, value, sk, pk)| {
            let address = Address::p2pkh(pk, None, &AddressParams::LIQUID);
            let script = address.script_pubkey();

            let index = tx_to_sign
                .input
                .iter()
                .position(|other| other == &txin)
                .expect("input to be in transaction");

            let sighash = SigHashCache::new(&tx_to_sign).segwitv0_sighash(
                index,
                &script,
                value,
                SigHashType::All,
            );
            let sig = SECP256K1.sign(&secp256k1_zkp::Message::from(sighash), sk);

            let mut serialized_signature = sig.serialize_der().to_vec();
            serialized_signature.push(SigHashType::All as u8);

            tx_to_sign.input[index as usize].witness.script_witness =
                vec![serialized_signature, pk.serialize().to_vec()];
        });

        tx_to_sign
    }

    pub fn verify_all_inputs_spend_correctly(&self, tx: &Transaction) -> Result<()> {
        for (index, txin) in tx.input.iter().enumerate() {
            let input = self
                .utxos
                .iter()
                .map(|(input, _, _)| input)
                .find(|input| input.txin == txin.previous_output)
                .context("at least one input doesn't come from this wallet")?;

            elements_consensus::verify(
                input.original_txout.script_pubkey.clone(),
                &input.original_txout.value,
                index,
                tx,
            )
            .expect("input index out of bounds")
            .with_context(|| format!("input {} of transaction incorrectly signed", index))?;
        }

        Ok(())
    }
}

pub fn make_keypair<R>(rng: &mut R) -> (SecretKey, PublicKey)
where
    R: RngCore + CryptoRng,
{
    let sk = SecretKey::new(rng);
    let pk = PublicKey::from_private_key(
        SECP256K1,
        &PrivateKey {
            compressed: true,
            network: Network::Regtest,
            key: sk,
        },
    );

    (sk, pk)
}
