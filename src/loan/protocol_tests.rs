#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use crate::loan::{oracle, Borrower0, Lender0};
    use anyhow::{Context, Result};
    use bitcoin_hashes::Hash;
    use elements::bitcoin::util::psbt::serialize::Serialize;
    use elements::bitcoin::{Amount, Network, PrivateKey, PublicKey};
    use elements::script::Builder;
    use elements::secp256k1_zkp::{SecretKey, SECP256K1};
    use elements::sighash::SigHashCache;
    use elements::{
        opcodes, Address, AddressParams, AssetId, OutPoint, Script, SigHashType, Transaction,
        TxOut, Txid,
    };
    use elements_harness::Elementsd;
    use elements_rpc::ElementsRpc;
    use rand::{CryptoRng, RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use testcontainers::clients::Cli;

    #[tokio::test]
    async fn borrow_and_repay() {
        init_logger();

        let mut rng = ChaChaRng::seed_from_u64(0);

        let tc_client = Cli::default();
        let (client, _container) = {
            let blockchain = Elementsd::new(&tc_client, "0.18.1.9").unwrap();

            (
                elements_rpc::Client::new(blockchain.node_url.clone().into()).unwrap(),
                blockchain,
            )
        };

        let bitcoin_asset_id = client.get_bitcoin_asset_id().await.unwrap();
        let usdt_asset_id = client.issueasset(40.0, 0.0, false).await.unwrap().asset;
        let (_oracle_sk, oracle_pk) = make_keypair(&mut rng);

        let miner_address = client.get_new_segwit_confidential_address().await.unwrap();

        client
            .send_asset_to_address(&miner_address, Amount::from_btc(5.0).unwrap(), None)
            .await
            .unwrap();
        client.generatetoaddress(10, &miner_address).await.unwrap();

        let (borrower, borrower_wallet) = {
            let mut wallet = Wallet::new(&mut rng);

            let collateral_amount = Amount::ONE_BTC;

            let address = wallet.address();
            let address_blinding_sk = wallet.dump_blinding_sk();

            // fund borrower address with bitcoin
            let txid = client
                .send_asset_to_address(&address, collateral_amount * 2, Some(bitcoin_asset_id))
                .await
                .unwrap();

            wallet.add_known_utxo(&client, txid).await;

            // fund wallet with some usdt to pay back the loan later on
            let txid = client
                .send_asset_to_address(
                    &address,
                    Amount::from_btc(2.0).unwrap(),
                    Some(usdt_asset_id),
                )
                .await
                .unwrap();
            wallet.add_known_utxo(&client, txid).await;

            client.generatetoaddress(1, &miner_address).await.unwrap();

            let timelock = 10;

            let borrower = Borrower0::new(
                &mut rng,
                {
                    let wallet = wallet.clone();
                    |amount, asset| async move { wallet.find_inputs(asset, amount).await }
                },
                address.clone(),
                address_blinding_sk,
                collateral_amount,
                Amount::ONE_SAT,
                timelock,
                bitcoin_asset_id,
                usdt_asset_id,
            )
            .await
            .unwrap();

            (borrower, wallet)
        };

        let (lender, _lender_address) = {
            let address = client.get_new_segwit_confidential_address().await.unwrap();
            let address_blinder = blinding_key(&client, &address).await.unwrap();

            let lender = Lender0::new(
                &mut rng,
                bitcoin_asset_id,
                usdt_asset_id,
                address.clone(),
                address_blinder,
                oracle_pk,
            )
            .unwrap();

            (lender, address)
        };

        let loan_request = borrower.loan_request();

        let lender = lender
            .interpret(
                &mut rng,
                &SECP256K1,
                {
                    let client = client.clone();
                    |amount, asset| async move { find_inputs(&client, asset, amount).await }
                },
                loan_request,
                38_000, // value of 1 BTC as of 18.06.2021
            )
            .await
            .unwrap();
        let loan_response = lender.loan_response();

        let borrower = borrower.interpret(&SECP256K1, loan_response).unwrap();
        let loan_transaction = borrower
            .sign({
                let wallet = borrower_wallet.clone();
                |transaction| async move { Ok(wallet.sign_all_inputs(transaction)) }
            })
            .await
            .unwrap();

        let loan_transaction = lender
            .finalise_loan(loan_transaction, {
                let client = client.clone();
                |transaction| async move { client.sign_raw_transaction(&transaction).await }
            })
            .await
            .unwrap();

        client
            .send_raw_transaction(&loan_transaction)
            .await
            .unwrap();

        client.generatetoaddress(1, &miner_address).await.unwrap();

        let loan_repayment_transaction = borrower
            .loan_repayment_transaction(
                &mut rng,
                &SECP256K1,
                {
                    let borrower_wallet = borrower_wallet.clone();
                    |amount, asset| async move { borrower_wallet.find_inputs(asset, amount).await }
                },
                |tx| async move { Ok(borrower_wallet.sign_all_inputs(tx)) },
                Amount::ONE_SAT,
            )
            .await
            .unwrap();

        client
            .send_raw_transaction(&loan_repayment_transaction)
            .await
            .expect("could not repay loan to reclaim collateral");
    }

    #[tokio::test]
    async fn lend_and_liquidate() {
        init_logger();

        let mut rng = ChaChaRng::seed_from_u64(0);

        let tc_client = Cli::default();
        let (client, _container) = {
            let blockchain = Elementsd::new(&tc_client, "0.18.1.9").unwrap();

            (
                elements_rpc::Client::new(blockchain.node_url.clone().into()).unwrap(),
                blockchain,
            )
        };

        let bitcoin_asset_id = client.get_bitcoin_asset_id().await.unwrap();
        let usdt_asset_id = client.issueasset(40.0, 0.0, false).await.unwrap().asset;
        let (_oracle_sk, oracle_pk) = make_keypair(&mut rng);

        let miner_address = client.get_new_segwit_confidential_address().await.unwrap();
        client
            .send_asset_to_address(&miner_address, Amount::from_btc(5.0).unwrap(), None)
            .await
            .unwrap();
        client.generatetoaddress(10, &miner_address).await.unwrap();

        let (borrower, borrower_wallet) = {
            let mut wallet = Wallet::new(&mut rng);

            let collateral_amount = Amount::ONE_BTC;

            let address = wallet.address();
            let address_blinding_sk = wallet.dump_blinding_sk();

            // fund borrower address with bitcoin
            let txid = client
                .send_asset_to_address(&address, collateral_amount * 2, Some(bitcoin_asset_id))
                .await
                .unwrap();

            wallet.add_known_utxo(&client, txid).await;

            // fund wallet with some usdt to pay back the loan later on
            let txid = client
                .send_asset_to_address(
                    &address,
                    Amount::from_btc(2.0).unwrap(),
                    Some(usdt_asset_id),
                )
                .await
                .unwrap();
            wallet.add_known_utxo(&client, txid).await;

            client.generatetoaddress(1, &miner_address).await.unwrap();

            let timelock = client.get_blockcount().await.unwrap() + 5;

            let borrower = Borrower0::new(
                &mut rng,
                {
                    let wallet = wallet.clone();
                    |amount, asset| async move { wallet.find_inputs(asset, amount).await }
                },
                address.clone(),
                address_blinding_sk,
                collateral_amount,
                Amount::ONE_SAT,
                timelock,
                bitcoin_asset_id,
                usdt_asset_id,
            )
            .await
            .unwrap();

            (borrower, wallet)
        };

        let (lender, _lender_address) = {
            let address = client.get_new_segwit_confidential_address().await.unwrap();
            let address_blinder = blinding_key(&client, &address).await.unwrap();

            let lender = Lender0::new(
                &mut rng,
                bitcoin_asset_id,
                usdt_asset_id,
                address.clone(),
                address_blinder,
                oracle_pk,
            )
            .unwrap();

            (lender, address)
        };

        let loan_request = borrower.loan_request();

        let lender = lender
            .interpret(
                &mut rng,
                &SECP256K1,
                {
                    let client = client.clone();
                    |amount, asset| async move { find_inputs(&client, asset, amount).await }
                },
                loan_request,
                38_000, // value of 1 BTC as of 18.06.2021
            )
            .await
            .unwrap();
        let loan_response = lender.loan_response();

        let borrower = borrower.interpret(&SECP256K1, loan_response).unwrap();
        let loan_transaction = borrower
            .sign(|transaction| async move { Ok(borrower_wallet.sign_all_inputs(transaction)) })
            .await
            .unwrap();

        let loan_transaction = lender
            .finalise_loan(loan_transaction, {
                let client = client.clone();
                |transaction| async move { client.sign_raw_transaction(&transaction).await }
            })
            .await
            .unwrap();

        client
            .send_raw_transaction(&loan_transaction)
            .await
            .unwrap();

        let liquidation_transaction = lender
            .liquidation_transaction(&mut rng, &SECP256K1, Amount::from_sat(1))
            .await
            .unwrap();

        client
            .send_raw_transaction(&liquidation_transaction)
            .await
            .expect_err("could liquidate before loan term");

        client.generatetoaddress(5, &miner_address).await.unwrap();

        client
            .send_raw_transaction(&liquidation_transaction)
            .await
            .expect("could not liquidate after loan term");
    }

    #[tokio::test]
    async fn lend_and_dynamic_liquidate() {
        init_logger();

        let mut rng = ChaChaRng::seed_from_u64(0);

        let tc_client = Cli::default();
        let (client, _container) = {
            let blockchain = Elementsd::new(&tc_client, "0.18.1.9").unwrap();

            (
                elements_rpc::Client::new(blockchain.node_url.clone().into()).unwrap(),
                blockchain,
            )
        };

        let bitcoin_asset_id = client.get_bitcoin_asset_id().await.unwrap();
        let usdt_asset_id = client.issueasset(40.0, 0.0, false).await.unwrap().asset;
        let (oracle_sk, oracle_pk) = make_keypair(&mut rng);

        let miner_address = client.get_new_segwit_confidential_address().await.unwrap();
        client
            .send_asset_to_address(&miner_address, Amount::from_btc(5.0).unwrap(), None)
            .await
            .unwrap();
        client.generatetoaddress(10, &miner_address).await.unwrap();

        let (borrower, borrower_wallet) = {
            let mut wallet = Wallet::new(&mut rng);

            let collateral_amount = Amount::ONE_BTC;

            let address = wallet.address();
            let address_blinding_sk = wallet.dump_blinding_sk();

            // fund borrower address with bitcoin
            let txid = client
                .send_asset_to_address(&address, collateral_amount * 2, Some(bitcoin_asset_id))
                .await
                .unwrap();

            wallet.add_known_utxo(&client, txid).await;

            // fund wallet with some usdt to pay back the loan later on
            let txid = client
                .send_asset_to_address(
                    &address,
                    Amount::from_btc(2.0).unwrap(),
                    Some(usdt_asset_id),
                )
                .await
                .unwrap();
            wallet.add_known_utxo(&client, txid).await;

            client.generatetoaddress(1, &miner_address).await.unwrap();

            let timelock = client.get_blockcount().await.unwrap() + 100;

            let borrower = Borrower0::new(
                &mut rng,
                {
                    let wallet = wallet.clone();
                    |amount, asset| async move { wallet.find_inputs(asset, amount).await }
                },
                address.clone(),
                address_blinding_sk,
                collateral_amount,
                Amount::ONE_SAT,
                timelock,
                bitcoin_asset_id,
                usdt_asset_id,
            )
            .await
            .unwrap();

            (borrower, wallet)
        };

        let (lender, _lender_address) = {
            let address = client.get_new_segwit_confidential_address().await.unwrap();
            let address_blinder = blinding_key(&client, &address).await.unwrap();

            let lender = Lender0::new(
                &mut rng,
                bitcoin_asset_id,
                usdt_asset_id,
                address.clone(),
                address_blinder,
                oracle_pk,
            )
            .unwrap();

            (lender, address)
        };

        let loan_request = borrower.loan_request();

        let lender = lender
            .interpret(
                &mut rng,
                &SECP256K1,
                {
                    let client = client.clone();
                    |amount, asset| async move { find_inputs(&client, asset, amount).await }
                },
                loan_request,
                38_000, // value of 1 BTC as of 18.06.2021
            )
            .await
            .unwrap();
        let loan_response = lender.loan_response();

        let borrower = borrower.interpret(&SECP256K1, loan_response).unwrap();
        let loan_transaction = borrower
            .sign(|transaction| async move { Ok(borrower_wallet.sign_all_inputs(transaction)) })
            .await
            .unwrap();

        let loan_transaction = lender
            .finalise_loan(loan_transaction, {
                let client = client.clone();
                |transaction| async move { client.sign_raw_transaction(&transaction).await }
            })
            .await
            .unwrap();

        client
            .send_raw_transaction(&loan_transaction)
            .await
            .unwrap();

        // Oracle message too early:
        {
            // before contract creation
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_timestamp = now - 3600;
            // price dips below minimum
            let current_btc_price = 0;

            let oracle_msg = oracle::Message::new(current_btc_price, current_timestamp);
            let oracle_sig = SECP256K1.sign(&oracle_msg.message_hash(), &oracle_sk);

            let liquidation_transaction = lender
                .dynamic_liquidation_transaction(
                    &mut rng,
                    &SECP256K1,
                    oracle_msg,
                    oracle_sig,
                    Amount::ONE_SAT,
                )
                .await
                .unwrap();

            client
                .send_raw_transaction(&liquidation_transaction)
                .await
                .expect_err("could liquidate with proof of dip before contract creation");
        }

        // Price too high:
        {
            // fast forward
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_timestamp = now + 3600;
            // price remains way above threshold
            let current_btc_price = 1_000_000;

            let oracle_msg = oracle::Message::new(current_btc_price, current_timestamp);
            let oracle_sig = SECP256K1.sign(&oracle_msg.message_hash(), &oracle_sk);

            let liquidation_transaction = lender
                .dynamic_liquidation_transaction(
                    &mut rng,
                    &SECP256K1,
                    oracle_msg,
                    oracle_sig,
                    Amount::ONE_SAT,
                )
                .await
                .unwrap();

            client
                .send_raw_transaction(&liquidation_transaction)
                .await
                .expect_err("could liquidate with proof of dip above threshold");
        }

        // Not signed by oracle:
        {
            // fast forward
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_timestamp = now + 3600;
            // price dips below minimum
            let current_btc_price = 0;

            let oracle_msg = oracle::Message::new(current_btc_price, current_timestamp);

            // signed by a fake oracle
            let (fake_oracle_sk, _) = make_keypair(&mut rng);
            let oracle_sig = SECP256K1.sign(&oracle_msg.message_hash(), &fake_oracle_sk);

            let liquidation_transaction = lender
                .dynamic_liquidation_transaction(
                    &mut rng,
                    &SECP256K1,
                    oracle_msg,
                    oracle_sig,
                    Amount::ONE_SAT,
                )
                .await
                .unwrap();

            client
                .send_raw_transaction(&liquidation_transaction)
                .await
                .expect_err("could liquidate with invalid valid proof of dip");
        }

        // Success:
        {
            // fast forward
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let current_timestamp = now + 3600;
            // price dips below minimum
            let current_btc_price = 0;

            let oracle_msg = oracle::Message::new(current_btc_price, current_timestamp);
            let oracle_sig = SECP256K1.sign(&oracle_msg.message_hash(), &oracle_sk);

            let liquidation_transaction = lender
                .dynamic_liquidation_transaction(
                    &mut rng,
                    &SECP256K1,
                    oracle_msg,
                    oracle_sig,
                    Amount::ONE_SAT,
                )
                .await
                .unwrap();

            client
                .send_raw_transaction(&liquidation_transaction)
                .await
                .expect("could not liquidate with valid proof of dip");
        }
    }

    fn init_logger() {
        // force enabling log output
        let _ = env_logger::builder().is_test(true).try_init();
    }

    async fn blinding_key(client: &elements_rpc::Client, address: &Address) -> Result<SecretKey> {
        let master_blinding_key = client.dumpmasterblindingkey().await?;
        let master_blinding_key = hex::decode(master_blinding_key)?;

        let sk = derive_blinding_key(master_blinding_key, address.script_pubkey())?;

        Ok(sk)
    }

    async fn find_inputs(
        client: &elements_rpc::Client,
        asset: AssetId,
        amount: Amount,
    ) -> Result<Vec<crate::input::Input>> {
        let inputs = client.select_inputs_for(asset, amount, false).await?;

        let master_blinding_key = client.dumpmasterblindingkey().await?;
        let master_blinding_key = hex::decode(master_blinding_key)?;

        let inputs = inputs
            .into_iter()
            .map(|(txin, tx_out)| {
                let input_blinding_sk =
                    derive_blinding_key(master_blinding_key.clone(), tx_out.script_pubkey.clone())?;

                Result::<_, anyhow::Error>::Ok(crate::input::Input {
                    txin,
                    original_txout: tx_out,
                    blinding_key: input_blinding_sk,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(inputs)
    }

    fn derive_blinding_key(
        master_blinding_key: Vec<u8>,
        script_pubkey: Script,
    ) -> Result<SecretKey> {
        use hmac::{Hmac, Mac, NewMac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_varkey(&master_blinding_key)
            .expect("HMAC can take key of any size");
        mac.update(script_pubkey.as_bytes());

        let result = mac.finalize();
        let blinding_sk = SecretKey::from_slice(&result.into_bytes())?;

        Ok(blinding_sk)
    }

    #[derive(Clone)]
    pub struct Wallet {
        keypair: (SecretKey, PublicKey),
        blinder_keypair: (SecretKey, PublicKey),
        address: Address,
        known_utxos: Vec<(Txid, usize, TxOut)>,
    }

    impl Wallet {
        pub fn new<R>(rng: &mut R) -> Self
        where
            R: RngCore + CryptoRng,
        {
            let (sk, pk) = make_keypair(rng);
            let (blinder_sk, blinder_pk) = make_keypair(rng);

            let address = Address::p2wpkh(&pk, Some(blinder_pk.key), &AddressParams::ELEMENTS);

            Wallet {
                keypair: (sk, pk),
                blinder_keypair: (blinder_sk, blinder_pk),
                address,
                known_utxos: vec![],
            }
        }

        pub fn address(&self) -> Address {
            self.address.clone()
        }

        pub fn dump_blinding_sk(&self) -> SecretKey {
            self.blinder_keypair.0
        }

        pub async fn add_known_utxo(&mut self, client: &elements_rpc::Client, txid: Txid) {
            let transaction = client.get_raw_transaction(txid).await.unwrap();

            let maybe_vout = transaction
                .output
                .iter()
                .position(|txout| txout.script_pubkey == self.address.script_pubkey());

            if let Some(vout) = maybe_vout {
                let txout = transaction.output.get(vout).unwrap();
                self.known_utxos.push((txid, vout, txout.clone()));
            }
        }

        async fn find_inputs(
            &self,
            asset: AssetId,
            target_amount: Amount,
        ) -> Result<Vec<crate::input::Input>> {
            let utxos = self.known_utxos.clone();

            let selected_coins = utxos
                .iter()
                .filter_map(|(txid, vout, tx_out)| {
                    let unblinded_txout = tx_out
                        .unblind(SECP256K1, self.blinder_keypair.0)
                        .expect("all utxos have the same blinding key");
                    let outpoint = OutPoint {
                        txid: *txid,
                        vout: *vout as u32,
                    };
                    let candidate_asset = unblinded_txout.asset;

                    if candidate_asset == asset {
                        Some((outpoint, unblinded_txout.value, tx_out, candidate_asset))
                    } else {
                        log::debug!(
                            "utxo {} with asset id {} is not the sell asset, ignoring",
                            outpoint,
                            candidate_asset
                        );
                        None
                    }
                })
                .find_map(|(outpoint, amount, tx_out, _)| {
                    (amount >= target_amount.as_sat()).then(|| crate::input::Input {
                        txin: outpoint,
                        original_txout: tx_out.clone(),
                        blinding_key: self.blinder_keypair.0,
                    })
                })
                .context("could not select coins")?;

            Ok(vec![selected_coins])
        }

        fn sign_all_inputs(&self, tx: Transaction) -> Transaction {
            let mut tx_to_sign = tx;
            // first try to find out which utxos we know
            let known_inputs = tx_to_sign.clone().input.into_iter().filter_map(|txin| {
                if let Some((_, _, outpoint)) = self
                    .known_utxos
                    .iter()
                    .find(|(txid, _, _)| txid == &txin.previous_output.txid)
                {
                    Some((txin, outpoint.value))
                } else {
                    None
                }
            });

            known_inputs.into_iter().for_each(|(txin, value)| {
                let hash = bitcoin_hashes::hash160::Hash::hash(&self.keypair.1.serialize());
                let script = Builder::new()
                    .push_opcode(opcodes::all::OP_DUP)
                    .push_opcode(opcodes::all::OP_HASH160)
                    .push_slice(&hash.into_inner())
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_CHECKSIG)
                    .into_script();

                let index = tx_to_sign
                    .input
                    .iter()
                    .position(|other| other == &txin)
                    .unwrap();

                let sighash = SigHashCache::new(&tx_to_sign).segwitv0_sighash(
                    index,
                    &script,
                    value,
                    SigHashType::All,
                );
                let sig = SECP256K1.sign(&secp256k1_zkp::Message::from(sighash), &self.keypair.0);

                let mut serialized_signature = sig.serialize_der().to_vec();
                serialized_signature.push(SigHashType::All as u8);

                tx_to_sign.input[index as usize].witness.script_witness =
                    vec![serialized_signature, self.keypair.1.serialize().to_vec()];
            });

            tx_to_sign
        }
    }

    fn make_keypair<R>(rng: &mut R) -> (SecretKey, PublicKey)
    where
        R: RngCore + CryptoRng,
    {
        let sk = SecretKey::new(rng);
        let pk = PublicKey::from_private_key(
            &SECP256K1,
            &PrivateKey {
                compressed: true,
                network: Network::Regtest,
                key: sk,
            },
        );

        (sk, pk)
    }
}
