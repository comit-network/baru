extern crate link_cplusplus;

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result};
use baru::loan::{Borrower0, CollateralContract, Lender0};
use baru::oracle;
use elements::bitcoin::Amount;
use elements::secp256k1_zkp::SECP256K1;
use elements::{Address, AddressParams, Transaction, TxOut};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use util::{make_keypair, Wallet};

mod util;

#[tokio::test]
async fn borrow_and_repay() {
    let mut rng = ChaChaRng::seed_from_u64(0);

    let bitcoin_asset_id = "0c5d451941f37b801d04c46920f2bc5bbd3986e5f56cb56c6b17bedc655e9fc6"
        .parse()
        .unwrap();
    let usdt_asset_id = "6b397062b69411b554ec398ae3b25fdc54fab1805126786581a56a7746afbab2"
        .parse()
        .unwrap();
    let (_oracle_sk, oracle_pk) = make_keypair(&mut rng);

    let mut wallet = Wallet::default();
    let borrower = {
        let (_sk, pk) = make_keypair(&mut rng);
        let (blinding_sk, blinding_pk) = make_keypair(&mut rng);
        let address = Address::p2pkh(&pk, Some(blinding_pk.key), &AddressParams::LIQUID);

        let collateral_amount = Amount::ONE_BTC;

        Borrower0::new(
            &mut rng,
            {
                let wallet = &mut wallet;
                |amount, asset| async move { wallet.coin_select(amount, asset) }
            },
            address,
            blinding_sk,
            collateral_amount,
            Amount::ONE_SAT,
            bitcoin_asset_id,
            usdt_asset_id,
        )
        .await
        .unwrap()
    };

    let (lender, _lender_address) = {
        let (_sk, pk) = make_keypair(&mut rng);
        let (blinding_sk, blinding_pk) = make_keypair(&mut rng);
        let address = Address::p2pkh(&pk, Some(blinding_pk.key), &AddressParams::LIQUID);

        let lender = Lender0::new(
            &mut rng,
            bitcoin_asset_id,
            usdt_asset_id,
            address.clone(),
            blinding_sk,
            oracle_pk,
        )
        .unwrap();

        (lender, address)
    };

    let timelock = 10;
    let principal_amount = Amount::from_btc(38_000.0).unwrap();
    let principal_inputs = wallet.coin_select(principal_amount, usdt_asset_id).unwrap();
    let repayment_amount = principal_amount + Amount::from_btc(1_000.0).unwrap();
    let min_collateral_price = 38_000;

    let lender = lender
        .build_loan_transaction(
            &mut rng,
            SECP256K1,
            borrower.fee_sats_per_vbyte(),
            (
                *borrower.collateral_amount(),
                borrower.collateral_inputs().to_vec(),
            ),
            (principal_amount, principal_inputs),
            repayment_amount,
            min_collateral_price,
            (borrower.pk(), borrower.address().clone()),
            timelock,
        )
        .await
        .unwrap();
    let loan_response = lender.loan_response();

    let borrower = borrower.interpret(SECP256K1, loan_response).unwrap();
    let loan_transaction = borrower
        .sign(|tx| async { Ok(wallet.sign_inputs(tx)) })
        .await
        .unwrap();

    let loan_transaction = lender
        .finalise_loan(loan_transaction, {
            |tx| async { Ok(wallet.sign_inputs(tx)) }
        })
        .await
        .unwrap();

    wallet
        .verify_wallet_transaction(&loan_transaction)
        .expect("loan transaction to be correctly signed");

    let wallet = Arc::new(Mutex::new(wallet));
    let loan_repayment_transaction = borrower
        .loan_repayment_transaction(
            &mut rng,
            SECP256K1,
            {
                let wallet = wallet.clone();
                |amount, asset| async move {
                    let mut wallet = wallet.lock().unwrap();
                    wallet.coin_select(amount, asset)
                }
            },
            {
                let wallet = wallet.clone();
                |tx| async move {
                    let wallet = wallet.lock().unwrap();
                    Ok(wallet.sign_inputs(tx))
                }
            },
            Amount::ONE_SAT,
        )
        .await
        .unwrap();

    let wallet_inputs = {
        let wallet = wallet.lock().unwrap();
        &wallet.used_txouts(&loan_repayment_transaction)
    };
    verify_spend_transaction(
        &loan_repayment_transaction,
        &loan_transaction,
        borrower.collateral_contract(),
        wallet_inputs,
    )
    .expect("repayment transaction to spend collateral correctly");
}

#[tokio::test]
async fn lend_and_liquidate() {
    let mut rng = ChaChaRng::seed_from_u64(0);

    let bitcoin_asset_id = "0c5d451941f37b801d04c46920f2bc5bbd3986e5f56cb56c6b17bedc655e9fc6"
        .parse()
        .unwrap();
    let usdt_asset_id = "6b397062b69411b554ec398ae3b25fdc54fab1805126786581a56a7746afbab2"
        .parse()
        .unwrap();
    let (_oracle_sk, oracle_pk) = make_keypair(&mut rng);

    let mut wallet = Wallet::default();
    let borrower = {
        let (_sk, pk) = make_keypair(&mut rng);
        let (blinding_sk, blinding_pk) = make_keypair(&mut rng);
        let address = Address::p2pkh(&pk, Some(blinding_pk.key), &AddressParams::LIQUID);

        let collateral_amount = Amount::ONE_BTC;

        Borrower0::new(
            &mut rng,
            {
                let wallet = &mut wallet;
                |amount, asset| async move { wallet.coin_select(amount, asset) }
            },
            address,
            blinding_sk,
            collateral_amount,
            Amount::ONE_SAT,
            bitcoin_asset_id,
            usdt_asset_id,
        )
        .await
        .unwrap()
    };

    let (lender, _lender_address) = {
        let (_sk, pk) = make_keypair(&mut rng);
        let (blinding_sk, blinding_pk) = make_keypair(&mut rng);
        let address = Address::p2pkh(&pk, Some(blinding_pk.key), &AddressParams::LIQUID);

        let lender = Lender0::new(
            &mut rng,
            bitcoin_asset_id,
            usdt_asset_id,
            address.clone(),
            blinding_sk,
            oracle_pk,
        )
        .unwrap();

        (lender, address)
    };

    let timelock = 10;
    let principal_amount = Amount::from_btc(38_000.0).unwrap();
    let principal_inputs = wallet.coin_select(principal_amount, usdt_asset_id).unwrap();
    let repayment_amount = principal_amount + Amount::from_btc(1_000.0).unwrap();
    let min_collateral_price = 38_000;

    let lender = lender
        .build_loan_transaction(
            &mut rng,
            SECP256K1,
            borrower.fee_sats_per_vbyte(),
            (
                *borrower.collateral_amount(),
                borrower.collateral_inputs().to_vec(),
            ),
            (principal_amount, principal_inputs),
            repayment_amount,
            min_collateral_price,
            (borrower.pk(), borrower.address().clone()),
            timelock,
        )
        .await
        .unwrap();
    let loan_response = lender.loan_response();

    let borrower = borrower.interpret(SECP256K1, loan_response).unwrap();
    let loan_transaction = borrower
        .sign(|tx| async { Ok(wallet.sign_inputs(tx)) })
        .await
        .unwrap();

    let loan_transaction = lender
        .finalise_loan(loan_transaction, {
            |tx| async { Ok(wallet.sign_inputs(tx)) }
        })
        .await
        .unwrap();

    wallet
        .verify_wallet_transaction(&loan_transaction)
        .expect("loan transaction to be correctly signed");

    let liquidation_transaction = lender
        .liquidation_transaction(&mut rng, SECP256K1, Amount::from_sat(1))
        .await
        .unwrap();

    verify_spend_transaction(
        &liquidation_transaction,
        &loan_transaction,
        lender.collateral_contract(),
        &wallet.used_txouts(&liquidation_transaction),
    )
    .expect("liquidation transaction to spend collateral correctly");
}

#[tokio::test]
async fn lend_and_dynamic_liquidate() {
    let mut rng = ChaChaRng::seed_from_u64(0);

    let bitcoin_asset_id = "0c5d451941f37b801d04c46920f2bc5bbd3986e5f56cb56c6b17bedc655e9fc6"
        .parse()
        .unwrap();
    let usdt_asset_id = "6b397062b69411b554ec398ae3b25fdc54fab1805126786581a56a7746afbab2"
        .parse()
        .unwrap();
    let (oracle_sk, oracle_pk) = make_keypair(&mut rng);

    let mut wallet = Wallet::default();
    let borrower = {
        let (_sk, pk) = make_keypair(&mut rng);
        let (blinding_sk, blinding_pk) = make_keypair(&mut rng);
        let address = Address::p2pkh(&pk, Some(blinding_pk.key), &AddressParams::LIQUID);

        let collateral_amount = Amount::ONE_BTC;

        Borrower0::new(
            &mut rng,
            {
                let wallet = &mut wallet;
                |amount, asset| async move { wallet.coin_select(amount, asset) }
            },
            address,
            blinding_sk,
            collateral_amount,
            Amount::ONE_SAT,
            bitcoin_asset_id,
            usdt_asset_id,
        )
        .await
        .unwrap()
    };

    let (lender, _lender_address) = {
        let (_sk, pk) = make_keypair(&mut rng);
        let (blinding_sk, blinding_pk) = make_keypair(&mut rng);
        let address = Address::p2pkh(&pk, Some(blinding_pk.key), &AddressParams::LIQUID);

        let lender = Lender0::new(
            &mut rng,
            bitcoin_asset_id,
            usdt_asset_id,
            address.clone(),
            blinding_sk,
            oracle_pk,
        )
        .unwrap();

        (lender, address)
    };

    let timelock = 10;
    let principal_amount = Amount::from_btc(38_000.0).unwrap();
    let principal_inputs = wallet.coin_select(principal_amount, usdt_asset_id).unwrap();
    let repayment_amount = principal_amount + Amount::from_btc(1_000.0).unwrap();
    let min_collateral_price = 38_000;

    let lender = lender
        .build_loan_transaction(
            &mut rng,
            SECP256K1,
            borrower.fee_sats_per_vbyte(),
            (
                *borrower.collateral_amount(),
                borrower.collateral_inputs().to_vec(),
            ),
            (principal_amount, principal_inputs),
            repayment_amount,
            min_collateral_price,
            (borrower.pk(), borrower.address().clone()),
            timelock,
        )
        .await
        .unwrap();
    let loan_response = lender.loan_response();

    let borrower = borrower.interpret(SECP256K1, loan_response).unwrap();
    let loan_transaction = borrower
        .sign(|tx| async { Ok(wallet.sign_inputs(tx)) })
        .await
        .unwrap();

    let loan_transaction = lender
        .finalise_loan(loan_transaction, {
            |tx| async { Ok(wallet.sign_inputs(tx)) }
        })
        .await
        .unwrap();

    wallet
        .verify_wallet_transaction(&loan_transaction)
        .expect("loan transaction to be correctly signed");

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
                SECP256K1,
                oracle_msg,
                oracle_sig,
                Amount::ONE_SAT,
            )
            .await
            .unwrap();

        verify_spend_transaction(
            &liquidation_transaction,
            &loan_transaction,
            lender.collateral_contract(),
            &wallet.used_txouts(&liquidation_transaction),
        )
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
                SECP256K1,
                oracle_msg,
                oracle_sig,
                Amount::ONE_SAT,
            )
            .await
            .unwrap();

        verify_spend_transaction(
            &liquidation_transaction,
            &loan_transaction,
            lender.collateral_contract(),
            &wallet.used_txouts(&liquidation_transaction),
        )
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
                SECP256K1,
                oracle_msg,
                oracle_sig,
                Amount::ONE_SAT,
            )
            .await
            .unwrap();

        verify_spend_transaction(
            &liquidation_transaction,
            &loan_transaction,
            lender.collateral_contract(),
            &wallet.used_txouts(&liquidation_transaction),
        )
        .expect_err("could liquidate with invalid proof of dip");
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
                SECP256K1,
                oracle_msg,
                oracle_sig,
                Amount::ONE_SAT,
            )
            .await
            .unwrap();

        verify_spend_transaction(
            &liquidation_transaction,
            &loan_transaction,
            lender.collateral_contract(),
            &wallet.used_txouts(&liquidation_transaction),
        )
        .expect("dynamic liquidation transaction to spend collateral correctly");
    }
}

fn verify_spend_transaction(
    spend_transaction: &Transaction,
    loan_transaction: &Transaction,
    collateral_contract: &CollateralContract,
    wallet_inputs: &[TxOut],
) -> Result<()> {
    let (vin, collateral) = spend_transaction
        .input
        .iter()
        .enumerate()
        .find_map(|(i, input)| {
            let comes_from_loan = input.previous_output.txid == loan_transaction.txid();

            let spent_output = &loan_transaction.output[input.previous_output.vout as usize];
            let is_collateral =
                { collateral_contract.address().script_pubkey() == spent_output.script_pubkey };

            (comes_from_loan && is_collateral).then(|| (i, spent_output))
        })
        .expect("spend transaction takes collateral output as input");

    elements_consensus::verify(
        collateral.script_pubkey.clone(),
        &collateral.value,
        vin,
        spend_transaction,
    )
    .expect("input index out of bounds")
    .context("spend transaction cannot spend collateral output")?;

    let spend_inputs = vec![wallet_inputs, &[collateral.clone()]].concat();

    spend_transaction
        .verify_tx_amt_proofs(SECP256K1, &spend_inputs)
        .expect("spend transaction amounts or assets don't add up");

    Ok(())
}
