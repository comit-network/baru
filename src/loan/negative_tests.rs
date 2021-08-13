use elements::confidential::{Asset, AssetBlindingFactor, ValueBlindingFactor};
use elements::secp256k1_zkp::{SecretKey, SECP256K1};
use elements::{
    Address, AddressParams, AssetId, AssetIssuance, OutPoint, Script, Transaction, TxIn,
    TxInWitness, TxOut, TxOutSecrets,
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

use super::{make_keypair, Chain, CollateralContract};

#[tokio::test]
async fn wrong_loan_repayment_amount() {
    let mut rng = ChaChaRng::seed_from_u64(0);

    let (
        mut repayment_tx,
        collateral_contract,
        collateral_output,
        expected_asset,
        expected_address,
        expected_amount,
        borrower_sk,
    ) = prepare_loan_repayment_tx(&mut rng);

    let wrong_amount = expected_amount - 5_000;
    add_repayment_output(
        &mut rng,
        &mut repayment_tx,
        wrong_amount,
        expected_address,
        expected_asset,
    );

    collateral_contract
        .satisfy_loan_repayment(
            &mut repayment_tx,
            collateral_output.value,
            0,
            |message| async move { Ok(SECP256K1.sign(&message, &borrower_sk)) },
        )
        .await
        .expect_err("could spend collateral with wrong repayment amount");
}

#[tokio::test]
async fn wrong_loan_repayment_address() {
    let mut rng = ChaChaRng::seed_from_u64(0);

    let (
        mut repayment_tx,
        collateral_contract,
        collateral_output,
        expected_asset,
        _expected_address,
        expected_amount,
        borrower_sk,
    ) = prepare_loan_repayment_tx(&mut rng);

    let wrong_address = {
        let (_wrong_sk, wrong_pk) = make_keypair(&mut rng);
        let (_wrong_blinding_sk, wrong_blinding_pk) = make_keypair(&mut rng);

        Address::p2pkh(
            &wrong_pk,
            Some(wrong_blinding_pk.key),
            &AddressParams::ELEMENTS,
        )
    };
    add_repayment_output(
        &mut rng,
        &mut repayment_tx,
        expected_amount,
        wrong_address,
        expected_asset,
    );

    collateral_contract
        .satisfy_loan_repayment(
            &mut repayment_tx,
            collateral_output.value,
            0,
            |message| async move { Ok(SECP256K1.sign(&message, &borrower_sk)) },
        )
        .await
        .expect_err("could spend collateral with wrong repayment address");
}

#[tokio::test]
async fn wrong_loan_repayment_asset() {
    let mut rng = ChaChaRng::seed_from_u64(0);

    let (
        mut repayment_tx,
        collateral_contract,
        collateral_output,
        _expected_asset,
        expected_address,
        expected_amount,
        borrower_sk,
    ) = prepare_loan_repayment_tx(&mut rng);

    let wrong_asset = "600c9579b066bd69632dbbf0686610d02a46295494d14071b2f569e3a2553795"
        .parse()
        .unwrap();
    add_repayment_output(
        &mut rng,
        &mut repayment_tx,
        expected_amount,
        expected_address,
        wrong_asset,
    );

    collateral_contract
        .satisfy_loan_repayment(
            &mut repayment_tx,
            collateral_output.value,
            0,
            |message| async move { Ok(SECP256K1.sign(&message, &borrower_sk)) },
        )
        .await
        .expect_err("could spend collateral with wrong repayment asset");
}

#[tokio::test]
async fn wrong_loan_repayment_signer() {
    let mut rng = ChaChaRng::seed_from_u64(0);

    let (
        mut repayment_tx,
        collateral_contract,
        collateral_output,
        expected_asset,
        expected_address,
        expected_amount,
        _borrower_sk,
    ) = prepare_loan_repayment_tx(&mut rng);

    add_repayment_output(
        &mut rng,
        &mut repayment_tx,
        expected_amount,
        expected_address,
        expected_asset,
    );

    let (wrong_signing_sk, _) = make_keypair(&mut rng);
    collateral_contract
        .satisfy_loan_repayment(
            &mut repayment_tx,
            collateral_output.value,
            0,
            |message| async move { Ok(SECP256K1.sign(&message, &wrong_signing_sk)) },
        )
        .await
        .expect_err("could spend collateral with wrong signature");
}

fn prepare_loan_repayment_tx<R>(
    rng: &mut R,
) -> (
    Transaction,
    CollateralContract,
    TxOut,
    AssetId,
    Address,
    u64,
    SecretKey,
)
where
    R: RngCore + CryptoRng,
{
    let collateral_asset_id = "0c5d451941f37b801d04c46920f2bc5bbd3986e5f56cb56c6b17bedc655e9fc6"
        .parse()
        .unwrap();
    let principal_asset_id = "6b397062b69411b554ec398ae3b25fdc54fab1805126786581a56a7746afbab2"
        .parse()
        .unwrap();

    let (_oracle_sk, oracle_pk) = make_keypair(rng);
    let (borrower_sk, borrower_pk) = make_keypair(rng);
    let (_lender_sk, lender_pk) = make_keypair(rng);
    let (_repayment_sk, repayment_pk) = make_keypair(rng);
    let (repayment_blinding_sk, repayment_blinding_pk) = make_keypair(rng);
    let repayment_address = Address::p2wpkh(
        &repayment_pk,
        Some(repayment_blinding_pk.key),
        &AddressParams::ELEMENTS,
    );
    let collateral_amount = 100_000;
    let repayment_amount = 20_000;
    let (repayment_output, _repayment_abf, _repayment_vbf) = {
        let input_abf = AssetBlindingFactor::new(rng);
        let input_asset = Asset::new_confidential(SECP256K1, principal_asset_id, input_abf);
        let input_amount = 0;
        let input_vbf = ValueBlindingFactor::new(rng);
        let input_secrets =
            TxOutSecrets::new(principal_asset_id, input_abf, input_amount, input_vbf);
        let inputs = [(input_asset, Some(&input_secrets))];

        TxOut::new_not_last_confidential(
            rng,
            SECP256K1,
            repayment_amount,
            repayment_address.clone(),
            principal_asset_id,
            &inputs,
        )
        .unwrap()
    };
    let (_collateral_blinding_sk, collateral_blinding_pk) = make_keypair(rng);
    let collateral_contract = CollateralContract::new(
        borrower_pk,
        lender_pk,
        10,
        (repayment_output, repayment_blinding_sk),
        oracle_pk,
        10_000,
        0,
        Chain::Elements,
    )
    .unwrap();
    let (collateral_output, _collateral_abf, _collateral_vbf) = {
        let input_abf = AssetBlindingFactor::new(rng);
        let input_asset = Asset::new_confidential(SECP256K1, collateral_asset_id, input_abf);
        let input_amount = 1_000_000;
        let input_vbf = ValueBlindingFactor::new(rng);
        let input_secrets =
            TxOutSecrets::new(collateral_asset_id, input_abf, input_amount, input_vbf);
        let inputs = [(input_asset, Some(&input_secrets))];
        TxOut::new_not_last_confidential(
            rng,
            SECP256K1,
            collateral_amount,
            collateral_contract.blinded_address(collateral_blinding_pk.key),
            collateral_asset_id,
            &inputs,
        )
        .unwrap()
    };

    let repayment_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: "e867486a7df31bece8cf85b27f30d9eaa7d1a9393da018ab614b39daf3042693"
                    .parse()
                    .unwrap(),
                vout: 0,
            },
            is_pegin: false,
            has_issuance: false,
            script_sig: Script::new(),
            sequence: 0,
            asset_issuance: AssetIssuance::default(),
            witness: TxInWitness::default(),
        }],
        output: Vec::new(),
    };

    (
        repayment_tx,
        collateral_contract,
        collateral_output,
        principal_asset_id,
        repayment_address,
        repayment_amount,
        borrower_sk,
    )
}

fn add_repayment_output<R>(
    rng: &mut R,
    tx: &mut Transaction,
    amount: u64,
    address: Address,
    asset: AssetId,
) where
    R: RngCore + CryptoRng,
{
    let (repayment_output, _repayment_abf, _repayment_vbf) = {
        let input_abf = AssetBlindingFactor::new(rng);
        let input_asset = Asset::new_confidential(SECP256K1, asset, input_abf);
        let input_amount = 0;
        let input_vbf = ValueBlindingFactor::new(rng);
        let input_secrets = TxOutSecrets::new(asset, input_abf, input_amount, input_vbf);
        let inputs = [(input_asset, Some(&input_secrets))];

        TxOut::new_not_last_confidential(rng, SECP256K1, amount, address, asset, &inputs).unwrap()
    };
    tx.output.push(repayment_output);
}
