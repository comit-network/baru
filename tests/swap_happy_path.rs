extern crate link_cplusplus;

use baru::swap::{alice_finalize_transaction, bob_create_transaction, Actor};
use elements::bitcoin::Amount;
use elements::secp256k1_zkp::SECP256K1;
use elements::{bitcoin, Address, AddressParams};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use util::{make_keypair, Wallet};

mod util;

#[tokio::test]
async fn collaborative_create_and_sign() {
    let mut rng = ChaChaRng::seed_from_u64(0);

    let btc_asset_id = "0c5d451941f37b801d04c46920f2bc5bbd3986e5f56cb56c6b17bedc655e9fc6"
        .parse()
        .unwrap();
    let usdt_asset_id = "6b397062b69411b554ec398ae3b25fdc54fab1805126786581a56a7746afbab2"
        .parse()
        .unwrap();

    let amount_alice = bitcoin::Amount::from_sat(50_000_000);
    let amount_bob = bitcoin::Amount::from_sat(25_000_000);

    let mut wallet = Wallet::default();

    let alice_inputs = wallet
        .coin_select(amount_bob + Amount::from_sat(100_000), usdt_asset_id)
        .unwrap();

    let final_address_alice = make_confidential_address(&mut rng);

    let alice = Actor::new(
        SECP256K1,
        alice_inputs.clone(),
        final_address_alice,
        btc_asset_id,
        amount_alice,
    )
    .unwrap();

    let bob_inputs = wallet
        .coin_select(amount_alice + Amount::from_sat(100_000), btc_asset_id)
        .unwrap();

    let final_address_bob = make_confidential_address(&mut rng);

    let bob = Actor::new(
        SECP256K1,
        bob_inputs.clone(),
        final_address_bob.clone(),
        usdt_asset_id,
        amount_bob,
    )
    .unwrap();

    let transaction = bob_create_transaction(
        &mut rng,
        SECP256K1,
        alice,
        bob,
        btc_asset_id,
        Amount::from_sat(1), // sats / vbyte
        |tx| async { Ok(wallet.sign_inputs(tx)) },
    )
    .await
    .unwrap();

    let transaction =
        alice_finalize_transaction(transaction, |tx| async { Ok(wallet.sign_inputs(tx)) })
            .await
            .unwrap();

    wallet
        .verify_wallet_transaction(&transaction)
        .expect("to have correctly signed all inputs");
}

pub fn make_confidential_address<R>(rng: &mut R) -> Address
where
    R: RngCore + CryptoRng,
{
    let (_sk, pk) = make_keypair(rng);
    let (_blinding_sk, blinding_pk) = make_keypair(rng);

    Address::p2wpkh(&pk, Some(blinding_pk.key), &AddressParams::ELEMENTS)
}
