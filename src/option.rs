use crate::COVENANT_PK;
use anyhow::Result;
use bitcoin_hashes::hex::ToHex;
use elements::bitcoin::secp256k1::rand::{CryptoRng, RngCore};
use elements::bitcoin::secp256k1::{Secp256k1, Signing, Verification};
use elements::bitcoin::PublicKey;
use elements::encode::serialize;
use elements::{Address, AddressParams, AssetId, Transaction, TxIn, TxOut};
use elements_miniscript::Descriptor;

fn option_descriptor(
    buyer_pk: PublicKey,
    underwriter_pk: PublicKey,
    exercise_timelock: u64,
    expiry_timelock: u64,
    strike_price_output: TxOut,
) -> Result<Descriptor<PublicKey>> {
    let strike_price_output = serialize(&strike_price_output).to_hex();

    let desc = format!(
        "elcovwsh(
                {},or_i(
                and_v(after({}), and_v(outputs_pref({}), v:pk({}))
                and_v(v:pk({}), after({}))
        )
        )",
        COVENANT_PK,
        exercise_timelock,
        strike_price_output,
        buyer_pk,
        underwriter_pk,
        expiry_timelock,
    )
    .parse::<Descriptor<elements::bitcoin::PublicKey>>()?;

    Ok(desc)
}

// This is the transaction that creates the option
pub fn btc_call_tx<R, C>(
    rng: &mut R,
    secp: &Secp256k1<C>,
    buyer_pk: PublicKey,
    underwriter_pk: PublicKey,
    underlying_amount: u64,
    premium_amount: u64,
    strike_price: u64,
    exercise_timelock: u64,
    expiry_timelock: u64,
    usdt_asset_id: AssetId,
    bitcoin_asset_id: AssetId,
    address_params: &'static AddressParams,
    mut bob_inputs: Vec<TxIn>,
    mut alice_inputs: Vec<TxIn>,
) -> Result<Transaction>
where
    R: RngCore + CryptoRng,
    C: Verification + Signing,
{
    // Bob provides inputs to fund the underlying amount
    // Alice provides inputs to pay the premium amount
    let mut inputs = vec![];
    inputs.append(&mut alice_inputs);
    inputs.append(&mut bob_inputs);

    // pay USDT from alice to Bob equal to strike price
    let (strike_price_output, ..) = TxOut::new_not_last_confidential(
        rng,
        secp,
        strike_price,
        Address::p2wpkh(&underwriter_pk, todo!(), address_params),
        usdt_asset_id,
        todo!(),
    )?;

    let script = option_descriptor(
        buyer_pk,
        underwriter_pk,
        exercise_timelock,
        expiry_timelock,
        strike_price_output,
    )?;

    let (contract_output, contract_abf, value_vbf) = TxOut::new_not_last_confidential(
        rng,
        secp,
        underlying_amount,
        Address::from_script(
            &script.as_cov()?.into_ms().encode(),
            todo!(),
            address_params,
        )
        .expect("Incorrect script type"),
        bitcoin_asset_id,
        todo!(),
    )?;

    // locked to bob
    let (premium_output, premium_abgf, value_vbf) = TxOut::new_not_last_confidential(
        rng,
        secp,
        premium_amount,
        Address::p2wpkh(&underwriter_pk, todo!(), address_params),
        usdt_asset_id,
        todo!(),
    )?;

    Ok(Transaction {
        version: 0,
        lock_time: 0,
        input: inputs,
        output: vec![contract_output, premium_output],
    })
}

// This is the transaction that exercises the option
struct ExerciseTx;

impl ExerciseTx {
    pub fn new() -> Self {
        Self
    }
}

// This is the transaction that refunds the underlying asset if the option expires
struct ExpiryTx;

impl ExpiryTx {
    pub fn new() -> Self {
        Self
    }
}
