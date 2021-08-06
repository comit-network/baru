use crate::estimate_transaction_size::estimate_virtual_size;
use crate::input::{Input, UnblindedInput};
use anyhow::{bail, Context, Result};
use elements::bitcoin::Amount;
use elements::hashes::{hash160, Hash};
use elements::script::Builder;
use elements::secp256k1_zkp::{Message, PublicKey};
use elements::sighash::SigHashCache;
use elements::{
    confidential, opcodes, Address, AssetId, SigHashType, Transaction, TxIn, TxOut, TxOutSecrets,
};
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{Secp256k1, SecretKey, Signing, Verification};
use std::future::Future;

// TODO: Replace this with a PSET
pub async fn bob_create_transaction<R, C, S, F>(
    rng: &mut R,
    secp: &Secp256k1<C>,
    alice: Actor,
    bob: Actor,
    fee_asset: AssetId,
    fee_sats_per_vbyte: Amount,
    bob_signer: S,
) -> Result<Transaction>
where
    R: RngCore + CryptoRng,
    C: Signing,
    S: FnOnce(Transaction) -> F,
    F: Future<Output = Result<Transaction>>,
{
    let alice_inputs = alice
        .inputs
        .iter()
        .map(|input| (input.txout.asset, &input.secrets));
    let bob_inputs = bob
        .inputs
        .iter()
        .map(|input| (input.txout.asset, &input.secrets));

    let inputs = alice_inputs.chain(bob_inputs).collect::<Vec<_>>();

    let fee_amount = Amount::from_sat(
        estimate_virtual_size(inputs.len() as u64, 4) * fee_sats_per_vbyte.as_sat(),
    );

    let change_amount_alice = alice
        .calculate_change_amount(bob.receive_asset, bob.receive_amount, fee_asset, fee_amount)
        .context("failed to calculate change amount for alice")?;
    let change_amount_bob = bob
        .calculate_change_amount(
            alice.receive_asset,
            alice.receive_amount,
            fee_asset,
            fee_amount,
        )
        .context("failed to calculate change amount for bob")?;

    let inputs_not_last_confidential = inputs
        .iter()
        .copied()
        .map(|(asset, secrets)| (asset, Some(secrets)))
        .collect::<Vec<_>>();
    let (receive_output_alice, abf_receive_alice, vbf_receive_alice) =
        TxOut::new_not_last_confidential(
            rng,
            secp,
            alice.receive_amount.as_sat(),
            alice.address.clone(),
            alice.receive_asset,
            inputs_not_last_confidential.as_slice(),
        )?;

    let (redeem_output_bob, abf_receive_bob, vbf_receive_bob) = TxOut::new_not_last_confidential(
        rng,
        secp,
        bob.receive_amount.as_sat(),
        bob.address.clone(),
        bob.receive_asset,
        &inputs_not_last_confidential,
    )?;
    let (change_output_alice, abf_change_alice, vbf_change_alice) =
        TxOut::new_not_last_confidential(
            rng,
            secp,
            change_amount_alice.as_sat(),
            alice.address.clone(),
            bob.receive_asset,
            &inputs_not_last_confidential,
        )?;

    let outputs = [
        &TxOutSecrets::new(
            alice.receive_asset,
            abf_receive_alice,
            alice.receive_amount.as_sat(),
            vbf_receive_alice,
        ),
        &TxOutSecrets::new(
            bob.receive_asset,
            abf_receive_bob,
            bob.receive_amount.as_sat(),
            vbf_receive_bob,
        ),
        &TxOutSecrets::new(
            bob.receive_asset,
            abf_change_alice,
            change_amount_alice.as_sat(),
            vbf_change_alice,
        ),
    ];

    let (change_output_bob, _, _) = TxOut::new_last_confidential(
        rng,
        secp,
        change_amount_bob.as_sat(),
        bob.address,
        alice.receive_asset,
        &inputs,
        &outputs[..],
    )?;

    let alice_inputs_iter = alice.inputs.iter().map(|input| input.txin);
    let bob_inputs_iter = bob.inputs.iter().map(|input| input.txin);
    let inputs = alice_inputs_iter
        .chain(bob_inputs_iter)
        .map(|previous_output| TxIn {
            previous_output,
            is_pegin: false,
            has_issuance: false,
            script_sig: Default::default(),
            sequence: 0,
            asset_issuance: Default::default(),
            witness: Default::default(),
        })
        .collect::<Vec<_>>();

    let fee = TxOut::new_fee(fee_amount.as_sat(), fee_asset);

    let transaction = Transaction {
        version: 2,
        lock_time: 0,
        input: inputs,
        output: vec![
            receive_output_alice,
            redeem_output_bob,
            change_output_alice,
            change_output_bob,
            fee,
        ],
    };

    let transaction = bob_signer(transaction).await?;

    Ok(transaction)
}

pub async fn alice_finalize_transaction<S, F>(
    transaction: Transaction,
    alice_signer: S,
) -> Result<Transaction>
where
    S: FnOnce(Transaction) -> F,
    F: Future<Output = Result<Transaction>>,
{
    alice_signer(transaction).await
}

pub fn sign_with_key<C>(
    secp: &Secp256k1<C>,
    cache: &mut SigHashCache<&Transaction>,
    index: usize,
    input_sk: &SecretKey,
    value: confidential::Value,
) -> Vec<Vec<u8>>
where
    C: Signing,
{
    let input_pk = PublicKey::from_secret_key(secp, input_sk);

    let hash = hash160::Hash::hash(&input_pk.serialize());
    let script = Builder::new()
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(&hash.into_inner())
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();

    let sighash = cache.segwitv0_sighash(index, &script, value, SigHashType::All);

    let sig = secp.sign(&Message::from(sighash), input_sk);

    let mut serialized_signature = sig.serialize_der().to_vec();
    serialized_signature.push(SigHashType::All as u8);

    vec![serialized_signature, input_pk.serialize().to_vec()]
}

#[derive(Debug)]
pub struct Actor {
    /// The inputs to cover for the trade.
    inputs: Vec<UnblindedInput>,
    /// The actors's address.
    ///
    /// Used for change as well as receive.
    address: Address,
    /// The ID of the asset the actor is receiving.
    receive_asset: AssetId,
    /// How much of the asset the actor is receiving.
    receive_amount: Amount,
}

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("The inputs contain an AssetId != {0}.")]
pub struct InvalidAssetTypes(pub AssetId);

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("Amount_in ({0}) < amount_out ({1})")]
pub struct InputAmountTooSmall(pub u64, pub u64);

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("Change_amount ({0}) < fee ({1})")]
pub struct ChangeAmountTooSmall(pub u64, pub u64);

impl Actor {
    pub fn new<C>(
        secp: &Secp256k1<C>,
        inputs: Vec<Input>,
        address: Address,
        receive_asset: AssetId,
        receive_amount: Amount,
    ) -> Result<Self>
    where
        C: Verification,
    {
        let inputs = inputs
            .into_iter()
            .map(|input| input.into_unblinded_input(secp))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            inputs,
            address,
            receive_asset,
            receive_amount,
        })
    }

    pub fn calculate_change_amount(
        &self,
        other_receive_asset: AssetId,
        other_receive_amount: Amount,
        fee_asset: AssetId,
        fee_amount: Amount,
    ) -> Result<Amount> {
        if self
            .inputs
            .iter()
            .any(|input| input.secrets.asset != other_receive_asset)
        {
            bail!(InvalidAssetTypes(other_receive_asset))
        }

        let amount_in = self.inputs.iter().map(|input| input.secrets.value).sum();

        let change_amount = Amount::from_sat(amount_in)
            .checked_sub(other_receive_amount)
            .with_context(|| InputAmountTooSmall(amount_in, other_receive_amount.as_sat()))?;

        let change_amount = if other_receive_asset == fee_asset {
            change_amount.checked_sub(fee_amount).with_context(|| {
                ChangeAmountTooSmall(change_amount.as_sat(), fee_amount.as_sat())
            })?
        } else {
            change_amount
        };

        Ok(change_amount)
    }
}
