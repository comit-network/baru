use crate::estimate_transaction_size::estimate_virtual_size;
use crate::input::Input;
use anyhow::{anyhow, bail, Context, Result};
use bitcoin_hashes::hex::ToHex;
use conquer_once::Lazy;
use elements::bitcoin::{Amount, Network, PrivateKey, PublicKey};
use elements::confidential::{Asset, AssetBlindingFactor, ValueBlindingFactor};
use elements::encode::serialize;
use elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use elements::secp256k1_zkp::{Secp256k1, SecretKey, Signing, Verification, SECP256K1};
use elements::sighash::SigHashCache;
use elements::{
    Address, AddressParams, AssetId, OutPoint, SigHashType, Transaction, TxIn, TxInWitness, TxOut,
    TxOutSecrets,
};
use elements_miniscript::descriptor::{CovSatisfier, ElementsTrait};
use elements_miniscript::miniscript::satisfy::After;
use elements_miniscript::{Descriptor, DescriptorTrait};
use secp256k1_zkp::{SurjectionProof, Tag};
use std::collections::HashMap;
use std::future::Future;
use std::str::FromStr;

#[cfg(test)]
mod protocol_tests;
mod stack_simulator;

/// Secret key used to produce a signature which proves that an
/// input's witness stack contains transaction data equivalent to the
/// transaction which includes the input itself.
///
/// This secret key MUST NOT be used for anything other than to
/// satisfy this verification step which enables transaction
/// introspection. It is therefore a global, publicly known secret key
/// to be used in every instance of this protocol.
static COVENANT_SK: Lazy<SecretKey> = Lazy::new(|| {
    SecretKey::from_str("cc5417e929f7756df9a599715ad0780cea75659279cd4e2c0a19adb6339d7011")
        .expect("is a valid key")
});

/// Public key of the `COVENANT_SK`, used to verify that the
/// transaction data on the input's witness stack is equivalent to the
/// transaction which inludes the input itself.
static COVENANT_PK: &str = "03b9b6059008e3576aad58e05a3a3e37133b05f68cda8535ec097ef4bae564a6af";

/// Generate the miniscript descriptor of the collateral output.
///
/// It defines a "liquidation branch" which allows the lender to claim
/// all the collateral for themself if the `timelock` expires. The
/// lender must identify themself by providing a signature on
/// `lender_pk`.
///
/// It also defines a "repayment branch" which allows the borrower to
/// repay the loan to reclaim the collateral. The borrower must
/// identify themself by providing a signature on `borrower_pk`. To
/// ensure that the borrower does indeed repay the loan, the script
/// will check that the spending transaction has the
/// `repayment_output` as vout 0.
///
/// The first element of the covenant descriptor is the shared
/// `covenant_pk`, which is only used to verify that the transaction
/// data on the witness stack matches the transaction which triggered
/// the call.
fn collateral_descriptor(
    borrower_pk: PublicKey,
    lender_pk: PublicKey,
    timelock: u64,
    repayment_output: TxOut,
) -> Result<Descriptor<PublicKey>> {
    let repayment_output = serialize(&repayment_output).to_hex();
    let desc = Descriptor::<elements::bitcoin::PublicKey>::from_str(
        &(format!(
            "elcovwsh({},or_i(and_v(v:pk({}),after({})),and_v(v:pk({}),outputs_pref({}))))",
            COVENANT_PK, lender_pk, timelock, borrower_pk, repayment_output,
        )),
    )?;

    Ok(desc)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoanRequest {
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    pub collateral_amount: Amount,
    collateral_inputs: Vec<Input>,
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    fee_sats_per_vbyte: Amount,
    borrower_pk: PublicKey,
    timelock: u64,
    borrower_address: Address,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoanResponse {
    // TODO: Use this where needed!
    #[serde(with = "transaction_as_string")]
    pub transaction: Transaction,
    lender_pk: PublicKey,
    repayment_collateral_input: Input,
    repayment_collateral_abf: AssetBlindingFactor,
    repayment_collateral_vbf: ValueBlindingFactor,
    pub timelock: u64,
    repayment_principal_output: TxOut,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Borrower0 {
    keypair: (SecretKey, PublicKey),
    address: Address,
    address_blinding_sk: SecretKey,
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    collateral_amount: Amount,
    collateral_inputs: Vec<Input>,
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    fee_sats_per_vbyte: Amount,
    timelock: u64,
    bitcoin_asset_id: AssetId,
    usdt_asset_id: AssetId,
}

impl Borrower0 {
    #[allow(clippy::too_many_arguments)]
    pub async fn new<R, CS, CF>(
        rng: &mut R,
        coin_selector: CS,
        address: Address,
        address_blinding_sk: SecretKey,
        collateral_amount: Amount,
        fee_sats_per_vbyte: Amount,
        timelock: u64,
        bitcoin_asset_id: AssetId,
        usdt_asset_id: AssetId,
    ) -> Result<Self>
    where
        R: RngCore + CryptoRng,
        CS: FnOnce(Amount, AssetId) -> CF,
        CF: Future<Output = Result<Vec<Input>>>,
    {
        let keypair = make_keypair(rng);
        let collateral_inputs = coin_selector(collateral_amount, bitcoin_asset_id).await?;

        Ok(Self {
            keypair,
            address,
            address_blinding_sk,
            collateral_amount,
            collateral_inputs,
            fee_sats_per_vbyte,
            timelock,
            bitcoin_asset_id,
            usdt_asset_id,
        })
    }

    pub fn loan_request(&self) -> LoanRequest {
        LoanRequest {
            collateral_amount: self.collateral_amount,
            collateral_inputs: self.collateral_inputs.clone(),
            fee_sats_per_vbyte: self.fee_sats_per_vbyte,
            borrower_pk: self.keypair.1,
            timelock: self.timelock,
            borrower_address: self.address.clone(),
        }
    }

    /// Interpret loan response from lender.
    ///
    /// This method does not check if the borrower agrees with the
    /// "repayment condition" i.e. the values in
    /// `repayment_collateral_input`. This belongs in a higher level,
    /// much like verifying that other loan conditions haven't
    /// changed.
    pub fn interpret<C>(self, secp: &Secp256k1<C>, loan_response: LoanResponse) -> Result<Borrower1>
    where
        C: Signing + Verification,
    {
        let transaction = loan_response.transaction;

        let principal_tx_out_amount = transaction
            .output
            .iter()
            .find_map(|out| {
                let unblinded_out = out.unblind(secp, self.address_blinding_sk).ok()?;
                let is_principal_out = unblinded_out.asset == self.usdt_asset_id
                    && out.script_pubkey == self.address.script_pubkey();

                is_principal_out.then(|| Amount::from_sat(unblinded_out.value))
            })
            .context("no principal txout")?;

        let collateral_descriptor = collateral_descriptor(
            self.keypair.1,
            loan_response.lender_pk,
            loan_response.timelock,
            loan_response.repayment_principal_output.clone(),
        )?;
        let collateral_address = collateral_descriptor.address(&AddressParams::ELEMENTS)?;

        let collateral_script_pubkey = collateral_address.script_pubkey();
        let collateral_blinding_sk = loan_response.repayment_collateral_input.blinding_key;
        transaction
            .output
            .iter()
            .find_map(|out| {
                let unblinded_out = out.unblind(secp, collateral_blinding_sk).ok()?;
                let is_collateral_out = unblinded_out.asset == self.bitcoin_asset_id
                    && unblinded_out.value == self.collateral_amount.as_sat()
                    && out.script_pubkey == collateral_script_pubkey;

                is_collateral_out.then(|| out)
            })
            .context("no collateral txout")?;

        let collateral_input_amount = self
            .collateral_inputs
            .iter()
            .map(|input| input.clone().into_unblinded_input(secp))
            .try_fold(0, |sum, input| {
                input.map(|input| sum + input.secrets.value).ok()
            })
            .context("could not sum collateral inputs")?;
        let tx_fee = Amount::from_sat(
            estimate_virtual_size(transaction.input.len() as u64, 4)
                * self.fee_sats_per_vbyte.as_sat(),
        );
        let collateral_change_amount = Amount::from_sat(collateral_input_amount)
            .checked_sub(self.collateral_amount)
            .map(|a| a.checked_sub(tx_fee))
            .flatten()
            .with_context(|| {
                format!(
                    "cannot pay for output {} and fee {} with input {}",
                    self.collateral_amount, tx_fee, collateral_input_amount,
                )
            })?;

        transaction
            .output
            .iter()
            .find_map(|out| {
                let unblinded_out = out.unblind(secp, self.address_blinding_sk).ok()?;
                let is_collateral_change_out = unblinded_out.asset == self.bitcoin_asset_id
                    && unblinded_out.value == collateral_change_amount.as_sat()
                    && out.script_pubkey == self.address.script_pubkey();

                is_collateral_change_out.then(|| out)
            })
            .context("no collateral change txout")?;

        Ok(Borrower1 {
            keypair: self.keypair,
            loan_transaction: transaction,
            collateral_amount: self.collateral_amount,
            collateral_descriptor,
            principal_tx_out_amount,
            address: self.address.clone(),
            repayment_collateral_input: loan_response.repayment_collateral_input,
            repayment_collateral_abf: loan_response.repayment_collateral_abf,
            repayment_collateral_vbf: loan_response.repayment_collateral_vbf,
            bitcoin_asset_id: self.bitcoin_asset_id,
            usdt_asset_id: self.usdt_asset_id,
            repayment_principal_output: loan_response.repayment_principal_output,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Borrower1 {
    keypair: (SecretKey, PublicKey),
    pub loan_transaction: Transaction,
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    pub collateral_amount: Amount,
    collateral_descriptor: Descriptor<PublicKey>,
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    pub principal_tx_out_amount: Amount,
    address: Address,
    /// Loan collateral expressed as an input for constructing the
    /// loan repayment transaction.
    repayment_collateral_input: Input,
    repayment_collateral_abf: AssetBlindingFactor,
    repayment_collateral_vbf: ValueBlindingFactor,
    bitcoin_asset_id: AssetId,
    usdt_asset_id: AssetId,
    repayment_principal_output: TxOut,
}

impl Borrower1 {
    pub async fn sign<S, F>(&self, signer: S) -> Result<Transaction>
    where
        S: FnOnce(Transaction) -> F,
        F: Future<Output = Result<Transaction>>,
    {
        signer(self.loan_transaction.clone()).await
    }

    pub async fn loan_repayment_transaction<R, C, CS, CF, SI, SF>(
        &self,
        rng: &mut R,
        secp: &Secp256k1<C>,
        coin_selector: CS,
        signer: SI,
        fee_sats_per_vbyte: Amount,
    ) -> Result<Transaction>
    where
        R: RngCore + CryptoRng,
        C: Verification + Signing,
        CS: FnOnce(Amount, AssetId) -> CF,
        CF: Future<Output = Result<Vec<Input>>>,
        SI: FnOnce(Transaction) -> SF,
        SF: Future<Output = Result<Transaction>>,
    {
        let repayment_amount = self.principal_tx_out_amount;

        // construct collateral input
        let collateral_input = self
            .repayment_collateral_input
            .clone()
            .into_unblinded_input(secp)
            .context("could not unblind repayment collateral input")?;
        let principal_inputs = coin_selector(repayment_amount, self.usdt_asset_id).await?;

        let unblinded_principal_inputs = principal_inputs
            .clone()
            .into_iter()
            .map(|input| input.into_unblinded_input(secp))
            .collect::<Result<Vec<_>>>()?;

        let inputs = {
            let mut borrower_inputs = unblinded_principal_inputs
                .iter()
                .map(|input| (input.txout.asset, &input.secrets))
                .collect::<Vec<_>>();
            borrower_inputs.push((collateral_input.txout.asset, &collateral_input.secrets));

            borrower_inputs
        };

        let mut repayment_principal_output = self.repayment_principal_output.clone();
        let domain = inputs
            .iter()
            .map(|(asset, secrets)| {
                Ok((
                    asset
                        .into_asset_gen(secp)
                        .ok_or_else(|| anyhow!("unexpected explicit or null asset"))?,
                    Tag::from(secrets.asset.into_inner().0),
                    secrets.asset_bf.into_inner(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        repayment_principal_output.witness.surjection_proof = Some(SurjectionProof::new(
            secp,
            rng,
            Tag::from(self.usdt_asset_id.into_inner().0),
            // TODO: Consider changing upstream API to take Tweak
            // SecretKey::from_slice(&self.repayment_collateral_abf.into_inner()[..]).unwrap(),
            self.repayment_collateral_abf.into_inner(),
            domain.as_slice(),
        )?);

        let principal_input_amount = unblinded_principal_inputs
            .iter()
            .fold(0, |acc, input| acc + input.secrets.value);
        let change_amount = Amount::from_sat(principal_input_amount)
            .checked_sub(repayment_amount)
            .with_context(|| {
                format!(
                    "cannot pay for output {} with input {}",
                    repayment_amount, principal_input_amount,
                )
            })?;

        let principal_repayment_output = TxOutSecrets::new(
            self.usdt_asset_id,
            self.repayment_collateral_abf,
            repayment_amount.as_sat(),
            self.repayment_collateral_vbf,
        );
        let mut outputs = vec![principal_repayment_output];

        let mut tx_ins: Vec<OutPoint> = unblinded_principal_inputs
            .clone()
            .into_iter()
            .map(|input| input.txin)
            .collect();
        tx_ins.push(collateral_input.txin);
        let tx_ins = tx_ins
            .into_iter()
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
        let inputs_not_last_confidential = inputs
            .iter()
            .copied()
            .map(|(asset, secrets)| (asset, Some(secrets)))
            .collect::<Vec<_>>();
        let change_output = match change_amount {
            Amount::ZERO => None,
            _ => {
                let (output, abf, vbf) = TxOut::new_not_last_confidential(
                    rng,
                    secp,
                    change_amount.as_sat(),
                    self.address.clone(),
                    self.usdt_asset_id,
                    &inputs_not_last_confidential,
                )
                .context("Change output creation failed")?;

                let principal_change_output =
                    TxOutSecrets::new(self.usdt_asset_id, abf, change_amount.as_sat(), vbf);
                outputs.push(principal_change_output);

                Some(output)
            }
        };
        let tx_fee = Amount::from_sat(
            estimate_virtual_size(tx_ins.len() as u64, 4) * fee_sats_per_vbyte.as_sat(),
        );
        let (collateral_output, _, _) = TxOut::new_last_confidential(
            rng,
            secp,
            (self.collateral_amount - tx_fee).as_sat(),
            self.address.clone(),
            self.bitcoin_asset_id,
            &inputs,
            outputs.iter().collect::<Vec<_>>().as_ref(),
        )
        .context("Creation of collateral output failed")?;

        let tx_fee_output = TxOut::new_fee(tx_fee.as_sat(), self.bitcoin_asset_id);

        let mut tx_outs = vec![repayment_principal_output.clone()];
        if let Some(change_output) = change_output {
            tx_outs.push(change_output)
        }
        tx_outs.push(collateral_output);
        tx_outs.push(tx_fee_output);

        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: tx_ins,
            output: tx_outs,
        };

        // fulfill collateral input covenant script
        {
            let descriptor = self.collateral_descriptor.clone();
            let descriptor_cov = descriptor.as_cov()?;

            let collateral_value = self.repayment_collateral_input.original_txout.value;
            let cov_script = descriptor_cov.cov_script_code();

            let cov_sat =
                CovSatisfier::new_segwitv0(&tx, 1, collateral_value, &cov_script, SigHashType::All);

            let cov_pk_sat = {
                let mut hash_map = HashMap::new();
                let sighash = cov_sat.segwit_sighash()?;
                let sighash = elements::secp256k1_zkp::Message::from(sighash);

                let sig = SECP256K1.sign(&sighash, &COVENANT_SK);
                hash_map.insert(*descriptor_cov.pk(), (sig, SigHashType::All));

                hash_map
            };

            let ident_pk_sat = {
                let mut hash_map = HashMap::new();

                let script = descriptor.explicit_script();
                let sighash = SigHashCache::new(&tx).segwitv0_sighash(
                    1,
                    &script,
                    collateral_value,
                    SigHashType::All,
                );
                let sighash = elements::secp256k1_zkp::Message::from(sighash);

                let sig = SECP256K1.sign(&sighash, &self.keypair.0);
                hash_map.insert(self.keypair.1, (sig, SigHashType::All));

                hash_map
            };

            let (script_witness, _) =
                descriptor_cov.get_satisfaction((cov_sat, cov_pk_sat, ident_pk_sat))?;

            tx.input[1].witness = TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness,
                pegin_witness: vec![],
            };
        };

        // sign repayment input of the principal amount
        let tx = { signer(tx).await? };

        Ok(tx)
    }
}

pub struct Lender0 {
    keypair: (SecretKey, PublicKey),
    address: Address,
    bitcoin_asset_id: AssetId,
    usdt_asset_id: AssetId,
}

impl Lender0 {
    pub fn new<R>(
        rng: &mut R,
        bitcoin_asset_id: AssetId,
        usdt_asset_id: AssetId,
        address: Address,
    ) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        let keypair = make_keypair(rng);

        Ok(Self {
            keypair,
            address,
            bitcoin_asset_id,
            usdt_asset_id,
        })
    }

    /// Interpret a loan request and performs lender logic.
    ///
    /// rate is expressed in usdt sats per btc, i.e. rate = 1 BTC / USDT
    pub async fn interpret<R, C, CS, CF>(
        self,
        rng: &mut R,
        secp: &Secp256k1<C>,
        coin_selector: CS,
        loan_request: LoanRequest,
        rate: u64,
    ) -> Result<Lender1>
    where
        R: RngCore + CryptoRng,
        C: Verification + Signing,
        CS: FnOnce(Amount, AssetId) -> CF,
        CF: Future<Output = Result<Vec<Input>>>,
    {
        let principal_amount = Lender0::calc_principal_amount(&loan_request, rate)?;
        let collateral_inputs = loan_request
            .collateral_inputs
            .into_iter()
            .map(|input| input.into_unblinded_input(secp))
            .collect::<Result<Vec<_>>>()?;

        let borrower_inputs = collateral_inputs
            .iter()
            .map(|input| (input.txout.asset, &input.secrets));

        let principal_inputs = coin_selector(principal_amount, self.usdt_asset_id).await?;
        let unblinded_principal_inputs = principal_inputs
            .clone()
            .into_iter()
            .map(|input| input.into_unblinded_input(secp))
            .collect::<Result<Vec<_>>>()?;
        let lender_inputs = unblinded_principal_inputs
            .iter()
            .map(|input| (input.txout.asset, &input.secrets))
            .collect::<Vec<_>>();

        let inputs = borrower_inputs.chain(lender_inputs).collect::<Vec<_>>();

        let collateral_input_amount = collateral_inputs
            .iter()
            .fold(0, |sum, input| sum + input.secrets.value);

        let collateral_amount = loan_request.collateral_amount;

        let (repayment_principal_output, repayment_collateral_abf, repayment_collateral_vbf) = {
            let dummy_asset_id = self.usdt_asset_id;
            let dummy_abf = AssetBlindingFactor::new(rng);
            let dummy_asset = Asset::new_confidential(secp, dummy_asset_id, dummy_abf);
            let dummy_amount = principal_amount.as_sat();
            let dummy_vbf = ValueBlindingFactor::new(rng);
            let dummy_secrets =
                TxOutSecrets::new(dummy_asset_id, dummy_abf, dummy_amount, dummy_vbf);
            let dummy_inputs = [(dummy_asset, Some(&dummy_secrets))];

            TxOut::new_not_last_confidential(
                rng,
                secp,
                principal_amount.as_sat(),
                self.address.clone(),
                self.usdt_asset_id,
                &dummy_inputs,
            )?
        };

        let (_, lender_pk) = self.keypair;
        let (collateral_blinding_sk, collateral_blinding_pk) = make_keypair(rng);

        let collateral_descriptor = collateral_descriptor(
            loan_request.borrower_pk,
            lender_pk,
            loan_request.timelock,
            repayment_principal_output.clone(),
        )
        .context("could not build collateral descriptor")?;
        let collateral_address = collateral_descriptor
            .blind_addr(Some(collateral_blinding_pk.key), &AddressParams::ELEMENTS)?;

        let inputs_not_last_confidential = inputs
            .iter()
            .map(|(asset, secrets)| (*asset, Some(*secrets)))
            .collect::<Vec<_>>();
        let (collateral_tx_out, abf_collateral, vbf_collateral) = TxOut::new_not_last_confidential(
            rng,
            secp,
            collateral_amount.as_sat(),
            collateral_address.clone(),
            self.bitcoin_asset_id,
            inputs_not_last_confidential.as_slice(),
        )
        .context("could not construct collateral txout")?;

        let (principal_tx_out, abf_principal, vbf_principal) = TxOut::new_not_last_confidential(
            rng,
            secp,
            principal_amount.as_sat(),
            loan_request.borrower_address.clone(),
            self.usdt_asset_id,
            inputs_not_last_confidential.as_slice(),
        )
        .context("could not construct principal txout")?;

        let principal_input_amount = unblinded_principal_inputs
            .iter()
            .fold(0, |sum, input| sum + input.secrets.value);
        let principal_change_amount = Amount::from_sat(principal_input_amount) - principal_amount;
        let (principal_change_tx_out, abf_principal_change, vbf_principal_change) =
            TxOut::new_not_last_confidential(
                rng,
                secp,
                principal_change_amount.as_sat(),
                self.address.clone(),
                self.usdt_asset_id,
                &inputs_not_last_confidential,
            )
            .context("could not construct principal change txout")?;

        let not_last_confidential_outputs = [
            &TxOutSecrets::new(
                self.bitcoin_asset_id,
                abf_collateral,
                collateral_amount.as_sat(),
                vbf_collateral,
            ),
            &TxOutSecrets::new(
                self.usdt_asset_id,
                abf_principal,
                principal_amount.as_sat(),
                vbf_principal,
            ),
            &TxOutSecrets::new(
                self.usdt_asset_id,
                abf_principal_change,
                principal_change_amount.as_sat(),
                vbf_principal_change,
            ),
        ];

        let tx_fee = Amount::from_sat(
            estimate_virtual_size(inputs.len() as u64, 4)
                * loan_request.fee_sats_per_vbyte.as_sat(),
        );
        let collateral_change_amount = Amount::from_sat(collateral_input_amount)
            .checked_sub(collateral_amount)
            .map(|a| a.checked_sub(tx_fee))
            .flatten()
            .with_context(|| {
                format!(
                    "cannot pay for output {} and fee {} with input {}",
                    collateral_amount, tx_fee, collateral_input_amount,
                )
            })?;
        let (collateral_change_tx_out, _, _) = TxOut::new_last_confidential(
            rng,
            secp,
            collateral_change_amount.as_sat(),
            loan_request.borrower_address,
            self.bitcoin_asset_id,
            inputs
                .iter()
                .map(|(asset, secrets)| (*asset, *secrets))
                .collect::<Vec<_>>()
                .as_slice(),
            &not_last_confidential_outputs,
        )
        .context("Creation of collateral change output failed")?;

        let tx_ins = {
            let borrower_inputs = collateral_inputs.iter().map(|input| input.txin);
            let lender_inputs = principal_inputs.iter().map(|input| input.txin);
            borrower_inputs
                .chain(lender_inputs)
                .map(|previous_output| TxIn {
                    previous_output,
                    is_pegin: false,
                    has_issuance: false,
                    script_sig: Default::default(),
                    sequence: 0,
                    asset_issuance: Default::default(),
                    witness: Default::default(),
                })
                .collect::<Vec<_>>()
        };

        let tx_fee_tx_out = TxOut::new_fee(tx_fee.as_sat(), self.bitcoin_asset_id);

        let loan_transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: tx_ins,
            output: vec![
                collateral_tx_out.clone(),
                principal_tx_out,
                principal_change_tx_out,
                collateral_change_tx_out,
                tx_fee_tx_out,
            ],
        };

        let repayment_collateral_input = {
            let vout = loan_transaction
                .output
                .iter()
                .position(|out| out.script_pubkey == collateral_address.script_pubkey())
                .expect("loan transaction contains collateral output");

            Input {
                txin: OutPoint {
                    txid: loan_transaction.txid(),
                    vout: vout as u32,
                },
                original_txout: collateral_tx_out,
                blinding_key: collateral_blinding_sk,
            }
        };

        Ok(Lender1 {
            keypair: self.keypair,
            address: self.address,
            timelock: loan_request.timelock,
            loan_transaction,
            collateral_descriptor,
            collateral_amount: loan_request.collateral_amount,
            repayment_collateral_input,
            repayment_collateral_abf,
            repayment_collateral_vbf,
            bitcoin_asset_id: self.bitcoin_asset_id,
            repayment_principal_output,
        })
    }

    fn calc_principal_amount(loan_request: &LoanRequest, rate: u64) -> Result<Amount> {
        use rust_decimal::prelude::ToPrimitive;
        use rust_decimal::Decimal;

        let sats = loan_request.collateral_amount.as_sat();
        let btc = Decimal::from(sats)
            .checked_div(Decimal::from(Amount::ONE_BTC.as_sat()))
            .ok_or_else(|| anyhow!("division overflow"))?;

        let satodollars_per_btc = Decimal::from(rate);
        let satodollars = satodollars_per_btc * btc;
        let satodollars = satodollars
            .to_u64()
            .ok_or_else(|| anyhow!("decimal cannot be represented as u64"))?;

        Ok(Amount::from_sat(satodollars))
    }
}

pub struct Lender1 {
    keypair: (SecretKey, PublicKey),
    address: Address,
    pub timelock: u64,
    loan_transaction: Transaction,
    collateral_descriptor: Descriptor<PublicKey>,
    collateral_amount: Amount,
    repayment_collateral_input: Input,
    repayment_collateral_abf: AssetBlindingFactor,
    repayment_collateral_vbf: ValueBlindingFactor,
    bitcoin_asset_id: AssetId,
    repayment_principal_output: TxOut,
}

impl Lender1 {
    pub fn loan_response(&self) -> LoanResponse {
        LoanResponse {
            transaction: self.loan_transaction.clone(),
            lender_pk: self.keypair.1,
            repayment_collateral_input: self.repayment_collateral_input.clone(),
            repayment_collateral_abf: self.repayment_collateral_abf,
            repayment_collateral_vbf: self.repayment_collateral_vbf,
            timelock: self.timelock,
            repayment_principal_output: self.repayment_principal_output.clone(),
        }
    }

    pub async fn finalise_loan<S, F>(
        &self,
        loan_transaction: Transaction,
        signer: S,
    ) -> Result<Transaction>
    where
        S: FnOnce(Transaction) -> F,
        F: Future<Output = Result<Transaction>>,
    {
        if self.loan_transaction.txid() != loan_transaction.txid() {
            bail!("wrong loan transaction")
        }

        signer(loan_transaction).await
    }

    pub fn liquidation_transaction<R, C>(
        &self,
        rng: &mut R,
        secp: &Secp256k1<C>,
        fee_sats_per_vbyte: Amount,
    ) -> Result<Transaction>
    where
        R: RngCore + CryptoRng,
        C: Verification + Signing,
    {
        // construct collateral input
        let collateral_input = self
            .repayment_collateral_input
            .clone()
            .into_unblinded_input(secp)
            .context("could not unblind repayment collateral input")?;

        let inputs = [(collateral_input.txout.asset, &collateral_input.secrets)];

        let tx_fee = Amount::from_sat(
            estimate_virtual_size(inputs.len() as u64, 4) * fee_sats_per_vbyte.as_sat(),
        );

        let (collateral_output, _, _) = TxOut::new_last_confidential(
            rng,
            secp,
            (self.collateral_amount - tx_fee).as_sat(),
            self.address.clone(),
            self.bitcoin_asset_id,
            &inputs,
            &[],
        )
        .context("Creation of collateral output failed")?;

        let tx_fee_output = TxOut::new_fee(tx_fee.as_sat(), self.bitcoin_asset_id);

        let tx_ins = vec![TxIn {
            previous_output: collateral_input.txin,
            is_pegin: false,
            has_issuance: false,
            script_sig: Default::default(),
            sequence: 0,
            asset_issuance: Default::default(),
            witness: Default::default(),
        }];
        let tx_outs = vec![collateral_output, tx_fee_output];

        let mut liquidation_transaction = Transaction {
            version: 2,
            lock_time: self.timelock as u32,
            input: tx_ins,
            output: tx_outs,
        };

        // fulfill collateral input covenant script to liquidate the position
        {
            let descriptor = self.collateral_descriptor.clone();
            let descriptor_cov = descriptor.as_cov()?;

            let collateral_value = self.repayment_collateral_input.original_txout.value;
            let cov_script = descriptor_cov.cov_script_code();

            let cov_sat = CovSatisfier::new_segwitv0(
                &liquidation_transaction,
                0,
                collateral_value,
                &cov_script,
                SigHashType::All,
            );

            let cov_pk_sat = {
                let mut hash_map = HashMap::new();
                let sighash = cov_sat.segwit_sighash()?;

                let sig = SECP256K1.sign(
                    &elements::secp256k1_zkp::Message::from(sighash),
                    &COVENANT_SK,
                );
                hash_map.insert(*descriptor_cov.pk(), (sig, SigHashType::All));

                hash_map
            };

            let ident_pk_sat = {
                let mut hash_map = HashMap::new();

                let script = descriptor.explicit_script();
                let sighash = SigHashCache::new(&liquidation_transaction).segwitv0_sighash(
                    0,
                    &script,
                    collateral_value,
                    SigHashType::All,
                );
                let sighash = elements::secp256k1_zkp::Message::from(sighash);

                let sig = SECP256K1.sign(&sighash, &self.keypair.0);
                hash_map.insert(self.keypair.1, (sig, SigHashType::All));

                hash_map
            };

            // TODO: Model timelocks as u32
            let after_sat = After(self.timelock as u32);

            let (script_witness, _) = self.collateral_descriptor.get_satisfaction((
                cov_sat,
                cov_pk_sat,
                ident_pk_sat,
                after_sat,
            ))?;
            liquidation_transaction.input[0].witness.script_witness = script_witness;
        }

        Ok(liquidation_transaction)
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

pub mod transaction_as_string {
    use elements::encode::serialize_hex;
    use elements::Transaction;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(a: &Transaction, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&serialize_hex(a))
    }

    pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Transaction, D::Error> {
        let string = String::deserialize(d)?;
        let bytes = hex::decode(string).map_err(D::Error::custom)?;
        let tx = elements::encode::deserialize(&bytes).map_err(D::Error::custom)?;

        Ok(tx)
    }
}
