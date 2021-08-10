use crate::estimate_transaction_size::estimate_virtual_size;
use crate::input::Input;
use crate::oracle;
use anyhow::{anyhow, bail, Context, Result};
use conquer_once::Lazy;
use elements::bitcoin::{Amount, Network, PrivateKey, PublicKey};
use elements::confidential::{self, Asset, AssetBlindingFactor, ValueBlindingFactor};
use elements::encode::serialize;
use elements::hashes::hex::ToHex;
use elements::pset::serialize::Serialize;
use elements::script::Builder;
use elements::secp256k1_zkp::{self, Secp256k1, SecretKey, Signing, Verification, SECP256K1};
use elements::sighash::SigHashCache;
use elements::{
    Address, AddressParams, AssetId, OutPoint, Script, SigHashType, Transaction, TxIn, TxInWitness,
    TxOut, TxOutSecrets,
};
use elements_miniscript::descriptor::CovSatisfier;
use elements_miniscript::miniscript::satisfy::After;
use elements_miniscript::{Descriptor, DescriptorTrait, Satisfier};
use rand::{CryptoRng, RngCore};
use secp256k1_zkp::{Signature, SurjectionProof, Tag};
use std::collections::HashMap;
use std::future::Future;
use std::str::FromStr;
use std::time::SystemTime;

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

/// Contract defining the conditions under which the collateral output
/// can be spent.
///
/// It has a "liquidation branch" which allows the lender to claim
/// all the collateral for themself if the `timelock` expires. The
/// lender must identify themself by providing a signature on
/// `lender_pk`.
///
/// It also includes a "repayment branch" which allows the borrower to
/// repay the loan to reclaim the collateral. The borrower must
/// identify themself by providing a signature on `borrower_pk`. To
/// ensure that the borrower does indeed repay the loan, the script
/// will check that the spending transaction has the
/// `repayment_principal_output` as vout 0.
///
/// Additionally, the contract can be spent by providing a signature
/// (and the corresponding message) from a valid oracle proving that
/// the price of the collateral has dropped below a threshold
/// determined at contract creation time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CollateralContract {
    /// Only includes the two branches that can be expressed using miniscript:
    ///
    /// - Liquidation after expiration.
    ///
    /// - Collateral reclamation after repayment.
    ///
    /// Kept around to more easily construct the witness stack for
    /// those two branches.
    descriptor: Descriptor<PublicKey>,
    /// The actual script, including the dynamic liquidation branch.
    raw_script: Script,
    /// The script after `OP_CODESEPARATOR`.
    ///
    /// This is the only part of the script which is included in the
    /// transaction sighash which is signed with `COVENANT_SK`.
    ///
    borrower_pk: PublicKey,
    lender_pk: PublicKey,
    repayment_principal_output: TxOut,
    repayment_principal_output_blinder: SecretKey,
    timelock: u32,
    chain: Chain,
    // Dynamic liquidation
    oracle_pk: PublicKey,
    min_price_btc: u64,
    min_timestamp: u64,
}

impl CollateralContract {
    /// The bytes of the Script to be included in the sighash which is signed to
    /// satisfy the covenant descriptor.
    ///
    /// In a regular `CovenantDescriptor` this is just
    /// `OP_CHECKSIGVERIFY` and `OP_CHECKSIGFROMSTACK`. In our case,
    /// it's `OP_CHECKSIGVERIFY`, `OP_CHECKSIGFROMSTACK` and
    /// `OP_ENDIF`.
    const COV_SCRIPT_BYTES: [u8; 3] = [0xad, 0xc1, 0x68];

    /// Fill in the collateral contract template with the provided arguments.
    #[allow(clippy::too_many_arguments)]
    fn new(
        borrower_pk: PublicKey,
        lender_pk: PublicKey,
        timelock: u32,
        (repayment_principal_output, repayment_principal_output_blinder): (TxOut, SecretKey),
        oracle_pk: PublicKey,
        min_price_btc: u64,
        min_timestamp: u64,
        chain: Chain,
    ) -> Result<Self> {
        use elements::opcodes::all::*;

        let repayment_principal_output_as_hex = serialize(&repayment_principal_output).to_hex();

        // the first element of the covenant descriptor is the shared
        // `covenant_pk`, which is only used to verify that the transaction
        // data on the witness stack matches the transaction which triggered
        // the call.
        let descriptor: Descriptor<elements::bitcoin::PublicKey> = format!(
            "elcovwsh({},or_i(and_v(v:pk({}),after({})),and_v(v:pk({}),outputs_pref({}))))",
            COVENANT_PK, lender_pk, timelock, borrower_pk, repayment_principal_output_as_hex,
        )
        .parse()
        .expect("valid collateral output descriptor");

        let dynamic_liquidation_branch = Builder::new()
            // check that the lender authorises the spend
            .push_slice(lender_pk.serialize().as_slice())
            .push_opcode(OP_CHECKSIGVERIFY)
            // copy message BTC price to top of stack
            .push_int(2)
            .push_opcode(OP_PICK)
            // copy message timestamp to top of stack
            .push_int(2)
            .push_opcode(OP_PICK)
            // reconstruct message as `timestamp:btc_price`
            .push_opcode(OP_CAT)
            // check if oracle has approved of the hashed message (OP_CSFS
            // implicitly hashes the message)
            .push_slice(oracle_pk.serialize().as_slice())
            .push_opcode(OP_CHECKSIGFROMSTACKVERIFY)
            // check if message is recent enough
            .push_int(min_timestamp as i64)
            .push_opcode(OP_GREATERTHANOREQUAL)
            .push_opcode(OP_VERIFY)
            // check if BTC price has dipped below minimum
            .push_int(min_price_btc as i64)
            .push_opcode(OP_LESSTHANOREQUAL)
            .into_script();

        // add dynamic liquidation branch, making the script look like:
        // OP_IF <dynamic_liquidation_branch> OP_ELSE <covenant_script> OP_ENDIF
        let raw_script = {
            let mut script = vec![OP_IF.into_u8()];
            script.append(&mut dynamic_liquidation_branch.to_bytes());
            script.push(OP_ELSE.into_u8());

            let mut desc_script = descriptor.explicit_script().to_bytes();
            script.append(&mut desc_script);

            script.push(OP_ENDIF.into_u8());

            script
        };

        // remove length check for the size of the script included in
        // the sighash, because after adding the dynamic liquidation
        // branch it no longer holds. We could alternatively replace
        // the expected value `3` with `4`, since the rest of the
        // script after the `OP_CODESEPARATOR` is `OP_CHECKSIGVERIFY`,
        // `OP_CHECKSIGFROMSTACK` and `OP_ENDIF`.
        let raw_script = {
            let mut script = raw_script;

            let pos = script
                .windows(3)
                .position(|window| window == [0x82u8, 0x53u8, 0x88u8])
                .expect("OP_SIZE OP_PUSHNUM_3 OP_EQUALVERIFY section to exist");

            let _ = script.drain(pos..pos + 3);

            Script::from(script)
        };

        Ok(Self {
            descriptor,
            raw_script,
            borrower_pk,
            lender_pk,
            repayment_principal_output,
            repayment_principal_output_blinder,
            timelock,
            chain,
            oracle_pk,
            min_price_btc,
            min_timestamp,
        })
    }

    async fn satisfy_loan_repayment<S, SF>(
        &self,
        transaction: &mut Transaction,
        input_value: confidential::Value,
        input_index: u32,
        identity_signer: S,
    ) -> Result<()>
    where
        S: FnOnce(secp256k1_zkp::Message) -> SF,
        SF: Future<Output = Result<Signature>>,
    {
        let transaction_cloned = transaction.clone();
        let cov_script = Script::from(Self::COV_SCRIPT_BYTES.to_vec());
        let satisfiers = self
            .descriptor_satisfiers(
                identity_signer,
                &transaction_cloned,
                input_value,
                input_index,
                self.borrower_pk,
                &cov_script,
            )
            .await?;

        self.satisfy(
            satisfiers,
            &mut transaction.input[input_index as usize].witness,
        )?;

        Ok(())
    }

    async fn satisfy_liquidation<S, SF>(
        &self,
        transaction: &mut Transaction,
        input_value: confidential::Value,
        input_index: u32,
        identity_signer: S,
    ) -> Result<()>
    where
        S: FnOnce(secp256k1_zkp::Message) -> SF,
        SF: Future<Output = Result<Signature>>,
    {
        let transaction_cloned = transaction.clone();
        let cov_script = Script::from(Self::COV_SCRIPT_BYTES.to_vec());
        let satisfiers = self
            .descriptor_satisfiers(
                identity_signer,
                &transaction_cloned,
                input_value,
                input_index,
                self.lender_pk,
                &cov_script,
            )
            .await?;
        let after_sat = After(self.timelock);

        self.satisfy(
            (satisfiers, after_sat),
            &mut transaction.input[input_index as usize].witness,
        )?;

        Ok(())
    }

    async fn satisfy_dynamic_liquidation<S, SF>(
        &self,
        identity_signer: S,
        transaction: &mut Transaction,
        input_value: confidential::Value,
        input_index: u32,
        oracle_msg: oracle::Message,
        oracle_sig: Signature,
    ) -> Result<()>
    where
        S: FnOnce(secp256k1_zkp::Message) -> SF,
        SF: Future<Output = Result<Signature>>,
    {
        let btc_price = oracle_msg.price_to_bytes();
        let timestamp = oracle_msg.timestamp_to_bytes();
        let oracle_sig = oracle_sig.serialize_der().to_vec();

        let script = &self.raw_script;
        let sighash = SigHashCache::new(&*transaction).segwitv0_sighash(
            input_index as usize,
            script,
            input_value,
            SigHashType::All,
        );
        let sighash = secp256k1_zkp::Message::from(sighash);

        let identity_sig = identity_signer(sighash)
            .await
            .context("could not sign on behalf of lender")?;
        let mut identity_sig = identity_sig.serialize_der().to_vec();
        identity_sig.push(SigHashType::All as u8);

        let if_flag = vec![0x01];
        let script = self.raw_script.to_bytes();

        transaction.input[input_index as usize]
            .witness
            .script_witness = vec![
            btc_price,
            timestamp,
            oracle_sig,
            identity_sig,
            if_flag,
            script,
        ];

        Ok(())
    }

    /// Construct the satisfiers which are always required to fulfill
    /// the requirements of the covenant descriptor part of the
    /// contract.
    async fn descriptor_satisfiers<'a, S, SF>(
        &'a self,
        identity_signer: S,
        transaction: &'a Transaction,
        input_value: confidential::Value,
        input_index: u32,
        identity_pk: PublicKey,
        cov_script: &'a Script,
    ) -> Result<impl Satisfier<PublicKey> + 'a>
    where
        S: FnOnce(secp256k1_zkp::Message) -> SF,
        SF: Future<Output = Result<Signature>>,
    {
        let descriptor_cov = &self.descriptor.as_cov().expect("covenant descriptor");

        let cov_sat = CovSatisfier::new_segwitv0(
            transaction,
            input_index,
            input_value,
            cov_script,
            SigHashType::All,
        );

        let cov_pk_sat = {
            let mut hash_map = HashMap::new();
            let sighash = cov_sat.segwit_sighash()?;
            let sighash = secp256k1_zkp::Message::from(sighash);

            let sig = SECP256K1.sign(&sighash, &COVENANT_SK);
            hash_map.insert(*descriptor_cov.pk(), (sig, SigHashType::All));

            hash_map
        };

        let ident_pk_sat = {
            let mut hash_map = HashMap::new();

            let script = &self.raw_script;
            let sighash = SigHashCache::new(&*transaction).segwitv0_sighash(
                input_index as usize,
                script,
                input_value,
                SigHashType::All,
            );
            let sighash = secp256k1_zkp::Message::from(sighash);

            let sig = identity_signer(sighash)
                .await
                .context("could not sign on behalf of lender")?;
            hash_map.insert(identity_pk, (sig, SigHashType::All));

            hash_map
        };

        Ok((cov_sat, cov_pk_sat, ident_pk_sat))
    }

    /// Satisfy the covenant descriptor based on the satisfier
    /// provided, and modify the value returned by
    /// `elements-miniscript` to account for the rest of the contract.
    ///
    /// As you can see from the suspicious code below, this is
    /// extremely hacky. We would like to just use
    /// `elements-minscript` but it is not (yet) possible to express
    /// all of the spending conditions we want.
    fn satisfy<S>(&self, satisfier: S, input_witness: &mut TxInWitness) -> Result<()>
    where
        S: Satisfier<PublicKey>,
    {
        let (mut script_witness, _) = self.descriptor.get_satisfaction(satisfier)?;

        {
            script_witness.pop();

            let if_flag = vec![];
            script_witness.push(if_flag);
            script_witness.push(self.raw_script.to_bytes())
        };

        input_witness.script_witness = script_witness;

        Ok(())
    }

    pub fn address(&self) -> Address {
        Address::p2wsh(&self.raw_script, None, self.chain.into())
    }

    fn blinded_address(&self, blinder: secp256k1_zkp::PublicKey) -> Address {
        Address::p2wsh(&self.raw_script, Some(blinder), self.chain.into())
    }

    fn repayment_amount<C>(&self, secp: &Secp256k1<C>) -> Result<Amount>
    where
        C: Verification,
    {
        let TxOutSecrets { value, .. } = self
            .repayment_principal_output
            .unblind(secp, self.repayment_principal_output_blinder)?;

        Ok(Amount::from_sat(value))
    }

    /// Get a reference to the collateral contract's timelock.
    pub fn timelock(&self) -> &u32 {
        &self.timelock
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoanRequest {
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    collateral_amount: Amount,
    collateral_inputs: Vec<Input>,
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    fee_sats_per_vbyte: Amount,
    borrower_pk: PublicKey,
    borrower_address: Address,
}

impl LoanRequest {
    /// Get a copy of the collateral amount.
    #[deprecated(note = "Use accessor on Borrower0 instead", since = "0.3.0")]
    pub fn collateral_amount(&self) -> Amount {
        self.collateral_amount
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoanResponse {
    // TODO: Use this where needed!
    #[serde(with = "transaction_as_string")]
    transaction: Transaction,
    collateral_contract: CollateralContract,
    repayment_collateral_input: Input,
    repayment_collateral_abf: AssetBlindingFactor,
    repayment_collateral_vbf: ValueBlindingFactor,
}

impl LoanResponse {
    /// Get a reference to the loan transaction.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
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
    bitcoin_asset_id: AssetId,
    usdt_asset_id: AssetId,
}

impl Borrower0 {
    #[allow(clippy::too_many_arguments)]
    pub async fn new<R>(
        rng: &mut R,
        collateral_inputs: Vec<Input>,
        address: Address,
        address_blinding_sk: SecretKey,
        collateral_amount: Amount,
        fee_sats_per_vbyte: Amount,
        bitcoin_asset_id: AssetId,
        usdt_asset_id: AssetId,
    ) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        let keypair = make_keypair(rng);

        Ok(Self {
            keypair,
            address,
            address_blinding_sk,
            collateral_amount,
            collateral_inputs,
            fee_sats_per_vbyte,
            bitcoin_asset_id,
            usdt_asset_id,
        })
    }

    #[deprecated(note = "Use accessors on Self instead", since = "0.3.0")]
    pub fn loan_request(&self) -> LoanRequest {
        LoanRequest {
            collateral_amount: self.collateral_amount,
            collateral_inputs: self.collateral_inputs.clone(),
            fee_sats_per_vbyte: self.fee_sats_per_vbyte,
            borrower_pk: self.keypair.1,
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

        let principal_amount = {
            let expected_output = transaction.output.iter().find_map(|out| {
                let unblinded_out = out.unblind(secp, self.address_blinding_sk).ok()?;
                let is_principal_out = unblinded_out.asset == self.usdt_asset_id
                    && out.script_pubkey == self.address.script_pubkey();

                is_principal_out.then(|| unblinded_out)
            });

            match expected_output {
                Some(out) => Amount::from_sat(out.value),
                None => bail!("could not find principal output"),
            }
        };

        let collateral_contract = loan_response.collateral_contract;
        let collateral_address = collateral_contract.address();

        let collateral_blinding_sk = loan_response.repayment_collateral_input.blinding_key;
        let collateral_script_pubkey = collateral_address.script_pubkey();

        let collateral_output = transaction.output.iter().find_map(|out| {
            let unblinded_out = out.unblind(secp, collateral_blinding_sk).ok()?;
            let is_collateral_out = unblinded_out.asset == self.bitcoin_asset_id
                && unblinded_out.value == self.collateral_amount.as_sat()
                && out.script_pubkey == collateral_script_pubkey;

            is_collateral_out.then(|| out)
        });

        if collateral_output.is_none() {
            bail!("could not find collateral output")
        }

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

        if collateral_change_amount != Amount::ZERO {
            let expected_output = transaction.output.iter().find_map(|out| {
                let unblinded_out = out.unblind(secp, self.address_blinding_sk).ok()?;
                let is_collateral_change_out = unblinded_out.asset == self.bitcoin_asset_id
                    && unblinded_out.value == collateral_change_amount.as_sat()
                    && out.script_pubkey == self.address.script_pubkey();

                is_collateral_change_out.then(|| out)
            });

            if expected_output.is_none() {
                bail!(
                    "could not find collateral change output with amount {}",
                    collateral_change_amount
                )
            }
        }

        Ok(Borrower1 {
            keypair: self.keypair,
            loan_transaction: transaction,
            collateral_amount: self.collateral_amount,
            collateral_contract,
            principal_amount,
            address: self.address.clone(),
            repayment_collateral_input: loan_response.repayment_collateral_input,
            repayment_collateral_abf: loan_response.repayment_collateral_abf,
            repayment_collateral_vbf: loan_response.repayment_collateral_vbf,
            bitcoin_asset_id: self.bitcoin_asset_id,
            usdt_asset_id: self.usdt_asset_id,
        })
    }

    /// Get a reference to the value of the collateral the borrower
    /// will put up for the loan.
    pub fn collateral_amount(&self) -> &Amount {
        &self.collateral_amount
    }

    /// Get a reference to the inputs the borrower will use to fund
    /// the loan transaction's collateral.
    pub fn collateral_inputs(&self) -> &[Input] {
        self.collateral_inputs.as_slice()
    }

    /// Get a copy of how many satoshis per vbyte the borrower will
    /// use to pay for the loan transaction's fees.
    pub fn fee_sats_per_vbyte(&self) -> Amount {
        self.fee_sats_per_vbyte
    }

    /// Get a reference to the borrower's address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get a copy of the borrower's PublicKey.
    pub fn pk(&self) -> PublicKey {
        self.keypair.1
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Borrower1 {
    keypair: (SecretKey, PublicKey),
    loan_transaction: Transaction,
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    collateral_amount: Amount,
    collateral_contract: CollateralContract,
    #[serde(with = "::elements::bitcoin::util::amount::serde::as_sat")]
    principal_amount: Amount,
    address: Address,
    /// Loan collateral expressed as an input for constructing the
    /// loan repayment transaction.
    repayment_collateral_input: Input,
    repayment_collateral_abf: AssetBlindingFactor,
    repayment_collateral_vbf: ValueBlindingFactor,
    bitcoin_asset_id: AssetId,
    usdt_asset_id: AssetId,
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
        // construct collateral input
        let collateral_input = self
            .repayment_collateral_input
            .clone()
            .into_unblinded_input(secp)
            .context("could not unblind repayment collateral input")?;
        let principal_inputs = coin_selector(
            self.collateral_contract.repayment_amount(secp)?,
            self.usdt_asset_id,
        )
        .await?;

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

        let repayment_amount = self.collateral_contract.repayment_amount(secp)?;
        let mut repayment_principal_output =
            self.collateral_contract.repayment_principal_output.clone();
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

        let repayment_principal_output_secrets = TxOutSecrets::new(
            self.usdt_asset_id,
            self.repayment_collateral_abf,
            repayment_amount.as_sat(),
            self.repayment_collateral_vbf,
        );
        let mut outputs = vec![repayment_principal_output_secrets];

        let mut tx_ins: Vec<OutPoint> = unblinded_principal_inputs
            .clone()
            .into_iter()
            .map(|input| input.txin)
            .collect();
        tx_ins.push(collateral_input.txin);
        let collateral_contract_index = (tx_ins.len() - 1) as u32;

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

        // fulfill collateral input contract
        self.collateral_contract
            .satisfy_loan_repayment(
                &mut tx,
                self.repayment_collateral_input.original_txout.value,
                collateral_contract_index,
                // TODO: Push ownership (and generation) of secret key outside of the library
                |message| async move { Ok(SECP256K1.sign(&message, &self.keypair.0)) },
            )
            .await
            .context("could not satisfy collateral input")?;

        // sign repayment input of the principal amount
        let tx = signer(tx).await?;

        Ok(tx)
    }

    /// Get a copy of the collateral amount.
    pub fn collateral_amount(&self) -> Amount {
        self.collateral_amount
    }

    /// Get a copy of the principal amount.
    pub fn principal_amount(&self) -> Amount {
        self.principal_amount
    }

    /// Get a reference to the collateral contract.
    pub fn collateral_contract(&self) -> &CollateralContract {
        &self.collateral_contract
    }

    /// Get a reference to the loan transaction.
    pub fn loan_transaction(&self) -> &Transaction {
        &self.loan_transaction
    }
}

pub struct Lender0 {
    keypair: (SecretKey, PublicKey),
    address: Address,
    address_blinder: SecretKey,
    oracle_pk: PublicKey,
    bitcoin_asset_id: AssetId,
    usdt_asset_id: AssetId,
}

impl Lender0 {
    pub fn new<R>(
        rng: &mut R,
        bitcoin_asset_id: AssetId,
        usdt_asset_id: AssetId,
        address: Address,
        address_blinder: SecretKey,
        oracle_pk: PublicKey,
    ) -> Result<Self>
    where
        R: RngCore + CryptoRng,
    {
        let keypair = make_keypair(rng);

        Ok(Self {
            keypair,
            address,
            address_blinder,
            oracle_pk,
            bitcoin_asset_id,
            usdt_asset_id,
        })
    }

    /// Interpret a loan request and performs lender logic.
    ///
    /// rate is expressed in usdt sats per btc, i.e. rate = 1 BTC / USDT
    #[deprecated(note = "Use build_loan_transaction instead", since = "0.3.0")]
    pub async fn interpret<R, C, CS, CF>(
        self,
        rng: &mut R,
        secp: &Secp256k1<C>,
        coin_selector: CS,
        loan_request: LoanRequest,
        timelock: u32,
        rate: u64,
    ) -> Result<Lender1>
    where
        R: RngCore + CryptoRng,
        C: Verification + Signing,
        CS: FnOnce(Amount, AssetId) -> CF,
        CF: Future<Output = Result<Vec<Input>>>,
    {
        let LoanAmounts {
            principal: principal_amount,
            repayment: repayment_amount,
            min_collateral_price,
        } = Lender0::calculate_loan_amounts(loan_request.collateral_amount, rate, 20, 10)?;

        let principal_inputs = coin_selector(principal_amount, self.usdt_asset_id).await?;

        self.build_loan_transaction(
            rng,
            secp,
            loan_request.fee_sats_per_vbyte,
            (
                loan_request.collateral_amount,
                loan_request.collateral_inputs,
            ),
            (principal_amount, principal_inputs),
            repayment_amount,
            min_collateral_price,
            (loan_request.borrower_pk, loan_request.borrower_address),
            timelock,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn build_loan_transaction<R, C>(
        self,
        rng: &mut R,
        secp: &Secp256k1<C>,
        fee_sats_per_vbyte: Amount,
        (collateral_amount, collateral_inputs): (Amount, Vec<Input>),
        (principal_amount, principal_inputs): (Amount, Vec<Input>),
        repayment_amount: Amount,
        min_collateral_price: u64,
        (borrower_pk, borrower_address): (PublicKey, Address),
        timelock: u32,
    ) -> Result<Lender1>
    where
        R: RngCore + CryptoRng,
        C: Verification + Signing,
    {
        let chain = Chain::new(&borrower_address, &self.address)?;

        let collateral_inputs = collateral_inputs
            .into_iter()
            .map(|input| input.into_unblinded_input(secp))
            .collect::<Result<Vec<_>>>()?;

        let borrower_inputs = collateral_inputs
            .iter()
            .map(|input| (input.txout.asset, &input.secrets));

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
        let inputs_not_last_confidential = inputs
            .iter()
            .map(|(asset, secrets)| (*asset, Some(*secrets)))
            .collect::<Vec<_>>();

        let collateral_input_amount = collateral_inputs
            .iter()
            .fold(0, |sum, input| sum + input.secrets.value);

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
                repayment_amount.as_sat(),
                self.address.clone(),
                self.usdt_asset_id,
                &dummy_inputs,
            )?
        };

        let (_, lender_pk) = self.keypair;
        let (collateral_blinding_sk, collateral_blinding_pk) = make_keypair(rng);

        // TODO: This API should change to allow the caller to
        // determine when oracle signatures will start being valid for
        // the collateral contract
        let now = std::time::SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let contract_creation_timestamp = now.as_secs() + 300;

        let (principal_tx_out, abf_principal, vbf_principal) = TxOut::new_not_last_confidential(
            rng,
            secp,
            principal_amount.as_sat(),
            borrower_address.clone(),
            self.usdt_asset_id,
            inputs_not_last_confidential.as_slice(),
        )
        .context("could not construct principal txout")?;

        let tx_fee = Amount::from_sat(
            estimate_virtual_size(inputs.len() as u64, 4) * fee_sats_per_vbyte.as_sat(),
        );

        let principal_input_amount = unblinded_principal_inputs
            .iter()
            .fold(0, |sum, input| sum + input.secrets.value);
        let principal_change_amount = Amount::from_sat(principal_input_amount) - principal_amount;

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

        let mut tx_outs = vec![principal_tx_out];
        let mut before_last_confidential_output_secrets = vec![TxOutSecrets::new(
            self.usdt_asset_id,
            abf_principal,
            principal_amount.as_sat(),
            vbf_principal,
        )];

        if collateral_change_amount == Amount::ZERO {
            log::info!(
                "No change output needed for collateral asset: {}",
                self.bitcoin_asset_id
            );
        } else {
            let (tx_out, abf, vbf) = TxOut::new_not_last_confidential(
                rng,
                secp,
                collateral_change_amount.as_sat(),
                borrower_address,
                self.bitcoin_asset_id,
                &inputs_not_last_confidential,
            )
            .with_context(|| {
                format!(
                    "could not construct change output for collateral asset: {}",
                    self.bitcoin_asset_id
                )
            })?;

            tx_outs.push(tx_out);
            before_last_confidential_output_secrets.push(TxOutSecrets::new(
                self.bitcoin_asset_id,
                abf,
                collateral_change_amount.as_sat(),
                vbf,
            ))
        }

        if principal_change_amount == Amount::ZERO {
            log::info!(
                "No change output needed for principal asset: {}",
                self.usdt_asset_id
            );
        } else {
            let (tx_out, abf, vbf) = TxOut::new_not_last_confidential(
                rng,
                secp,
                principal_change_amount.as_sat(),
                self.address.clone(),
                self.usdt_asset_id,
                &inputs_not_last_confidential,
            )
            .with_context(|| {
                format!(
                    "could not construct change output for principal asset: {}",
                    self.usdt_asset_id
                )
            })?;

            tx_outs.push(tx_out);
            before_last_confidential_output_secrets.push(TxOutSecrets::new(
                self.usdt_asset_id,
                abf,
                principal_change_amount.as_sat(),
                vbf,
            ))
        }

        let collateral_contract = CollateralContract::new(
            borrower_pk,
            lender_pk,
            timelock,
            (repayment_principal_output, self.address_blinder),
            self.oracle_pk,
            min_collateral_price,
            contract_creation_timestamp,
            chain,
        )
        .context("could not build collateral contract")?;
        let collateral_address = collateral_contract.blinded_address(collateral_blinding_pk.key);
        let (collateral_tx_out, _, _) = TxOut::new_last_confidential(
            rng,
            secp,
            collateral_amount.as_sat(),
            collateral_address.clone(),
            self.bitcoin_asset_id,
            inputs
                .iter()
                .map(|(asset, secrets)| (*asset, *secrets))
                .collect::<Vec<_>>()
                .as_slice(),
            &before_last_confidential_output_secrets
                .iter()
                .collect::<Vec<_>>(),
        )
        .context("could not construct collateral txout")?;

        tx_outs.push(collateral_tx_out.clone());

        let tx_fee_tx_out = TxOut::new_fee(tx_fee.as_sat(), self.bitcoin_asset_id);
        tx_outs.push(tx_fee_tx_out);

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

        let loan_transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: tx_ins,
            output: tx_outs,
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
            timelock,
            loan_transaction,
            collateral_contract,
            collateral_amount,
            repayment_collateral_input,
            repayment_collateral_abf,
            repayment_collateral_vbf,
            bitcoin_asset_id: self.bitcoin_asset_id,
        })
    }

    fn calculate_loan_amounts(
        collateral_amount: Amount,
        rate: u64,
        overcollateralization_percentage: u8,
        interest_percentage: u8,
    ) -> Result<LoanAmounts> {
        use rust_decimal::prelude::ToPrimitive;
        use rust_decimal::Decimal;

        let sats = collateral_amount.as_sat();
        let btc = Decimal::from(sats)
            .checked_div(Decimal::from(Amount::ONE_BTC.as_sat()))
            .context("division overflow")?;

        let satodollars_per_btc = Decimal::from(rate);
        let overcollateralization_factor = Decimal::from(overcollateralization_percentage + 100)
            .checked_div(Decimal::from(100))
            .context("division overflow")?;

        let satodollars_per_btc_adjusted = satodollars_per_btc
            .checked_div(overcollateralization_factor)
            .context("division overflow")?;

        let principal = satodollars_per_btc_adjusted * btc;
        let principal = principal
            .to_u64()
            .context("decimal cannot be represented as u64")?;
        let principal = Amount::from_sat(principal);

        let interest_factor = Decimal::from(interest_percentage + 100)
            .checked_div(Decimal::from(100))
            .context("division overflow")?;
        let repayment = Decimal::from(principal.as_sat()) * interest_factor;

        let min_price_btc = repayment.checked_div(btc).context("division overflow")?;
        let min_collateral_price = min_price_btc
            .to_u64()
            .context("decimal cannot be represented as u64")?;

        let repayment = repayment
            .to_u64()
            .context("decimal cannot be represented as u64")?;
        let repayment = Amount::from_sat(repayment);

        Ok(LoanAmounts {
            principal,
            repayment,
            min_collateral_price,
        })
    }
}

struct LoanAmounts {
    /// Principal amount, in satodollars.
    principal: Amount,
    /// Repayment amount, in satodollars.
    repayment: Amount,
    /// Price under which the lender will be able to unilaterally
    /// liquidate the collateral contract, in whole USD.
    min_collateral_price: u64,
}

pub struct Lender1 {
    keypair: (SecretKey, PublicKey),
    address: Address,
    timelock: u32,
    loan_transaction: Transaction,
    collateral_contract: CollateralContract,
    collateral_amount: Amount,
    repayment_collateral_input: Input,
    repayment_collateral_abf: AssetBlindingFactor,
    repayment_collateral_vbf: ValueBlindingFactor,
    bitcoin_asset_id: AssetId,
}

impl Lender1 {
    pub fn loan_response(&self) -> LoanResponse {
        LoanResponse {
            transaction: self.loan_transaction.clone(),
            collateral_contract: self.collateral_contract.clone(),
            repayment_collateral_input: self.repayment_collateral_input.clone(),
            repayment_collateral_abf: self.repayment_collateral_abf,
            repayment_collateral_vbf: self.repayment_collateral_vbf,
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

    pub async fn liquidation_transaction<R, C>(
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
            lock_time: self.timelock,
            input: tx_ins,
            output: tx_outs,
        };

        // fulfill collateral input contract
        self.collateral_contract
            .satisfy_liquidation(
                &mut liquidation_transaction,
                self.repayment_collateral_input.original_txout.value,
                0,
                |message| async move { Ok(SECP256K1.sign(&message, &self.keypair.0)) },
            )
            .await
            .context("could not satisfy collateral input")?;

        Ok(liquidation_transaction)
    }

    pub async fn dynamic_liquidation_transaction<R, C>(
        &self,
        rng: &mut R,
        secp: &Secp256k1<C>,
        oracle_msg: oracle::Message,
        oracle_sig: Signature,
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
            lock_time: 0,
            input: tx_ins,
            output: tx_outs,
        };
        self.collateral_contract
            .satisfy_dynamic_liquidation(
                |message| async move { Ok(SECP256K1.sign(&message, &self.keypair.0)) },
                &mut liquidation_transaction,
                self.repayment_collateral_input.original_txout.value,
                0,
                oracle_msg,
                oracle_sig,
            )
            .await?;

        Ok(liquidation_transaction)
    }

    /// Get a reference to the collateral contract.
    pub fn collateral_contract(&self) -> &CollateralContract {
        &self.collateral_contract
    }
}

fn make_keypair<R>(rng: &mut R) -> (SecretKey, PublicKey)
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

/// Possible networks on which the loan contract may be deployed.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
enum Chain {
    Elements,
    Liquid,
}

impl Chain {
    /// Calculate the `Chain` based on the addresses of the borrower and the lender.
    ///
    /// If their `AddressParams` don't match it means that the parties
    /// are not on the same network, so we return an error.
    ///
    /// If their `AddressParams` don't describe a known chain, we
    /// return an error.
    fn new(borrower: &Address, lender: &Address) -> Result<Self, ChainError> {
        let borrower = borrower.params;
        let lender = lender.params;

        if borrower != lender {
            return Err(ChainError::Different { borrower, lender });
        }

        match *borrower {
            AddressParams::ELEMENTS => Ok(Self::Elements),
            AddressParams::LIQUID => Ok(Self::Liquid),
            _ => Err(ChainError::Custom(borrower)),
        }
    }
}

impl From<Chain> for &AddressParams {
    fn from(from: Chain) -> Self {
        match from {
            Chain::Elements => &AddressParams::ELEMENTS,
            Chain::Liquid => &AddressParams::LIQUID,
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum ChainError {
    #[error("Borrower and lender are on different chains: {borrower:?} vs {lender:?}")]
    Different {
        borrower: &'static AddressParams,
        lender: &'static AddressParams,
    },
    #[error("Unsupported custom chain: {0:?}")]
    Custom(&'static AddressParams),
}

#[cfg(test)]
mod constant_tests {
    use super::*;

    #[test]
    fn covenant_pk_is_the_public_key_of_covenant_sk() {
        let pk = PublicKey::from_private_key(
            SECP256K1,
            &PrivateKey::new(*COVENANT_SK, elements::bitcoin::Network::Regtest),
        );

        assert_eq!(format!("{}", pk), COVENANT_PK)
    }

    #[test]
    fn cov_script_bytes_represents_correct_script() {
        use elements::opcodes::all::*;

        let expected = Builder::new()
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_opcode(OP_CHECKSIGFROMSTACK)
            .push_opcode(OP_ENDIF)
            .into_script();
        let actual = Script::from(CollateralContract::COV_SCRIPT_BYTES.to_vec());

        assert_eq!(actual, expected);
    }
}
