# Project Baru

Library to facilitate DeFi on liquid.

## Loan Protocol

1. The lender and borrower need to agree on the principal, loan_term, collateral of the loan contract.
2. The borrower sends the lender the LoanRequest with the UTXO's to fund the collateral, collateral amount, borrower_address,
   borrower_public_key(not associated witht he borrower address).
3. The lender receives the message and creates the loan transaction:
   inputs:
   principal_inputs: coming from the the lender
   collateral_inputs: coming from the borrower
   outputs:
   collateral_output: locked by the collateral output locking script (defined below)
   principal_output: locked to borrower address
   borrower_change_output
   lender_change_output
   fees.
4. The loan transaction is unsigned, the lender sends it to the borrower to sign along with some secret values to enable
   repayment later on (blinding factors)
5. The borrower verifies (fancy because of confidential transaction) the transaction and signs the collateral inputs.
6. The borrower send the signed transaction to the lender.
7. The lender signs the principal inputs.
8. The lender broadcasts the loan transaction

### Collateral Output Locking Script

```
if is_repayment {
    if the tx that is using the collateral output as an input:
        1. includes and output that pays the principal + interest to the lender
        2. the sender is the borrower
        return 1
    else
        return 0
} else {
    //liquidation at expiration
    if the current block number is < loan_term
        return 0
    if the sender is not the lender
        return 0
    return 1
}
```

## Releases

We will release every Friday with the intention of frequently pushing out features and enhancements for Project Baru's stream-aligned team to use.

### Steps

1. Update the version number in [Cargo.toml](Cargo.toml) according to SemVer.
2. Update the [changelog](CHANGELOG.md) and make sure that all breaking changes and new additions have been mentioned.
3. Generate a GitHub release of the library's master branch.
4. Publish on [crates.io](https://crates.io) using the `cargo publish` subcommand.
