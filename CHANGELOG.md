# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2021-08-20

### Added

- EncryptedWallet format which allows users to encrypt the Wallet using a password and the `Wallet::encrypt` method.
  The encrypted format can be used to persist and retrieve the wallet.
  The user can recover the Wallet by calling `Wallet::decrypt` on the EncryptedWallet.
  The Utxo cache is dropped during encryption.
  `Wallet::sync` should be called after decrypting the EncryptedWallet to refresh the Utxo cache.
  API's to encrypt the xprv key and access the salt to have been deprecated as the EncryptedWallet should be used instead.

## [0.4.0] - 2021-08-13

### Added

- Wallet which allows users to select coins through a backend configured by them via the `GetUtxos` trait.
  The provided wallet comes with a UTXO cache which this is updated using `Wallet::sync`.
  This allows users of the library to optimise the number of requests to their backend.
  Users can also sign said UTXOs by calling `Wallet::sign`.
- `Timelock` type to allow users of the library to explicitly choose the type of timelock they want to use when building the loan transaction.
  For the time being, users can still pass in a `u32`, but they are encouraged not to.

### Changed

- The borrower can now choose the collateral inputs before calling `Borrower0::new`.

### Fixed

- The loan transaction no longer expects collateral and principal change outputs.
  We were unconditionally adding them to the transaction which could result in attempting to [build a 0-valued confidential transaction output, which is invalid](https://github.com/comit-network/baru/issues/38).

## [0.3.0] - 2021-08-06

### Added

- Chain on which the loan protocol takes place is no longer hard-coded to Elements (local development node).
  The chain is implicitly configured by the addresses that are passed in.
  Furthermore, the protocol now verifies that borrower and lender are on the same chain.
- New API `build_loan_transaction` on `Lender0`, which wraps the now deprecated `interpret`:
  - The lender now has direct control over the `principal_amount`, `principal_inputs`, `repayment_amount` and `min_collateral_price`.

### Fixed

- Always satisfy the collateral contract input in the loan repayment transaction correctly.
  We used to assume that it was located at index `1`, but this could change if the number of inputs used to cover the repayment output was greater than 1.

### Changed

- Lender sets collateral contract timelock, as opposed to the borrower.
- Deprecated all APIs which use `LoanRequest`, to give users more control over how they want to serialize the parameters inside loan request.

## [0.2.0] - 2021-07-30

### Added

- Dynamic liquidation branch to the loan protocol:
  - New `async fn dynamic_liquidation_transaction()` API on `Lender1`.
    It takes a message of the form `price:timestamp` and an oracle's signature on the hash of the message, so that a _lender_ can unilaterally liquidate the loan if the `price` falls below a threshold and the `timestamp` is past a certain time.
  - `Lender0` constructor now requires blinding key of lender address and an oracle public key.

### Changed

- `loan::LoanResponse` fields:
  - Made `timelock` private, but accessible via `LoanResponse::collateral_contract(&self).timelock()`.
  - Made `transaction` private, accessible via getter.
  - Made `collateral_amount` private, but accessible via getter.
- `loan::Borrower1` fields:
  - Made `loan_transaction` private, but accessible via getter.
  - Made `collateral_amount` private, but accessible via getter.
- `loan::Lender1` fields:
  - Made `timelock` private, but accessible via getter.
- `fn liquidation_transaction()` API on `Lender1` is now `async`.
- Model the collateral contract's timelock as a `u32`.

### Fixed

- Squashed an [elusive bug](https://github.com/comit-network/baru/issues/35) preventing users from building version `0.1.0` of this library.
  This required updating `rust-elements` to version `0.18`.

## [0.1.0] - 2021-07-16

### Added

- Loan protocol and swap libraries originally developed in [Project Waves](https://github.com/comit-network/waves).

[Unreleased]: https://github.com/comit-network/baru/compare/0.4.0...HEAD
[0.4.0]: https://github.com/comit-network/baru/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/comit-network/baru/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/comit-network/baru/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/comit-network/baru/releases/tag/0.1.0
