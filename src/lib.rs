use conquer_once::Lazy;
use elements::bitcoin::{Network, PrivateKey, PublicKey};
use elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use elements::secp256k1_zkp::{SecretKey, SECP256K1};

pub mod input;
pub mod loan;
pub mod swap;

mod estimate_transaction_size;

/// Secret key used to produce a signature which proves that an
/// input's witness stack contains transaction data equivalent to the
/// transaction which includes the input itself.
///
/// This secret key MUST NOT be used for anything other than to
/// satisfy this verification step which enables transaction
/// introspection. It is therefore a global, publicly known secret key
/// to be used in every instance of this protocol.
static COVENANT_SK: Lazy<SecretKey> = Lazy::new(|| {
    "cc5417e929f7756df9a599715ad0780cea75659279cd4e2c0a19adb6339d7011"
        .parse()
        .expect("is a valid key")
});

/// Public key of the `COVENANT_SK`, used to verify that the
/// transaction data on the input's witness stack is equivalent to the
/// transaction which inludes the input itself.
static COVENANT_PK: &str = "03b9b6059008e3576aad58e05a3a3e37133b05f68cda8535ec097ef4bae564a6af";

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
