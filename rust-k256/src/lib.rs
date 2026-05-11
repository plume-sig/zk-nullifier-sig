// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

//! A library for generating PLUME signatures.
//!
//! See <https://blog.aayushg.com/nullifier> for more information.
//!
//! Find the crate to use with `arkworks-rs` crate as `plume_arkworks`.
//
//! # Examples
//! If you want more control or to be more generic on traits `use` [`PlumeSigner`] from [`randomizedsigner`]
//! ```rust
//! use plume_rustcrypto::{PlumeSignature, SecretKey};
//! use rand_core::OsRng;
//! # fn main() {
//! #   let sk = SecretKey::random(&mut OsRng);
//! #       
//!     let sig_v1 = PlumeSignature::sign_v1(
//!         &sk, b"ZK nullifier signature", &mut OsRng
//!     );
//!
//!     let sig_v2 = PlumeSignature::sign_v2(
//!         &sk, b"ZK nullifier signature", &mut OsRng
//!     );
//! # }
//! ```

use k256::ProjectivePoint;
use signature::RandomizedSigner;

/// Exports types from the `k256` crate:
///
/// - `NonZeroScalar`: A secret 256-bit scalar value.
/// - `SecretKey`: A secret 256-bit scalar wrapped in a struct.  
/// - `AffinePoint`: A public elliptic curve point.
pub use k256::{AffinePoint, NonZeroScalar, SecretKey};
/// Re-exports the [`CryptoRngCore`] trait from the [`rand_core`] crate.
/// This allows it to be used from the current module.
pub use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
/// Provides the ability to serialize and deserialize data using the Serde library.
/// The `Serialize` and `Deserialize` traits from the Serde library are re-exported for convenience.
pub use serde::{Deserialize, Serialize};

#[cfg(test)]
mod utils;
#[cfg(test)]
// not published due to use of `Projective...`; these utils can be found in other crates
use utils::*;

/// Provides the [`RandomizedSigner`] trait implementation over [`PlumeSignature`].
pub mod randomizedsigner;
use randomizedsigner::PlumeSigner;

/// The domain separation tag used for hashing to the `secp256k1` curve
pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm

/// Struct holding signature data for a PLUME signature.
///
/// `v1specific` field differintiate whether V1 or V2 protocol will be used.
///
/// Non-zk verification is intentionally kept out of the public API because it
/// requires witness values that are not handled appropriately for production use.
///
/// ```compile_fail
/// use plume_rustcrypto::PlumeSignature;
///
/// fn verify_publicly(sig: PlumeSignature) {
///     let _ = sig.verify();
/// }
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlumeSignature {
    /// The message that was signed.
    pub message: Vec<u8>,
    /// The public key used to verify the signature.
    pub pk: AffinePoint,
    /// The nullifier.
    pub nullifier: AffinePoint,
    /// Part of the signature data. SHA-256 interpreted as a scalar.
    pub c: NonZeroScalar,
    /// Part of the signature data, a scalar value.
    pub s: NonZeroScalar,
    /// Optional signature data for variant 1 signatures.
    pub v1specific: Option<PlumeSignatureV1Fields>,
}
/// Nested struct holding additional signature data used in variant 1 of the protocol.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlumeSignatureV1Fields {
    /// Part of the signature data, a curve point.  
    pub r_point: AffinePoint,
    /// Part of the signature data, a curve point.
    pub hashed_to_curve_r: AffinePoint,
}
impl PlumeSignature {
    /// Yields the signature with `None` for `v1specific`. Same as using [`RandomizedSigner`] with [`PlumeSigner`];
    /// use it when you don't want to `use` PlumeSigner and the trait in your code.
    pub fn sign_v1(secret_key: &SecretKey, msg: &[u8], rng: &mut impl CryptoRngCore) -> Self {
        PlumeSigner::new(secret_key, true).sign_with_rng(rng, msg)
    }
    /// Yields the signature with `Some` for `v1specific`. Same as using [`RandomizedSigner`] with [`PlumeSigner`];
    /// use it when you don't want to `use` PlumeSigner and the trait in your code.
    pub fn sign_v2(secret_key: &SecretKey, msg: &[u8], rng: &mut impl CryptoRngCore) -> Self {
        PlumeSigner::new(secret_key, false).sign_with_rng(rng, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use k256::Scalar;

    // Test encode_pt()
    #[test]
    fn test_encode_pt() {
        let g_as_bytes = encode_pt(&ProjectivePoint::GENERATOR);
        assert_eq!(
            hex::encode(g_as_bytes),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    /// Convert a 32-byte array to a scalar
    fn byte_array_to_scalar(bytes: &[u8]) -> Scalar {
        // From https://docs.rs/ark-ff/0.3.0/src/ark_ff/fields/mod.rs.html#371-393
        assert!(bytes.len() == 32);
        let mut res = Scalar::from(0u64);
        let window_size = Scalar::from(256u64);
        for byte in bytes.iter() {
            res *= window_size;
            res += Scalar::from(*byte as u64);
        }
        res
    }

    // Test byte_array_to_scalar()
    #[test]
    fn test_byte_array_to_scalar() {
        let scalar = byte_array_to_scalar(&hex!(
            "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
        ));
        assert_eq!(
            hex::encode(scalar.to_bytes()),
            "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
        );
    }
}
