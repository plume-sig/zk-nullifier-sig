//! This crate provides the PLUME signature scheme.
//!
//! See <https://blog.aayushg.com/nullifier> for more information.
//!
//! Find the crate to use with RustCrypto as `plume_rustcrypto`.
//!
//! # Examples
//! ```rust
//! use plume_arkworks::{
//!     PlumeSignaturePublic, PlumeSignaturePrivate, PlumeVersion, sign, SWCurveConfig, CurveGroup,
//!     secp256k1::{Fr, Config},
//!     rand::rngs::OsRng
//! };
//!
//! # fn main() {
//!     let message_the = b"ZK nullifier signature";
//!     // you should get the real secret key you for signing
//!     let sk = <Fr as ark_ff::UniformRand>::rand(&mut OsRng);
//!
//!     let sig = sign(
//!         &mut OsRng, (
//!             &(Config::GENERATOR * sk).into_affine(),
//!             &sk,
//!         ), message_the.as_slice(), PlumeVersion::V1
//!     );
//! # }
//! ```
// TODO the example is lame, but I'm first worried if it's the right `OsRng` utilization or it's ok to just continue to use the same on the other occurence

/// Stand-in solution until [the default hasher issue](https://github.com/arkworks-rs/algebra/issues/849) is fixed.
pub mod fixed_hasher; // #standinDependencies
/// Stand-in solution until [the curve hashing support](https://github.com/arkworks-rs/algebra/pull/863) is merged.
pub mod secp256k1; // #standinDependencies

pub use ark_ec::{
    hashing::{
        curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
        HashToCurveError,
    },
    models::short_weierstrass::SWCurveConfig,
    short_weierstrass, AffineRepr, CurveGroup,
};
pub use ark_std::rand;

pub use ark_ff::{BigInteger, PrimeField};

/// Re-exports the `CanonicalDeserialize` and `CanonicalSerialize` traits from `ark_serialize` crate.
///
/// These traits provide methods for serializing and deserializing data in a canonical format.
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use fixed_hasher::FixedFieldHasher;
pub use sha2::{digest::Output, Digest, Sha256};
use std::ops::Mul;
pub use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

/// Re-exports the `Affine` and `Fr` types from `secp256k1` module.
///
/// `Affine` represents an affine point on `secp256k1` elliptic curve.
/// `Fr` represents an element of the scalar field of the secp256k1 elliptic curve.
pub use secp256k1::{Affine, Fr};

/// An `enum` representing the variant of the PLUME protocol.
#[derive(Debug, Clone, Copy, PartialEq /* Eq, Hash */)]
pub enum PlumeVersion {
    V1,
    V2,
}

/// Converts an affine point on the curve to the byte representation.
///
/// Serializes the affine point to its SEC1 compressed encoding and returns the raw bytes.
///
/// Note that the identity element is coded with the `Vec` of single zero byte.
pub fn affine_to_bytes(point: &Affine) -> Vec<u8> {
    if point.is_zero() {
        return [0].into();
    }
    let mut compressed_bytes = Vec::new();
    point.serialize_compressed(&mut compressed_bytes).expect("it's actually infallible here because the `BaseField` is a proper `Fp` (no flags on serialization)");
    compressed_bytes.reverse();
    compressed_bytes[0] = if point
        .y()
        .expect("zero check have been done above")
        .into_bigint()
        .is_odd()
    {
        3
    } else {
        2
    };
    compressed_bytes
}

pub fn hash_to_curve(message: &[u8], pk: &Affine) -> Result<Affine, HashToCurveError> {
    MapToCurveBasedHasher::<
        ark_ec::short_weierstrass::Projective<secp256k1::Config>,
        FixedFieldHasher<Sha256>,
        WBMap<secp256k1::Config>,
    >::new(b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_")?
    .hash(
        [message, affine_to_bytes(pk).as_slice()]
            .concat()
            .as_slice(),
    )
}

fn compute_c_v1(
    pk: &secp256k1::Affine,
    hashed_to_curve: &secp256k1::Affine,
    nullifier: &secp256k1::Affine,
    r_point: &secp256k1::Affine,
    hashed_to_curve_r: &secp256k1::Affine,
) -> Output<Sha256> {
    // Compute c = sha256([g, pk, h, nul, g^r, z])
    let c_preimage_vec = [
        affine_to_bytes(&secp256k1::Config::GENERATOR),
        affine_to_bytes(pk),
        affine_to_bytes(hashed_to_curve),
        affine_to_bytes(nullifier),
        affine_to_bytes(r_point),
        affine_to_bytes(hashed_to_curve_r),
    ]
    .concat();

    Sha256::digest(c_preimage_vec.as_slice())
}

fn compute_c_v2(
    nullifier: &secp256k1::Affine,
    r_point: &secp256k1::Affine,
    hashed_to_curve_r: &secp256k1::Affine,
) -> Output<Sha256> {
    // Compute c = sha256([nul, g^r, z])
    let nul_bytes = affine_to_bytes(nullifier);
    let g_r_bytes = affine_to_bytes(r_point);
    let z_bytes = affine_to_bytes(hashed_to_curve_r);

    let c_preimage_vec = [nul_bytes, g_r_bytes, z_bytes].concat();

    Sha256::digest(c_preimage_vec.as_slice())
}

/// A struct containing parameters for the SW model, including the generator point `g_point`.
/// This struct implements traits for (de)serialization.
#[derive(
    Copy,
    Clone,
    ark_serialize_derive::CanonicalSerialize,
    ark_serialize_derive::CanonicalDeserialize,
)]
pub struct Parameters<P: SWCurveConfig> {
    /// The generator point for the SW model parameters.
    pub g_point: short_weierstrass::Affine<P>,
}

/// PLUME signature instance
#[derive(
    // Copy,
    Clone,
    // ark_serialize_derive::CanonicalSerialize,
    // ark_serialize_derive::CanonicalDeserialize,
)]
pub struct PlumeSignaturePublic {
    pub message: Vec<u8>,
    pub s: Fr,
    /// The nullifier.
    pub nullifier: Affine,
    pub variant: Option<PlumeVersion>,
}
/// PLUME signature witness. Store securely and choose which data from the public part you will use to identify this part.
#[derive(Clone)]
pub struct PlumeSignaturePrivate {
    /// The hash-to-curve output multiplied by the random `r`.  
    pub hashed_to_curve_r: Affine,
    /// The randomness `r` represented as the curve point.
    pub r_point: Affine,
    pub digest_private: Fr,
    pub variant: PlumeVersion,
}
impl Zeroize for PlumeSignaturePrivate {
    fn zeroize(&mut self) {
        self.digest_private.zeroize();
        self.hashed_to_curve_r.zeroize();
        self.r_point.zeroize();
    }
}
impl ZeroizeOnDrop for PlumeSignaturePrivate {}
impl Drop for PlumeSignaturePrivate {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// These aliases should be gone in #88 . If they won't TODO pay attention to the warning about `trait` boundaries being not checked for aliases
//      also not enforcing trait bounds can impact PublicKey -- it's better to find appropriate upstream type

/// The public key.
pub type PublicKey = Affine;
/// The scalar field element representing the secret key.
pub type SecretKeyMaterial = Fr;

/// Sign a message using the specified `r` value.
///
/// # WARNING
/// Makes sense only in a constrained environment which lacks a secure RNG.
// TODO it'd be nice to feature flag this, but for current level of traction a warning is a more natural communication to an user
pub fn sign_with_r(
    keypair: (&PublicKey, &SecretKeyMaterial),
    message: &[u8],
    r_scalar: Fr,
    version: PlumeVersion,
) -> Result<(PlumeSignaturePublic, PlumeSignaturePrivate), HashToCurveError> {
    let r_point = secp256k1::Config::GENERATOR.mul(r_scalar).into_affine();

    // Compute h = htc([m, pk])
    let hashed_to_curve: secp256k1::Affine = hash_to_curve(message, keypair.0)?;

    // Compute z = h^r
    let hashed_to_curve_r = hashed_to_curve.mul(r_scalar).into_affine();

    // Compute nul = h^sk
    let nullifier = hashed_to_curve.mul(*keypair.1).into_affine();

    // Compute c = sha256([g, pk, h, nul, g^r, z])
    let c = match version {
        PlumeVersion::V1 => compute_c_v1(
            keypair.0,
            &hashed_to_curve,
            &nullifier,
            &r_point,
            &hashed_to_curve_r,
        ),
        PlumeVersion::V2 => compute_c_v2(&nullifier, &r_point, &hashed_to_curve_r),
    };
    let c_scalar = secp256k1::Fr::from_be_bytes_mod_order(c.as_ref());
    // Compute s = r + sk ⋅ c
    let sk_c = keypair.1 * &c_scalar;
    let s = r_scalar + sk_c;

    let s_scalar = secp256k1::Fr::from(s);

    Ok((
        PlumeSignaturePublic {
            message: message.into(),
            s: s_scalar,
            nullifier,
            variant: Some(version),
        },
        PlumeSignaturePrivate {
            hashed_to_curve_r,
            r_point,
            digest_private: c_scalar,
            variant: version,
        },
    ))
}

/// Sign a message.
pub fn sign(
    rng: &mut (impl rand::CryptoRng + rand::Rng),
    keypair: (&PublicKey, &SecretKeyMaterial),
    message: &[u8],
    version: PlumeVersion,
) -> Result<(PlumeSignaturePublic, PlumeSignaturePrivate), HashToCurveError> {
    // Pick a random r from Fp
    let r_scalar = secp256k1::Fr::rand(rng);

    sign_with_r(keypair, message, r_scalar, version)
}

#[cfg(test)]
mod tests;
