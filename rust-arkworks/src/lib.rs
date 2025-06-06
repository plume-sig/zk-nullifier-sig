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

/// Serializes the affine point to its SEC1 compressed encoding and returns the raw bytes.
/// Returns `None` if `affine` is the identity element.
///
/// Note that the identity element is SEC1 coded with the `[0u8]`.
/// Though the scheme shouldn't really encounter this case.
pub fn sec1_affine(affine: &Affine) -> Option<[u8; 33]> {
    let mut writer = [0u8; 33];
    CanonicalSerialize::serialize_compressed(affine, writer.as_mut_slice())
    .expect("the type serialization is completely covered and the `writer` accomodates the `Result` completely");
    writer.reverse();
    writer[0] =
        if ark_ff::BigInteger::is_odd(&ark_ff::PrimeField::into_bigint(AffineRepr::y(affine)?)) {
            3
        } else {
            2
        };
    Some(writer)
}

pub fn hash_to_curve(message: &[u8], pk: &Affine) -> Result<Affine, HashToCurveError> {
    MapToCurveBasedHasher::<
        ark_ec::short_weierstrass::Projective<secp256k1::Config>,
        FixedFieldHasher<Sha256>,
        WBMap<secp256k1::Config>,
    >::new(b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_")?
    .hash(
        [
            message,
            &sec1_affine(pk).ok_or(HashToCurveError::MapToCurveError(
                "`pk` shouldn't be the identity element".into(),
            ))?,
        ]
        .concat()
        .as_slice(),
    )
}

#[deprecated(
    note = "it's an awful hack, but it doesn't make the thing worse than it already is, 
and @skaunov expanded [the issue](https://github.com/plume-sig/zk-nullifier-sig/issues/111#issuecomment-2949397220) to fix it"
)]
fn helper(b: Option<[u8; 33]>) -> Vec<u8> {
    if b.is_some() {
        b.unwrap().into()
    } else {
        vec![0u8]
    }
}

fn compute_c_v1(
    pk: &secp256k1::Affine,
    hashed_to_curve: &secp256k1::Affine,
    nullifier: &secp256k1::Affine,
    r_point: &secp256k1::Affine,
    hashed_to_curve_r: &secp256k1::Affine,
    // ) -> Result<Output<Sha256>> {
) -> Output<Sha256> {
    // if pk.is_zero() {return  Err("()");}

    // sec1_affine(pk).expect("checked in the early `return Err`").as_slice(),
    // {if hashed_to_curve.is_zero() {&[0u8]} else {sec1_affine(hashed_to_curve).expect("checked conditionally").as_slice()}},

    // Compute c = sha256([g, pk, h, nul, g^r, z])
    let c_preimage_vec = [
        sec1_affine(&secp256k1::Config::GENERATOR)
            .expect("the generator can't be the identity element")
            .to_vec(),
        // .as_slice(),
        helper(sec1_affine(pk)),
        helper(sec1_affine(hashed_to_curve)),
        helper(sec1_affine(nullifier)),
        helper(sec1_affine(r_point)),
        helper(sec1_affine(hashed_to_curve_r)),
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
    let nul_bytes = helper(sec1_affine(nullifier));
    let g_r_bytes = helper(sec1_affine(r_point));
    let z_bytes = helper(sec1_affine(hashed_to_curve_r));

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
