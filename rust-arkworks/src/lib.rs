//! This crate provides the PLUME signature scheme.
//!
//! See <https://blog.aayushg.com/nullifier> for more information.
//!
//! Find the crate to use with RustCrypto as `plume_rustcrypto`.
//!
//! # Examples
//! ```rust
//! use plume_arkworks::{PlumeSignature, PlumeVersion, SWCurveConfig};
//! use rand_core::OsRng;
//!
//! # fn main() {
//!     let message_the = b"ZK nullifier signature";
//!     let sk = PlumeSignature::keygen(&mut OsRng);
//!
//!     let sig = PlumeSignature::sign(
//!         &mut OsRng, (&sk.0, &sk.1), message_the.as_slice(), PlumeVersion::V1
//!     );
//!
//!     assert!(
//!         sig.unwrap()
//!         .verify_non_zk(
//!             &plume_arkworks::Parameters{
//!                 g_point: plume_arkworks::secp256k1::Config::GENERATOR
//!             },
//!             &sk.0,
//!             message_the,
//!             PlumeVersion::V1
//!         ).unwrap()
//!     );
//! # }
//! ```

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
/// Re-exports the `Rng` trait from `rand` crate in `ark_std`.
///
/// `Rng` provides methods for generating random values.
pub use ark_std::rand::Rng;

pub use ark_ff::{BigInteger, PrimeField};

/// Re-exports the `CanonicalDeserialize` and `CanonicalSerialize` traits from `ark_serialize` crate.
///
/// These traits provide methods for serializing and deserializing data in a canonical format.
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use fixed_hasher::FixedFieldHasher;
use sha2::{digest::Output, Digest, Sha256};
use std::ops::Mul;

/// Re-exports the `Affine` and `Fr` types from `secp256k1` module.
///
/// `Affine` represents an affine point on `secp256k1` elliptic curve.
/// `Fr` represents an element of the scalar field of the secp256k1 elliptic curve.
pub use secp256k1::{Affine, Fr};

/// An `enum` representing the variant of the PLUME protocol.
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

fn hash_to_curve(message: &[u8], pk: &Affine) -> Result<Affine, HashToCurveError> {
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

/// A struct containing the PLUME signature data
#[derive(
    Copy,
    Clone,
    ark_serialize_derive::CanonicalSerialize,
    ark_serialize_derive::CanonicalDeserialize,
)]
pub struct PlumeSignature {
    /// The hash-to-curve output multiplied by the random `r`.  
    pub hashed_to_curve_r: Affine,
    /// The randomness `r` represented as the curve point.
    pub r_point: Affine,
    pub s: Fr,
    pub c: Fr,
    /// The nullifier.
    pub nullifier: Affine,
}

// These aliases should be gone in #88 . If they won't TODO pay attention to the warning about `trait` boundaries being not checked for aliases
//      also not enforcing trait bounds can impact PublicKey -- it's better to find appropriate upstream type

/// A type alias for a byte slice reference, used for representing the message.
pub type Message<'a> = &'a [u8];
/// The public key.
pub type PublicKey = Affine;
/// The scalar field element representing the secret key.
pub type SecretKeyMaterial = Fr;

impl PlumeSignature {
    /// Generate the public key and a private key.
    pub fn keygen(rng: &mut impl Rng) -> (PublicKey, SecretKeyMaterial) {
        let secret_key = SecretKeyMaterial::rand(rng);
        let public_key = secp256k1::Config::GENERATOR * secret_key;
        (public_key.into_affine(), secret_key)
    }

    /// Sign a message using the specified `r` value
    pub fn sign_with_r(
        keypair: (&PublicKey, &SecretKeyMaterial),
        message: Message,
        r_scalar: Fr,
        version: PlumeVersion,
    ) -> Result<Self, HashToCurveError> {
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

        let signature = PlumeSignature {
            hashed_to_curve_r,
            s: s_scalar,
            r_point,
            c: c_scalar,
            nullifier,
        };
        Ok(signature)
    }

    /// Sign a message.
    pub fn sign(
        rng: &mut impl Rng,
        keypair: (&PublicKey, &SecretKeyMaterial),
        message: Message,
        version: PlumeVersion,
    ) -> Result<Self, HashToCurveError> {
        // Pick a random r from Fp
        let r_scalar = secp256k1::Fr::rand(rng);

        Self::sign_with_r(keypair, message, r_scalar, version)
    }

    /// Verifies a PLUME signature.
    /// Returns `true` if the signature is valid, `false` otherwise.
    ///
    /// Computes the curve points and scalars needed for verification from the
    /// signature parameters. Then performs the verification steps:
    /// - Confirm g^s * pk^-c = g^r
    /// - Confirm h^s * nul^-c = z
    /// - Confirm c = c'
    ///
    /// Rejects if any check fails.
    pub fn verify_non_zk(
        self,
        pp: &Parameters<secp256k1::Config>,
        pk: &PublicKey,
        message: Message,
        version: PlumeVersion,
    ) -> Result<bool, HashToCurveError> {
        // Compute h = htc([m, pk])
        let hashed_to_curve = hash_to_curve(message, pk)?;

        // Compute c' = sha256([g, pk, h, nul, g^r, z]) for v1
        //         c' = sha256([nul, g^r, z]) for v2
        let c = match version {
            PlumeVersion::V1 => compute_c_v1(
                pk,
                &hashed_to_curve,
                &self.nullifier,
                &self.r_point,
                &self.hashed_to_curve_r,
            ),
            PlumeVersion::V2 => {
                compute_c_v2(&self.nullifier, &self.r_point, &self.hashed_to_curve_r)
            }
        };
        let c_scalar = secp256k1::Fr::from_be_bytes_mod_order(c.as_ref());

        // Reject if g^s ⋅ pk^{-c} != g^r
        let g_s = pp.g_point.mul(self.s);
        let pk_c = pk.mul(self.c);
        let g_s_pk_c = g_s - pk_c;

        if self.r_point != g_s_pk_c {
            return Ok(false);
        }

        // Reject if h^s ⋅ nul^{-c} = z
        let h_s = hashed_to_curve.mul(self.s);
        let nul_c = self.nullifier.mul(self.c);
        let h_s_nul_c = h_s - nul_c;

        if self.hashed_to_curve_r != h_s_nul_c {
            return Ok(false);
        }

        // Reject if c != c'
        if c_scalar != self.c {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests;
