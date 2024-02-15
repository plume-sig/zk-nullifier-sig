// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

//! A library for generating (coming [soon](https://github.com/plume-sig/zk-nullifier-sig/issues/84)) and verifying PLUME signatures.
//!
//! See <https://blog.aayushg.com/nullifier> for more information.
//!
// Find `arkworks-rs` crate as `plume_arkworks`.
//
// # Examples
// For V2 just set `v1` to `None`
// ```rust
// # fn main() {
//     let sig_good = PlumeSignature<'a>{
//         message: &b"An example app message string",
//         pk: ProjectivePoint::GENERATOR * Scalar::from_repr(hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").into()).unwrap(),
//         ...
//     };
// # }
// ```

use k256::{
    elliptic_curve::ops::ReduceNonZero,
    elliptic_curve::{
        bigint::ArrayEncoding, group::ff::PrimeField, hash2curve::GroupDigest
    },
    FieldBytes, U256,
}; // requires 'getrandom' feature
// TODO
pub use k256::ProjectivePoint;
/// Re-exports the [`Scalar`] type, [`Sha256`] hash function, and [`Output`] type
/// from the [`k256`] crate's [`sha2`] module. This allows them to be used
/// from the current module.
pub use k256::{
    sha2::{digest::Output, Digest, Sha256},
    Scalar, SecretKey
};
use std::ops::Mul;
use std::panic;

mod utils;
// not published due to use of `Projective...`; these utils can be found in other crates
use utils::*;

/// The domain separation tag used for hashing to the `secp256k1` curve
pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm

/// Struct holding signature data for a PLUME signature.
///
/// `v1` field differintiate whether V1 or V2 protocol will be used.
pub struct PlumeSignature {
    /// The message that was signed.
    pub message: Vec<u8>,
    /// The public key used to verify the signature.
    pub pk: ProjectivePoint,
    /// The nullifier.
    pub nullifier: ProjectivePoint,
    /// Part of the signature data.
    pub c: Output<Sha256>,
    /// Part of the signature data, a scalar value.
    pub s: Scalar,
    /// Optional signature data for variant 1 signatures.
    pub v1: Option<PlumeSignatureV1Fields>,
}
/// Nested struct holding additional signature data used in variant 1 of the protocol.
#[derive(Debug)]
pub struct PlumeSignatureV1Fields {
    /// Part of the signature data, a curve point.  
    pub r_point: ProjectivePoint,
    /// Part of the signature data, a curve point.
    pub hashed_to_curve_r: ProjectivePoint,
}
impl PlumeSignature {
    pub fn sign(
        rng: &mut impl Rng,
        key: SecretKey,
        message: &[u8],
        v1: bool,
        // r_scalar: Option<SecretKey>
    ) -> Result<PlumeSignature, k256::elliptic_curve::Error> {
        // Compute h = htc([m, pk])
        let hashed_to_curve = k256::Secp256k1::hash_from_bytes(&[message], &[DST])?;

        // Compute z = h^r
        let hashed_to_curve_r = hashed_to_curve.mul(r_scalar).into_affine();

        // Compute nul = h^sk
        let nullifier = hashed_to_curve.mul(*keypair.1).into_affine();

        // Compute c = sha512([g, pk, h, nul, g^r, z])
        let c = match version {
            PlumeVersion::V1 => compute_c_v1::<P>(
                &g_point,
                keypair.0,
                &hashed_to_curve,
                &nullifier,
                &r_point,
                &hashed_to_curve_r,
            ),
            PlumeVersion::V2 => compute_c_v2(&nullifier, &r_point, &hashed_to_curve_r),
        };
        let c_scalar = P::ScalarField::from_be_bytes_mod_order(c.as_ref());
        // Compute s = r + sk ⋅ c
        let sk_c = keypair.1.into_repr().into() * c_scalar.into_repr().into();
        let s = r_scalar.into_repr().into() + sk_c;

        let s_scalar = P::ScalarField::from(s);

        let signature = PlumeSignature {
            hashed_to_curve_r,
            s: s_scalar,
            r_point,
            c: c_scalar,
            nullifier,
        };
        Ok(signature)
    }
    
    /// Verifies a PLUME signature.
    /// Returns `true` if the signature is valid.
    pub fn verify(&self) -> bool {
        // Verifier check in SNARK:
        // g^[r + sk * c] / (g^sk)^c = g^r
        // hash[m, gsk]^[r + sk * c] / (hash[m, pk]^sk)^c = hash[m, pk]^r
        // c = hash2(g, g^sk, hash[m, g^sk], hash[m, pk]^sk, gr, hash[m, pk]^r)

        // don't forget to check `c` is `Output<Sha256>` in the #API
        let c = panic::catch_unwind(|| Output::<Sha256>::from_slice(self.c));
        if c.is_err() {
            return false;
        }
        let c = c.unwrap();

        // TODO should we allow `c` input greater than BaseField::MODULUS?
        // TODO `reduce_nonzero` doesn't seems to be correct here. `NonZeroScalar` should be appropriate.
        let c_scalar = &Scalar::reduce_nonzero(U256::from_be_byte_array(c.to_owned()));

        let r_point = ProjectivePoint::GENERATOR * self.s - self.pk * c_scalar;

        let hashed_to_curve = hash_to_curve(self.message, self.pk);
        if hashed_to_curve.is_err() {
            return false;
        }
        let hashed_to_curve = hashed_to_curve.unwrap();

        let hashed_to_curve_r = hashed_to_curve * self.s - self.nullifier * c_scalar;

        if let Some(PlumeSignatureV1Fields {
            r_point: sig_r_point,
            hashed_to_curve_r: sig_hashed_to_curve_r,
        }) = self.v1
        {
            // Check whether g^r equals g^s * pk^{-c}
            if &r_point != sig_r_point {
                return false;
            }

            // Check whether h^r equals h^{r + sk * c} * nullifier^{-c}
            if &hashed_to_curve_r != sig_hashed_to_curve_r {
                return false;
            }

            // Check if the given hash matches
            c == &c_sha256_vec_signal(vec![
                &ProjectivePoint::GENERATOR,
                self.pk,
                &hashed_to_curve,
                self.nullifier,
                &r_point,
                &hashed_to_curve_r,
            ])
        } else {
            // Check if the given hash matches
            c == &c_sha256_vec_signal(vec![self.nullifier, &r_point, &hashed_to_curve_r])
        }
    }
}
impl signature::RandomizedSigner for PlumeSignature {
    
}

fn c_sha256_vec_signal(values: Vec<&ProjectivePoint>) -> Output<Sha256> {
    let preimage_vec = values
        .into_iter()
        .map(encode_pt)
        .collect::<Vec<_>>()
        .concat();
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(preimage_vec.as_slice());
    sha256_hasher.finalize()
}

// Withhold removing this before implementing `sign`
fn sha256hash6signals(
    g: &ProjectivePoint,
    pk: &ProjectivePoint,
    hash_m_pk: &ProjectivePoint,
    nullifier: &ProjectivePoint,
    g_r: &ProjectivePoint,
    hash_m_pk_pow_r: &ProjectivePoint,
) -> Scalar {
    let g_bytes = encode_pt(g);
    let pk_bytes = encode_pt(pk);
    let h_bytes = encode_pt(hash_m_pk);
    let nul_bytes = encode_pt(nullifier);
    let g_r_bytes = encode_pt(g_r);
    let z_bytes = encode_pt(hash_m_pk_pow_r);

    let c_preimage_vec = [g_bytes, pk_bytes, h_bytes, nul_bytes, g_r_bytes, z_bytes].concat();

    //println!("c_preimage_vec: {:?}", c_preimage_vec);

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(c_preimage_vec.as_slice());
    let sha512_hasher_result = sha256_hasher.finalize(); //512 bit hash

    let c_bytes = FieldBytes::from_iter(sha512_hasher_result.iter().copied());
    Scalar::from_repr(c_bytes).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

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
        )); // TODO this `fn` looks suspicious as in reproducing const time ops
        assert_eq!(
            hex::encode(scalar.to_bytes()),
            "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
        );
    }
}
