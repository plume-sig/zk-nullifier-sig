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
    elliptic_curve::{
        bigint::ArrayEncoding, hash2curve::{
            ExpandMsgXmd, GroupDigest
        }, ops::ReduceNonZero, point::NonIdentity, sec1::ToEncodedPoint, subtle::CtOption
    }, NonZeroScalar, Secp256k1, U256
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
use rand_core::CryptoRngCore;
use signature::{Error, RandomizedSigner};
use std::panic;

mod utils;
// not published due to use of `Projective...`; these utils can be found in other crates
use utils::*;

/// The domain separation tag used for hashing to the `secp256k1` curve
pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm

impl PlumeSignature {
    /// Verifies a PLUME signature.
    /// Returns `true` if the signature is valid.
    pub fn verify(&self) -> bool {
        // Verifier check in SNARK:
        // g^[r + sk * c] / (g^sk)^c = g^r
        // hash[m, gsk]^[r + sk * c] / (hash[m, pk]^sk)^c = hash[m, pk]^r
        // c = hash2(g, g^sk, hash[m, g^sk], hash[m, pk]^sk, gr, hash[m, pk]^r)

        let c_scalar = *self.c;

        let r_point = ProjectivePoint::GENERATOR * *self.s - self.pk * c_scalar;

        let hashed_to_curve = hash_to_curve(&self.message, &self.pk);
        if hashed_to_curve.is_err() {
            return false;
        }
        let hashed_to_curve = hashed_to_curve.unwrap();

        let hashed_to_curve_r = hashed_to_curve * *self.s - self.nullifier * c_scalar;

        if let Some(PlumeSignatureV1Fields {
            r_point: sig_r_point,
            hashed_to_curve_r: sig_hashed_to_curve_r,
        }) = self.v1specific
        {
            // Check whether g^r equals g^s * pk^{-c}
            if &r_point != &sig_r_point {
                return false;
            }

            // Check whether h^r equals h^{r + sk * c} * nullifier^{-c}
            if &hashed_to_curve_r != &sig_hashed_to_curve_r {
                return false;
            }

            let c_computed = NonZeroScalar::from_repr(c_sha256_vec_signal(vec![
                &ProjectivePoint::GENERATOR,
                &self.pk,
                &hashed_to_curve,
                &self.nullifier,
                &r_point,
                &hashed_to_curve_r,
            ])); 
            if c_computed.is_none().into() {false}
            else {
                // Check if the given hash matches
                c_scalar == *c_computed.unwrap()
            }
        } else {
            let c_computed = NonZeroScalar::from_repr(c_sha256_vec_signal(vec![&self.nullifier, &r_point, &hashed_to_curve_r]));
            if c_computed.is_none().into() {false}
            else {
                // Check if the given hash matches
                c_scalar == *c_computed.unwrap()
            }
        }
    }

    /// Same as using [`RandomizedSigner`] with [`PlumeSigner`], but with dedicated method for a variant; use it when you don't want to `use` PlumeSigner and the trait in your code.
    pub fn sign_v1(secret_key: &SecretKey, msg: &[u8], rng: &mut impl CryptoRngCore) -> Self {PlumeSigner::new(secret_key, true).sign_with_rng(rng, msg)}
    pub fn sign_v2(secret_key: &SecretKey, msg: &[u8], rng: &mut impl CryptoRngCore) -> Self {PlumeSigner::new(secret_key, false).sign_with_rng(rng, msg)}
}

pub struct PlumeSigner<'signing> {
    secret_key: &'signing SecretKey,
    // Since #lastoponsecret seems to me indistinguishible between variants here's `bool` is used instead of `subtle`
    pub v1: bool
}
impl<'signing> PlumeSigner<'signing> {pub fn new(secret_key: &SecretKey, v1: bool) -> PlumeSigner {PlumeSigner { secret_key, v1 }}}
impl<'signing> signature::RandomizedSigner<PlumeSignature> for PlumeSigner<'signing> {
    fn try_sign_with_rng(
        &self, rng: &mut impl CryptoRngCore, msg: &[u8]
    ) -> Result<PlumeSignature, Error> {
        // Pick a random r from Fp
        let r_scalar = SecretKey::random(rng);

        let r_point = r_scalar.public_key();
        
        // TODO remove me!
        use k256::elliptic_curve::point::AffineCoordinates;
        println!("{:x}", r_point.as_affine().x()); 
        dbg!("{}", r_point.as_affine().y_is_odd());

        let pk = self.secret_key.public_key();
        let pk_bytes = pk.to_encoded_point(true).to_bytes();
        
        // Compute h = htc([m, pk])
        let hashed_to_curve = NonIdentity::new(Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
            &[msg, &pk_bytes], &[DST]
        ).map_err(|_| Error::new())?).expect(
            "something is drammatically wrong if the input hashed to the identity"
        );
        println!("`hashed_to_curve`:{:x}", hashed_to_curve.to_point().to_affine().x()); // TODO remove me!
        
        // it feels not that scary to store `r_scalar` as `NonZeroScalar` (compared to `self.secret_key`)
        let r_scalar = r_scalar.to_nonzero_scalar();

        // Compute z = h^r
        let hashed_to_curve_r = hashed_to_curve * r_scalar;
        println!("`hashed_to_curve_r $x$:`{:x}", hashed_to_curve_r.to_point().to_affine().x()); // TODO remove me!
        
        // Compute nul = h^sk
        let nullifier = hashed_to_curve * self.secret_key.to_nonzero_scalar();
        
        // Compute c = sha512([g, pk, h, nul, g^r, z])
        let mut hasher = Sha256::new();
        // shorthand for updating the hasher which repeats a lot below
        macro_rules! updhash {
            ($p:ident) => {
                hasher.update($p.to_encoded_point(true).as_bytes())
            };
        }
        if self.v1 {
            hasher.update(ProjectivePoint::GENERATOR.to_encoded_point(true).as_bytes());
            hasher.update(pk_bytes);
            updhash!(hashed_to_curve);
        }
        updhash!(nullifier);
        updhash!(r_point);
        updhash!(hashed_to_curve_r);
        
        let c = hasher.finalize();
        // let c_scalar = NonZeroScalar::reduce_nonzero(
        //     U256::from_be_byte_array(c)
        // );
        let c_scalar = 
            // <NonZeroScalar as ReduceNonZero<U256>>::reduce_nonzero_bytes(&c);
            NonZeroScalar::from_repr(c).unwrap(); // TODO replace `unwrap`
        println!("c:{:x}", c_scalar); // TODO remove me!
        // Compute $s = r + sk ⋅ c$. #lastoponsecret
        let s_scalar = NonZeroScalar::new(*r_scalar + *(c_scalar * self.secret_key.to_nonzero_scalar()))
            .expect("something is terribly wrong if the nonce is equal to negated product of the secret and the hash");
        println!("sk_c:{:x}", self.secret_key.to_nonzero_scalar() * c_scalar); // TODO remove me!
        println!("sk:{:x}", self.secret_key.to_nonzero_scalar()); // TODO remove me!
        
        Ok(PlumeSignature{
            message: msg.to_owned(),
            pk: pk.into(),
            nullifier: nullifier.to_point(),
            c: c_scalar,
            s: s_scalar,
            v1specific: 
                if self.v1 {Some(PlumeSignatureV1Fields{
                    r_point: r_point.into(),
                    hashed_to_curve_r: hashed_to_curve_r.to_point(),
                })}
                else {None}
        })
    }
}
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
    pub c: NonZeroScalar,
    /// Part of the signature data, a scalar value.
    pub s: NonZeroScalar,
    /// Optional signature data for variant 1 signatures.
    pub v1specific: Option<PlumeSignatureV1Fields>,
}
/// Nested struct holding additional signature data used in variant 1 of the protocol.
#[derive(Debug)]
pub struct PlumeSignatureV1Fields {
    /// Part of the signature data, a curve point.  
    pub r_point: ProjectivePoint,
    /// Part of the signature data, a curve point.
    pub hashed_to_curve_r: ProjectivePoint,
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
