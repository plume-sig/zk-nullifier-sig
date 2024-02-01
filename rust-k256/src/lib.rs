// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

use k256::{
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
    elliptic_curve::ops::ReduceNonZero,
    elliptic_curve::sec1::ToEncodedPoint,
    elliptic_curve::{bigint::ArrayEncoding, group::ff::PrimeField},
    sha2::{digest::Output, Digest, Sha256},
    FieldBytes, Scalar, Secp256k1, U256,
}; // requires 'getrandom' feature
use std::panic;
// TODO #86
pub use k256::ProjectivePoint;

const L: usize = 48;
const COUNT: usize = 2;
const OUT: usize = L * COUNT;
pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
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

// Hashes two values to the curve
fn hash_to_curve(m: &[u8], pk: &ProjectivePoint) -> Result<ProjectivePoint, k256::elliptic_curve::Error> {
    Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[[m, &encode_pt(pk)].concat().as_slice()],
        //b"CURVE_XMD:SHA-256_SSWU_RO_",
        &[DST],
    )
}

/* currently seems to right place for this `struct` declaration;
should be moved (to the beginning of the file?) during refactoring for proper order of the items */
/* while no consistent #API is present here it's completely `pub`;
when API will be designed it should include this `struct` (and it also probably will hold values instead of references) */
#[derive(Debug)]
pub struct PlumeSignature<'a> {
    pub message: &'a [u8],
    pub pk: &'a ProjectivePoint,
    pub nullifier: &'a ProjectivePoint,
    pub c: &'a [u8],
    pub s: &'a Scalar,
    pub v1: Option<PlumeSignatureV1Fields<'a>>,
}
#[derive(Debug)]
pub struct PlumeSignatureV1Fields<'a> {
    pub r_point: &'a ProjectivePoint,
    pub hashed_to_curve_r: &'a ProjectivePoint,
}
impl PlumeSignature<'_> {
    // Verifier check in SNARK:
    // g^[r + sk * c] / (g^sk)^c = g^r
    // hash[m, gsk]^[r + sk * c] / (hash[m, pk]^sk)^c = hash[m, pk]^r
    // c = hash2(g, g^sk, hash[m, g^sk], hash[m, pk]^sk, gr, hash[m, pk]^r)
    pub fn verify_signals(&self) -> bool {
        // don't forget to check `c` is `Output<Sha256>` in the #API
        let c = panic::catch_unwind(|| {Output::<Sha256>::from_slice(self.c)});
        if c.is_err() {return false;}
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

/// Encodes the point by compressing it to 33 bytes
fn encode_pt(point: &ProjectivePoint) -> Vec<u8> {
    point.to_encoded_point(true).to_bytes().to_vec()
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
