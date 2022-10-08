#![allow(dead_code)]
#![allow(unused_variables)]
// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::{
    // ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::group::ff::PrimeField,
    sha2::{Digest, Sha256, Sha512},
    FieldBytes,
    ProjectivePoint,
    Scalar,
    Secp256k1,
}; // requires 'getrandom' feature

use crate::serialize::encode_pt;

const L: usize = 48;
const COUNT: usize = 2;
const OUT: usize = L * COUNT;
pub const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm

#[derive(Debug, PartialEq)]
pub enum Error {
    IsPointAtInfinityError,
}

pub fn sha512hash6signals(
    g: &ProjectivePoint,
    pk: &ProjectivePoint,
    hash_m_pk: &ProjectivePoint,
    nullifier: &ProjectivePoint,
    g_r: &ProjectivePoint,
    hash_m_pk_pow_r: &ProjectivePoint,
) -> Scalar {
    let g_bytes = encode_pt(*g).unwrap();
    let pk_bytes = encode_pt(*pk).unwrap();
    let h_bytes = encode_pt(*hash_m_pk).unwrap();
    let nul_bytes = encode_pt(*nullifier).unwrap();
    let g_r_bytes = encode_pt(*g_r).unwrap();
    let z_bytes = encode_pt(*hash_m_pk_pow_r).unwrap();

    let c_preimage_vec = [g_bytes, pk_bytes, h_bytes, nul_bytes, g_r_bytes, z_bytes].concat();

    //println!("c_preimage_vec: {:?}", c_preimage_vec);

    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(c_preimage_vec.as_slice());
    let sha512_hasher_result = sha512_hasher.finalize(); //512 bit hash

    let c_bytes = FieldBytes::from_iter(sha512_hasher_result.iter().copied());
    let c_scalar = Scalar::from_repr(c_bytes).unwrap();
    c_scalar
}

// Calls the hash to curve function for secp256k1, and returns the result as a ProjectivePoint
pub fn hash_to_secp(s: &[u8]) -> ProjectivePoint {
    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[s],
        //b"CURVE_XMD:SHA-256_SSWU_RO_"
        DST,
    )
    .unwrap();
    pt
}

// Hashes two values to the curve
pub fn hash_m_pk_to_secp(m: &[u8], pk: &ProjectivePoint) -> ProjectivePoint {
    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[[m, &encode_pt(*pk).unwrap()].concat().as_slice()],
        //b"CURVE_XMD:SHA-256_SSWU_RO_",
        DST,
    )
    .unwrap();
    pt
}

// Verifier check in SNARK:
// g^[r + sk * c] / (g^sk)^c = g^r
// hash[m, gsk]^[r + sk * c] / (hash[m, pk]^sk)^c = hash[m, pk]^r
// c = hash2(g, g^sk, hash[m, g^sk], hash[m, pk]^sk, gr, hash[m, pk]^r)
pub fn verify_signals(
    m: &[u8],
    pk: &ProjectivePoint,
    nullifier: &ProjectivePoint,
    c: &Scalar,
    r_sk_c: &Scalar,
    g_r_option: &Option<ProjectivePoint>,
    hash_m_pk_pow_r_option: &Option<ProjectivePoint>,
) -> bool {
    let mut verified: bool = true;

    // The base point or generator of the curve.
    let g = &ProjectivePoint::GENERATOR;

    // hash[m, pk]
    let hash_m_pk = &hash_m_pk_to_secp(m, pk);

    // Check whether g^r equals g^s * pk^{-c}
    let g_r: ProjectivePoint;
    match *g_r_option {
        Some(_g_r_value) => {
            if (g * r_sk_c - pk * c) != _g_r_value {
                verified = false;
            }
        }
        None => println!("g^r not provided, check skipped"),
    }
    g_r = g * r_sk_c - pk * c;

    // Check whether h^r equals h^{r + sk * c} * nullifier^{-c}
    let hash_m_pk_pow_r: ProjectivePoint;
    match *hash_m_pk_pow_r_option {
        Some(_hash_m_pk_pow_r_value) => {
            if (hash_m_pk * r_sk_c - nullifier * c) != _hash_m_pk_pow_r_value {
                verified = false;
            }
        }
        None => println!("hash_m_pk_pow_r not provided, check skipped"),
    }
    hash_m_pk_pow_r = hash_m_pk * r_sk_c - nullifier * c;

    // Check if the given hash matches
    if (sha512hash6signals(g, pk, hash_m_pk, nullifier, &g_r, &hash_m_pk_pow_r)) != *c {
        verified = false;
    }
    verified
}
