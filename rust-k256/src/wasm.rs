use k256::{elliptic_curve::group::ff::PrimeField, ProjectivePoint, Scalar};
use rand::{rngs::StdRng, Rng, SeedableRng};
use wasm_bindgen::prelude::{wasm_bindgen}; // requires 'getrandom' feature

use crate::nullifier::{hash_m_pk_to_secp};
use crate::serialize::{byte_array_to_scalar, encode_pt};

#[wasm_bindgen]
pub fn make_nullifier(sk_hex: String, message: String, rng_seed: &[u8]) -> String {
    console_error_panic_hook::set_once();

    let sk = hex::decode(sk_hex).unwrap();
    let sk = byte_array_to_scalar(&sk);

    // The base point or generator of the curve.
    let g = ProjectivePoint::GENERATOR;

    let rng_seed: [u8; 32] = rng_seed.try_into().unwrap();
    let rng = &mut StdRng::from_seed(rng_seed);
    let r_bytes = rng.gen::<[u8; 32]>();
    // The signer's secret key. It is only accessed within the secure enclave.
    let r = Scalar::from_repr(r_bytes.into()).unwrap();

    // The user's public key: g^sk.
    let pk = &g * &sk;

    // The generator exponentiated by r: g^r.
    let g_r = &g * &r;

    // hash[m, pk]
    let hash_m_pk = hash_m_pk_to_secp(message.as_bytes(), &pk);

    // hash[m, pk]^r
    let hash_m_pk_pow_r = &hash_m_pk * &r;

    // The public nullifier: hash[m, pk]^sk.
    let nullifier = &hash_m_pk * &sk;

    // // The Fiat-Shamir type step.
    // let c = sha512hash6signals(&g, &pk, &hash_m_pk, &nullifier, &g_r, &hash_m_pk_pow_r);

    // // This value is part of the discrete log equivalence (DLEQ) proof.
    // let r_sk_c = r + sk * c;

    // // Return the signature.
    // (pk, nullifier, c, r_sk_c, g_r, hash_m_pk_pow_r)

    let nullifier = encode_pt(nullifier).unwrap();
    hex::encode(nullifier)
}