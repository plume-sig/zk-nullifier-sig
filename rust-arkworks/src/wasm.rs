use ark_ec::{short_weierstrass_jacobian::GroupAffine, AffineCurve};
use ark_ff::{biginteger, ToBytes};

use secp256k1::{Affine, Secp256k1Parameters};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::hash_to_curve::hash_to_curve;

fn compute_h(message: &str, sk_hex: &str) -> GroupAffine<Secp256k1Parameters> {
    let sk = hex_to_fr(sk_hex);
    let g = Affine::prime_subgroup_generator();
    let pk_projective = g.mul(sk);
    let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);

    let h = hash_to_curve::<secp256k1::fields::Fq, Secp256k1Parameters>(message.as_bytes(), &pk);
    h
}

fn hex_to_fr(hex: &str) -> secp256k1::fields::Fr {
    let num_field_bytes = 320;
    let mut sk_bytes_vec = vec![0u8; num_field_bytes];
    let mut sk_bytes = hex::decode(hex).unwrap();

    sk_bytes.reverse();

    for (i, _) in sk_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(&mut sk_bytes_vec[i], sk_bytes[i]);
    }

    <secp256k1::fields::Fr as ark_ff::FromBytes>::read(sk_bytes_vec.as_slice()).unwrap()
}

fn coord_to_hex(coord: biginteger::BigInteger320) -> String {
    let mut coord_bytes = vec![];
    let _ = coord.write(&mut coord_bytes);
    coord_bytes.reverse();

    hex::encode(coord_bytes)
}

#[wasm_bindgen]
pub fn make_nullifier(sk_hex: &str, message: &str) -> String {
    let h = compute_h(message, sk_hex);
    let sk = hex_to_fr(sk_hex);

    let h_sk_projective = h.mul(sk);
    let h_sk = GroupAffine::<Secp256k1Parameters>::from(h_sk_projective);

    coord_to_hex(h_sk.x.into())
}
