use std::convert::TryInto;

use halo2curves_axiom::{
  bn256::Fr,
  secp256k1::{ Fp, Fq, Secp256k1, Secp256k1Affine },
  CurveAffine,
};
use k256::{
  elliptic_curve::{
    group::Curve,
    hash2curve::{ ExpandMsgXmd, GroupDigest },
    sec1::ToEncodedPoint,
    Field,
    PrimeField,
  },
  Secp256k1 as K256Secp256k1,
};
use num_bigint::BigUint;
use num_traits::Num;
use pse_poseidon::Poseidon;
use rand::rngs::OsRng;
use serde::{ Deserialize, Serialize };
use tsify::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct PlumeInputs {
  pub plume: String,
  pub public_key: String,
  pub hash_m_pk_pow_r: String,
  pub g_pow_r: String,
  pub c: String,
  pub s: String,
}

pub fn compress_point(point: &Secp256k1Affine) -> [u8; 33] {
  let mut x = point.x.to_bytes();
  x.reverse();
  let y_is_odd = if point.y.is_odd().unwrap_u8() == 1u8 { 3u8 } else { 2u8 };
  let mut compressed_pk = [0u8; 33];
  compressed_pk[0] = y_is_odd;
  compressed_pk[1..].copy_from_slice(&x);

  compressed_pk
}

pub fn hash_to_curve(message: &[u8], compressed_pk: &[u8; 33]) -> Secp256k1Affine {
  let hashed_to_curve = K256Secp256k1::hash_from_bytes::<ExpandMsgXmd<Poseidon<Fr, 3, 2>>>(
    &[[message, compressed_pk].concat().as_slice()],
    &[b"QUUX-V01-CS02-with-secp256k1_XMD:POSEIDON_SSWU_RO_"]
  )
    .unwrap()
    .to_affine();
  let hashed_to_curve = hashed_to_curve.to_encoded_point(false).to_bytes().into_vec();
  assert_eq!(hashed_to_curve.len(), 65);

  let mut x = hashed_to_curve[1..33].to_vec();
  x.reverse();
  let mut y = hashed_to_curve[33..].to_vec();
  y.reverse();

  Secp256k1Affine::from_xy(
    Fp::from_bytes(x.as_slice().try_into().unwrap()).unwrap(),
    Fp::from_bytes(y.as_slice().try_into().unwrap()).unwrap()
  ).unwrap()
}

pub fn gen_nullifier(
  sk: Fq,
  message: &[u8]
) -> (Secp256k1Affine, Secp256k1Affine, Fq, Fq, Secp256k1Affine, Secp256k1Affine) {
  let pk = Secp256k1Affine::from(Secp256k1::generator() * sk);
  let compressed_pk = compress_point(&pk);

  let hashed_to_curve = hash_to_curve(message, &compressed_pk);

  let hashed_to_curve_sk = (hashed_to_curve * sk).to_affine();

  let r = Fq::random(&mut OsRng);
  let g_r = (Secp256k1::generator() * r).to_affine();
  let hashed_to_curve_r = (hashed_to_curve * r).to_affine();

  let mut poseidon_hasher = Poseidon::<Fr, 3, 2>::new(8, 57);
  poseidon_hasher.update(
    &[
      compress_point(&Secp256k1::generator().to_affine()),
      compressed_pk,
      compress_point(&hashed_to_curve),
      compress_point(&hashed_to_curve_sk),
      compress_point(&g_r),
      compress_point(&hashed_to_curve_r),
    ]
      .concat()
      .iter()
      .map(|v| Fr::from(*v as u64))
      .collect::<Vec<Fr>>()
  );

  let c = poseidon_hasher.squeeze_and_reset();

  let c = Fq::from_bytes(&c.to_bytes()).unwrap();
  let s = r + sk * c;

  (pk, hashed_to_curve_sk, s, c, hashed_to_curve_r, g_r)
}

#[wasm_bindgen(js_name = computeAllInputs)]
pub fn compute_all_inputs(
  message: String,
  secret_key: String,
  _r: Option<String>,
  _version: Option<u8>
) -> PlumeInputs {
  let message_bytes = message.as_bytes();
  let secret_key = BigUint::from_str_radix(&secret_key, 16).unwrap().to_bytes_le();
  let secret_key = Fq::from_bytes(&secret_key[..32].try_into().unwrap()).unwrap();

  let (pk, plume, s, c, hash_m_pk_pow_r, g_pow_r) = gen_nullifier(secret_key, message_bytes);

  let pk_str = "0x".to_string() + &hex::encode(compress_point(&pk));
  let plume_str = "0x".to_string() + &hex::encode(compress_point(&plume));
  let s_str = "0x".to_string() + &BigUint::from_bytes_le(s.to_bytes().as_slice()).to_str_radix(16);
  let c_str = "0x".to_string() + &BigUint::from_bytes_le(c.to_bytes().as_slice()).to_str_radix(16);
  let hash_m_pk_pow_r_str = "0x".to_string() + &hex::encode(compress_point(&hash_m_pk_pow_r));
  let g_pow_r_str = "0x".to_string() + &hex::encode(compress_point(&g_pow_r));

  PlumeInputs {
    plume: plume_str,
    public_key: pk_str,
    hash_m_pk_pow_r: hash_m_pk_pow_r_str,
    g_pow_r: g_pow_r_str,
    c: c_str,
    s: s_str,
  }
}
