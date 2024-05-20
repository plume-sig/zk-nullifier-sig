use halo2_base::{
  halo2_proofs::halo2curves::{
    bn256::Fr,
    secp256k1::{ Fp, Fq, Secp256k1, Secp256k1Affine },
    CurveAffine,
  },
  utils::ScalarField,
};
use k256::{
  elliptic_curve::{
    group::Curve,
    hash2curve::{ ExpandMsgXmd, GroupDigest },
    sec1::ToEncodedPoint,
    Field,
    PrimeField,
  },
  sha2::{ Digest, Sha256 as K256Sha256 },
  Secp256k1 as K256Secp256k1,
};
use rand::rngs::OsRng;

use crate::PlumeCircuitInput;

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
  let hashed_to_curve = K256Secp256k1::hash_from_bytes::<ExpandMsgXmd<K256Sha256>>(
    &[[message, compressed_pk].concat().as_slice()],
    &[b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"]
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
    Fp::from_bytes_le(x.as_slice()),
    Fp::from_bytes_le(y.as_slice())
  ).unwrap()
}

pub fn verify_nullifier(
  message: &[u8],
  nullifier: &Secp256k1Affine,
  pk: &Secp256k1Affine,
  s: &Fq,
  c: &Fq
) {
  let compressed_pk = compress_point(&pk);
  let hashed_to_curve = hash_to_curve(message, &compressed_pk);
  let hashed_to_curve_s_nullifier_c = (hashed_to_curve * s - nullifier * c).to_affine();
  let gs_pkc = (Secp256k1::generator() * s - pk * c).to_affine();

  let mut sha_hasher = K256Sha256::new();
  sha_hasher.update(
    vec![
      compress_point(&Secp256k1::generator().to_affine()),
      compressed_pk,
      compress_point(&hashed_to_curve),
      compress_point(&nullifier),
      compress_point(&gs_pkc),
      compress_point(&hashed_to_curve_s_nullifier_c)
    ].concat()
  );

  let mut _c = sha_hasher.finalize();
  _c.reverse();
  let _c = Fq::from_bytes_le(_c.as_slice());

  assert_eq!(*c, _c);
}

pub fn gen_test_nullifier(sk: &Fq, message: &[u8]) -> (Secp256k1Affine, Fq, Fq) {
  let pk = (Secp256k1::generator() * sk).to_affine();
  let compressed_pk = compress_point(&pk);

  let hashed_to_curve = hash_to_curve(message, &compressed_pk);

  let hashed_to_curve_sk = (hashed_to_curve * sk).to_affine();

  let r = Fq::random(OsRng);
  let g_r = (Secp256k1::generator() * r).to_affine();
  let hashed_to_curve_r = (hashed_to_curve * r).to_affine();

  let mut sha_hasher = K256Sha256::new();
  sha_hasher.update(
    vec![
      compress_point(&Secp256k1::generator().to_affine()),
      compressed_pk,
      compress_point(&hashed_to_curve),
      compress_point(&hashed_to_curve_sk),
      compress_point(&g_r),
      compress_point(&hashed_to_curve_r)
    ].concat()
  );

  let mut c = sha_hasher.finalize();
  c.reverse();

  let c = Fq::from_bytes_le(c.as_slice());
  let s = r + sk * c;

  (hashed_to_curve_sk, s, c)
}

pub fn generate_test_data(msg: &[u8]) -> PlumeCircuitInput {
  let m = msg
    .iter()
    .map(|b| Fr::from(*b as u64))
    .collect::<Vec<_>>();

  let sk = Fq::random(OsRng);
  let pk = Secp256k1Affine::from(Secp256k1::generator() * sk);
  let (nullifier, s, c) = gen_test_nullifier(&sk, msg);
  verify_nullifier(msg, &nullifier, &pk, &s, &c);

  PlumeCircuitInput {
    nullifier: (nullifier.x, nullifier.y),
    s,
    c,
    pk: (pk.x, pk.y),
    m,
  }
}
