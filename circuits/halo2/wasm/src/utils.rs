use halo2_wasm::{
  halo2_base::utils::{ biguint_to_fe, ScalarField },
  halo2_proofs::{ arithmetic::CurveAffine, halo2curves::ff::PrimeField },
  halo2lib::ecc::{ Bn254Fr as Fr, Secp256k1Affine, Secp256k1Fp as Fp, Secp256k1Fq as Fq },
};
use num_bigint::BigUint;
use num_traits::Num;

pub fn parse_compressed_point(compressed_pt: String) -> Secp256k1Affine {
  let bytes = BigUint::from_str_radix(&compressed_pt[2..], 16)
    .unwrap()
    .to_bytes_le();

  let y_is_odd = bytes[bytes.len() - 1] == 3;

  let x = BigUint::from_bytes_le(&bytes[..bytes.len() - 1]);

  let modulus = BigUint::from_str_radix(&Fp::MODULUS.to_string()[2..], 16).unwrap();
  let y2 = (x.modpow(&BigUint::from(3u64), &modulus) + BigUint::from(7u64)) % &modulus;
  let mut y = y2.modpow(&((modulus.clone() + BigUint::from(1u64)) / BigUint::from(4u64)), &modulus);
  if y.bit(0) != y_is_odd {
    y = modulus - y;
  }

  Secp256k1Affine::from_xy(biguint_to_fe::<Fp>(&x), biguint_to_fe::<Fp>(&y)).unwrap()
}

pub fn parse_scalar(s: String) -> Fq {
  ScalarField::from_bytes_le(
    BigUint::from_str_radix(&s[2..], 16)
      .unwrap()
      .to_bytes_le()
      .as_slice()
  )
}

pub fn parse_fr(s: String) -> Fr {
  Fr::from_bytes_le(
    BigUint::from_str_radix(&s[2..], 16)
      .unwrap()
      .to_bytes_le()
      .as_slice()
  )
}
