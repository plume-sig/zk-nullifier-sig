// use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ec::{AffineRepr, CurveGroup, CurveConfig, short_weierstrass::SWCurveConfig};
use tiny_keccak::{Hasher, Shake, Xof};
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::AffinePoint;
use k256::sha2::Sha256;
use elliptic_curve::sec1::ToEncodedPoint;
// use ark_ec::short_weierstrass_jacobian::GroupAffine;
use k256::{ProjectivePoint, Secp256k1};
use ark_ff::{BigInteger, BigInt, fields::{Field, PrimeField}};

const fn digest_len(modulus_bit_size: u32) -> usize {(modulus_bit_size/8 + if modulus_bit_size % 8 != 0 {1} else {0}) as usize}
const fn bigint_len(bytearray_size: usize) -> usize {bytearray_size/8 + if bytearray_size % 8 != 0 {1} else {0}}

/// Kobi's hash_to_curve function, here for reference only
struct NaiveBytes(Vec<u8>);
impl Default for NaiveBytes {fn default() -> Self {Self(vec![0])}}
impl NaiveBytes {fn incement(&mut self) {
    // TODO would be nice to make field private so that `unwrap` had no chance to panic
    if self.0.iter().last().unwrap() == &u8::MAX {self.0.push(0);}
    else {
        self.0[self.0.len() - 1] += 1;
    }
}}

pub fn _try_and_increment<C: CurveGroup + SWCurveConfig>(msg: &[u8]) -> C::Affine {
// pub fn _try_and_increment<C: SWCurveConfig>(msg: &[u8]) -> Affine<C> {
// `SWCurveConfig` chosen here just as a most general curve description, which can be tuned further with more appropriate to the task modules
    let nonce = NaiveBytes::default();
    loop {
        let mut h = Shake::v128();
        h.update(&nonce.0);
        h.update(msg.as_ref());
        // let width_bits = C::Affine::MODULUS_BIT_SIZE /* + 1 */;
        // let output_size = width_bits / 8 + if width_bits % 8 != 0 {1} else {0};
        
        // as this one isn't intended to work with greater than 256 bits groups, checks for digest being long enough are omitted here
        assert!(<<C as CurveGroup>::BaseField as Field>::BasePrimeField::MODULUS_BIT_SIZE <= 256u32); // just to be sure
           
        let mut output_u8 = [0u8; digest_len(<<C as CurveGroup>::BaseField as Field>::BasePrimeField::MODULUS_BIT_SIZE)];
        h.squeeze(&mut output_u8);
        
        // `from_bytes_be(sign: Sign, bytes: &[u8])`
        // `assert_eq!(BigInt::from_bytes_be(Sign::Plus, b"A"),
        //    BigInt::parse_bytes(b"65", 10).unwrap());`
        
        let output_u64 = output_u8.into_iter().chunk(8).map(|(i, chunk)| {chunk as u64});
        // TODO check that `BigInt::new` is actually BE
        if BigInt::new(output_u64).into() < <<C as CurveGroup>::BaseField as Field>::BasePrimeField::MODULUS {
            if let Some(
                result
            ) = ark_ec::short_weierstrass::Affine::get_point_from_x_unchecked(
            // ) = ark_ec::models::short_weierstrass::Affine::get_point_from_x_unchecked(
                <<C as CurveConfig>::BaseField as Field>::BasePrimeField::from_be_bytes_mod_order(&output_u8),
                nonce.0.iter().last().unwrap() % 2 == 1
            ) {return result.into_group().into_affine();}
        }
        // else {dbg!(nonce.0)}
    }
}
