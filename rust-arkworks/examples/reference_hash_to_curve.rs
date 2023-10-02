#![feature(iter_array_chunks)]

use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr, CurveConfig,
};
use ark_ff::{
    fields::{Field, PrimeField},
    BigInteger,
};
use bitvec::prelude::*;
use tiny_keccak::{Hasher, Shake, Xof};

/// Kobi's hash_to_curve function, here for reference only
///
/// WARNING: Not tested -- bugs expected. Don't use the reference example for practical cryptography.
pub fn _try_and_increment<C: SWCurveConfig>(msg: &[u8]) -> Affine<C> {
    /* `SWCurveConfig` is chosen here just as a most general curve description, which can be 
    tuned further with more appropriate to the task modules.
    Anyway if you really need to implement _hash to curve_, you should start from most close 
    implementation in the library that serves your particular needs, not from generic example. */
    let mut nonce = NaiveBytes::default();
    loop {
        let mut h = Shake::v128();
        h.update(&nonce.0);
        h.update(msg.as_ref());

        // as this one isn't intended to work with greater than 256 bits groups, checks for digest being long enough are omitted here
        assert!(<C::BaseField as Field>::BasePrimeField::MODULUS_BIT_SIZE <= 256u32); // just to be sure

        let mut output_u8 =
            vec![0u8; digest_len(<C::BaseField as Field>::BasePrimeField::MODULUS_BIT_SIZE)];
        h.squeeze(&mut output_u8);

        let output_bigint = <<<C as CurveConfig>::BaseField as Field>::BasePrimeField as PrimeField>::BigInt::from_bits_le(
            bitvec::vec::BitVec::<u8, Lsb0>::from_vec(output_u8.clone()).into_iter().collect::<Vec<bool>>().as_slice()
        );
        if output_bigint < <<C::BaseField as Field>::BasePrimeField as PrimeField>::MODULUS {
            if let Some(result) = Affine::get_point_from_x_unchecked(
                <C as CurveConfig>::BaseField::from_base_prime_field(
                    <<<C as CurveConfig>::BaseField as Field>::BasePrimeField as PrimeField>::from_be_bytes_mod_order(&output_u8)
                ),
                nonce.0.iter().last().unwrap() % 2 == 1
            ) {return result.clear_cofactor();}
        }
        // else {dbg!(nonce.0)}
        nonce.increment();
    }
}

/// Takes bit size and returns minimal number of bytes to fit these bits
const fn digest_len(modulus_bit_size: u32) -> usize {
    (modulus_bit_size / 8 + if modulus_bit_size % 8 != 0 { 1 } else { 0 }) as usize
}

struct NaiveBytes(Vec<u8>);
impl Default for NaiveBytes {
    fn default() -> Self {
        Self(vec![0])
    }
}
impl NaiveBytes {
    fn increment(&mut self) {
        // TODO would be nice to make field private so that `unwrap` had no chance to panic
        if self.0.iter().last().unwrap() == &u8::MAX {
            self.0.push(0);
        } else {
            *self.0.last_mut().unwrap() += 1;
        }
    }
}
