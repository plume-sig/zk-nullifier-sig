use noir_bigcurve::scalar_field::ScalarField;
use noir_bigcurve::curves::bn254::{BN254, BN254_Fq_Params, BN254Fq, BN254Scalar};
use crate::curves::bn254::hash_to_curve;
use std::embedded_curve_ops::EmbeddedCurveScalar as Scalar;

pub type ScalarWithOps = BN254Fq;

global TWO_POW_128: Field = 0x100000000000000000000000000000000;
global TWO_POW_120: Field = 0x1000000000000000000000000000000;
global TWO_POW_112: Field = 0x10000000000000000000000000000;

unconstrained fn __field_to_be_bytes(x: Field) -> [u8; 32] {
    let x_bytes_slice: [u8; 32] = x.to_be_bytes();
    let mut x_bytes = [0; 32];
    for i in 0..32 {
        x_bytes[i] = x_bytes_slice[i];
    }
    x_bytes
}

unconstrained fn __field_to_bignum(x: Field) -> ScalarWithOps {
    let x_bytes = __field_to_be_bytes(x);
    ScalarWithOps::from_be_bytes(x_bytes)
}

unconstrained fn __field_to_bignum_limbs(x: Field) -> [Field; 3] {
    __field_to_bignum(x).limbs
}

// "Unsafe" because it only works for bignums with modulus larger than the BN Fr size.
// TODO: this isn't-yet secure. See comment within.
pub fn field_to_bignum_unsafe(x: Field) -> ScalarWithOps {
    let __x_limbs = unsafe {
        __field_to_bignum_limbs(x)
    };
    // Range check the limbs
    __x_limbs[0].assert_max_bit_size::<120>();
    __x_limbs[1].assert_max_bit_size::<120>();
    __x_limbs[2].assert_max_bit_size::<14>();
    let mut check = __x_limbs[3 - 1];
    for i in 1..3 {
        // TODO: need to ensure this doesn't overflow, in a similar way as shown in noir_stdlib/src/field/bn254.nr 
        // Also see explanation here: https://github.com/noir-lang/noir/commit/1f9cad00c57ea257f57419d2446a46938beb19f9
        check = check * TWO_POW_120 + __x_limbs[3 - i - 1];
    }
    assert(check == x);

    ScalarWithOps::from_slice(__x_limbs)
}


unconstrained fn __get_x1_split_hint(x: ScalarWithOps) -> (u8, Field) {
    let x1_bytes: [u8; 15] = x.limbs[1].to_le_bytes();
    let x1_le_byte_0 = x1_bytes[0];

    let mut x1_bytes_shifted_right = [0; 14];
    for i in 0..14 {
        x1_bytes_shifted_right[i] = x1_bytes[i+1];
    }

    let mut x1_byte_shifted_right: Field = x1_bytes_shifted_right[13] as Field;
    for i in 0..13 {
        let j = 13 - 1 - i;
        x1_byte_shifted_right = x1_byte_shifted_right * 256 + x1_bytes_shifted_right[j] as Field;
    }
    (x1_le_byte_0, x1_byte_shifted_right)
}

pub(crate) fn bignum_to_scalar(x: ScalarWithOps) -> Scalar {
    // We assume the bignum limbs have already been checked to be < 120 bits.
    let (x1_le_byte_0, x1_byte_shifted_right) = unsafe {
        __get_x1_split_hint(x)
    };

    let x1_le_byte_0_as_field = x1_le_byte_0 as Field;

    x1_byte_shifted_right.assert_max_bit_size::<112>();

    let x1_check = x1_le_byte_0_as_field + x1_byte_shifted_right * 256;

    assert(x1_check == x.limbs[1]);

    let lo = x.limbs[0] + TWO_POW_120 * x1_le_byte_0_as_field;
    let hi = x1_byte_shifted_right + x.limbs[2] * TWO_POW_112;
    Scalar { lo, hi }
}


pub(crate) fn hash_to_curve_bn254(msg: [u8; 41]) -> BN254 {
    let p = hash_to_curve(msg);
    BN254 {
        x: field_to_bignum_unsafe(p.x),
        y: field_to_bignum_unsafe(p.y),
        is_infinity: p.is_infinite,
    }
}
