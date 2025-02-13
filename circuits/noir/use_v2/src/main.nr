use bignum::BigNum;
use noir_bigcurve::BigCurve;
use noir_bigcurve::curves::secp256k1::{Secp256k1, Secp256k1Fq, Secp256k1Scalar};
use noir_bigcurve::scalar_field::ScalarField;

use plume::plume_v2;

global MSG_LEN: u32 = 32;

// We don't use nested arrays for points, since `InputMap` in TS doesn't support them.
pub fn main(
    msg: [u8; MSG_LEN],
    c: [u8; 32],
    s: [u8; 32],
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    nullifier_x: [u8; 32],
    nullifier_y: [u8; 32],
) -> pub (Secp256k1, Secp256k1) {
    plume_v2(
        msg,
        as_scalar(c),
        as_scalar(s),
        as_point([pk_x, pk_y]),
        as_point([nullifier_x, nullifier_y]),
    )
}

fn as_scalar(bytes: [u8; 32]) -> Secp256k1Scalar {
    let scalar: Secp256k1Fq = Secp256k1Fq::from_be_bytes(bytes);
    Secp256k1Scalar::from_bignum(scalar)
}

fn as_point(bytes: [[u8; 32]; 2]) -> Secp256k1 {
    Secp256k1 {
        x: Secp256k1Fq::from_be_bytes(bytes[0]),
        y: Secp256k1Fq::from_be_bytes(bytes[1]),
        is_infinity: false,
    }
}
