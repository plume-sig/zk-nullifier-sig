/*
    Simplified SWU (Shallue-van de Woestijne-Ulas) method for secp256k1.
    
    See the link below for more details:

    https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#name-simplified-shallue-van-de-w
*/

use bignum::BigNum;
use noir_bigcurve::BigCurve;
use noir_bigcurve::curves::secp256k1::{Secp256k1, Secp256k1_Params, Secp256k1Fq};

// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#section-8.7
global Z: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xfffffffffffffffffffffefffffc24,
    0xffffffffffffffffffffffffffffff,
    0xffff,
]);
global A: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x53d363cb6f0e5d405447c01a444533,
    0x31abdd661adca08a5558f0f5d272e9,
    0x3f87,
]);
global B: Secp256k1Fq = Secp256k1Fq::from_slice([0x6eb, 0, 0]);

comptime global ONE: Secp256k1Fq = Secp256k1Fq::one();

// Returns point E' isogeneous to secp256k1.
pub fn map_to_curve(u: Secp256k1Fq) -> Secp256k1 {
    let tv1 = ONE / (Z * Z * u * u * u * u + Z * u * u);
    let x1 = (B.neg() / A) * (ONE + tv1);

    let gx1 = x1 * x1 * x1 + A * x1 + B;
    let x2 = Z * u * u * x1;
    let gx2 = x2 * x2 * x2 + A * x2 + B;
    let (x, mut y) = select_xy(x1, x2, gx1, gx2);

    let ubyte: [u8; 32] = u.to_le_bytes();
    let ybyte: [u8; 32] = y.to_le_bytes();
    let u_sign: u1 = (ubyte[0] as Field).to_le_bits::<8>()[0];
    let y_sign: u1 = (ybyte[0] as Field).to_le_bits::<8>()[0];

    if u_sign != y_sign {
        y = y.neg();
    }

    BigCurve { x, y, is_infinity: false }
}

fn select_xy(
    x1: Secp256k1Fq,
    x2: Secp256k1Fq,
    gx1: Secp256k1Fq,
    gx2: Secp256k1Fq,
) -> (Secp256k1Fq, Secp256k1Fq) {
    let gx1_sqrt = unsafe { gx1.__tonelli_shanks_sqrt() };
    let gx2_sqrt = unsafe { gx2.__tonelli_shanks_sqrt() };

    let gx1_is_square = gx1_sqrt.is_some();

    let x: Secp256k1Fq = if gx1_is_square { x1 } else { x2 };
    let y = gx1_sqrt.xor(gx2_sqrt).unwrap();

    let y_preimage: Secp256k1Fq = if gx1_is_square { gx1 } else { gx2 };

    // Constrain out-of-circuit root computation.
    let y_squared = y * y;
    assert(y_preimage == y_squared, "Square root is incorrect");

    (x, y)
}

#[test]
fn test_inverse() {
    let value: Secp256k1Fq = Secp256k1Fq::from_slice([
        0x387936733e29cddb43759809208354,
        0xc334daf72303fb27f6aad8201a9465,
        0xc6f1,
    ]);

    let actual = ONE / value;

    let expected: [u8; 32] = [
        211, 142, 221, 78, 176, 90, 13, 18, 140, 253, 186, 38, 111, 230, 156, 220, 55, 89, 204, 218,
        31, 162, 175, 33, 15, 146, 219, 86, 70, 80, 101, 19,
    ];

    assert(actual.to_le_bytes() == expected);
}

#[test]
fn test_select_xy_1() {
    let x1: Secp256k1Fq = Secp256k1Fq::from_slice([123, 0, 0]);
    let x2: Secp256k1Fq = Secp256k1Fq::from_slice([200, 0, 0]);
    let gx1: Secp256k1Fq = Secp256k1Fq::from_slice([4, 0, 0]);
    let gx2: Secp256k1Fq = Secp256k1Fq::from_slice([5, 0, 0]);

    let (actual_x, actual_y) = select_xy(x1, x2, gx1, gx2);

    assert(actual_x == x1);
    assert(actual_y == Secp256k1Fq::from_slice([2, 0, 0]));
}

#[test]
fn test_select_xy_2() {
    let x1: Secp256k1Fq = Secp256k1Fq::from_slice([123, 0, 0]);
    let x2: Secp256k1Fq = Secp256k1Fq::from_slice([200, 1, 0]);
    let gx1: Secp256k1Fq = Secp256k1Fq::from_slice([5, 0, 0]);
    let gx2: Secp256k1Fq = Secp256k1Fq::from_slice([4, 0, 0]);

    let (actual_x, actual_y) = select_xy(x1, x2, gx1, gx2);

    assert(actual_x == x2);
    assert(actual_y == Secp256k1Fq::from_slice([2, 0, 0]));
}

#[test]
fn test_map_to_curve() {
    let u = Secp256k1Fq::from_slice([
        0x491f544767e18a4873f397b08a2b61,
        0xab5d3679a1f7601e3bdf94ced1f43e,
        0x128a,
    ]);

    let actual_p = map_to_curve(u);

    let expected_x = [
        181, 145, 157, 194, 47, 137, 194, 182, 137, 175, 255, 248, 220, 155, 21, 208, 170, 147, 24,
        158, 1, 255, 122, 7, 138, 168, 206, 231, 17, 190, 219, 242,
    ];
    let expected_y = [
        229, 169, 131, 251, 47, 167, 25, 23, 58, 145, 104, 47, 28, 167, 183, 142, 222, 47, 130, 14,
        237, 125, 44, 130, 236, 154, 191, 129, 133, 161, 34, 59,
    ];

    assert(actual_p.x.to_le_bytes() == expected_x);
    assert(actual_p.y.to_le_bytes() == expected_y);
}
