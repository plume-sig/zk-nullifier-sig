/*
    3-isogeny map from E' to E for secp256k1.
    
    See the link below for more details:

    https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#name-3-isogeny-map-for-secp256k1
*/

use bignum::BigNum;
use noir_bigcurve::BigCurve;
use noir_bigcurve::curves::secp256k1::{Secp256k1, Secp256k1Fq};

global K1_0: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xe38e38e38e38e38e38e38daaaaa8c7,
    0xe38e38e38e38e38e38e38e38e38e38,
    0x8e38,
]);
global K1_1: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x95d2fc0bf63b92dfff1044f17c6581,
    0xd4c80bc321d5b9f315cea7fd44c5d5,
    0x7d3,
]);
global K1_2: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x506144037c40314ecbd0b53d9dd262,
    0x328d23f234e6e2a413deca25caece4,
    0x534c,
]);
global K1_3: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xe38e38e38e38e38e38e38daaaaa88c,
    0xe38e38e38e38e38e38e38e38e38e38,
    0x8e38,
]);

global K2_0: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xcd409542f8487d9fe6b745781eb49b,
    0x71193d94918a9ca34ccbb7b640dd86,
    0xd357,
]);
global K2_1: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xd36b641f5e41bbc52a56612a8c6d14,
    0xc6f64383dc1df7c4b2d51b54225406,
    0xedad,
]);

global K3_0: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x684bda12f684bda12f684b8e38e23c,
    0x12f684bda12f684bda12f684bda12f,
    0x4bda,
]);
global K3_1: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x7ab046d686da6fdffc90fc201d71a3,
    0xc32d5cb7c0fa9d0a54b12a0a6d564,
    0xc75e,
]);
global K3_2: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x2830a201be2018a765e85a9ecee931,
    0x194691f91a73715209ef6512e57672,
    0x29a6,
]);
global K3_3: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xa12f684bda12f684bda12f38e38d84,
    0x4bda12f684bda12f684bda12f684bd,
    0x2f68,
]);

global K4_0: Secp256k1Fq = Secp256k1Fq::from_slice([
    0xfffffffffffffffffffffefffff93b,
    0xffffffffffffffffffffffffffffff,
    0xffff,
]);
global K4_1: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x67c1bfc8e8d978dfb425d2685c2573,
    0x534bb8bdb49fd5e9e6632722c29894,
    0x7a06,
]);
global K4_2: Secp256k1Fq = Secp256k1Fq::from_slice([
    0x3d21162f0d6299a7bf8192bfd2a76f,
    0xaa716545ca2cf3a70c3fa8fe337e0a,
    0x6484,
]);

pub fn iso_map(p: Secp256k1) -> Secp256k1 {
    let x2 = p.x * p.x;
    let x3 = x2 * p.x;

    let x_num = x_num(p.x, x2, x3);
    let x_den = x_den(p.x, x2);
    let y_num = y_num(p.x, x2, x3);
    let y_den = y_den(p.x, x2, x3);

    let x = (x_num / x_den);
    let y = (p.y * y_num / y_den);

    BigCurve { x, y, is_infinity: false }
}

fn x_num(x: Secp256k1Fq, x2: Secp256k1Fq, x3: Secp256k1Fq) -> Secp256k1Fq {
    K1_0 + K1_1 * x + K1_2 * x2 + K1_3 * x3
}

fn x_den(x: Secp256k1Fq, x2: Secp256k1Fq) -> Secp256k1Fq {
    x2 + K2_1 * x + K2_0
}

fn y_num(x: Secp256k1Fq, x2: Secp256k1Fq, x3: Secp256k1Fq) -> Secp256k1Fq {
    K3_0 + K3_1 * x + K3_2 * x2 + K3_3 * x3
}

fn y_den(x: Secp256k1Fq, x2: Secp256k1Fq, x3: Secp256k1Fq) -> Secp256k1Fq {
    K4_0 + K4_1 * x + K4_2 * x2 + x3
}

#[test]
fn test_iso_map() {
    let p = Secp256k1 {
        x: Secp256k1Fq::from_slice([
            0xf7ae5f23c431edeb6be5bb360925ea,
            0xce532d92416a9488104157036455a0,
            0x8dec,
        ]),
        y: Secp256k1Fq::from_slice([
            0x13d22e4d45e5bef361e486c6a5da4a,
            0xae1c326847bd4a133e5dee6b2ca67c,
            0xe249,
        ]),
        is_infinity: false,
    };

    let actual = iso_map(p);

    let expected = Secp256k1 {
        x: Secp256k1Fq::from_slice([
            0x7c2a947a20fd9ad71039f8b0e29ff8,
            0x6d261a5e00fe5cf45e827b507643e6,
            0xf89d,
        ]),
        y: Secp256k1Fq::from_slice([
            0x1ce936d563bc1cee1dcffc806caf57,
            0x55e0cc34a9176ead91c6c3acb1aacb,
            0xb338,
        ]),
        is_infinity: false,
    };

    assert(actual == expected);
}
