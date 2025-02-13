mod hash_to_curve;
mod hash_to_field;
mod expand_message_xmd;
mod map_to_curve;
mod iso_map;

use crate::hash_to_curve::hash_to_curve;
use bignum::BigNum;
use nodash::array::pack_bytes;
use noir_bigcurve::BigCurve;
use noir_bigcurve::curves::secp256k1::{Secp256k1, Secp256k1Fr, Secp256k1Fq, Secp256k1Scalar};
use noir_bigcurve::scalar_field::ScalarField;
use std::hash::poseidon2::Poseidon2::hash;

comptime global G: Secp256k1 = BigCurve::one();
comptime global COMPRESSED_SIZE_BYTES: u32 = 33;

pub fn plume_v1<let N: u32>(
    msg: [u8; N],
    c: Secp256k1Scalar,
    s: Secp256k1Scalar,
    pk: Secp256k1,
    nullifier: Secp256k1,
) -> Field {
    let (r_point, hashed_to_curve_r, hashed_to_curve) =
        check_ec_equations(msg, c, s, pk, nullifier);

    poseidon_12_coordinates(pk, hashed_to_curve, nullifier, r_point, hashed_to_curve_r)
}

pub fn plume_v2<let N: u32>(
    msg: [u8; N],
    c: Secp256k1Scalar,
    s: Secp256k1Scalar,
    pk: Secp256k1,
    nullifier: Secp256k1,
) -> (Secp256k1, Secp256k1) {
    let (r_point, hashed_to_curve_r, _) = check_ec_equations(msg, c, s, pk, nullifier);

    (r_point, hashed_to_curve_r)
}

fn check_ec_equations<let N: u32>(
    msg: [u8; N],
    c: Secp256k1Scalar,
    s: Secp256k1Scalar,
    pk: Secp256k1,
    nullifier: Secp256k1,
) -> (Secp256k1, Secp256k1, Secp256k1) {
    let s_point = G.mul(s);
    let r_point = s_point - pk.mul(c);

    let plume_msg = form_plume_msg(msg, pk);
    let hashed_to_curve = hash_to_curve(plume_msg);
    let h_pow_s = hashed_to_curve.mul(s);
    let hashed_to_curve_r = h_pow_s - nullifier.mul(c);

    (r_point, hashed_to_curve_r, hashed_to_curve)
}

fn form_plume_msg<let N: u32>(msg: [u8; N], pk: Secp256k1) -> [u8; N + COMPRESSED_SIZE_BYTES] {
    let mut plume_msg = [0; N + COMPRESSED_SIZE_BYTES];

    for i in 0..N {
        plume_msg[i] = msg[i];
    }

    let compressed_pk = compress_ec_point(pk);
    for i in 0..COMPRESSED_SIZE_BYTES {
        plume_msg[N + i] = compressed_pk[i];
    }

    plume_msg
}

fn compress_ec_point(p: Secp256k1) -> [u8; COMPRESSED_SIZE_BYTES] {
    let x: [u8; 32] = p.x.to_le_bytes();
    let mut compressed = [0 as u8; COMPRESSED_SIZE_BYTES];

    let sign = p.y.to_le_bytes::<32>()[0] & 1;
    compressed[0] = sign + 2; // convention to encode `y` as 02 or 03
    for i in 0..32 {
        compressed[32 - i] = x[i];
    }

    compressed
}

fn poseidon_12_coordinates(
    pk: Secp256k1,
    h: Secp256k1,
    nullifier: Secp256k1,
    gr: Secp256k1,
    hr: Secp256k1,
) -> Field {
    let mut compressed = [[0 as u8; COMPRESSED_SIZE_BYTES]; 6];
    compressed[0] = compress_ec_point(G);
    compressed[1] = compress_ec_point(pk);
    compressed[2] = compress_ec_point(h);
    compressed[3] = compress_ec_point(nullifier);
    compressed[4] = compress_ec_point(gr);
    compressed[5] = compress_ec_point(hr);

    // Concatenate
    let mut res = [0 as u8; COMPRESSED_SIZE_BYTES * 6];
    for i in 0..6 {
        for j in 0..COMPRESSED_SIZE_BYTES {
            res[i * COMPRESSED_SIZE_BYTES + j] = compressed[i][j];
        }
    }

    let packed_res = pack_bytes(res);

    hash(packed_res, packed_res.len())
}

#[test]
fn test_compress_ec_point() {
    let sk: Secp256k1Fr = Secp256k1Fr::from_be_bytes([
        141, 102, 7, 178, 108, 210, 195, 217, 224, 140, 81, 3, 56, 193, 15, 69, 117, 230, 143, 45,
        65, 58, 179, 31, 202, 239, 115, 0, 202, 161, 243, 112,
    ]);
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);
    let pk = G.mul(sk);

    let actual = compress_ec_point(pk);

    let expected = [
        2, 251, 188, 92, 195, 140, 107, 160, 47, 132, 242, 112, 141, 138, 178, 59, 234, 158, 144,
        47, 203, 20, 59, 174, 56, 127, 68, 229, 111, 95, 233, 172, 226,
    ];

    assert(actual == expected);
}

#[test]
fn test_nullifier() {
    let sk: Secp256k1Fr = Secp256k1Fr::from_be_bytes([
        81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11,
        78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100,
    ]);
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

    let H = Secp256k1 {
        x: Secp256k1Fq::from_slice([
            0x2affbc49c54d1136a2190db0800b65,
            0x2d0e12679f23c218889395abcdc01f,
            0xbcac,
        ]),
        y: Secp256k1Fq::from_slice([
            0xa91a53e32b3752145d87f0cd70966e,
            0xb339c974c0e757d348081f90a123b0,
            0x3bcf,
        ]),
        is_infinity: false,
    };

    let actual = H.mul(sk);

    let expected: Secp256k1 = Secp256k1 {
        x: Secp256k1Fq::from_be_bytes([
            87, 188, 62, 210, 129, 114, 239, 138, 221, 228, 185, 224, 194, 204, 231, 69, 252, 197,
            166, 100, 115, 164, 92, 30, 98, 111, 29, 12, 103, 229, 88, 48,
        ]),
        y: Secp256k1Fq::from_be_bytes([
            106, 47, 65, 72, 141, 88, 243, 58, 228, 110, 221, 33, 136, 225, 17, 96, 159, 159, 58,
            230, 126, 163, 143, 168, 145, 214, 8, 127, 229, 158, 203, 115,
        ]),
        is_infinity: false,
    };

    assert(actual == expected);
}

/* Too slow for CI. Run manually.

#[test]
fn test_r_point() {
    let sk: Secp256k1Fr = BigNum::from_be_bytes(
        [
        81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100
    ]
    );
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

    let s: Secp256k1Fr = BigNum::from_be_bytes(
        [
        230, 159, 2, 125, 132, 203, 111, 229, 247, 97, 227, 51, 209, 46, 151, 95, 177, 144, 209, 99, 232, 234, 19, 45, 125, 224, 189, 96, 121, 186, 40, 202
    ]
    );
    let s: Secp256k1Scalar = ScalarField::from_bignum(s);

    let c: Secp256k1Fr = BigNum::from_be_bytes(
        [
        198, 167, 252, 44, 146, 109, 219, 175, 32, 115, 26, 71, 159, 182, 86, 111, 45, 170, 85, 20, 186, 174, 82, 35, 254, 59, 50, 237, 188, 232, 50, 84
    ]
    );
    let c: Secp256k1Scalar = ScalarField::from_bignum(c);

    let pk = G.mul(sk);
    let s_point = G.mul(s);

    let actual = s_point - pk.mul(c);

    let expected: Secp256k1 = BigCurve {
        x: BigNum::from_be_bytes(
            [
            157, 140, 164, 53, 14, 126, 42, 210, 122, 188, 109, 42, 40, 19, 101, 129, 128, 118, 102, 41, 98, 162, 132, 41, 89, 14, 45, 199, 54, 254, 152, 4
        ]
        ),
        y: BigNum::from_be_bytes(
            [
            255, 8, 195, 11, 138, 253, 78, 133, 70, 35, 200, 53, 217, 195, 170, 198, 188, 235, 228, 81, 18, 71, 45, 155, 144, 84, 129, 106, 118, 112, 197, 161
        ]
        ),
        is_infinity: false
    };

    assert(actual == expected);
}

#[test]
fn test_hashed_to_curve_plume_msg() {
    let sk: Secp256k1Fr = BigNum::from_be_bytes(
        [
        81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100
    ]
    );
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

    let pk = G.mul(sk);
    let msg = [
        65, 110, 32, 101, 120, 97, 109, 112, 108, 101, 32, 97, 112, 112, 32, 109, 101, 115, 115, 97, 103, 101, 32, 115, 116, 114, 105, 110, 103
    ];

    let plume_msg = form_plume_msg(msg, pk);

    let actual = hash_to_curve(plume_msg);

    let expected: Secp256k1 = BigCurve {
        x: BigNum::from_be_bytes(
            [
            188, 172, 45, 14, 18, 103, 159, 35, 194, 24, 136, 147, 149, 171, 205, 192, 31, 42, 255, 188, 73, 197, 77, 17, 54, 162, 25, 13, 176, 128, 11, 101
        ]
        ),
        y: BigNum::from_be_bytes(
            [
            59, 207, 179, 57, 201, 116, 192, 231, 87, 211, 72, 8, 31, 144, 161, 35, 176, 169, 26, 83, 227, 43, 55, 82, 20, 93, 135, 240, 205, 112, 150, 110
        ]
        ),
        is_infinity: false
    };

    assert(actual == expected);
}

#[test]
fn test_hashed_to_curve_r() {
    let s: Secp256k1Fr = BigNum::from_be_bytes(
        [
        230, 159, 2, 125, 132, 203, 111, 229, 247, 97, 227, 51, 209, 46, 151, 95, 177, 144, 209, 99, 232, 234, 19, 45, 125, 224, 189, 96, 121, 186, 40, 202
    ]
    );
    let s: Secp256k1Scalar = ScalarField::from_bignum(s);

    let sk: Secp256k1Fr = BigNum::from_be_bytes(
        [
        81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100
    ]
    );
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

    let H: Secp256k1 = BigCurve {
        x: BigNum::from_slice([0x2affbc49c54d1136a2190db0800b65, 0x2d0e12679f23c218889395abcdc01f, 0xbcac]),
        y: BigNum::from_slice([0xa91a53e32b3752145d87f0cd70966e, 0xb339c974c0e757d348081f90a123b0, 0x3bcf]),
        is_infinity: false
    };

    let c: Secp256k1Fr = BigNum::from_be_bytes(
        [
        198, 167, 252, 44, 146, 109, 219, 175, 32, 115, 26, 71, 159, 182, 86, 111, 45, 170, 85, 20, 186, 174, 82, 35, 254, 59, 50, 237, 188, 232, 50, 84
    ]
    );
    let c: Secp256k1Scalar = ScalarField::from_bignum(c);

    let nullifier = H.mul(sk);
    let h_pow_s = H.mul(s);

    let actual = h_pow_s - nullifier.mul(c);

    let expected : Secp256k1 = BigCurve {
        x: BigNum::from_be_bytes(
            [
            109, 1, 124, 111, 99, 197, 159, 167, 165, 177, 233, 166, 84, 226, 125, 40, 105, 87, 159, 77, 21, 33, 49, 219, 39, 5, 88, 252, 205, 39, 185, 124
        ]
        ),
        y: BigNum::from_be_bytes(
            [
            88, 108, 67, 251, 92, 153, 129, 140, 86, 74, 143, 128, 168, 138, 101, 248, 62, 63, 68, 211, 198, 202, 245, 161, 164, 226, 144, 183, 119, 172, 86, 237
        ]
        ),
        is_infinity: false
    };

    assert(actual == expected);
}

#[test]
fn test_sha_256_12_coordinates() {
    let hashed_to_curve: Secp256k1 = BigCurve {
        x: BigNum::from_slice([0x2affbc49c54d1136a2190db0800b65, 0x2d0e12679f23c218889395abcdc01f, 0xbcac]),
        y: BigNum::from_slice([0xa91a53e32b3752145d87f0cd70966e, 0xb339c974c0e757d348081f90a123b0, 0x3bcf]),
        is_infinity: false
    };

    let r_point: Secp256k1 = BigCurve {
        x: BigNum::from_slice([0x76662962a28429590e2dc736fe9804, 0xa4350e7e2ad27abc6d2a2813658180, 0x9d8c]),
        y: BigNum::from_slice([0xebe45112472d9b9054816a7670c5a1, 0xc30b8afd4e854623c835d9c3aac6bc, 0xff08]),
        is_infinity: false
    };

    let hashed_to_curve_r: Secp256k1 = BigCurve {
        x: BigNum::from_slice([0x579f4d152131db270558fccd27b97c, 0x7c6f63c59fa7a5b1e9a654e27d2869, 0x6d01]),
        y: BigNum::from_slice([0x3f44d3c6caf5a1a4e290b777ac56ed, 0x43fb5c99818c564a8f80a88a65f83e, 0x586c]),
        is_infinity: false
    };

    let sk: Secp256k1Fr = BigNum::from_be_bytes(
        [
        81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100
    ]
    );
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

    let pk = G.mul(sk);
    let nullifier = hashed_to_curve.mul(sk);

    let actual = poseidon_12_coordinates(pk, hashed_to_curve, nullifier, r_point, hashed_to_curve_r);

    let expected = [
        198, 167, 252, 44, 146, 109, 219, 175, 32, 115, 26, 71, 159, 182, 86, 111, 45, 170, 85, 20, 186, 174, 82, 35, 254, 59, 50, 237, 188, 232, 50, 84
    ];

    assert(actual == expected);
}

#[test]
fn test_plume_v1() {
    let msg = [
        65, 110, 32, 101, 120, 97, 109, 112, 108, 101, 32, 97, 112, 112, 32, 109, 101, 115, 115, 97, 103, 101, 32, 115, 116, 114, 105, 110, 103
    ];

    let c = [
        198, 167, 252, 44, 146, 109, 219, 175, 32, 115, 26, 71, 159, 182, 86, 111, 45, 170, 85, 20, 186, 174, 82, 35, 254, 59, 50, 237, 188, 232, 50, 84
    ];
    let expected = c;
    let c: Secp256k1Fr = BigNum::from_be_bytes(c);
    let c: Secp256k1Scalar = ScalarField::from_bignum(c);

    let s: Secp256k1Fr = BigNum::from_be_bytes(
        [
        230, 159, 2, 125, 132, 203, 111, 229, 247, 97, 227, 51, 209, 46, 151, 95, 177, 144, 209, 99, 232, 234, 19, 45, 125, 224, 189, 96, 121, 186, 40, 202
    ]
    );
    let s: Secp256k1Scalar = ScalarField::from_bignum(s);

    let sk: Secp256k1Fr = BigNum::from_be_bytes(
        [
        81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100
    ]
    );
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

    let pk = G.mul(sk);

    let H: Secp256k1 = BigCurve {
        x: BigNum::from_slice([0x2affbc49c54d1136a2190db0800b65, 0x2d0e12679f23c218889395abcdc01f, 0xbcac]),
        y: BigNum::from_slice([0xa91a53e32b3752145d87f0cd70966e, 0xb339c974c0e757d348081f90a123b0, 0x3bcf]),
        is_infinity: false
    };

    let nullifier = H.mul(sk);

    let actual = plume_v1(msg, c, s, pk, nullifier);

    assert(expected == actual);
}

#[test]
fn test_plume_v2() {
    let msg = [
        65, 110, 32, 101, 120, 97, 109, 112, 108, 101, 32, 97, 112, 112, 32, 109, 101, 115, 115, 97, 103, 101, 32, 115, 116, 114, 105, 110, 103
    ];

    let c2 = [
        61, 191, 183, 23, 112, 80, 16, 212, 244, 74, 112, 114, 12, 149, 231, 75, 71, 91, 211, 167, 131, 171, 11, 158, 138, 107, 59, 54, 52, 52, 235, 150
    ];
    let expected = c2;
    let c2: Secp256k1Fr = BigNum::from_be_bytes(c2);
    let c2: Secp256k1Scalar = ScalarField::from_bignum(c2);

    let s2: Secp256k1Fr = BigNum::from_be_bytes(
        [
        82, 142, 143, 187, 100, 82, 248, 34, 0, 121, 123, 26, 115, 178, 148, 122, 146, 82, 75, 214, 17, 8, 90, 146, 15, 17, 119, 203, 128, 152, 19, 107
    ]
    );
    let s2: Secp256k1Scalar = ScalarField::from_bignum(s2);

    let sk: Secp256k1Fr = BigNum::from_be_bytes(
        [
        81, 155, 66, 61, 113, 95, 139, 88, 31, 79, 168, 238, 89, 244, 119, 26, 91, 68, 200, 19, 11, 78, 62, 172, 202, 84, 165, 109, 218, 114, 180, 100
    ]
    );
    let sk: Secp256k1Scalar = ScalarField::from_bignum(sk);

    let pk = G.mul(sk);

    let H: Secp256k1 = BigCurve {
        x: BigNum::from_slice([0x2affbc49c54d1136a2190db0800b65, 0x2d0e12679f23c218889395abcdc01f, 0xbcac]),
        y: BigNum::from_slice([0xa91a53e32b3752145d87f0cd70966e, 0xb339c974c0e757d348081f90a123b0, 0x3bcf]),
        is_infinity: false
    };

    let nullifier = H.mul(sk);

    let (r_point, hashed_to_curve_r) = plume_v2(msg, c2, s2, pk, nullifier);

    let mut compressed = [[0 as u8; COMPRESSED_SIZE_BYTES]; 3];
    compressed[0] = compress_ec_point(nullifier);
    compressed[1] = compress_ec_point(r_point);
    compressed[2] = compress_ec_point(hashed_to_curve_r);

    let mut res = [0 as u8; COMPRESSED_SIZE_BYTES * 3];
    for i in 0..3 {
        for j in 0..COMPRESSED_SIZE_BYTES {
            res[i*COMPRESSED_SIZE_BYTES + j] = compressed[i][j];
        }
    }
    let actual = hash(res);

    assert(expected == actual);
}
*/
