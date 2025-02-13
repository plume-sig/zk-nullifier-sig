/*
    Expand message XMD with SHA-256.
    
    See the link below for more details:

    https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html#name-expand_message_xmd
*/

use nodash::array::pack_bytes;
use std::hash::poseidon2::Poseidon2::hash;

comptime global DST_PRIME: [u8; 50] = [
    81, 85, 85, 88, 45, 86, 48, 49, 45, 67, 83, 48, 50, 45, 119, 105, 116, 104, 45, 115, 101, 99,
    112, 50, 53, 54, 107, 49, 95, 88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85,
    95, 82, 79, 95, 49,
];

pub fn expand_message_xmd<let N: u32>(msg: [u8; N]) -> [u8; 96] {
    let b0 = msg_prime(msg);
    let b1 = hash_b(1, b0);
    let b2 = hash_bi(2, b0, b1);
    let b3 = hash_bi(3, b0, b2);

    let mut out = [0 as u8; 96];
    for i in 0..32 {
        out[i] = b1[i];
    }
    for i in 0..32 {
        out[32 + i] = b2[i];
    }
    for i in 0..32 {
        out[64 + i] = b3[i];
    }

    out
}

fn msg_prime<let N: u32>(msg: [u8; N]) -> [u8; 32] {
    let mut preimage = [0; 64 + N + 2 + 1 + 50];

    for i in 0..N {
        preimage[64 + i] = msg[i];
    }

    let lib_str = [0, 96];
    for i in 0..lib_str.len() {
        preimage[64 + N + i] = lib_str[i];
    }

    preimage[64 + N + 2] = 0;

    for i in 0..50 {
        preimage[64 + N + 2 + 1 + i] = DST_PRIME[i];
    }

    let packed_preimage = pack_bytes(preimage);
    hash(packed_preimage, packed_preimage.len()).to_le_bytes()
}

fn hash_bi(b_idx: u8, b0: [u8; 32], b1: [u8; 32]) -> [u8; 32] {
    assert(b_idx < 8);

    let mut res = [0 as u8; 32];
    for i in 0..32 {
        res[i] = b0[i] ^ b1[i];
    }

    hash_b(b_idx, res)
}

fn hash_b(b_idx: u8, b: [u8; 32]) -> [u8; 32] {
    assert(b_idx < 8);
    let mut preimage = [0; 32 + 1 + 50];

    for i in 0..32 {
        preimage[i] = b[i];
    }

    preimage[32] = b_idx;

    for i in 0..50 {
        preimage[32 + 1 + i] = DST_PRIME[i];
    }

    let packed_preimage = pack_bytes(preimage);

    hash(packed_preimage, packed_preimage.len()).to_le_bytes()
}

#[test]
fn test_b0() {
    let msg = [97, 98, 99];

    let actual_b0 = msg_prime(msg);

    let expected_b0 = [
        228, 104, 184, 167, 234, 119, 63, 174, 73, 124, 173, 5, 192, 232, 133, 134, 85, 3, 200, 9,
        83, 117, 70, 147, 122, 212, 172, 21, 134, 100, 228, 9,
    ];

    assert(actual_b0 == expected_b0);
}

#[test]
fn test_b1() {
    let b0 = [
        99, 4, 75, 36, 124, 254, 65, 234, 207, 65, 212, 122, 206, 186, 87, 48, 157, 28, 243, 255,
        59, 178, 30, 40, 136, 85, 202, 99, 135, 177, 127, 169,
    ];

    let actual_b1 = hash_b(1, b0);

    let expected_b1 = [
        73, 43, 24, 183, 62, 176, 195, 132, 193, 74, 110, 167, 227, 136, 203, 116, 49, 47, 137, 76,
        197, 137, 240, 27, 73, 4, 199, 242, 177, 132, 153, 35,
    ];

    assert(actual_b1 == expected_b1);
}

#[test]
fn test_b2() {
    let b0 = [
        99, 4, 75, 36, 124, 254, 65, 234, 207, 65, 212, 122, 206, 186, 87, 48, 157, 28, 243, 255,
        59, 178, 30, 40, 136, 85, 202, 99, 135, 177, 127, 169,
    ];
    let b1 = [
        232, 52, 124, 173, 72, 171, 78, 49, 157, 123, 39, 85, 32, 234, 129, 207, 18, 138, 171, 93,
        54, 121, 161, 247, 96, 30, 59, 222, 172, 154, 81, 208,
    ];

    let actual_b2 = hash_bi(2, b0, b1);

    let expected_b2 = [
        112, 13, 46, 2, 147, 132, 94, 227, 55, 152, 104, 233, 105, 231, 105, 7, 77, 223, 107, 174,
        22, 151, 25, 122, 211, 249, 169, 197, 191, 20, 2, 5,
    ];

    assert(actual_b2 == expected_b2);
}

#[test]
fn test_b3() {
    let b0 = [
        99, 4, 75, 36, 124, 254, 65, 234, 207, 65, 212, 122, 206, 186, 87, 48, 157, 28, 243, 255,
        59, 178, 30, 40, 136, 85, 202, 99, 135, 177, 127, 169,
    ];
    let b2 = [
        197, 77, 255, 208, 84, 39, 78, 219, 36, 136, 85, 230, 17, 144, 196, 98, 167, 187, 97, 236,
        186, 142, 64, 10, 154, 118, 213, 174, 1, 78, 135, 255,
    ];

    let actual_b3 = hash_bi(3, b0, b2);

    let expected_b3 = [
        65, 128, 124, 229, 75, 222, 29, 56, 73, 250, 61, 106, 165, 246, 136, 163, 73, 238, 182, 246,
        248, 125, 183, 247, 252, 252, 198, 140, 145, 187, 200, 36,
    ];

    assert(actual_b3 == expected_b3);
}

#[test]
fn tests_expand_message_xmd() {
    let msg = [97, 98, 99];

    let actual = expand_message_xmd(msg);

    let expected = [
        79, 124, 187, 85, 246, 98, 214, 245, 100, 61, 184, 206, 134, 155, 190, 140, 80, 177, 9, 108,
        148, 153, 209, 71, 32, 157, 171, 1, 211, 173, 38, 6, 39, 165, 226, 246, 236, 248, 29, 27,
        102, 64, 236, 176, 110, 39, 102, 17, 205, 4, 30, 102, 2, 157, 193, 27, 134, 67, 247, 96,
        189, 48, 231, 22, 229, 160, 59, 162, 199, 89, 173, 239, 56, 191, 22, 25, 55, 54, 229, 50,
        115, 9, 132, 114, 250, 7, 58, 218, 117, 161, 123, 133, 151, 132, 16, 5,
    ];

    assert(actual == expected);
}
