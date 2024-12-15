mod test_vectors;

use crate::secp256k1::{Affine, Config};
use crate::{secp256k1, PlumeSignature, PlumeVersion};
use ark_ec::AffineRepr;
use ark_std::rand;
use rand::{prelude::ThreadRng, thread_rng};

use crate::secp256k1::fq::Fq;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_ff::{BigInt, BigInteger};
use std::ops::Mul;

type Parameters = crate::Parameters<Config>;

fn test_template() -> (ThreadRng, Affine) {
    let rng = thread_rng();
    let g = Affine::generator();

    (rng, g)
}

fn hex_to_fr(hex: &str) -> crate::secp256k1::Fr {
    let num_field_bits = 320;
    let mut sk_bytes_vec = vec![0u8; num_field_bits];
    let mut sk_bytes = hex::decode(hex).unwrap();

    sk_bytes.reverse();

    for (i, _) in sk_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(&mut sk_bytes_vec[i], sk_bytes[i]);
    }

    crate::secp256k1::Fr::from_le_bytes_mod_order(sk_bytes_vec.as_slice())
}

fn coord_to_hex(coord: Fq) -> String {
    let mut coord_bytes = coord.into_bigint().to_bytes_le();
    coord_bytes.reverse();

    String::from(hex::encode(coord_bytes))
}

fn hardcoded_sk() -> String {
    "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464".to_string()
}

fn hardcoded_r() -> String {
    "93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808".to_string()
}

pub fn hardcoded_msg() -> String {
    "An example app message string".to_string()
}

#[test]
pub fn test_keygen() {
    let (mut rng, g) = test_template();
    let pp = Parameters { g_point: g };

    let (pk, sk) = PlumeSignature::keygen(&mut rng);

    let expected_pk = g.mul(sk);
    assert_eq!(pk, expected_pk);
}

#[test]
pub fn test_sign_and_verify() {
    let (mut rng, g) = test_template();
    let pp = Parameters { g_point: g };

    let message = b"Message";
    let keypair = PlumeSignature::keygen(&mut rng);

    let sig = PlumeSignature::sign(
        &mut rng,
        (&keypair.0, &keypair.1),
        message,
        PlumeVersion::V1,
    )
    .unwrap();

    let is_valid = sig.verify_non_zk(&pp, &keypair.0, message, PlumeVersion::V1);
    assert!(is_valid.unwrap());

    let sig = PlumeSignature::sign(
        &mut rng,
        (&keypair.0, &keypair.1),
        message,
        PlumeVersion::V2,
    )
    .unwrap();

    let is_valid = sig.verify_non_zk(&pp, &keypair.0, message, PlumeVersion::V2);
    assert!(is_valid.unwrap());
}

pub fn hash_to_curve_with_testvalues() -> Affine {
    let msg = hardcoded_msg();
    let message = msg.as_bytes();

    let sk = hex_to_fr(&hardcoded_sk());
    let (_, g) = test_template();
    let pk_projective = g * sk;

    super::hash_to_curve(message, &pk_projective.into_affine()).unwrap()
}

#[test]
pub fn test_against_zk_nullifier_sig_pk() {
    // Check the pubkey generated from the hardcoded secret key
    let sk = hex_to_fr(&hardcoded_sk());

    let (_, g) = test_template();
    let pk_projective = g.mul(sk);
    let pk = Affine::from(pk_projective);

    assert_eq!(
        coord_to_hex(pk.x.into()),
        "0cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae"
    );
    assert_eq!(
        coord_to_hex(pk.y.into()),
        "eff471fba0409897b6a48e8801ad12f95d0009b753cf8f51c128bf6b0bd27fbd"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_g_r() {
    // Test g^r using the hardcoded r
    let r = crate::secp256k1::Fr::from(hex_to_fr(&hardcoded_r()));
    let (_, g) = test_template();
    let g_r_projective = g.mul(r);
    let g_r = Affine::from(g_r_projective);
    assert_eq!(
        coord_to_hex(g_r.x.into()),
        "9d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804"
    );
    assert_eq!(
        coord_to_hex(g_r.y.into()),
        "ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_h() {
    let h = hash_to_curve_with_testvalues();

    assert_eq!(
        coord_to_hex(h.x.into()),
        "bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65"
    );
    assert_eq!(
        coord_to_hex(h.y.into()),
        "3bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_h_r() {
    let h = hash_to_curve_with_testvalues();

    // Test h^r using the hardcoded r
    let r = crate::secp256k1::Fr::from(hex_to_fr(&hardcoded_r()));
    let h_r_projective = h * r;
    let h_r = Affine::from(h_r_projective);
    assert_eq!(
        coord_to_hex(h_r.x.into()),
        "6d017c6f63c59fa7a5b1e9a654e27d2869579f4d152131db270558fccd27b97c"
    );
    assert_eq!(
        coord_to_hex(h_r.y.into()),
        "586c43fb5c99818c564a8f80a88a65f83e3f44d3c6caf5a1a4e290b777ac56ed"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_h_sk() {
    let h = hash_to_curve_with_testvalues();
    let sk = hex_to_fr(&hardcoded_sk());

    // Test h^r using the hardcoded sk
    let h_sk_projective = h * sk;
    let h_sk = h_sk_projective.into_affine();
    assert_eq!(
        coord_to_hex(h_sk.x.into()),
        "57bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830"
    );
    assert_eq!(
        coord_to_hex(h_sk.y.into()),
        "6a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_c_and_s() {
    let r = crate::secp256k1::Fr::from(hex_to_fr(&hardcoded_r()));
    let message = hardcoded_msg();
    let message = message.as_bytes();
    let sk = hex_to_fr(&hardcoded_sk());
    let (_, g) = test_template();
    let pp = Parameters { g_point: g };
    let pk_projective = g * sk;
    let pk = Affine::from(pk_projective);

    let keypair = (pk, sk);
    let sig = PlumeSignature::sign_with_r((&keypair.0, &keypair.1), message, r, PlumeVersion::V1)
        .unwrap();

    assert_eq!(
        sig.c.into_bigint(),
        BigInt!("0xc6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254")
    );
    assert_eq!(
        sig.s.into_bigint(),
        BigInt!("0xe69f027d84cb6fe5f761e333d12e975fb190d163e8ea132d7de0bd6079ba28ca")
    );

    let sig = PlumeSignature::sign_with_r((&keypair.0, &keypair.1), message, r, PlumeVersion::V2)
        .unwrap();

    assert_eq!(
        sig.c.into_bigint(),
        BigInt!("0x3dbfb717705010d4f44a70720c95e74b475bd3a783ab0b9e8a6b3b363434eb96")
    );
    assert_eq!(
        sig.s.into_bigint(),
        BigInt!("0x528e8fbb6452f82200797b1a73b2947a92524bd611085a920f1177cb8098136b")
    );
}

#[test]
fn test_point_sec1_encoding() {
    let vectors = test_vectors::encoding_test_vectors();

    let generator = secp256k1::Affine::generator();

    for vector in vectors {
        let k = vector.0;
        let point = (generator * secp256k1::Fr::from(k)).into_affine();

        assert_eq!(
            super::affine_to_bytes(&point),
            hex::decode(vector.1.as_bytes()).unwrap()
        );
    }
}
