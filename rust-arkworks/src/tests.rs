use crate::hash_to_curve::{hash_to_curve, k256_affine_to_arkworks_secp256k1_affine};
use crate::{PlumeSignature, PlumeVersion};
use ark_ec::models::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::biginteger;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_std::rand;
use k256::{ProjectivePoint, Scalar};
use rand::{prelude::ThreadRng, thread_rng};
use secp256k1::curves::Affine;
use secp256k1::curves::Secp256k1Parameters;
use secp256k1::fields::Fq;

type Parameters = crate::Parameters<Secp256k1Parameters>;

fn test_template() -> (ThreadRng, Affine) {
    let rng = thread_rng();
    let g = Affine::prime_subgroup_generator();

    (rng, g)
}

#[test]
pub fn test_k256_affine_to_arkworks_secp256k1_affine() {
    for i in 1..50 {
        let i_u64 = i as u64;
        let k256_scalar = Scalar::from(i_u64);
        let ark_scalar = Fq::from(i_u64);

        // Compute g^i_u64
        let k256_pt = ProjectivePoint::GENERATOR.to_affine() * k256_scalar;
        let ark_pt = Affine::prime_subgroup_generator().mul(ark_scalar);

        // Convert k256_pt to an arkworks point
        let converted_pt =
            k256_affine_to_arkworks_secp256k1_affine::<Secp256k1Parameters>(k256_pt.to_affine());

        // The points should match
        assert_eq!(ark_pt.into_affine(), converted_pt.unwrap());
    }
}

fn hex_to_fr(hex: &str) -> secp256k1::fields::Fr {
    let num_field_bits = 320;
    let mut sk_bytes_vec = vec![0u8; num_field_bits];
    let mut sk_bytes = hex::decode(hex).unwrap();

    sk_bytes.reverse();

    for (i, _) in sk_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(&mut sk_bytes_vec[i], sk_bytes[i]);
    }

    secp256k1::fields::Fr::read(sk_bytes_vec.as_slice()).unwrap()
}

fn coord_to_hex(coord: biginteger::BigInteger320) -> String {
    let mut coord_bytes = vec![];
    let _ = coord.write(&mut coord_bytes);
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

    let (pk, sk) = PlumeSignature::keygen(&pp, &mut rng);

    let expected_pk = g.mul(sk);
    assert_eq!(pk, expected_pk);
}

#[test]
pub fn test_sign_and_verify() {
    let (mut rng, g) = test_template();
    let pp = Parameters { g_point: g };

    let message = b"Message";
    let keypair = PlumeSignature::keygen(&pp, &mut rng);

    let sig = PlumeSignature::sign(
        &pp,
        &mut rng,
        (&keypair.0, &keypair.1),
        message,
        PlumeVersion::V1,
    )
    .unwrap();

    let is_valid = sig.verify_non_zk(&pp, &keypair.0, message, PlumeVersion::V1);
    assert!(is_valid.unwrap());

    let sig = PlumeSignature::sign(
        &pp,
        &mut rng,
        (&keypair.0, &keypair.1),
        message,
        PlumeVersion::V2,
    )
    .unwrap();

    let is_valid = sig.verify_non_zk(&pp, &keypair.0, message, PlumeVersion::V2);
    assert!(is_valid.unwrap());
}

pub fn compute_h() -> GroupAffine<Secp256k1Parameters> {
    let msg = hardcoded_msg();
    let message = msg.as_bytes();

    let sk = hex_to_fr(&hardcoded_sk());
    let (_, g) = test_template();
    let pk_projective = g.mul(sk);
    let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);

    hash_to_curve::<secp256k1::fields::Fq, Secp256k1Parameters>(message, &pk).unwrap()
}

#[test]
pub fn test_against_zk_nullifier_sig_pk() {
    // Check the pubkey generated from the hardcoded secret key
    let sk = hex_to_fr(&hardcoded_sk());

    let (_, g) = test_template();
    let pk_projective = g.mul(sk);
    let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);

    assert_eq!(
        coord_to_hex(pk.x.into()),
        "00000000000000000cec028ee08d09e02672a68310814354f9eabfff0de6dacc1cd3a774496076ae"
    );
    assert_eq!(
        coord_to_hex(pk.y.into()),
        "0000000000000000eff471fba0409897b6a48e8801ad12f95d0009b753cf8f51c128bf6b0bd27fbd"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_g_r() {
    // Test g^r using the hardcoded r
    let r = secp256k1::fields::Fr::from(hex_to_fr(&hardcoded_r()));
    let (_, g) = test_template();
    let g_r_projective = g.mul(r);
    let g_r = GroupAffine::<Secp256k1Parameters>::from(g_r_projective);
    assert_eq!(
        coord_to_hex(g_r.x.into()),
        "00000000000000009d8ca4350e7e2ad27abc6d2a281365818076662962a28429590e2dc736fe9804"
    );
    assert_eq!(
        coord_to_hex(g_r.y.into()),
        "0000000000000000ff08c30b8afd4e854623c835d9c3aac6bcebe45112472d9b9054816a7670c5a1"
    );
}

//TODO: add test vectors for hash_to_curve
#[test]
pub fn test_against_zk_nullifier_sig_h() {
    let h = compute_h();

    assert_eq!(
        coord_to_hex(h.x.into()),
        "0000000000000000bcac2d0e12679f23c218889395abcdc01f2affbc49c54d1136a2190db0800b65"
    );
    assert_eq!(
        coord_to_hex(h.y.into()),
        "00000000000000003bcfb339c974c0e757d348081f90a123b0a91a53e32b3752145d87f0cd70966e"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_h_r() {
    let h = compute_h();

    // Test h^r using the hardcoded r
    let r = secp256k1::fields::Fr::from(hex_to_fr(&hardcoded_r()));
    let h_r_projective = h.mul(r);
    let h_r = GroupAffine::<Secp256k1Parameters>::from(h_r_projective);
    assert_eq!(
        coord_to_hex(h_r.x.into()),
        "00000000000000006d017c6f63c59fa7a5b1e9a654e27d2869579f4d152131db270558fccd27b97c"
    );
    assert_eq!(
        coord_to_hex(h_r.y.into()),
        "0000000000000000586c43fb5c99818c564a8f80a88a65f83e3f44d3c6caf5a1a4e290b777ac56ed"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_h_sk() {
    let h = compute_h();
    let sk = hex_to_fr(&hardcoded_sk());

    // Test h^r using the hardcoded sk
    let h_sk_projective = h.mul(sk);
    let h_sk = GroupAffine::<Secp256k1Parameters>::from(h_sk_projective);
    assert_eq!(
        coord_to_hex(h_sk.x.into()),
        "000000000000000057bc3ed28172ef8adde4b9e0c2cce745fcc5a66473a45c1e626f1d0c67e55830"
    );
    assert_eq!(
        coord_to_hex(h_sk.y.into()),
        "00000000000000006a2f41488d58f33ae46edd2188e111609f9f3ae67ea38fa891d6087fe59ecb73"
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_c_and_s() {
    let r = secp256k1::fields::Fr::from(hex_to_fr(&hardcoded_r()));
    let message = hardcoded_msg();
    let message = message.as_bytes();
    let sk = hex_to_fr(&hardcoded_sk());
    let (_, g) = test_template();
    let pp = Parameters { g_point: g };
    let pk_projective = g.mul(sk);
    let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);

    let keypair = (pk, sk);
    let sig =
        PlumeSignature::sign_with_r(&pp, (&keypair.0, &keypair.1), message, r, PlumeVersion::V1)
            .unwrap();

    assert_eq!(
        coord_to_hex(sig.c.into()),
        "0000000000000000c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
    );
    assert_eq!(
        coord_to_hex(sig.s.into()),
        "0000000000000000e69f027d84cb6fe5f761e333d12e975fb190d163e8ea132d7de0bd6079ba28ca"
    );

    let sig =
        PlumeSignature::sign_with_r(&pp, (&keypair.0, &keypair.1), message, r, PlumeVersion::V2)
            .unwrap();
    
    assert_eq!(
        coord_to_hex(sig.c.into()),
        "00000000000000003dbfb717705010d4f44a70720c95e74b475bd3a783ab0b9e8a6b3b363434eb96"
    );
    assert_eq!(
        coord_to_hex(sig.s.into()),
        "0000000000000000528e8fbb6452f82200797b1a73b2947a92524bd611085a920f1177cb8098136b"
    );
}
