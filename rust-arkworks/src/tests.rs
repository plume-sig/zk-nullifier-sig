mod test_vectors;

use crate::secp256k1::{Affine, Config};
use crate::{secp256k1, PlumeSignaturePrivate, PlumeSignaturePublic, PlumeVersion};
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::AffineRepr;
use ark_std::rand;
use rand::{prelude::ThreadRng, thread_rng};

use crate::secp256k1::fq::Fq;
use ark_ec::CurveGroup;
use ark_ff::BigInteger;
use ark_ff::{PrimeField, UniformRand};
use serde::Deserialize;
use std::ops::Mul;

type Parameters = crate::Parameters<Config>;

#[derive(Deserialize)]
struct SharedVectors {
    vectors: Vec<TestVector>,
}

#[derive(Deserialize)]
struct TestVector {
    message: String,
    secret_key: String,
    nonce: String,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    public_key: PointVector,
    hash_m_pk: PointVector,
    nullifier: PointVector,
    r_point: PointVector,
    hashed_to_curve_r: PointVector,
    v1: SignatureVector,
    v2: SignatureVector,
}

#[derive(Deserialize)]
struct PointVector {
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct SignatureVector {
    c: String,
    s: String,
}

fn shared_vector() -> TestVector {
    serde_json::from_str::<SharedVectors>(include_str!(
        "../../test-vectors/plume-signatures.json"
    ))
    .unwrap()
    .vectors
    .into_iter()
    .next()
    .unwrap()
}

/// Verifies a PLUME signature.
/// Returns `true` if the signature is valid, `false` otherwise.
///
/// Computes the curve points and scalars needed for verification from the
/// signature parameters. Then performs the verification steps:
/// - Confirm g^s * pk^-c = g^r
/// - Confirm h^s * nul^-c = z
/// - Confirm c = c'
///
/// Rejects if any check fails.
pub fn verify_non_zk(
    sig: (PlumeSignaturePublic, PlumeSignaturePrivate),
    pp: &super::Parameters<secp256k1::Config>,
    pk: &super::PublicKey,
    message: &[u8],
    version: PlumeVersion,
) -> Result<bool, super::HashToCurveError> {
    // Compute h = htc([m, pk])
    let hashed_to_curve = super::hash_to_curve(message, pk)?;

    // Compute c' = sha256([g, pk, h, nul, g^r, z]) for v1
    //         c' = sha256([nul, g^r, z]) for v2
    let c = match version {
        PlumeVersion::V1 => super::compute_c_v1(
            pk,
            &hashed_to_curve,
            &sig.0.nullifier,
            &sig.1.r_point,
            &sig.1.hashed_to_curve_r,
        ),
        PlumeVersion::V2 => {
            super::compute_c_v2(&sig.0.nullifier, &sig.1.r_point, &sig.1.hashed_to_curve_r)
        }
    };
    let c_scalar = secp256k1::Fr::from_be_bytes_mod_order(c.as_ref());

    // Reject if g^s ⋅ pk^{-c} != g^r
    let g_s = pp.g_point.mul(sig.0.s);
    let pk_c = pk.mul(sig.1.digest_private);
    let g_s_pk_c = g_s - pk_c;

    if sig.1.r_point != g_s_pk_c {
        return Ok(false);
    }

    // Reject if h^s ⋅ nul^{-c} = z
    let h_s = hashed_to_curve.mul(sig.0.s);
    let nul_c = sig.0.nullifier.mul(sig.1.digest_private);
    let h_s_nul_c = h_s - nul_c;

    if sig.1.hashed_to_curve_r != h_s_nul_c {
        return Ok(false);
    }

    // Reject if c != c'
    if c_scalar != sig.1.digest_private {
        return Ok(false);
    }

    Ok(true)
}

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

fn hex_to_fr_be(hex: &str) -> crate::secp256k1::Fr {
    crate::secp256k1::Fr::from_be_bytes_mod_order(&hex::decode(hex).unwrap())
}

fn coord_to_hex(coord: Fq) -> String {
    let mut coord_bytes = coord.into_bigint().to_bytes_le();
    coord_bytes.reverse();

    String::from(hex::encode(coord_bytes))
}

fn hardcoded_sk() -> String {
    shared_vector().secret_key
}

fn hardcoded_r() -> String {
    shared_vector().nonce
}

pub fn hardcoded_msg() -> String {
    shared_vector().message
}

/// Generate the public key and a private key.
pub fn keygen(rng: &mut impl super::rand::Rng) -> (super::PublicKey, super::SecretKeyMaterial) {
    let secret_key = super::SecretKeyMaterial::rand(rng);
    let public_key = secp256k1::Config::GENERATOR * secret_key;
    (public_key.into_affine(), secret_key)
}

#[test]
pub fn test_keygen() {
    let (mut rng, g) = test_template();
    let pp = Parameters { g_point: g };

    let (pk, sk) = keygen(&mut rng);

    let expected_pk = g.mul(sk);
    assert_eq!(pk, expected_pk);
}

#[test]
pub fn test_sign_and_verify() {
    let (mut rng, g) = test_template();
    let pp = Parameters { g_point: g };

    let message = b"Message";
    let keypair = keygen(&mut rng);

    let sig = super::sign(
        &mut rng,
        (&keypair.0, &keypair.1),
        message,
        PlumeVersion::V1,
    )
    .unwrap();

    let is_valid = verify_non_zk(sig, &pp, &keypair.0, message, PlumeVersion::V1);
    assert!(is_valid.unwrap());

    let sig = super::sign(
        &mut rng,
        (&keypair.0, &keypair.1),
        message,
        PlumeVersion::V2,
    )
    .unwrap();

    let is_valid = verify_non_zk(sig, &pp, &keypair.0, message, PlumeVersion::V2);
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
    let vector = shared_vector();
    // Check the pubkey generated from the hardcoded secret key
    let sk = hex_to_fr(&hardcoded_sk());

    let (_, g) = test_template();
    let pk_projective = g.mul(sk);
    let pk = Affine::from(pk_projective);

    assert_eq!(coord_to_hex(pk.x.into()), vector.expected.public_key.x);
    assert_eq!(coord_to_hex(pk.y.into()), vector.expected.public_key.y);
}

#[test]
pub fn test_against_zk_nullifier_sig_g_r() {
    let vector = shared_vector();
    // Test g^r using the hardcoded r
    let r = crate::secp256k1::Fr::from(hex_to_fr(&hardcoded_r()));
    let (_, g) = test_template();
    let g_r_projective = g.mul(r);
    let g_r = Affine::from(g_r_projective);
    assert_eq!(coord_to_hex(g_r.x.into()), vector.expected.r_point.x);
    assert_eq!(coord_to_hex(g_r.y.into()), vector.expected.r_point.y);
}

#[test]
pub fn test_against_zk_nullifier_sig_h() {
    let vector = shared_vector();
    let h = hash_to_curve_with_testvalues();

    assert_eq!(coord_to_hex(h.x.into()), vector.expected.hash_m_pk.x);
    assert_eq!(coord_to_hex(h.y.into()), vector.expected.hash_m_pk.y);
}

#[test]
pub fn test_against_zk_nullifier_sig_h_r() {
    let vector = shared_vector();
    let h = hash_to_curve_with_testvalues();

    // Test h^r using the hardcoded r
    let r = crate::secp256k1::Fr::from(hex_to_fr(&hardcoded_r()));
    let h_r_projective = h * r;
    let h_r = Affine::from(h_r_projective);
    assert_eq!(
        coord_to_hex(h_r.x.into()),
        vector.expected.hashed_to_curve_r.x
    );
    assert_eq!(
        coord_to_hex(h_r.y.into()),
        vector.expected.hashed_to_curve_r.y
    );
}

#[test]
pub fn test_against_zk_nullifier_sig_h_sk() {
    let vector = shared_vector();
    let h = hash_to_curve_with_testvalues();
    let sk = hex_to_fr(&hardcoded_sk());

    // Test h^r using the hardcoded sk
    let h_sk_projective = h * sk;
    let h_sk = h_sk_projective.into_affine();
    assert_eq!(coord_to_hex(h_sk.x.into()), vector.expected.nullifier.x);
    assert_eq!(coord_to_hex(h_sk.y.into()), vector.expected.nullifier.y);
}

#[test]
pub fn test_against_zk_nullifier_sig_c_and_s() {
    let vector = shared_vector();
    let r = crate::secp256k1::Fr::from(hex_to_fr(&hardcoded_r()));
    let message = hardcoded_msg();
    let message = message.as_bytes();
    let sk = hex_to_fr(&hardcoded_sk());
    let (_, g) = test_template();
    let pp = Parameters { g_point: g };
    let pk_projective = g * sk;
    let pk = Affine::from(pk_projective);

    let keypair = (pk, sk);
    let sig =
        super::sign_with_r((&keypair.0, &keypair.1), message, r, PlumeVersion::V1).unwrap();

    assert_eq!(sig.1.digest_private, hex_to_fr_be(&vector.expected.v1.c));
    assert_eq!(sig.0.s, hex_to_fr_be(&vector.expected.v1.s));

    let sig =
        super::sign_with_r((&keypair.0, &keypair.1), message, r, PlumeVersion::V2).unwrap();

    assert_eq!(sig.1.digest_private, hex_to_fr_be(&vector.expected.v2.c));
    assert_eq!(sig.0.s, hex_to_fr_be(&vector.expected.v2.s));
}

#[test]
fn test_point_sec1_encoding() {
    let vectors = test_vectors::encoding_test_vectors();

    let generator = secp256k1::Affine::generator();

    for vector in vectors {
        let k = vector.0;
        let point = (generator * secp256k1::Fr::from(k)).into_affine();

        assert_eq!(
            super::helper(super::sec1_affine(&point)),
            hex::decode(vector.1.as_bytes()).unwrap()
        );
    }
}
