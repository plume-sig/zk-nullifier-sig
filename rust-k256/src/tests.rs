use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use k256::{elliptic_curve::group::ff::PrimeField, ProjectivePoint, Scalar}; // requires 'getrandom' feature

use crate::nullifier::*;
use crate::serialize::*;

// Generates a deterministic secret key for us temporarily. Can be replaced by random oracle anytime.
fn gen_test_scalar_x() -> Scalar {
    Scalar::from_repr(
        hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").into(),
    )
    .unwrap()
}

// Generates a deterministic r for us temporarily. Can be replaced by random oracle anytime.
fn gen_test_scalar_r() -> Scalar {
    Scalar::from_repr(
        hex!("93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808").into(),
    )
    .unwrap()
}

// These generate test signals as if it were passed from a secure enclave to wallet. Note that leaking these signals would leak pk, but not sk.
// Outputs these 6 signals, in this order
// g^sk																(private)
// hash[m, pk]^sk 													public nullifier
// c = hash2(g, pk, hash[m, pk], hash[m, pk]^sk, gr, hash[m, pk]^r)	(public or private)
// r + sk * c														(public or private)
// g^r																(private, optional)
// hash[m, pk]^r													(private, optional)
fn test_gen_signals(
    m: &[u8],
) -> (
    ProjectivePoint,
    ProjectivePoint,
    Scalar,
    Scalar,
    Option<ProjectivePoint>,
    Option<ProjectivePoint>,
) {
    // The base point or generator of the curve.
    let g = ProjectivePoint::GENERATOR;

    // The signer's secret key. It is only accessed within the secure enclave.
    let sk = gen_test_scalar_x();

    // A random value r. It is only accessed within the secure enclave.
    let r = gen_test_scalar_r();

    // The user's public key: g^sk.
    let pk = &g * &sk;

    // The generator exponentiated by r: g^r.
    let g_r = &g * &r;

    // hash[m, pk]
    let hash_m_pk = hash_m_pk_to_secp(m, &pk);

    println!(
        "h.x: {:?}",
        hex::encode(hash_m_pk.to_affine().to_encoded_point(false).x().unwrap())
    );
    println!(
        "h.y: {:?}",
        hex::encode(hash_m_pk.to_affine().to_encoded_point(false).y().unwrap())
    );

    // hash[m, pk]^r
    let hash_m_pk_pow_r = &hash_m_pk * &r;
    println!(
        "hash_m_pk_pow_r.x: {:?}",
        hex::encode(
            hash_m_pk_pow_r
                .to_affine()
                .to_encoded_point(false)
                .x()
                .unwrap()
        )
    );
    println!(
        "hash_m_pk_pow_r.y: {:?}",
        hex::encode(
            hash_m_pk_pow_r
                .to_affine()
                .to_encoded_point(false)
                .y()
                .unwrap()
        )
    );

    // The public nullifier: hash[m, pk]^sk.
    let nullifier = &hash_m_pk * &sk;

    // The Fiat-Shamir type step.
    let c = sha512hash6signals(&g, &pk, &hash_m_pk, &nullifier, &g_r, &hash_m_pk_pow_r);

    // This value is part of the discrete log equivalence (DLEQ) proof.
    let r_sk_c = r + sk * c;

    // Return the signature.
    (pk, nullifier, c, r_sk_c, Some(g_r), Some(hash_m_pk_pow_r))
}

// NOTE: MAKE SURE TO HAVE RUST-ANALYZER ENABLED IN VSCODE EXTENSIONS TO FILL IN INFERRED TYPES
#[test]
fn main() {
    let g = ProjectivePoint::GENERATOR;

    let m = b"An example app message string";

    // Fixed key nullifier, secret key, and random value for testing
    // Normally a secure enclave would generate these values, and output to a wallet implementation
    let (pk, nullifier, c, r_sk_c, g_r, hash_m_pk_pow_r) = test_gen_signals(m);

    // The signer's secret key. It is only accessed within the secure enclave.
    let sk = gen_test_scalar_x();

    // The user's public key: g^sk.
    let pk = &g * &sk;

    // Verify the signals, normally this would happen in ZK with only the nullifier public, which would have a zk verifier instead
    // The wallet should probably run this prior to snarkify-ing as a sanity check
    // m and nullifier should be public, so we can verify that they are correct
    let verified = verify_signals(m, &pk, &nullifier, &c, &r_sk_c, &g_r, &hash_m_pk_pow_r);
    println!("Verified: {}", verified);

    // Print nullifier
    println!(
        "nullifier.x: {:?}",
        hex::encode(nullifier.to_affine().to_encoded_point(false).x().unwrap())
    );
    println!(
        "nullifier.y: {:?}",
        hex::encode(nullifier.to_affine().to_encoded_point(false).y().unwrap())
    );

    // Print c
    println!("c: {:?}", hex::encode(&c.to_bytes()));

    // Print r_sk_c
    println!("r_sk_c: {:?}", hex::encode(r_sk_c.to_bytes()));

    // Print g_r
    println!(
        "g_r.x: {:?}",
        hex::encode(
            g_r.unwrap()
                .to_affine()
                .to_encoded_point(false)
                .x()
                .unwrap()
        )
    );
    println!(
        "g_r.y: {:?}",
        hex::encode(
            g_r.unwrap()
                .to_affine()
                .to_encoded_point(false)
                .y()
                .unwrap()
        )
    );

    // Print hash_m_pk_pow_r
    println!(
        "hash_m_pk_pow_r.x: {:?}",
        hex::encode(
            hash_m_pk_pow_r
                .unwrap()
                .to_affine()
                .to_encoded_point(false)
                .x()
                .unwrap()
        )
    );
    println!(
        "hash_m_pk_pow_r.y: {:?}",
        hex::encode(
            hash_m_pk_pow_r
                .unwrap()
                .to_affine()
                .to_encoded_point(false)
                .y()
                .unwrap()
        )
    );

    // Test encode_pt()
    let g_as_bytes = encode_pt(g).unwrap();
    assert_eq!(
        hex::encode(g_as_bytes),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );

    // Test byte_array_to_scalar()
    let bytes_to_convert = c.to_bytes();
    let scalar = byte_array_to_scalar(&bytes_to_convert);
    assert_eq!(
        hex::encode(scalar.to_bytes()),
        "7da1ad3f63c6180beefd0d6a8e3c87620b54f1b1d2c8287d104da9e53b6b5524"
    );

    // Test the hash-to-curve algorithm
    let h = hash_to_secp(b"abc");
    assert_eq!(
        hex::encode(h.to_affine().to_encoded_point(false).x().unwrap()),
        "3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"
    );
    assert_eq!(
        hex::encode(h.to_affine().to_encoded_point(false).y().unwrap()),
        "7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"
    );
}
