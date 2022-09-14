#![allow(dead_code)]
#![allow(unused_variables)]
// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use hex_literal::hex;
use k256::{
    // ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::group::ff::PrimeField,
    sha2::{Digest, Sha256, Sha512},
    FieldBytes,
    ProjectivePoint,
    Scalar,
    Secp256k1,
}; // requires 'getrandom' feature

const L: usize = 48;
const COUNT: usize = 2;
const OUT: usize = L * COUNT;
const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"; // Hash to curve algorithm

#[derive(Debug, PartialEq)]
pub enum Error {
    IsPointAtInfinityError,
}


fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

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

    println!("h.x: {:?}", hex::encode(hash_m_pk.to_affine().to_encoded_point(false).x().unwrap()));
    println!("h.y: {:?}", hex::encode(hash_m_pk.to_affine().to_encoded_point(false).y().unwrap()));

    // hash[m, pk]^r
    let hash_m_pk_pow_r = &hash_m_pk * &r;

    // The public nullifier: hash[m, pk]^sk.
    let nullifier = &hash_m_pk * &sk;

    // The Fiat-Shamir type step.
    let c = sha512hash6signals(&g, &pk, &hash_m_pk, &nullifier, &g_r, &hash_m_pk_pow_r);

    // This value is part of the discrete log equivalence (DLEQ) proof.
    let r_sk_c = r + sk * c;

    // Return the signature.
    (pk, nullifier, c, r_sk_c, Some(g_r), Some(hash_m_pk_pow_r))
}

fn sha512hash6signals(
    g: &ProjectivePoint,
    pk: &ProjectivePoint,
    hash_m_pk: &ProjectivePoint,
    nullifier: &ProjectivePoint,
    g_r: &ProjectivePoint,
    hash_m_pk_pow_r: &ProjectivePoint,
) -> Scalar {
    let g_bytes = encode_pt(*g).unwrap();
    let pk_bytes = encode_pt(*pk).unwrap();
    let h_bytes = encode_pt(*hash_m_pk).unwrap();
    let nul_bytes = encode_pt(*nullifier).unwrap();
    let g_r_bytes = encode_pt(*g_r).unwrap();
    let z_bytes = encode_pt(*hash_m_pk_pow_r).unwrap();

    let c_preimage_vec = [
        g_bytes,
        pk_bytes,
        h_bytes,
        nul_bytes,
        g_r_bytes,
        z_bytes,
    ].concat();

    //println!("c_preimage_vec: {:?}", c_preimage_vec);

    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(c_preimage_vec.as_slice());
    let sha512_hasher_result = sha512_hasher.finalize(); //512 bit hash

    let c_bytes = FieldBytes::from_iter(sha512_hasher_result.iter().copied());
    let c_scalar = Scalar::from_repr(c_bytes).unwrap();
    c_scalar
}

// Calls the hash to curve function for secp256k1, and returns the result as a ProjectivePoint
fn hash_to_secp(s: &[u8]) -> ProjectivePoint {
    let pt: ProjectivePoint =
        Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[s], b"CURVE_XMD:SHA-256_SSWU_RO_")
            .unwrap();
    pt
}

// Hashes two values to the curve
fn hash_m_pk_to_secp(m: &[u8], pk: &ProjectivePoint) -> ProjectivePoint {
    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[[m, &encode_pt(*pk).unwrap()].concat().as_slice()],
        b"CURVE_XMD:SHA-256_SSWU_RO_",
    )
    .unwrap();
    pt
}

// Verifier check in SNARK:
// g^[r + sk * c] / (g^sk)^c = g^r
// hash[m, gsk]^[r + sk * c] / (hash[m, pk]^sk)^c = hash[m, pk]^r
// c = hash2(g, g^sk, hash[m, g^sk], hash[m, pk]^sk, gr, hash[m, pk]^r)
fn verify_signals(
    m: &[u8],
    pk: &ProjectivePoint,
    nullifier: &ProjectivePoint,
    c: &Scalar,
    r_sk_c: &Scalar,
    g_r_option: &Option<ProjectivePoint>,
    hash_m_pk_pow_r_option: &Option<ProjectivePoint>,
) -> bool {
    let mut verified: bool = true;

    // The base point or generator of the curve.
    let g = &ProjectivePoint::GENERATOR;

    // hash[m, pk]
    let hash_m_pk = &hash_m_pk_to_secp(m, pk);
    
    // Check whether g^r equals g^s * pk^{-c}
    let g_r: ProjectivePoint;
    match *g_r_option {
        Some(_g_r_value) => {
            if (g * r_sk_c - pk * c) != _g_r_value {
                verified = false;
            }
        }
        None => println!("g^r not provided, check skipped"),
    }
    g_r = g * r_sk_c - pk * c;

    // Check whether h^r equals h^{r + sk * c} * nullifier^{-c}
    let hash_m_pk_pow_r: ProjectivePoint;
    match *hash_m_pk_pow_r_option {
        Some(_hash_m_pk_pow_r_value) => {
            if (hash_m_pk * r_sk_c - nullifier * c) != _hash_m_pk_pow_r_value {
                verified = false;
            }
        }
        None => println!("hash_m_pk_pow_r not provided, check skipped"),
    }
    hash_m_pk_pow_r = hash_m_pk * r_sk_c - nullifier * c;

    // Check if the given hash matches
    if (sha512hash6signals(g, pk, hash_m_pk, nullifier, &g_r, &hash_m_pk_pow_r)) != *c {
        verified = false;
    }
    verified
}

// NOTE: MAKE SURE TO HAVE RUST-ANALYZER ENABLED IN VSCODE EXTENSIONS TO FILL IN INFERRED TYPES
fn main() -> Result<(), ()> {
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
    println!("nullifier.x: {:?}", hex::encode(nullifier.to_affine().to_encoded_point(false).x().unwrap()));
    println!("nullifier.y: {:?}", hex::encode(nullifier.to_affine().to_encoded_point(false).y().unwrap()));

    // Print c
    println!("c: {:?}", hex::encode(&c.to_bytes()));
    
    // Print r_sk_c
    println!("r_sk_c: {:?}", hex::encode(r_sk_c.to_bytes()));
    
    // Print g_r
    println!("g_r.x: {:?}", hex::encode(g_r.unwrap().to_affine().to_encoded_point(false).x().unwrap()));
    println!("g_r.y: {:?}", hex::encode(g_r.unwrap().to_affine().to_encoded_point(false).y().unwrap()));
    
    // Print hash_m_pk_pow_r
    println!("hash_m_pk_pow_r.x: {:?}", hex::encode(hash_m_pk_pow_r.unwrap().to_affine().to_encoded_point(false).x().unwrap()));
    println!("hash_m_pk_pow_r.y: {:?}", hex::encode(hash_m_pk_pow_r.unwrap().to_affine().to_encoded_point(false).y().unwrap()));

    // Test encode_pt()
    let g_as_bytes = encode_pt(g).unwrap();
    assert_eq!(hex::encode(g_as_bytes), "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    // Test byte_array_to_scalar()
    let bytes_to_convert = c.to_bytes();
    let scalar = byte_array_to_scalar(&bytes_to_convert);
    assert_eq!(hex::encode(scalar.to_bytes()), "9de4daa951b8728db267eea9aa54ae48f8496bfde11387e91a39b261782a2b43");

    Ok(())
}

/// Format a ProjectivePoint to 64 bytes - the concatenation of the x and y values.  We use 64
/// bytes instead of SEC1 encoding as our arkworks secp256k1 implementation doesn't support SEC1
/// encoding yet.
fn encode_pt(
    point: ProjectivePoint
) -> Result<Vec::<u8>, Error> {
    let encoded = point.to_encoded_point(true);
    Ok(encoded.to_bytes().to_vec())
}

/// Convert a 32-byte array to a scalar
fn byte_array_to_scalar(
    bytes: &[u8],
) -> Scalar {
    // From https://docs.rs/ark-ff/0.3.0/src/ark_ff/fields/mod.rs.html#371-393
    assert!(bytes.len() == 32);
    let mut res = Scalar::from(0u64);
    let window_size = Scalar::from(256u64);
    for byte in bytes.iter() {
        res *= window_size;
        res += Scalar::from(*byte as u64);
    }
    res
}
