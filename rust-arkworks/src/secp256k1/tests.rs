#![allow(unused_imports)]
use ark_ec::hashing::HashToCurve;
use ark_ec::AffineRepr;
use ark_ff::field_hashers::HashToField;
use ark_ff::BigInt;
// use crate::test_vectors;
// use crate::sec1::Sec1EncodePoint;
// use crate::fields::{Fr, Fq};
// use crate::curves::*;
use ark_std::{io::BufReader, rand::Rng, string::String, test_rng, vec::Vec};
// use ark_algebra_test_templates::{
//     fields::*,
//     curves::*,
//     msm::test_var_base_msm,
//     groups::group_test,
// };
// use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{
    biginteger::BigInteger320,
    vec,
    BigInteger,
    PrimeField,
    // ToBytes,
    // FromBytes,
    ToConstraintField,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::string::ToString;
use hex::ToHex;
use sha2::Sha256;

use crate::fixed_hasher::FixedFieldHasher;
use crate::secp256k1;

// #[test]
// fn test_fr() {
//     let mut rng = test_rng();
//     for _ in 0..5 {
//         let a: Fr = rng.gen();

//         sqrt_field_test(a);
//         fft_field_test::<Fr>();
//         primefield_test::<Fr>();

//         let b: Fr = rng.gen();
//         field_test::<Fr>(a, b);
//     }
// }

// #[test]
// fn test_fq() {
//     let mut rng = test_rng();
//     for _ in 0..5 {
//         let a: Fq = rng.gen();

//         sqrt_field_test(a);
//         fft_field_test::<Fq>();
//         primefield_test::<Fq>();
//         let b: Fq = rng.gen();
//         field_test::<Fq>(a, b);
//     }
// }

// #[test]
// fn test_secp256k1_curve() {
//     let mut rng = ark_std::test_rng();
//     let a: Projective = rng.gen();
//     let b: Projective = rng.gen();
//     group_test(a, b);

//     curve_tests::<Projective>();

//     test_var_base_msm::<Affine>();

//     // Fails in arkworks 0.3.0 but the next version should have a fix
//     sw_tests::<Secp256k1Parameters>();

//     test_var_base_msm::<Affine>();
// }

#[test]
fn test_secp256k1_generator() {
    let generator = super::Affine::generator();
    assert!(generator.is_on_curve());
    assert!(generator.is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn test_h2c() {
    /* suite   = secp256k1_XMD:SHA-256_SSWU_RO_
    dst     = QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_

    msg     =
    P.x     = c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346
                C1CAE290E291AEE617EBAEF1BE6D73861479C48B841EABA9B7B5852DDFEB1346
    P.y     = 64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067
                64FA678E07AE116126F08B022A94AF6DE15985C996C3A91B64C406A960E51067
    u[0]    = 6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e57
            3cab002fb3
    u[1]    = 1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d579
            9fd8f09e16
    Q0.x    = 74519ef88b32b425a095e4ebcc84d81b64e9e2c2675340a720bb1a
            1857b99f1e
    Q0.y    = c174fa322ab7c192e11748beed45b508e9fdb1ce046dee9c2cd3a2
            a86b410936
    Q1.x    = 44548adb1b399263ded3510554d28b4bead34b8cf9a37b4bd0bd2b
            a4db87ae63
    Q1.y    = 96eb8e2faf05e368efe5957c6167001760233e6dd2487516b46ae7
            25c4cce0c6 */
    use std::str::FromStr;

    // assert_eq!(
    //     ExpanderXmd::expand([]),
    //     hex::decode("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
    // );

    let dst = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

    let defhasher: FixedFieldHasher<Sha256> =
        <FixedFieldHasher<Sha256> as HashToField<secp256k1::fq::Fq>>::new(dst);
    let u: [secp256k1::fq::Fq; 2] = defhasher.hash_to_field::<2>(&[]);
    println!("{}", u[0]);
    assert_eq!(
        u[0],
        secp256k1::fq::Fq::new(
            BigInt::from_str(
                "48425033926223359121679389614872723077618800904285921194876400224709273202611"
            )
            .unwrap()
        ),
    );

    assert_eq!(
        ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher::<
            ark_ec::short_weierstrass::Projective<secp256k1::Config>,
            FixedFieldHasher<Sha256>,
            ark_ec::hashing::curve_maps::wb::WBMap<secp256k1::Config>,
        >::new(dst)
        .unwrap()
        .hash(&[])
        .unwrap(),
        secp256k1::Affine::new(
            secp256k1::fq::Fq::new(
                BigInt::from_str(
                    "87654846584422849836571930156466438379984710599888121545025567473301233275718"
                )
                .unwrap()
            ),
            secp256k1::fq::Fq::new(
                BigInt::from_str(
                    "45673711333516174500892987253036094404176536844955599116957274814081860440167"
                )
                .unwrap()
            ),
        )
    );
}
