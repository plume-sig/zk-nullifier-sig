//! The suite consists of two tests; one for each type of signature. One of them also do printings of the values,
//! which can be useful to you when comparing different implementations.
//! Their setup is shared, `mod helpers` contains barely not refactored code, which is still instrumental to the tests.

use helpers::{gen_test_scalar_sk, test_gen_signals, PlumeVersion};
use k256::{elliptic_curve::sec1::ToEncodedPoint, NonZeroScalar};
use plume_rustcrypto::{PlumeSignature, PlumeSignatureV1Fields, ProjectivePoint};

const G: ProjectivePoint = ProjectivePoint::GENERATOR;
const M: &[u8; 29] = b"An example app message string";
const C_V1: [u8; 32] =
    hex_literal::hex!("c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254");

// `test_gen_signals` provides fixed key nullifier, secret key, and the random value for testing
// Normally a secure enclave would generate these values, and output to a wallet implementation

// `gen_test_scalar_sk()` provides the signer's secret key. It is only accessed within the secure enclave.

// The user's public key goes to the `pk` field as $g^sk$.

// Both tests finish with the signals verification, normally this would happen in ZK with only the nullifier public, which would have a zk verifier instead
// The wallet should probably run this prior to snarkify-ing as a sanity check
// `M` and nullifier should be public, so we can verify that they are correct

#[test]
fn plume_v1_test() {
    let test_data = test_gen_signals(M, PlumeVersion::V1);
    let r_point = test_data.4.unwrap();
    let hashed_to_curve_r = test_data.5.unwrap();

    println!("{:?}", test_data.3);
    println!("{}", NonZeroScalar::new(test_data.3).unwrap().to_string());

    let sig = PlumeSignature {
        message: M.to_owned().into(),
        pk: G * gen_test_scalar_sk(),
        nullifier: test_data.1,
        c: NonZeroScalar::from_repr(C_V1.into()).unwrap(),
        s: NonZeroScalar::new(test_data.3).unwrap(),
        v1specific: Some(PlumeSignatureV1Fields {
            r_point,
            hashed_to_curve_r,
        }),
    };
    let verified = sig.verify();
    println!("Verified: {}", verified);

    // Print nullifier
    println!(
        "nullifier.x: {:?}",
        hex::encode(
            sig.nullifier
                .to_affine()
                .to_encoded_point(false)
                .x()
                .unwrap()
        )
    );
    println!(
        "nullifier.y: {:?}",
        hex::encode(
            sig.nullifier
                .to_affine()
                .to_encoded_point(false)
                .y()
                .unwrap()
        )
    );
    // Print c
    println!("c: {:?}", hex::encode(C_V1));
    // Print r_sk_c
    println!("r_sk_c: {:?}", hex::encode(sig.s.to_bytes()));
    // Print g_r
    println!(
        "g_r.x: {:?}",
        hex::encode(r_point.to_affine().to_encoded_point(false).x().unwrap())
    );
    println!(
        "g_r.y: {:?}",
        hex::encode(r_point.to_affine().to_encoded_point(false).y().unwrap())
    );
    // Print hash_m_pk_pow_r
    println!(
        "hash_m_pk_pow_r.x: {:?}",
        hex::encode(
            hashed_to_curve_r
                .to_affine()
                .to_encoded_point(false)
                .x()
                .unwrap()
        )
    );
    println!(
        "hash_m_pk_pow_r.y: {:?}",
        hex::encode(
            hashed_to_curve_r
                .to_affine()
                .to_encoded_point(false)
                .y()
                .unwrap()
        )
    );

    assert!(verified);
}

#[test]
fn plume_v2_test() {
    let test_data = test_gen_signals(M, PlumeVersion::V2);
    assert!(PlumeSignature {
        message: M.to_owned().into(),
        pk: G * gen_test_scalar_sk(),
        nullifier: test_data.1,
        c: NonZeroScalar::from_repr(test_data.2).unwrap(),
        s: NonZeroScalar::new(test_data.3).unwrap(),
        v1specific: None
    }
    .verify());
}

mod helpers {
    /* Feels like this one could/should be replaced with static/constant values. Preserved for historical reasons.
    For the same reasons calls for internal `fn` are commented and replaced by "one-liners" adapted from current implementation. */
    use super::*;
    use hex_literal::hex;
    use k256::{
        elliptic_curve::{
            bigint::ArrayEncoding,
            hash2curve::{ExpandMsgXmd, GroupDigest},
            ops::ReduceNonZero,
            PrimeField,
        },
        sha2::{digest::Output, Digest, Sha256},
        Scalar, Secp256k1, U256,
    };

    #[derive(Debug)]
    pub enum PlumeVersion {
        V1,
        V2,
    }

    // Generates a deterministic secret key for deterministic testing. Should be replaced by random oracle in production deployments.
    pub fn gen_test_scalar_sk() -> Scalar {
        Scalar::from_repr(
            hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464").into(),
        )
        .unwrap()
    }

    // Generates a deterministic r for deterministic testing. Should be replaced by random oracle in production deployments.
    fn gen_test_scalar_r() -> Scalar {
        Scalar::from_repr(
            hex!("93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808").into(),
        )
        .unwrap()
    }

    // Calls the hash to curve function for secp256k1, and returns the result as a ProjectivePoint
    pub fn hash_to_secp(s: &[u8]) -> ProjectivePoint {
        let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
            &[s],
            //b"CURVE_XMD:SHA-256_SSWU_RO_"
            &[plume_rustcrypto::DST],
        )
        .unwrap();
        pt
    }

    // These generate test signals as if it were passed from a secure enclave to wallet. Note that leaking these signals would leak pk, but not sk.
    // Outputs these 6 signals, in this order
    // g^sk																(private)
    // hash[m, pk]^sk 													public nullifier
    // c = hash2(g, pk, hash[m, pk], hash[m, pk]^sk, gr, hash[m, pk]^r)	(public or private)
    // r + sk * c														(public or private)
    // g^r																(private, optional)
    // hash[m, pk]^r													(private, optional)
    pub fn test_gen_signals(
        m: &[u8],
        version: PlumeVersion,
    ) -> (
        ProjectivePoint,
        ProjectivePoint,
        Output<Sha256>,
        Scalar,
        Option<ProjectivePoint>,
        Option<ProjectivePoint>,
    ) {
        // The base point or generator of the curve.
        let g = ProjectivePoint::GENERATOR;

        // The signer's secret key. It is only accessed within the secure enclave.
        let sk = gen_test_scalar_sk();

        // A random value r. It is only accessed within the secure enclave.
        let r = gen_test_scalar_r();

        // The user's public key: g^sk.
        let pk = &g * &sk;

        // The generator exponentiated by r: g^r.
        let g_r = &g * &r;

        // hash[m, pk]
        let hash_m_pk =
            // zk_nullifier::hash_to_curve(m, &pk)
            Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
                &[[
                    m,
                    // &encode_pt(pk)
                    &pk.to_encoded_point(true).to_bytes().to_vec()
                ].concat().as_slice()],
                //b"CURVE_XMD:SHA-256_SSWU_RO_",
                &[plume_rustcrypto::DST],
            )
            .unwrap();

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
        let c = match version {
            PlumeVersion::V1 => Sha256::digest(
                vec![&g, &pk, &hash_m_pk, &nullifier, &g_r, &hash_m_pk_pow_r]
                    .into_iter()
                    .map(|x| x.to_encoded_point(true).to_bytes().to_vec())
                    .collect::<Vec<_>>()
                    .concat()
                    .as_slice(),
            ),
            PlumeVersion::V2 => {
                dbg!("entering `Sha256::digest` for `V2`");
                let result = Sha256::digest(
                    vec![&nullifier, &g_r, &hash_m_pk_pow_r]
                        .into_iter()
                        .map(|x| x.to_encoded_point(true).to_bytes().to_vec())
                        .collect::<Vec<_>>()
                        .concat()
                        .as_slice(),
                );
                dbg!("finished `Sha256::digest` for `V2`");
                result
            }
        };
        dbg!(&c, version);

        let c_scalar = Scalar::from_repr(c).unwrap();
        // This value is part of the discrete log equivalence (DLEQ) proof.
        let r_sk_c = r + sk * c_scalar;

        // Return the signature.
        (pk, nullifier, c, r_sk_c, Some(g_r), Some(hash_m_pk_pow_r))
    }

    /* Yes, testing the tests isn't a conventional things.
    This should be straightened if `helpers` will be refactored. */
    #[cfg(test)]
    mod tests {
        use super::*;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        // Test the hash-to-curve algorithm
        #[test]
        fn test_hash_to_curve() {
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
    }
}
