// #![feature(generic_const_expr)]
// #![allow(incomplete_features)]

use k256::{
    // ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::{hash2curve::{ExpandMsgXmd, GroupDigest}},
    elliptic_curve::sec1::ToEncodedPoint,
    elliptic_curve::{bigint::ArrayEncoding, group::ff::PrimeField},
    elliptic_curve::ops::ReduceNonZero,
    sha2::{digest::Output, Digest, Sha256},
    FieldBytes,
    ProjectivePoint,
    Scalar,
    Secp256k1,
    U256,
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

fn c_sha256_vec_signal(values: Vec<&ProjectivePoint>) -> Output<Sha256> {
    let preimage_vec = values
        .into_iter()
        .map(|value| encode_pt(value).unwrap())
        .collect::<Vec<_>>()
        .concat();
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(preimage_vec.as_slice());
    sha256_hasher.finalize()
}

fn sha256hash6signals(
    g: &ProjectivePoint,
    pk: &ProjectivePoint,
    hash_m_pk: &ProjectivePoint,
    nullifier: &ProjectivePoint,
    g_r: &ProjectivePoint,
    hash_m_pk_pow_r: &ProjectivePoint,
) -> Scalar {
    let g_bytes = encode_pt(g).unwrap();
    let pk_bytes = encode_pt(pk).unwrap();
    let h_bytes = encode_pt(hash_m_pk).unwrap();
    let nul_bytes = encode_pt(nullifier).unwrap();
    let g_r_bytes = encode_pt(g_r).unwrap();
    let z_bytes = encode_pt(hash_m_pk_pow_r).unwrap();

    let c_preimage_vec = [g_bytes, pk_bytes, h_bytes, nul_bytes, g_r_bytes, z_bytes].concat();

    //println!("c_preimage_vec: {:?}", c_preimage_vec);

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(c_preimage_vec.as_slice());
    let sha512_hasher_result = sha256_hasher.finalize(); //512 bit hash

    let c_bytes = FieldBytes::from_iter(sha512_hasher_result.iter().copied());
    Scalar::from_repr(c_bytes).unwrap()
}

// Hashes two values to the curve
fn hash_to_curve(m: &[u8], pk: &ProjectivePoint) -> ProjectivePoint {
    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[[m, &encode_pt(pk).unwrap()].concat().as_slice()],
        //b"CURVE_XMD:SHA-256_SSWU_RO_",
        &[DST],
    )
    .unwrap();
    pt
}

/* currently seems to right place for this `struct` declaration;
should be moved (to the beginning of the file?) during refactoring for proper order of the items */
/* while no consistent #API is present here it's completely `pub`;
when API will be designed it should include this `struct` (and it also probably will hold values instead of references) */
pub struct PlumeSignature<'a> {
    pub message: &'a [u8],
    pub pk: &'a ProjectivePoint,
    pub nullifier: &'a ProjectivePoint,
    pub c: &'a [u8],
    pub s: &'a Scalar,
    pub v1: Option<PlumeSignatureV1Fields<'a>>,
}
pub struct PlumeSignatureV1Fields<'a> {
    pub r_point: &'a ProjectivePoint,
    pub hashed_to_curve_r: &'a ProjectivePoint,
}
impl PlumeSignature<'_> {
    /// WARNING: panics when `self.c` isn't an `Output::<Sha256>`.
    /// So catch it if it's a possible case for you.
    // Verifier check in SNARK:
    // g^[r + sk * c] / (g^sk)^c = g^r
    // hash[m, gsk]^[r + sk * c] / (hash[m, pk]^sk)^c = hash[m, pk]^r
    // c = hash2(g, g^sk, hash[m, g^sk], hash[m, pk]^sk, gr, hash[m, pk]^r)
    pub fn verify_signals(&self) -> bool {
        // don't forget to check `c` is `Output<Sha256>` in the #API
        let c = Output::<Sha256>::from_slice(self.c);
        // TODO should we allow `c` input greater than BaseField::MODULUS?
        let c_scalar = &Scalar::reduce_nonzero(U256::from_be_byte_array(c.clone())); 
        /* @skaunov would be glad to discuss with @Divide-By-0 excessive of the following check.
        Though I should notice that it at least doesn't breaking anything. */
        if c_scalar.is_zero().into() {
            return false;
        }

        let r_point = ProjectivePoint::GENERATOR * self.s - self.pk * &c_scalar;
        let hashed_to_curve = hash_to_curve(self.message, self.pk);
        let hashed_to_curve_r = &hashed_to_curve * self.s - self.nullifier * &c_scalar;

        // Check if the given hash matches
        let result = |components: Vec<&ProjectivePoint>| -> bool {
            if &c_sha256_vec_signal(components) == c {
                true
            } else {
                false
            }
        };

        if let Some(PlumeSignatureV1Fields {
            r_point: sig_r_point,
            hashed_to_curve_r: sig_hashed_to_curve_r,
        }) = self.v1
        {
            // Check whether g^r equals g^s * pk^{-c}
            if &r_point != sig_r_point {
                return false;
            }

            // Check whether h^r equals h^{r + sk * c} * nullifier^{-c}
            if &hashed_to_curve_r != sig_hashed_to_curve_r {
                return false;
            }

            result(vec![
                &ProjectivePoint::GENERATOR,
                self.pk,
                &hashed_to_curve,
                self.nullifier,
                &r_point,
                &hashed_to_curve_r,
            ])
        } else {
            result(vec![self.nullifier, &r_point, &hashed_to_curve_r])
        }
    }
}

/// Encodes the point by compressing it to 33 bytes
fn encode_pt(point: &ProjectivePoint) -> Result<Vec<u8>, Error> {
    let encoded = point.to_encoded_point(true);
    Ok(encoded.to_bytes().to_vec())
}

/// Convert a 32-byte array to a scalar
fn byte_array_to_scalar(bytes: &[u8]) -> Scalar {
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

#[cfg(test)]
mod tests {
    use super::*;

    use helpers::{gen_test_scalar_sk, hash_to_secp, test_gen_signals, PlumeVersion};
    mod helpers {
        use super::*;
        use hex_literal::hex;

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
                &[DST],
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
            let hash_m_pk = hash_to_curve(m, &pk);

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
                PlumeVersion::V1 => c_sha256_vec_signal(vec![
                    &g,
                    &pk,
                    &hash_m_pk,
                    &nullifier,
                    &g_r,
                    &hash_m_pk_pow_r,
                ]),
                PlumeVersion::V2 => c_sha256_vec_signal(vec![&nullifier, &g_r, &hash_m_pk_pow_r]),
            };
            dbg!(&c, version);

            let c_scalar = &Scalar::reduce_nonzero(U256::from_be_byte_array(c.to_owned()));
            // This value is part of the discrete log equivalence (DLEQ) proof.
            let r_sk_c = r + sk * c_scalar;

            // Return the signature.
            (pk, nullifier, c, r_sk_c, Some(g_r), Some(hash_m_pk_pow_r))
        }
    }

    #[test]
    fn plume_v1_test() {
        let g = ProjectivePoint::GENERATOR;

        let m = b"An example app message string";

        // Fixed key nullifier, secret key, and random value for testing
        // Normally a secure enclave would generate these values, and output to a wallet implementation
        let (pk, nullifier, c, r_sk_c, g_r, hash_m_pk_pow_r) =
            test_gen_signals(m, PlumeVersion::V1);

        // The signer's secret key. It is only accessed within the secure enclave.
        let sk = gen_test_scalar_sk();

        // The user's public key: g^sk.
        let pk = &g * &sk;

        // Verify the signals, normally this would happen in ZK with only the nullifier public, which would have a zk verifier instead
        // The wallet should probably run this prior to snarkify-ing as a sanity check
        // m and nullifier should be public, so we can verify that they are correct
        let verified = PlumeSignature {
            message: m,
            pk: &pk,
            nullifier: &nullifier,
            c: &c,
            s: &r_sk_c,
            v1: Some(PlumeSignatureV1Fields {
                r_point: &g_r.unwrap(),
                hashed_to_curve_r: &hash_m_pk_pow_r.unwrap(),
            }),
        }
        .verify_signals();
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
        println!("c: {:?}", hex::encode(&c));

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
        let g_as_bytes = encode_pt(&g).unwrap();
        assert_eq!(
            hex::encode(g_as_bytes),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );

        // Test byte_array_to_scalar()
        let scalar = byte_array_to_scalar(&c); // TODO this `fn` looks suspicious as in reproducing const time ops
        assert_eq!(
            hex::encode(scalar.to_bytes()),
            "c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254"
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
        assert!(verified);
    }

    #[test]
    fn plume_v2_test() {
        let g = ProjectivePoint::GENERATOR;

        let m = b"An example app message string";

        // Fixed key nullifier, secret key, and random value for testing
        // Normally a secure enclave would generate these values, and output to a wallet implementation
        let (pk, nullifier, c, r_sk_c, g_r, hash_m_pk_pow_r) =
            test_gen_signals(m, PlumeVersion::V2);

        // The signer's secret key. It is only accessed within the secu`re enclave.
        let sk = gen_test_scalar_sk();

        // The user's public key: g^sk.
        let pk = &g * &sk;

        // Verify the signals, normally this would happen in ZK with only the nullifier public, which would have a zk verifier instead
        // The wallet should probably run this prior to snarkify-ing as a sanity check
        // m and nullifier should be public, so we can verify that they are correct
        let verified = PlumeSignature {
            message: m,
            pk: &pk,
            nullifier: &nullifier,
            c: &c,
            s: &r_sk_c,
            v1: None,
        }
        .verify_signals();
        assert!(verified)
    }
}
