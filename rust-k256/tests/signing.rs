use k256::{elliptic_curve::PrimeField, Scalar};
use plume_rustcrypto::{PlumeSignature, SecretKey};
use rand_core::CryptoRng;
use serde::Deserialize;
use signature::RandomizedSigner;
use std::convert::TryInto;

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
    v1: SignatureVector,
    v2: SignatureVector,
}

#[derive(Deserialize)]
struct SignatureVector {
    c: String,
    s: String,
}

fn shared_vectors() -> Vec<TestVector> {
    serde_json::from_str::<SharedVectors>(include_str!(
        "../../test-vectors/plume-signatures.json"
    ))
    .unwrap()
    .vectors
}

fn hex_32(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

struct Mock {
    nonce: [u8; 32],
}
impl rand_core::RngCore for Mock {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert_eq!(dest.len(), self.nonce.len());
        dest.copy_from_slice(&self.nonce);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unimplemented!()
    }
}
impl CryptoRng for Mock {}

// values for both test are from `plume_arkworks`

#[test]
pub fn test_sign_v1() {
    for vector in shared_vectors() {
        let sk = SecretKey::from_bytes(&hex_32(&vector.secret_key).into()).unwrap();

        let sig = PlumeSignature::sign_v1(
            &sk,
            vector.message.as_bytes(),
            &mut Mock {
                nonce: hex_32(&vector.nonce),
            },
        );
        assert_eq!(
            Scalar::from_repr(hex_32(&vector.expected.v1.c).into()).unwrap(),
            *sig.c
        );
        assert_eq!(
            Scalar::from_repr(hex_32(&vector.expected.v1.s).into()).unwrap(),
            *sig.s
        );
    }
}

#[test]
pub fn test_sign_v2() {
    for vector in shared_vectors() {
        let sk = SecretKey::from_bytes(&hex_32(&vector.secret_key).into()).unwrap();

        let sig = PlumeSignature::sign_v2(
            &sk,
            vector.message.as_bytes(),
            &mut Mock {
                nonce: hex_32(&vector.nonce),
            },
        );
        assert_eq!(
            Scalar::from_repr(hex_32(&vector.expected.v2.c).into()).unwrap(),
            *sig.c
        );
        assert_eq!(
            Scalar::from_repr(hex_32(&vector.expected.v2.s).into()).unwrap(),
            *sig.s
        );
    }
}
