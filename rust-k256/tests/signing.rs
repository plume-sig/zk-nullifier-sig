use k256::{
    elliptic_curve::{point::AffineCoordinates, PrimeField},
    FieldBytes, Scalar,
};
use plume_rustcrypto::{PlumeSignature, SecretKey};
use rand_core::CryptoRng;
use signature::RandomizedSigner;

const message: &[u8; 29] = b"An example app message string";
const R: &[u8] =
    &hex_literal::hex!("93b9323b629f251b8f3fc2dd11f4672c5544e8230d493eceea98a90bda789808");
const SK: [u8; 32] =
    hex_literal::hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464");
const V1_C: [u8; 32] =
    hex_literal::hex!("c6a7fc2c926ddbaf20731a479fb6566f2daa5514baae5223fe3b32edbce83254");
const V1_S: [u8; 32] =
    hex_literal::hex!("e69f027d84cb6fe5f761e333d12e975fb190d163e8ea132d7de0bd6079ba28ca");
const V2_C: [u8; 32] =
    hex_literal::hex!("3dbfb717705010d4f44a70720c95e74b475bd3a783ab0b9e8a6b3b363434eb96");
const V2_S: [u8; 32] =
    hex_literal::hex!("528e8fbb6452f82200797b1a73b2947a92524bd611085a920f1177cb8098136b");

struct Mock {}
impl rand_core::RngCore for Mock {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(dest.len() == R.len());
        assert!(dest.len() == 32);
        dest.iter_mut()
            .enumerate()
            .for_each(|(i, x)| *x = R[/* 31 -  */i]);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        unimplemented!()
    }
}
impl CryptoRng for Mock {}

// values for both test are from `plume_arkworks`

#[test]
pub fn test_sign_v1() {
    let sk = SecretKey::from_bytes(&SK.into()).unwrap();

    let sig = PlumeSignature::sign_v1(&sk, message, &mut Mock {});
    assert_eq!(Scalar::from_repr(V1_C.into()).unwrap(), *sig.c);
    assert_eq!(Scalar::from_repr(V1_S.into()).unwrap(), *sig.s);
}

#[test]
pub fn test_sign_v2() {
    let sk = SecretKey::from_bytes(&SK.into()).unwrap();

    let sig = PlumeSignature::sign_v2(&sk, message, &mut Mock {});
    assert_eq!(Scalar::from_repr(V2_C.into()).unwrap(), *sig.c);
    assert_eq!(Scalar::from_repr(V2_S.into()).unwrap(), *sig.s);
}
