use digest::generic_array::GenericArray;
use elliptic_curve::group::GroupEncoding;
use k256::ProjectivePoint;
use rand::{rngs::StdRng, SeedableRng};
use rand_core::OsRng;
use wasm_bindgen::prelude::wasm_bindgen;
// requires 'getrandom' feature
use wasm_bindgen::JsValue;

use crate::{
    serialize::{byte_array_to_scalar, encode_pt},
    utils::set_panic_hook,
};

// TODO: Probaly have to use a "serde_as" annotation here to serialize the ProjectivePoint as a byte array
// https://github.com/RustCrypto/elliptic-curves/issues/393
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct NullifierSignature(pub(crate) crate::nullifier::NullifierSignature);

// const fields are not yet supported in wasm-bindgen, so placing them outside of the struct
const PPOINT_LEN: usize = 33;
const SCALAR_LEN: usize = 32;

#[wasm_bindgen]
impl NullifierSignature {
    #[wasm_bindgen(getter, js_name = "publicKey")]
    pub fn public_key(&self) -> Vec<u8> {
        encode_pt(self.0.pk)
    }

    #[wasm_bindgen(getter, js_name = "nullifier")]
    pub fn nullifier(&self) -> Vec<u8> {
        encode_pt(self.0.nullifier)
    }

    #[wasm_bindgen(getter, js_name = "c")]
    pub fn c(&self) -> Vec<u8> {
        self.0.c.to_bytes().to_vec()
    }

    #[wasm_bindgen(getter, js_name = "r_sk_c")]
    pub fn r_sk_c(&self) -> Vec<u8> {
        self.0.r_sk_c.to_bytes().to_vec()
    }

    #[wasm_bindgen(getter, js_name = "g_r")]
    pub fn g_r(&self) -> Vec<u8> {
        encode_pt(self.0.g_r)
    }

    #[wasm_bindgen(getter, js_name = "hash_m_pk_pow_r")]
    pub fn hash_m_pk_pow_r(&self) -> Vec<u8> {
        encode_pt(self.0.hash_m_pk_pow_r)
    }

    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.public_key().as_slice());
        bytes.extend_from_slice(self.nullifier().as_slice());
        bytes.extend_from_slice(self.c().as_slice());
        bytes.extend_from_slice(self.r_sk_c().as_slice());
        bytes.extend_from_slice(self.g_r().as_slice());
        bytes.extend_from_slice(self.hash_m_pk_pow_r().as_slice());
        bytes
    }

    #[wasm_bindgen(js_name = "serializedLength")]
    pub fn serialized_len() -> usize {
        PPOINT_LEN * 4 + SCALAR_LEN * 2
    }

    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<NullifierSignature, JsValue> {
        set_panic_hook();

        if bytes.len() != Self::serialized_len() {
            panic!("Invalid length for NullifierSignature");
        }

        let pk_last_idx = PPOINT_LEN;
        let pk =
            ProjectivePoint::from_bytes(GenericArray::from_slice(&bytes[0..pk_last_idx])).unwrap();

        let nullifier_last_idx = pk_last_idx + PPOINT_LEN;
        let nullifier = ProjectivePoint::from_bytes(GenericArray::from_slice(
            &bytes[pk_last_idx..nullifier_last_idx],
        ))
        .unwrap();

        let c_last_idx = nullifier_last_idx + SCALAR_LEN;
        let c = byte_array_to_scalar(&bytes[nullifier_last_idx..c_last_idx]);

        let r_sk_c_last_idx = c_last_idx + SCALAR_LEN;
        let r_sk_c = byte_array_to_scalar(&bytes[c_last_idx..r_sk_c_last_idx]);

        let g_r_last_idx = r_sk_c_last_idx + PPOINT_LEN;
        let g_r = ProjectivePoint::from_bytes(GenericArray::from_slice(
            &bytes[r_sk_c_last_idx..g_r_last_idx],
        ))
        .unwrap();

        let hash_m_pk_pow_r =
            ProjectivePoint::from_bytes(GenericArray::from_slice(&bytes[g_r_last_idx..])).unwrap();

        Ok(NullifierSignature(crate::nullifier::NullifierSignature {
            pk,
            nullifier,
            c,
            r_sk_c,
            g_r,
            hash_m_pk_pow_r,
        }))
    }
}

#[wasm_bindgen]
impl NullifierSignature {
    #[wasm_bindgen]
    pub fn new(sk: &[u8], message: &str, rng_seed: Option<Box<[u8]>>) -> Self {
        set_panic_hook();

        if sk.len() != 32 {
            panic!("Invalid secret key length");
        }

        let mut rng = match rng_seed {
            Some(seed) => {
                let seed: [u8; 32] = seed.as_ref().try_into().unwrap();

                StdRng::from_seed(seed)
            }
            None => StdRng::from_rng(OsRng).unwrap(),
        };
        let sk = byte_array_to_scalar(sk);

        let nullifier_signature =
            crate::nullifier::NullifierSignature::new(&sk, message.as_bytes(), &mut rng);

        Self(nullifier_signature)
    }
}

#[cfg(test)]
mod wasm_test {
    use elliptic_curve::Field;
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    fn serializes_and_deserializes_nullifier() {
        let rng = rand::thread_rng();
        let sk = k256::Scalar::random(rng).to_bytes().to_vec();
        let message = "Hello, world!".to_string();

        let sig = super::NullifierSignature::new(&sk, &message, None);
        let bytes = sig.to_bytes();
        let sig2 = super::NullifierSignature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.to_bytes(), sig2.to_bytes());
    }
}
