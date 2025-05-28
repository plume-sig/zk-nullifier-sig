//! sadly `wasm-bindgen` doesn't support top-level @module docs yet

use wasm_bindgen::prelude::*;

#[cfg(feature = "verify")]
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ToEncodedPoint;
use signature::RandomizedSigner;
use std::convert::TryInto;
use zeroize::Zeroize;

const MSG_EXPECT: &str = "`k256` restricts this type to proper keys, so it's serialized representation shouldn't have a chance to fail";

#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignature - This was the wrapper around [`plume_rustcrypto::PlumeSignature`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignature.html)
/// . Now it's separated into the public values available as an object for further manipulation, and secret values capable of `zeroize` and available via getters.
pub struct PlumeSignature {
    /// @type PlumeSignaturePublic 
    pub instance: js_sys::Object, 
    pub witness: PlumeSignaturePrivate
}
#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignaturePublic - Public part of [`plume_rustcrypto::PlumeSignature`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignature.html).
#[derive(serde::Serialize)]
pub struct PlumeSignaturePublic {
    pub message: Vec<u8>,
    /// [`plume_rustcrypto::AffinePoint`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.AffinePoint.html) 
    /// is represented as an `Uint8Array` containing SEC1 encoded point.
    pub nullifier: Vec<u8>,
    /// [`plume_rustcrypto::NonZeroScalar`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/type.NonZeroScalar.html) 
    /// is represented as an `Uint8Array` containing SEC1 DER secret key.
    pub s: Vec<u8>,
    /// The optional property to help distinguish the used variant.
    pub is_v1: Option<bool>
}
#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignaturePrivate - Private part of [`plume_rustcrypto::PlumeSignature`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignature.html).
/// [`plume_rustcrypto::AffinePoint`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.AffinePoint.html) is represented as an `Uint8Array` containing SEC1 encoded point.
/// 
/// `digest_private` was named `c` in those docs.
// no `message_bytes` here since it's not available as an object
#[derive(Clone)]
pub struct PlumeSignaturePrivate {
    pub pk: Vec<u8>,
    /// [`plume_rustcrypto::NonZeroScalar`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/type.NonZeroScalar.html) 
    /// is represented as an `Uint8Array` containing SEC1 DER secret key.
    pub digest_private: Vec<u8>,
    pub v1specific: Option<PlumeSignatureV1Fields>,
}

#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignatureV1Fields - Wrapper around 
/// [`plume_rustcrypto::PlumeSignatureV1Fields`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignatureV1Fields.html).
#[derive(Clone)]
pub struct PlumeSignatureV1Fields {
    pub r_point: Vec<u8>,
    pub hashed_to_curve_r: Vec<u8>,
}

#[wasm_bindgen]
impl PlumeSignature/* Private */ {
    #[wasm_bindgen]
    /// Zeroize the witness values from the Wasm memory.
    pub fn zeroize(&mut self) {
        self.witness.digest_private.zeroize();
        self.witness.pk.zeroize();
        if let Some(v1) = self.witness.v1specific.as_mut() {
            v1.hashed_to_curve_r.zeroize();
            v1.r_point.zeroize();
        }
    }
}

#[wasm_bindgen(skip_jsdoc)]
/// @throws a "crypto error" in case of a problem with the secret key
/// @param {boolean} v1 - is the flag to choose between V1 and V2 output.
/// @param {Uint8Array} sk - secret key in SEC1 DER format.
/// @param {Uint8Array} msg
/// @returns {PlumeSignature}
pub fn sign(v1: bool, sk: &mut [u8], msg: &[u8]) -> Result<PlumeSignature, JsError> {
    let sk_z = plume_rustcrypto::SecretKey::from_sec1_der(sk)?;
    sk.zeroize();
    let signer = plume_rustcrypto::randomizedsigner::PlumeSigner::new(&sk_z, v1);

    Ok(signer
    .sign_with_rng(&mut signature::rand_core::OsRng, msg)
    .try_into()?)
}

// the code can be a part of `sign` but historically it was a trait `impl` and that makes no sense to refactor this
impl std::convert::TryFrom<plume_rustcrypto::PlumeSignature> for PlumeSignature {
    type Error = serde_wasm_bindgen::Error;
    fn try_from(value: plume_rustcrypto::PlumeSignature) -> Result<Self, Self::Error> {
        Ok(PlumeSignature {
            instance: serde_wasm_bindgen::to_value(&PlumeSignaturePublic { 
                message: value.message, 
                nullifier: value.nullifier.to_encoded_point(true).as_bytes().to_vec(), 
                s: plume_rustcrypto::SecretKey::from(value.s).to_sec1_der().expect(MSG_EXPECT).to_vec(),
                is_v1: Some(value.v1specific.is_some())
            })?.into(),
            witness: PlumeSignaturePrivate { 
                pk: value.pk.to_encoded_point(true).as_bytes().to_vec(), 
                digest_private: plume_rustcrypto::SecretKey::from(value.c).to_sec1_der().expect(MSG_EXPECT)
                .to_vec(),
                v1specific: value.v1specific.map(|v1| {PlumeSignatureV1Fields {
                    r_point: v1.r_point.to_encoded_point(true).as_bytes().to_vec(),
                    hashed_to_curve_r: v1.hashed_to_curve_r.to_encoded_point(true).as_bytes().to_vec(),
                }}),
            }
        })
    }
}

#[wasm_bindgen(js_name = sec1DerScalarToBigint)]
/// This might leave the values in the memory! Don't use for the private values.
/// JS most native format for a scalar is `BigInt`, but it's not really transportable or secure, so for uniformity of the approach `s` in the public part of `PlumeSignature` is defined similar 
/// to `c`; but if you want to have it as a `BigInt` you can use this utility.
pub fn sec1derscalar_to_bigint(scalar: &[u8]) -> Result<js_sys::BigInt, JsError> {
    Ok(js_sys::BigInt::new(&JsValue::from_str(
        ("0x".to_owned()
            + plume_rustcrypto::SecretKey::from_sec1_der(scalar)?
                .to_nonzero_scalar()
                .to_string()
                .as_str())
        .as_str(),
    ))
    .expect(
        "`BigInt` always can be created from hex string, and `v.to_string()` always produce that",
    ))
}

// TODO deprecate when `verify` gone
#[cfg(feature = "verify")]
impl TryInto<plume_rustcrypto::PlumeSignature> for PlumeSignature {
    type Error = JsError;

    fn try_into(self) -> Result<plume_rustcrypto::PlumeSignature, Self::Error> {
        let point_check = |point_bytes: Vec<u8>| -> Result<AffinePoint, anyhow::Error> {
            let point_encoded = sec1::point::EncodedPoint::from_bytes(point_bytes)?; // TODO improve formatting (quotes e.g.)
            let result = plume_rustcrypto::AffinePoint::from_encoded_point(&point_encoded);
            if result.is_none().into() {
                Err(anyhow::Error::msg("the point isn't on the curve"))
            } else {
                Ok(result.expect("`None` is processed the line above"))
            }
        };

        let err_field_wrap = |name_field: &str, er: anyhow::Error| -> JsError {
            JsError::new(
                ("while proccessing ".to_owned() + name_field + " :" + er.to_string().as_str())
                    .as_str(),
            )
        };

        Ok(plume_rustcrypto::PlumeSignature {
            message: self.message,
            pk: point_check(self.pk).map_err(|er| err_field_wrap("`pk`", er))?,
            // plume_rustcrypto::AffinePoint::try_from(self.pk)?, //.try_into<[u8; 33]>()?.into(),
            nullifier: point_check(self.nullifier)
                .map_err(|er| err_field_wrap("`nullifier`", er))?,
            c: plume_rustcrypto::SecretKey::from_sec1_der(&self.c)?.into(),
            s: plume_rustcrypto::SecretKey::from_sec1_der(&self.s)?.into(), //scalar_from_bigint(self.s).map_err(|er| err_field_wrap("`s`", er))?,
            v1specific: if let Some(v1) = self.v1specific {
                Some(plume_rustcrypto::PlumeSignatureV1Fields {
                    r_point: point_check(v1.r_point)
                        .map_err(|er| err_field_wrap("`r_point`", er))?,
                    hashed_to_curve_r: point_check(v1.hashed_to_curve_r)
                        .map_err(|er| err_field_wrap("`hashed_to_curve_r`", er))?,
                })
            } else {
                None
            },
        })
    }
}
