//! Will this add module JSdoc?
// TODO add interop testing for JSON
// TODO should I do examples rustdoc style or javadoc?
/* 
I want to have a look at good and *small* example for...
* JS tests and CI
* documenting
* setters/getters/exporting, general tricks, API, constructors */

mod utils; // TODO I guess this one isn't panicing,

// use std::convert::{TryFrom, TryInto};

use k256::pkcs8::DecodePrivateKey;
use k256::SecretKey;
use plume_rustcrypto::AffinePoint;
use wasm_bindgen::prelude::*;

use elliptic_curve::sec1::FromEncodedPoint;
use zeroize::Zeroize;
use elliptic_curve::rand_core::SeedableRng;
use elliptic_curve::sec1::ToEncodedPoint;
use signature::RandomizedSigner;

use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignature - Wrapper around [`plume_rustcrypto::PlumeSignature`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignature.html).
/// [`plume_rustcrypto::AffinePoint`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.AffinePoint.html) is represented as a `Uint8Array` containing SEC1 encoded point.
/// [`plume_rustcrypto::NonZeroScalar`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/type.NonZeroScalar.html) is represented as a `BigInt`.
/// `Option` can be `undefined` or instance of [`PlumeSignatureV1Fields`].
pub struct PlumeSignature {
    pub message: Vec<u8>,
    pub pk: Vec<u8>, // TODO protect with public `web_sys::CryptoKey`
    pub nullifier: Vec<u8>,
    pub c: web_sys::CryptoKey,
    pub s: js_sys::BigInt, // it's overprotected in the crate, no need for `CryptoKey` here
    pub v1specific: Option<PlumeSignatureV1Fields>,
}

#[wasm_bindgen(getter_with_clone)]
/// @typedef {Object} PlumeSignatureV1Fields - Wrapper around [`plume_rustcrypto::PlumeSignatureV1Fields`](https://docs.rs/plume_rustcrypto/latest/plume_rustcrypto/struct.PlumeSignatureV1Fields.html).
#[derive(Clone)]
pub struct PlumeSignatureV1Fields {
    pub r_point: Vec<u8>,
    pub hashed_to_curve_r: Vec<u8>,
}
#[wasm_bindgen()]
impl PlumeSignatureV1Fields {
    #[wasm_bindgen(constructor)]
    pub fn new(r_point: Vec<u8>, hashed_to_curve_r: Vec<u8>) -> PlumeSignatureV1Fields {
        PlumeSignatureV1Fields { r_point, hashed_to_curve_r }
    }
}

#[wasm_bindgen]
impl PlumeSignature {
    // #[wasm_bindgen(setter)]
    // pub fn set_message(&mut self, field: Vec<u8>) {
    //     self.message = field;
    // }
    
    /// `v1specific` discriminates if it's V1 or V2 scheme used. Pls, see wrapped docs for details.
    #[wasm_bindgen(constructor)]
    pub fn new(
        message: Vec<u8>,
        pk: Vec<u8>,
        nullifier: Vec<u8>,
        c: web_sys::CryptoKey,
        s: js_sys::BigInt,
        v1specific: Option<PlumeSignatureV1Fields>
    ) -> PlumeSignature {
        PlumeSignature {
            /* I really wonder how good is this pattern. But taking so much of args isn't good, and builder pattern seems redundant as all 
            of the fields are required, and setters are just assignments. */
            // TODO solve/test v1 field: start with adding its constructor
            message, pk, nullifier, c, s, 
            v1specific//: if v1specific.is_falsy() {None} else {Some(v1specific)}
        }

        // js_sys::Object::from_entries(&values)?
        // values.get
    }
}

#[wasm_bindgen(skip_jsdoc)]
/// @throws a "crypto error" in case of a problem with the secret key
/// @param {boolean} v1 - is the flag to choose between V1 and V2 output.
/// @param {Uint8Array} sk - must be exactly 32 bytes, and strictly represent a non-zero scalar of `secp256` in big-endian.
/// @param {Uint8Array} msg
/// @returns {PlumeSignature}
// Wasm environment doesn't have a suitable way to get randomness for the signing process, so this instantiates ChaCha20 RNG with the provided seed.
// @throws a "crypto error" in case of a problem with the secret key, and a verbal error on a problem with `seed`
// @param {Uint8Array} seed - must be exactly 32 bytes.
// pub fn sign(seed: &mut [u8], v1: bool, sk: &mut [u8], msg: &[u8]) -> Result<PlumeSignature, JsError> {
pub async fn sign(v1: bool, sk: web_sys::CryptoKey, msg: &[u8]) -> Result<PlumeSignature, JsError> {
    if sk.type_() != "secret" {return Err(JsError::new("`sk` must be secret key"))}
    if !js_sys::Object::values(&sk.algorithm().map_err(
        |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
    )?).includes(&JsValue::from_str("P-256"), 0) {return Err(JsError::new("`sk` must be from `secp256`"))}
    
    // this was my approach, but seems I got what they did at <https://github.com/rust-random/getrandom/blob/master/src/js.rs>
    // js_sys::global().entries().find(); // TODO throw if no Crypto in global

    let global_the: Global = js_sys::global().unchecked_into(); // is it not `dyn_into` here for speed? https://github.com/rust-random/getrandom/commit/120a1d7f4796356a1f60cd84bd7a0ceafbac9d0e#commitcomment-143690574
    let crypto_the: web_sys::Crypto = global_the.crypto();
    let subtle_the = crypto_the.subtle();
    // let sk = JsFuture::from(subtle_the.export_key("pkcs8", &sk)?).await?;

    let mut sk_z = 
        // plume_rustcrypto::SecretKey
            // ::from(plume_rustcrypto::NonZeroScalar::try_from(sk.as_ref())?);
            // ::from_pkcs8_der(js_sys::ArrayBuffer::from(sk).try_into()?)?;
        zeroize::Zeroizing::new(js_sys::Uint8Array::from(JsFuture::from(subtle_the.export_key("pkcs8", &sk).map_err(
            |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
        )?).await.map_err(
            |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
        )?).to_vec());
    let sk = plume_rustcrypto::SecretKey::from_pkcs8_der(sk_z.as_ref())?;
    sk_z.zeroize();
    let signer = plume_rustcrypto::randomizedsigner::PlumeSigner::new(&sk, v1);
    // let seed_z: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(seed.try_into()?);
    // // TODO protect `seed` with ~~zeroization~~ and so on
    // seed.zeroize();

    // TODO switch to `wasi-random` when that will be ready for crypto
    // let sig = match v1 {
    //     true => plume_rustcrypto::PlumeSignature::sign_v1(
    //         &sk_z, msg, &mut rand_chacha::ChaCha20Rng::from_seed(seed_z)
    //     ),
    //     false => plume_rustcrypto::PlumeSignature::sign_v2(
    //         &sk_z, msg, &mut rand_chacha::ChaCha20Rng::from_seed(seed_z)
    //     ),
    // };

    /* current implementation does bad job protecting few parts meant to be private, see <https://github.com/plume-sig/zk-nullifier-sig/issues/113>
    I feel it doesn't make sense to try mitigating that in the wrapper, but just to update this when the issue is solved */
    let sig_the = signer.sign_with_rng(
        // &mut rand_chacha::ChaCha20Rng::from_seed(*seed_z), 
        &mut rand::rngs::OsRng,
        msg
    );
    // I had the trait for this, but due to `async` it seems more natural to just move that code here.
    // impl From <plume_rustcrypto::PlumeSignature> for PlumeSignature {
        // fn from(value: plume_rustcrypto::PlumeSignature) -> Self {
            let nonzeroscalartobigint = |v: plume_rustcrypto::NonZeroScalar| -> js_sys::BigInt {
                js_sys::BigInt::new(&JsValue::from_str(("0x".to_owned() + v.to_string().as_str()).as_str())).expect("`BigInt` always can be created from hex string, and `v.to_string()` always produce that")
            };
            
            Ok(PlumeSignature {
                message: msg.to_vec(),
                pk: sig_the.pk.to_encoded_point(true).as_bytes().to_vec(),
                nullifier: sig_the.nullifier.to_encoded_point(true).as_bytes().to_vec(),
                c: JsFuture::from(subtle_the.import_key_with_object(
                    "pkcs8",
                    js_sys::Uint8Array::from(SecretKey::from(sig_the.c).to_sec1_der()?.as_ref()).as_ref(),
                    web_sys::EcKeyImportParams::new("ECDSA").named_curve("P-256"),
                    true,
                    js_sys::Array::new().as_ref(), // I can't see a valid usage for this among <https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#keyusages>
                ).map_err(
                    |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
                )?).await.map_err(
                    |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
                )?.dyn_into().map_err(
                    |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
                )?,
                s: nonzeroscalartobigint(sig_the.s),
                v1specific: if let Some(v1) = sig_the.v1specific {Some(
                    PlumeSignatureV1Fields {
                        r_point: v1.r_point.to_encoded_point(true).as_bytes().to_vec(),
                        hashed_to_curve_r: v1.hashed_to_curve_r.to_encoded_point(true).as_bytes().to_vec(),
                    }
                )} else {None},
            })
        // }
    // }
    
    // let debugging = signer.sign_with_rng(
    //     &mut rand_chacha::ChaCha20Rng::from_seed(*seed_z), msg
    // );
    // js_sys::BigInt::new(&JsValue::from_str(("0x".to_owned() + debugging.c.to_string().as_str()).as_str())).expect("`BigInt` always can be created from decimal string, and `c.to_string()` always produce that");
    // // Err(JsError::new(debugging.c.to_string().as_str()))
    // Ok(
    //     PlumeSignature{ message: Default::default(), pk: Default::default(), nullifier: Default::default(), c: Default::default(), s: Default::default(), v1specific: Default::default() }
    // )
}
#[wasm_bindgen]
extern "C" {
    // Return type of js_sys::global()
    type Global;
    // // Web Crypto API: Crypto interface (https://www.w3.org/TR/WebCryptoAPI/)
    // type WebCrypto;
    // Getters for the WebCrypto API
    #[wasm_bindgen(method, getter)]
    fn crypto(this: &Global) -> web_sys::Crypto;
}

// this was a `PlumeSignature` method, but thanks to `async` it been moved to standalone
/// @deprecated Use this only for testing purposes.
/// @throws a error if the data in the object doesn't let it to properly run verification; message contains nature of the problem and indicates relevant property of the object. In case of other (crypto) problems returns `false`.
#[wasm_bindgen]
pub async fn verify(self_: PlumeSignature) -> Result<bool, JsError> {
    // #async #traits
    // impl TryInto<plume_rustcrypto::PlumeSignature> for PlumeSignature {
    //     type Error = JsError;
    
    //     fn try_into(self) -> Result<plume_rustcrypto::PlumeSignature, Self::Error> {
            // if let Some(v1) = self.v1specific {Some(
            //     plume_rustcrypto::PlumeSignatureV1Fields{
            //         r_point: v1.r_point.try_into()?,
            //         hashed_to_curve_r: v1.hashed_to_curve_r.try_into()?,
            //     }
            // )}
    
            // let mut points = [self.pk, self.nullifier]; //, self.v1specific);
            // if Some(points_v1) = self.v1specific {po}
    
            let point_check = |/* name_field: &str, */ point_bytes: Vec<u8>| -> Result<AffinePoint, anyhow::Error> {
                let point_encoded = sec1::point::EncodedPoint::from_bytes(point_bytes)?; // TODO improve formatting (quotes e.g.)
                let result = plume_rustcrypto::AffinePoint::from_encoded_point(&point_encoded);
                if result.is_none().into() {Err(anyhow::Error::msg("the point isn't on the curve"))} 
                else {Ok(result.expect(EXPECT_NONEALREADYCHECKED))}
            };
    
            // plume_rustcrypto::Scalar::try_from(self.c.to_string(16)?.as_string()?);
            // k256::Scalar::from_repr(hex::decode(self.c.to_string(16)?.as_ref())?); // TODO test endianness here and correctness
            let scalar_from_bigint = 
                |/* name_field: &str, */ n: js_sys::BigInt| -> Result<plume_rustcrypto::NonZeroScalar, anyhow::Error> {
                    let result = plume_rustcrypto::NonZeroScalar::from_repr(k256::FieldBytes::from_slice(
                        hex::decode({
                            let hexstring_freelen = n.to_string(16).map_err(
                                |er| 
                                    anyhow::Error::msg(er.as_string().expect("`RangeError` can be printed out"))
                            )?.as_string().expect("on `JsString` this always produce a `String`");
                            let l = hexstring_freelen.len();
                            if l > 32*2 {return Err(anyhow::Error::msg("too many digits"))}
                            else {["0".repeat(64-l), hexstring_freelen].concat()}
                        })?.as_slice()
                    ).to_owned());
                    if result.is_none().into() {Err(anyhow::Error::msg("isn't valid `secp256` non-zero scalar"))} 
                    else {Ok(result.expect(EXPECT_NONEALREADYCHECKED))}
                };
            const EXPECT_NONEALREADYCHECKED: &'static str = "`None` is processed the line above";
    
            let err_field_wrap = |name_field: &str, er: anyhow::Error| -> JsError {JsError::new(
                ("while proccessing ".to_owned() + name_field + " :" + er.to_string().as_str()).as_str()
                /* "while proccessing ".to_owned().join(),
                name_field,
                " :",
                er.to_string().as_str()
            ].concat()) */)};
    
            // zeroization protection ommitted here due to deprecation // <https://github.com/plume-sig/zk-nullifier-sig/issues/112>
            // mostly boilerplate from signing; also some excessive ops left for the same reason
            // TODO align error-handling in this part
            if self_.c.type_() != "secret" {return Err(JsError::new("`c` must be secret key"))}
            if !js_sys::Object::values(&self_.c.algorithm().map_err(
                |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
            )?).includes(&JsValue::from_str("P-256"), 0) {return Err(JsError::new("`c` must be from `secp256`"))}
            //  TODO finish
            // this was my approach, but seems I got what they did at <https://github.com/rust-random/getrandom/blob/master/src/js.rs>
            // js_sys::global().entries().find(); // TODO throw if no Crypto in global
            let global_the: Global = js_sys::global().unchecked_into();
            let crypto_the: web_sys::Crypto = global_the.crypto();
            let subtle_the = crypto_the.subtle();
            let c_pkcs = //zeroize::Zeroizing::new(
                js_sys::Uint8Array::from(JsFuture::from(subtle_the.export_key("pkcs8", &self_.c).map_err(
                    |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
                )?).await.map_err(
                    |er| JsError::new(er.as_string().expect("TODO check how this is failing").as_str())
                )?).to_vec();
            // );
            let c_scalar = &plume_rustcrypto::SecretKey::from_pkcs8_der(&c_pkcs)?.to_nonzero_scalar();
            // sk_z.zeroize();
    
            Ok(plume_rustcrypto::PlumeSignature{
                message: self_.message,
                pk: point_check(self_.pk).map_err(|er| err_field_wrap("`pk`", er))?,
                // plume_rustcrypto::AffinePoint::try_from(self.pk)?, //.try_into<[u8; 33]>()?.into(),
                nullifier: point_check(self_.nullifier).map_err(|er| err_field_wrap("`nullifier`", er))?,
                c: *c_scalar,
                s: scalar_from_bigint(self_.s).map_err(|er| err_field_wrap("`s`", er))?,
                v1specific: if let Some(v1) = self_.v1specific {Some(
                    plume_rustcrypto::PlumeSignatureV1Fields{
                        r_point: point_check(v1.r_point).map_err(|er| err_field_wrap("`r_point`", er))?,
                        hashed_to_curve_r: point_check(v1.hashed_to_curve_r).map_err(|er| err_field_wrap("`hashed_to_curve_r`", er))?,
                    }
                )} else {None},
            }.verify())
        // }
    // }
}