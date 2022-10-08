use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
use js_sys::Error;


fn compute_h(message: String, sk_hex: String) -> GroupAffine::<Secp256k1Parameters> {
    let sk = hex_to_fr(&sk_hex);
    let g = Affine::prime_subgroup_generator();
    let pk_projective = g.mul(sk);
    let pk = GroupAffine::<Secp256k1Parameters>::from(pk_projective);

    let h = hash_to_curve::<secp256k1::fields::Fq, Secp256k1Parameters>(message.to_bytes(), &pk);
    h
}

fn hex_to_fr(
    hex: &str,
) -> secp256k1::fields::Fr {
    let num_field_bytes = 320;
    let mut sk_bytes_vec = vec![0u8; num_field_bytes];
    let mut sk_bytes = hex::decode(hex).unwrap();

    sk_bytes.reverse();

    for (i, _) in sk_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(&mut sk_bytes_vec[i], sk_bytes[i]);
    }

    secp256k1::fields::Fr::read(sk_bytes_vec.as_slice()).unwrap()
}

fn coord_to_hex(coord: biginteger::BigInteger320) -> String {
    let mut coord_bytes = vec![];
    let _ = coord.write(&mut coord_bytes);
    coord_bytes.reverse();

    String::from(hex::encode(coord_bytes))
}


#[wasm_bindgen]
pub fn make_nullifier(sk_hex: String, message: String) -> String {
    let h = compute_h(&message);
    let sk = hex_to_fr(&sk_hex);

    let h_sk_projective = h.mul(sk);
    let h_sk = GroupAffine::<Secp256k1Parameters>::from(h_sk_projective);
    let h_sk_hex = coord_to_hex(h_sk.x.into());
    h_sk_hex
}