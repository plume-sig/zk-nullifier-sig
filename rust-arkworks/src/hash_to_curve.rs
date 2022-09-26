use crate::error::CryptoError;
use ark_ec::{AffineCurve, ProjectiveCurve};
use tiny_keccak::{Hasher, Shake, Xof};
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::{AffinePoint};
use k256::sha2::Sha256;
use elliptic_curve::sec1::ToEncodedPoint;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use k256::{ProjectivePoint, Secp256k1};
use ark_ff::FromBytes;
use secp256k1::Sec1EncodePoint;

pub fn hash_to_curve<
    Fp: ark_ff::PrimeField,
    P: ark_ec::SWModelParameters,
>(
    msg: &[u8],
    pk: &GroupAffine<P>,
) -> GroupAffine<P> {

    let pk_encoded = pk.to_encoded_point(true);
    let b = hex::decode(pk_encoded).unwrap();
    let x = [msg, b.as_slice()];
    let x = x.concat().clone();
    let x = x.as_slice();

    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[x],
        b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"
    ).unwrap();

    let pt_affine = pt.to_affine();

    k256_affine_to_arkworks_secp256k1_affine::<Fp, P>(pt_affine)
}

pub fn k256_affine_to_arkworks_secp256k1_affine<
    Fp: ark_ff::PrimeField,
    P: ark_ec::SWModelParameters
>(
    k_pt: AffinePoint,
) -> GroupAffine<P> {
    let encoded_pt = k_pt.to_encoded_point(false);

    let num_field_bytes = 320;

    // extract k_pt.x
    let k_pt_x_bytes = encoded_pt.x().unwrap();

    // pad x bytes
    let mut k_pt_x_bytes_vec = vec![0u8; num_field_bytes];
    for (i, _) in k_pt_x_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(&mut k_pt_x_bytes_vec[i], k_pt_x_bytes[k_pt_x_bytes.len() - 1 - i]);
    }
    let reader = std::io::BufReader::new(k_pt_x_bytes_vec.as_slice());
    let g_x = P::BaseField::read(reader).unwrap();

    // extract k_pt.y
    let k_pt_y_bytes = encoded_pt.y().unwrap();

    // pad y bytes
    let mut k_pt_y_bytes_vec = vec![0u8; num_field_bytes];
    for (i, _) in k_pt_y_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(&mut k_pt_y_bytes_vec[i], k_pt_y_bytes[k_pt_y_bytes.len() - 1 - i]);
    }

    let reader = std::io::BufReader::new(k_pt_y_bytes_vec.as_slice());
    let g_y = P::BaseField::read(reader).unwrap();

    GroupAffine::<P>::new(g_x, g_y, false)
}

/// Kobi's hash_to_curve function, here for reference only
pub fn _try_and_increment<C: ProjectiveCurve>(msg: &[u8]) -> Result<C::Affine, CryptoError> {
    for nonce in 0u8..=255 {
        let mut h = Shake::v128();
        h.update(&[nonce]);
        h.update(msg.as_ref());
        let output_size = C::zero().serialized_size();
        let mut output = vec![0u8; output_size];
        h.squeeze(&mut output);

        if let Some(p) = C::Affine::from_random_bytes(&output) {
            return Ok(p);
        }
    }

    Err(CryptoError::CannotHashToCurve)
}
