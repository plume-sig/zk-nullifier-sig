use crate::error::HashToCurveError;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::FromBytes;
use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::sec1::ToEncodedPoint;
// TODO why not ark libs for these? oO
use k256::{sha2::Sha256, AffinePoint, ProjectivePoint, Secp256k1};
use secp256k1::Sec1EncodePoint;
use tiny_keccak::{Hasher, Shake, Xof};

pub fn hash_to_curve<Fp: ark_ff::PrimeField, P: ark_ec::SWModelParameters>(
    msg: &[u8],
    pk: &GroupAffine<P>,
) -> Result<GroupAffine<P>, HashToCurveError> {
    let b = hex::decode(&pk.to_encoded_point(true)).expect(super::EXPECT_MSG_DECODE);
    let x = [msg, b.as_slice()];
    let x = x.concat().clone();
    let x = x.as_slice();

    let pt: ProjectivePoint = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[x],
        b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_",
    )
    .map_err(|_| HashToCurveError::Legacy)?;

    let pt_affine = pt.to_affine();

    k256_affine_to_arkworks_secp256k1_affine::<P>(pt_affine)
}

pub fn k256_affine_to_arkworks_secp256k1_affine<P: ark_ec::SWModelParameters>(
    k_pt: AffinePoint,
) -> Result<GroupAffine<P>, HashToCurveError> {
    let encoded_pt = k_pt.to_encoded_point(false);

    let num_field_bytes = 40;

    // extract k_pt.x
    let k_pt_x_bytes = encoded_pt.x().ok_or(HashToCurveError::Legacy)?;

    // pad x bytes
    let mut k_pt_x_bytes_vec = vec![0u8; num_field_bytes];
    for (i, _) in k_pt_x_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(
            &mut k_pt_x_bytes_vec[i],
            k_pt_x_bytes[k_pt_x_bytes.len() - 1 - i],
        );
    }
    let reader = std::io::BufReader::new(k_pt_x_bytes_vec.as_slice());
    let g_x = P::BaseField::read(reader).map_err(|_| HashToCurveError::Legacy)?;

    // extract k_pt.y
    let k_pt_y_bytes = encoded_pt.y().ok_or(HashToCurveError::Legacy)?;

    // pad y bytes
    let mut k_pt_y_bytes_vec = vec![0u8; num_field_bytes];
    for (i, _) in k_pt_y_bytes.clone().iter().enumerate() {
        let _ = std::mem::replace(
            &mut k_pt_y_bytes_vec[i],
            k_pt_y_bytes[k_pt_y_bytes.len() - 1 - i],
        );
    }

    let reader = std::io::BufReader::new(k_pt_y_bytes_vec.as_slice());
    let g_y = P::BaseField::read(reader).map_err(|_| HashToCurveError::Legacy)?;

    Ok(GroupAffine::<P>::new(g_x, g_y, false))
}

/// Kobi's hash_to_curve function, here for reference only
pub fn _try_and_increment<C: ProjectiveCurve>(msg: &[u8]) -> Result<C::Affine, HashToCurveError> {
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

    Err(HashToCurveError::ReferenceTryAndIncrement)
}
