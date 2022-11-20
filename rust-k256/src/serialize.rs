use elliptic_curve::sec1::ToEncodedPoint;

use k256::{
    // ecdsa::{signature::Signer, Signature, SigningKey},
    ProjectivePoint,
    Scalar,
};

// Format a ProjectivePoint to 64 bytes - the concatenation of the x and y values.  We use 64
/// bytes instead of SEC1 encoding as our arkworks secp256k1 implementation doesn't support SEC1
/// encoding yet.
pub fn encode_pt(point: ProjectivePoint) -> Vec<u8> {
    let encoded = point.to_encoded_point(true);
    encoded.to_bytes().to_vec()
}

/// Convert a 32-byte array to a scalar
pub fn byte_array_to_scalar(bytes: &[u8]) -> Scalar {
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
