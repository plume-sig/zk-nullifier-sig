use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint};

/// Encodes the point by compressing it to 33 bytes
pub(crate) fn encode_pt(point: &ProjectivePoint) -> Vec<u8> {
    point.to_encoded_point(true).to_bytes().to_vec()
}
