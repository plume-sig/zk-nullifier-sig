// Legacy definitions for errors which will be gone with arkworks upgrade to `>=0.4.0`.
// `use ark_ec::hashing::HashToCurveError;`

// use thiserror::Error;

/// This is an error that could occur when running a cryptograhic primitive
// #[derive(Error, Debug, PartialEq)]
// pub enum CryptoError {
// #[error("Cannot hash to curve")]
// CannotHashToCurve,

// #[error("Cannot encode a point not on the curve")]
// PointNotOnCurve,
// }

// Let's outline what errors will be in `~0.4.0`
#[derive(Debug, Clone)]
pub enum HashToCurveError {
    UnsupportedCurveError(String),
    MapToCurveError(String),
    /* let's add two more items to absorb everything
    in `crate::hash_to_curve` which is
    subject to deprecation */
    Legacy,
    ReferenceTryAndIncrement,
}
