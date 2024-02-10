// Legacy definitions for errors which will be gone with arkworks upgrade to `>=0.4.0`.
// `use ark_ec::hashing::HashToCurveError;`

// use thiserror::Error;

// /// This is an error that could occur when running a cryptograhic primitive
// #[derive(Error, Debug, PartialEq)]
// pub enum CryptoError {
// #[error("Cannot hash to curve")]
// CannotHashToCurve,

// #[error("Cannot encode a point not on the curve")]
// PointNotOnCurve,
// }

// Let's outline what errors will be in `~0.4.0`
/// It's an interim `enum` between legacy definition of the errors and prospective which will be relying on [`ark_ec::hashing::HashToCurveError`]. 
#[derive(Debug, Clone)]
pub enum HashToCurveError {
    /// Mimics the `ark_ec::hashing::HashToCurveError` enum
    UnsupportedCurveError(String),
    /// Mimics the `ark_ec::hashing::HashToCurveError` enum
    MapToCurveError(String),
    /* let's add two more items to absorb everything
    in `crate::hash_to_curve` which is
    subject to deprecation */
    /// Absorbs any legacy error in [`mod@crate::hash_to_curve`]. They will be deprecated with upgrade to `~0.4.0`.
    Legacy,
    /// A special case for a reference function. It will be moved to <./examples> with the upgrade to `~0.4.0`.
    ReferenceTryAndIncrement,
}
