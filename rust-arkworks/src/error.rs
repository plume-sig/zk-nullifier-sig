use thiserror::Error;

/// This is an error that could occur when running a cryptograhic primitive
#[derive(Error, Debug, PartialEq)]
pub enum CryptoError {
    #[error("Cannot hash to curve")]
    CannotHashToCurve,

    #[error("Cannot encode a point not on the curve")]
    PointNotOnCurve,
}
