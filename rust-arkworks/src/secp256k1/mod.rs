#![deny(
    warnings,
    unused,
    // future_incompatible,
    nonstandard_style,
    rust_2018_idioms
)]
#![allow(rustdoc::bare_urls)]
#![forbid(unsafe_code)]

pub mod curves;
pub use curves::*;

pub mod fields;
pub use fields::*;

// pub mod sec1;
// pub use sec1::*;

// pub mod test_vectors;
mod tests;
