//! Types for release artifact meta data.
//!
//! Provides serde support and string parsing for types
//! that can be supplied as command line arguments.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub use semver;

mod artifact;
mod error;
mod release;

pub use artifact::*;
pub use error::Error;
pub use release::*;
