#![deny(missing_docs)]
#![forbid(unsafe_code)]
//! Release artifact meta data for the [Save Our Secrets](https://saveoursecrets.com) SDK.

pub use semver;

mod artifact;
mod error;
mod release;

pub use artifact::*;
pub use error::Error;
pub use release::*;
