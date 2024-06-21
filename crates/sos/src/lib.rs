//! Command line tools for [Save Our Secrets](https://saveoursecrets.com).
//!
//! This crate contains the binary for the `sos`; more information is on the
//! [command line tools](https://saveoursecrets.com/command-line-tools/) downloads page; for the server binary see the [sos-server](https://docs.rs/sos-server/) crate.
//!
//! See the [CLI documentation](https://saveoursecrets.com/docs/cli/) for usage information or browse the [online help manual](https://saveoursecrets.com/docs/cli/help/); the libraries are available at [sos-sdk](https://docs.rs/sos-sdk/) and [sos-net](https://docs.rs/sos-net/).
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[doc(hidden)]
pub mod cli;
#[doc(hidden)]
pub mod commands;
mod error;

pub(crate) mod helpers;

#[doc(hidden)]
pub use helpers::USER;

pub use sos_cli_helpers::*;

#[doc(hidden)]
pub use error::Error;

/// Result type for the executable library.
#[doc(hidden)]
pub type Result<T> = std::result::Result<T, error::Error>;