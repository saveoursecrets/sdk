#![deny(missing_docs)]
#![forbid(unsafe_code)]
//! Parses the output of the `dump-keychain` command
//! of `security(1)` on MacOS.

mod error;
mod parser;

pub use error::Error;
pub use parser::*;

/// Result type for keychain parser.
pub type Result<T> = std::result::Result<T, Error>;
