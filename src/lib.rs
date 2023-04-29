/// Target for tracing macros.
///
/// Used so that error messages are succinct rather than
/// including the full module path.
pub const TARGET: &str = "sos";

pub mod cli;
pub mod commands;
mod error;
pub(crate) mod helpers;

pub use error::Error;
pub type Result<T> = std::result::Result<T, error::Error>;
