/// Target for tracing macros.
///
/// Used so that error messages are succinct rather than
/// including the full module path.
pub const TARGET: &str = "sos";

#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
#[cfg(not(target_arch = "wasm32"))]
pub mod commands;
#[cfg(not(target_arch = "wasm32"))]
mod error;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod helpers;

#[cfg(not(target_arch = "wasm32"))]
pub use error::Error;
#[cfg(not(target_arch = "wasm32"))]
pub type Result<T> = std::result::Result<T, error::Error>;
