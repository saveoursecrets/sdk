pub mod commands;
pub(crate) mod helpers;
mod error;

pub use error::Error;
pub type Result<T> = std::result::Result<T, error::Error>;
