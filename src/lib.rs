pub mod commands;
mod error;

pub use error::Error;
pub type Result<T> = std::result::Result<T, error::Error>;
