mod error;
mod input;

pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;
pub use input::*;
