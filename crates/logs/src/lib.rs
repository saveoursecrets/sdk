//! Log tracing output to disc.
mod error;
mod logger;

pub use error::Error;
pub use logger::Logger;

pub(crate) type Result<T> = std::result::Result<T, Error>;
