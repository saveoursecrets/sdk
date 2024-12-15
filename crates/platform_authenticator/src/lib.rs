mod error;

pub mod keyring_password;
pub mod local_auth;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
