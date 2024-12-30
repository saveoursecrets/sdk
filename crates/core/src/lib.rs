pub mod commit;
pub mod constants;
mod error;
mod origin;

pub use error::Error;
pub use origin::Origin;

pub use rs_merkle as merkle;

pub type Result<T> = std::result::Result<T, Error>;
