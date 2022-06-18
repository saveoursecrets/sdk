mod client;
mod error;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use client::Client;
