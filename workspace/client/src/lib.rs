mod client;
mod error;
mod shell;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use client::Client;
pub use error::Error;
pub use shell::{exec, list_vaults, ShellState};
