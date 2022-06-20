use std::future::Future;
use tokio::runtime::Runtime;

mod client;
mod error;
mod shell;
mod signup;

pub type Result<T> = std::result::Result<T, error::Error>;

/// Runs a future blocking the current thread so we can
/// merge the synchronous nature of the shell prompt with the
/// asynchronous API exposed by the client.
pub(crate) fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>> + Send,
    R: Send,
{
    Ok(Runtime::new().unwrap().block_on(func)?)
}

pub(crate) fn display_passphrase(
    heading: &str,
    detail: &str,
    passphrase: &str,
) {
    println!("### {}", heading);
    println!("#");
    println!("# {}", detail);
    println!("#");
    println!("# {}", passphrase);
    println!("#");
    println!("###");
}

pub use client::{Client, VaultInfo};
pub use error::Error;
pub use shell::{exec, list_vaults, ShellState};
pub use signup::signup;
