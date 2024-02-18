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

pub use helpers::USER;

use serde::{Serialize, Deserialize};

/// Command tree used to print help output for the website.
#[doc(hidden)]
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandTree {
    /// Name of the command.
    pub name: String,
    /// Subcommands.
    pub commands: Vec<CommandTree>,
}

impl From<&clap::Command> for CommandTree {
    fn from(value: &clap::Command) -> Self {
        CommandTree {
            name: value.get_name().to_string(),
            commands: value.get_subcommands().map(|c| c.into()).collect(),
        }
    }
}
