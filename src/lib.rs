//! Command line tools for [Save Our Secrets](https://saveoursecrets.com).
//!
//! This crate contains the binaries for the `sos` client and
//! the `sos-server` reference server; more information is on the
//! [command line tools](https://saveoursecrets.com/command-line-tools/) downloads page.
//!
//! See the [CLI documentation](https://saveoursecrets.com/docs/cli/) for usage information or browse the [online help manual](https://saveoursecrets.com/docs/cli/help/); the libraries are available at [sos-sdk](https://docs.rs/sos-sdk/) and [sos-net](https://docs.rs/sos-net/).
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[doc(hidden)]
pub mod cli;
#[doc(hidden)]
pub mod commands;
mod error;

pub(crate) mod helpers;

#[doc(hidden)]
pub use helpers::{messages::*, USER};

#[doc(hidden)]
pub use error::Error;

/// Result type for the executable library.
#[doc(hidden)]
pub type Result<T> = std::result::Result<T, error::Error>;

/// Command tree used to print help output for the website.
#[doc(hidden)]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
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
