//! Helper types and functions for command line executables.

pub mod messages;

/// Command tree used to print help output for the website.
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
