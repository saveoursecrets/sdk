use clap::Subcommand;

use crate::{Error, Result};

use crate::helpers::account::{list_accounts, local_signup};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create an account.
    New {
        /// Name for the new account.
        name: String,

        /// Name for the default folder.
        #[clap(short, long)]
        folder_name: Option<String>,
    },
    /// List accounts.
    #[clap(alias = "ls")]
    List,
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::New { name, folder_name } => {
            local_signup(name, folder_name)?;
        }

        Command::List => {
            list_accounts()?;
        }
    }

    Ok(())
}
