use std::path::PathBuf;
use clap::Subcommand;

use crate::{
    helpers::account::{account_info, list_accounts, account_backup, local_signup},
    Error, Result,
};

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
    List {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,
    },
    /// Print account information.
    Info {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Include system folders.
        #[clap(short, long)]
        system: bool,

        /// Account name.
        account_name: String,
    },
    /// Create secure backup as a zip archive.
    Backup {
        /// Output file.
        #[clap(short, long)]
        output: PathBuf,

        /// Force overwrite of existing file.
        #[clap(short, long)]
        force: bool,

        /// Account name.
        account_name: String,
    },
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::New { name, folder_name } => {
            local_signup(name, folder_name)?;
        }
        Command::List { verbose } => {
            list_accounts(verbose)?;
        }
        Command::Info {
            account_name,
            verbose,
            system,
        } => {
            account_info(&account_name, verbose, system)?;
        }
        Command::Backup {
            account_name,
            output,
            force,
        } => {
            account_backup(&account_name, output, force)?;
        }
    }

    Ok(())
}
