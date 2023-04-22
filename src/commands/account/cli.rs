use clap::Subcommand;
use std::path::PathBuf;

use crate::{
    helpers::account::{
        account_backup, account_info, account_restore, list_accounts,
        local_signup,
    },
    Result,
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
        /// Output zip archive.
        #[clap(short, long)]
        output: PathBuf,

        /// Force overwrite of existing file.
        #[clap(short, long)]
        force: bool,

        /// Account name.
        account_name: String,
    },
    /// Restore account from secure backup.
    Restore {
        /// Input zip archive.
        #[clap(short, long)]
        input: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::New { name, folder_name } => {
            local_signup(name, folder_name).await?;
        }
        Command::List { verbose } => {
            list_accounts(verbose)?;
        }
        Command::Info {
            account_name,
            verbose,
            system,
        } => {
            account_info(&account_name, verbose, system).await?;
        }
        Command::Backup {
            account_name,
            output,
            force,
        } => {
            account_backup(&account_name, output, force)?;
        }
        Command::Restore { input } => {
            if let Some(account) = account_restore(input).await? {
                println!("{} ({}) ✓", account.label, account.address);
            }
        }
    }

    Ok(())
}
