use clap::Subcommand;
use std::path::PathBuf;

use sos_core::account::AccountRef;

use crate::{
    helpers::account::{
        account_backup, account_info, account_rename, account_restore,
        list_accounts, local_signup,
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

        /// Account name or address.
        account: Option<AccountRef>,
    },
    /// Create secure backup as a zip archive.
    Backup {
        /// Output zip archive.
        #[clap(short, long)]
        output: PathBuf,

        /// Force overwrite of existing file.
        #[clap(short, long)]
        force: bool,

        /// Account name or address.
        account: Option<AccountRef>,
    },
    /// Restore account from secure backup.
    Restore {
        /// Input zip archive.
        #[clap(short, long)]
        input: PathBuf,
    },
    /// Rename an account.
    Rename {
        /// Name for the account.
        #[clap(short, long)]
        name: String,

        /// Account name or address.
        account: Option<AccountRef>,
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
            account,
            verbose,
            system,
        } => {
            account_info(account, verbose, system).await?;
        }
        Command::Backup {
            account,
            output,
            force,
        } => {
            account_backup(account, output, force).await?;
        }
        Command::Restore { input } => {
            if let Some(account) = account_restore(input).await? {
                println!("{} ({}) ✓", account.label(), account.address());
            }
        }
        Command::Rename { name, account } => {
            account_rename(account, name).await?;
            println!("account renamed ✓");
        }
    }

    Ok(())
}
