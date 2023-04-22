use clap::Subcommand;

use crate::Result;

use crate::helpers::account::{account_info, list_accounts, local_signup};

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
    }

    Ok(())
}
