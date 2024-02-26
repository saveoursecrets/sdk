use crate::{
    helpers::{
        account::resolve_account_address,
    },
    Result,
};
use clap::Subcommand;
use sos_net::sdk::prelude::*;

/// Filter used for printing paths.
pub enum PathFilter {
    Documents,
    Identity,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print environment variables.
    #[clap(alias = "var")]
    Vars,
    /// Print account paths.
    #[clap(alias = "path")]
    Paths {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
}

/// Handle env commands.
pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Vars => {
            let vars = [SOS_DATA_DIR, SOS_OFFLINE, SOS_PROMPT];
            for var in vars {
                print!("{}=", var);
                match std::env::var(var) {
                    Ok(val) => println!("{}", val),
                    Err(_) => println!("unset"),
                }
            }
        }
        Command::Paths { account } => {
            let address = resolve_account_address(account.as_ref())
                .await?;
            let paths = Paths::new(Paths::data_dir()?, address.to_string());
            let value = toml::to_string_pretty(&paths)?;
            print!("{}", value);
        }
    }
    Ok(())
}
