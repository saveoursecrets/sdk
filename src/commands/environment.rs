use crate::{
    helpers::{
        account::resolve_account_address,
    },
    Result,
};
use clap::Subcommand;
use std::{str::FromStr, fmt};
use sos_net::sdk::prelude::*;

/// Filter used for printing paths.
#[derive(Debug, Clone)]
pub enum PathFilter {
    /// Root data directory.
    Data,
    /// Directory for identity folders.
    Identity,
    /// Account storage directory.
    Accounts,
    /// Logs directory.
    Logs,
    /// Audit file.
    Audit,
    /// User directory.
    User,
    /// User files directory.
    Files,
    /// User folders directory.
    Folders,
    /// Device vault.
    Device,
    /// Identity vault.
    IdentityVault,
    /// Identity events.
    IdentityEvents,
    /// Account events.
    AccountEvents,
    /// Device events.
    DeviceEvents,
    /// File events.
    FileEvents,
}

impl PathFilter {
    fn print(&self, paths: &Paths) {
        match self {
            Self::Data => println!("{}", paths.documents_dir().display()),
            Self::Identity => println!("{}", paths.identity_dir().display()),
            Self::Accounts => println!("{}", paths.local_dir().display()),
            Self::Logs => println!("{}", paths.logs_dir().display()),
            Self::Audit => println!("{}", paths.audit_file().display()),
            Self::User => println!("{}", paths.user_dir().display()),
            Self::Files => println!("{}", paths.files_dir().display()),
            Self::Folders => println!("{}", paths.vaults_dir().display()),
            Self::Device => println!("{}", paths.device_file().display()),
            Self::IdentityVault => println!("{}", paths.identity_vault().display()),
            Self::IdentityEvents => println!("{}", paths.identity_events().display()),
            Self::AccountEvents => println!("{}", paths.account_events().display()),
            Self::DeviceEvents => println!("{}", paths.device_events().display()),
            Self::FileEvents => println!("{}", paths.file_events().display()),
        }
    }
}

impl fmt::Display for PathFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data => write!(f, "data"),
            Self::Identity => write!(f, "identity"),
            Self::Accounts => write!(f, "accounts"),
            Self::Logs => write!(f, "logs"),
            Self::Audit => write!(f, "audit"),
            Self::User => write!(f, "user"),
            Self::Files => write!(f, "files"),
            Self::Folders => write!(f, "folders"),
            Self::Device => write!(f, "device"),
            Self::IdentityVault => write!(f, "identity-vault"),
            Self::IdentityEvents => write!(f, "identity-events"),
            Self::AccountEvents => write!(f, "account-events"),
            Self::DeviceEvents => write!(f, "device-events"),
            Self::FileEvents => write!(f, "file-events"),
        }
    }
}

impl FromStr for PathFilter {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "data" => Self::Data,
            "identity" => Self::Identity,
            "accounts" => Self::Accounts,
            "logs" => Self::Logs,
            "audit" => Self::Audit,
            "user" => Self::User,
            "files" => Self::Files,
            "folders" => Self::Folders,
            "device" => Self::Device,
            "identity-vault" => Self::IdentityVault,
            "identity-events" => Self::IdentityEvents,
            "account-events" => Self::AccountEvents,
            "device-events" => Self::DeviceEvents,
            "file-events" => Self::FileEvents,
            _ => return Err(crate::Error::UnknownPathFilter(s.to_string())),
        })
    }
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

        /// Filter paths to print.
        #[clap(short, long)]
        filter: Vec<PathFilter>,
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
        Command::Paths { account, filter } => {
            let address = resolve_account_address(account.as_ref())
                .await?;
            let paths = Paths::new(Paths::data_dir()?, address.to_string());
            if filter.is_empty() {
                let value = toml::to_string_pretty(&paths)?;
                print!("{}", value);
            } else {
                for item in filter {
                    item.print(&paths);
                }
            }
        }
    }
    Ok(())
}
