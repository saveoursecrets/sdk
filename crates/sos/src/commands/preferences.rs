use crate::{
    helpers::{
        account::resolve_user,
        messages::{fail, success},
    },
    Error, Result,
};
use clap::Subcommand;
use sos_net::extras::preferences::*;
use sos_net::sdk::prelude::{Account, AccountRef};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List preferences.
    #[clap(alias = "ls")]
    List {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
    /// Print a preference.
    Get {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Preference key.
        key: String,
    },
    /// Remove a preference.
    #[clap(alias = "rm")]
    Remove {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Preference key.
        key: String,
    },
    /// Set a boolean preference.
    #[clap(alias = "bool")]
    Boolean {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Preference key.
        key: String,

        /// Boolean value.
        value: String,
    },
    /// Set a number preference.
    #[clap(alias = "num")]
    Number {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Preference key.
        key: String,

        /// Numeric value (IEEE754).
        value: f64,
    },
    /// Set a string preference.
    #[clap(alias = "str")]
    String {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Preference key.
        key: String,

        /// String value.
        value: String,
    },
    /// Set a string list preference.
    StringList {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Preference key.
        key: String,

        /// String values.
        value: Vec<String>,
    },
    /// Remove all preferences.
    Clear {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
}

/// Handle preferences commands.
pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::List { account } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let paths = owner.paths();
            let mut prefs = Preferences::new(&paths);
            prefs.load().await?;
            if prefs.is_empty() {
                println!("No preferences yet");
            } else {
                for (key, pref) in prefs.iter() {
                    println!("{}={}", key, pref);
                }
            }
        }
        Command::Get { account, key } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let paths = owner.paths();
            let mut prefs = Preferences::new(&paths);
            prefs.load().await?;
            if let Some(pref) = prefs.get_unchecked(&key) {
                println!("{}={}", key, pref);
            } else {
                fail(format!("preference {} not found", key));
            }
        }
        Command::Remove { account, key } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let paths = owner.paths();
            let mut prefs = Preferences::new(&paths);
            prefs.load().await?;
            let pref = prefs.remove(&key).await?;
            if pref.is_some() {
                success(format!("Removed preference {}", key));
            } else {
                fail(format!("preference {} not found", key));
            }
        }
        Command::Boolean {
            account,
            key,
            value,
        } => {
            let value: bool = value.parse()?;
            set_pref(account, key, Preference::Bool(value)).await?;
        }
        Command::Number {
            account,
            key,
            value,
        } => {
            set_pref(account, key, Preference::Number(value)).await?;
        }
        Command::String {
            account,
            key,
            value,
        } => {
            set_pref(account, key, Preference::String(value)).await?;
        }
        Command::StringList {
            account,
            key,
            value,
        } => {
            set_pref(account, key, Preference::StringList(value)).await?;
        }
        Command::Clear { account } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let paths = owner.paths();
            let mut prefs = Preferences::new(&paths);
            prefs.clear().await?;
            success("Cleared all preferences");
        }
    }
    Ok(())
}

async fn set_pref(
    account: Option<AccountRef>,
    key: String,
    pref: Preference,
) -> Result<()> {
    let user = resolve_user(account.as_ref(), false).await?;
    let owner = user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    let paths = owner.paths();
    let mut prefs = Preferences::new(&paths);
    prefs.load().await?;
    prefs.insert(key.clone(), pref).await?;
    success(format!("Set {}", key));
    Ok(())
}
