use clap::{CommandFactory, Parser, Subcommand};
use sos_net::sdk::{identity::AccountRef, vault::FolderRef, Paths};
use std::path::PathBuf;

use crate::{
    commands::{
        account, device, environment, folder, preferences, secret, server,
        shell, sync, tools, AccountCommand, DeviceCommand,
        EnvironmentCommand, FolderCommand, PreferenceCommand, SecretCommand,
        ServerCommand, SyncCommand, ToolsCommand,
    },
    helpers::{account::SHELL, PROGRESS_MONITOR},
    CommandTree, Result,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Sos {
    /// Set the account password.
    ///
    /// Used for debugging and test purposes,
    /// not available in a release build to
    /// prevent misuse (passwords appearing in
    /// shell history).
    #[cfg(any(test, debug_assertions))]
    #[clap(
        long,
        env = "SOS_PASSWORD",
        hide = true,
        hide_env = true,
        hide_env_values = true,
        hide_short_help = true,
        hide_long_help = true
    )]
    password: Option<String>,

    /// Local storage directory.
    #[clap(long, env = "SOS_DATA_DIR", hide_env_values = true)]
    storage: Option<PathBuf>,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage local accounts.
    Account {
        #[clap(subcommand)]
        cmd: AccountCommand,
    },
    /// Trusted device management
    Device {
        #[clap(subcommand)]
        cmd: DeviceCommand,
    },
    /// Inspect and modify folders.
    Folder {
        #[clap(subcommand)]
        cmd: FolderCommand,
    },
    /// Create, edit and delete secrets.
    Secret {
        #[clap(subcommand)]
        cmd: SecretCommand,
    },
    /// Add and remove servers.
    Server {
        #[clap(subcommand)]
        cmd: ServerCommand,
    },
    /// Sync with remote servers.
    Sync {
        #[clap(subcommand)]
        cmd: SyncCommand,
    },
    /*
    /// Inspect external files and file transfers.
    File {
        #[clap(subcommand)]
        cmd: FileCommand,
    },
    */
    /// Interactive login shell.
    Shell {
        /// Folder name or identifier.
        #[clap(short, long)]
        folder: Option<FolderRef>,

        /// Account name or address.
        account: Option<AccountRef>,
    },
    /// View and edit account preferences.
    #[clap(alias = "prefs")]
    Preferences {
        #[clap(subcommand)]
        cmd: PreferenceCommand,
    },
    /// Print environment and paths.
    #[clap(alias = "env")]
    Environment {
        #[clap(subcommand)]
        cmd: EnvironmentCommand,
    },
    /// Utility tools.
    #[clap(alias = "tool")]
    Tools {
        #[clap(subcommand)]
        cmd: ToolsCommand,
    },
}

pub async fn run() -> Result<()> {
    // Support JSON output of command tree
    if std::env::var("SOS_CLI_JSON").ok().is_some() {
        let cmd = Sos::command();
        let tree: CommandTree = (&cmd).into();
        serde_json::to_writer_pretty(std::io::stdout(), &tree)?;
        std::process::exit(0);
    }

    ctrlc::set_handler(move || {
        let is_shell = *SHELL.lock();
        if is_shell {
            let tx = PROGRESS_MONITOR.lock();
            if let Some(tx) = &*tx {
                let _ = tx.send(());
            } else {
                std::process::exit(1);
            }
        } else {
            std::process::exit(1);
        }
    })?;

    #[allow(unused_mut)]
    let mut args = Sos::parse();

    if let Some(storage) = &args.storage {
        Paths::set_data_dir(storage.clone());
    }
    Paths::scaffold(args.storage).await?;

    #[cfg(any(test, debug_assertions))]
    if let Some(password) = args.password.take() {
        std::env::set_var("SOS_PASSWORD", password);
    }

    match args.cmd {
        Command::Account { cmd } => account::run(cmd).await?,
        Command::Device { cmd } => device::run(cmd).await?,
        Command::Folder { cmd } => folder::run(cmd).await?,
        Command::Secret { cmd } => secret::run(cmd).await?,
        Command::Server { cmd } => server::run(cmd).await?,
        Command::Sync { cmd } => sync::run(cmd).await?,
        // Command::File { cmd } => file::run(cmd).await?,
        Command::Shell { account, folder } => {
            shell::run(account, folder).await?
        }
        Command::Preferences { cmd } => preferences::run(cmd).await?,
        Command::Environment { cmd } => environment::run(cmd).await?,
        Command::Tools { cmd } => tools::run(cmd).await?,
    }
    Ok(())
}
