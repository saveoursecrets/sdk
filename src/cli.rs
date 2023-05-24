use clap::{Parser, Subcommand};
use sos_net::client::provider::ProviderFactory;
use sos_sdk::{
    account::AccountRef, storage::StorageDirs, url::Url, vault::VaultRef,
};
use std::path::PathBuf;

use super::{
    commands::{
        account, audit, changes, check, device, folder, rendezvous, secret,
        server, shell, AccountCommand, AuditCommand, CheckCommand,
        DeviceCommand, FolderCommand, SecretCommand,
    },
    Result,
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

    /// Storage provider factory.
    #[clap(long, env = "SOS_PROVIDER")]
    provider: Option<ProviderFactory>,

    /// Local storage directory.
    #[clap(long, env = "SOS_CACHE")]
    cache: Option<PathBuf>,

    /// Affirmative for all confirmation prompts.
    #[clap(long, env = "SOS_YES")]
    yes: bool,

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
    /// Print and monitor audit logs.
    Audit {
        #[clap(subcommand)]
        cmd: AuditCommand,
    },

    /// Listen to changes event stream.
    Changes {
        /// Server URL.
        #[clap(short, long)]
        server: Url,

        /// Account name or address.
        #[clap(short, long)]
        account: AccountRef,
    },
    /// Check file status and integrity.
    Check {
        #[clap(subcommand)]
        cmd: CheckCommand,
    },
    /// Peer to peer rendezvous server.
    Rendezvous {
        /// Hex encoded 32 byte Ed25519 secret key.
        #[clap(short, long, env = "SOS_IDENTITY", hide_env_values = true)]
        identity: Option<String>,

        /// Bind address.
        #[clap(short, long, default_value = "0.0.0.0:3505")]
        bind: String,
    },
    /// Storage web service.
    Server {
        /// Override the audit log file path.
        #[clap(short, long)]
        audit_log: Option<PathBuf>,

        /// Override the reap interval for expired sessions in seconds.
        #[clap(long)]
        reap_interval: Option<u64>,

        /// Override the default session duration in seconds.
        #[clap(long)]
        session_duration: Option<u64>,

        /// Bind to host:port.
        #[clap(short, long, default_value = "0.0.0.0:5053")]
        bind: String,

        /// Config file to load.
        #[clap(short, long)]
        config: PathBuf,
    },
    /// Interactive login shell.
    Shell {
        /// Folder name or identifier.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Account name or address.
        account: Option<AccountRef>,
    },
}

pub async fn run() -> Result<()> {
    let mut args = Sos::parse();
    let factory = args.provider.unwrap_or_default();

    if let Some(cache) = args.cache.take() {
        StorageDirs::set_cache_dir(cache);
    }
    StorageDirs::skeleton().await?;

    #[cfg(any(test, debug_assertions))]
    if let Some(password) = args.password.take() {
        std::env::set_var("SOS_PASSWORD", password);
    }

    match args.cmd {
        Command::Account { cmd } => account::run(cmd, factory).await?,
        Command::Device { cmd } => device::run(cmd, factory).await?,
        Command::Folder { cmd } => folder::run(cmd, factory).await?,
        Command::Secret { cmd } => secret::run(cmd, factory).await?,
        Command::Audit { cmd } => audit::run(cmd).await?,
        Command::Changes { server, account } => {
            changes::run(server, account).await?
        }
        Command::Check { cmd } => check::run(cmd).await?,
        Command::Shell { account, folder } => {
            shell::run(factory, account, folder).await?
        }
        Command::Server {
            audit_log,
            reap_interval,
            session_duration,
            bind,
            config,
        } => {
            server::run(
                audit_log,
                reap_interval,
                session_duration,
                bind,
                config,
            )
            .await?
        }
        Command::Rendezvous { identity, bind } => {
            rendezvous::run(identity, bind).await?
        }
    }
    Ok(())
}
