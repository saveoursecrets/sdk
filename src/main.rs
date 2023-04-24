use clap::{Parser, Subcommand};
use sos::{
    commands::{
        account, audit, changes, check, rendezvous, server, shell,
        AccountCommand, AuditCommand, CheckCommand,
    },
    Result,
};
use sos_core::{url::Url, account::AccountRef};
use sos_node::client::provider::ProviderFactory;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Sos {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage local accounts.
    Account {
        #[clap(subcommand)]
        cmd: AccountCommand,
    },
    /// Print and monitor audit logs.
    Audit {
        #[clap(subcommand)]
        cmd: AuditCommand,
    },

    /// Listen to events on a server changes stream.
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
        #[clap(short, long, env, hide_env_values = true)]
        identity: Option<String>,

        /// Bind address.
        #[clap(short, long, default_value = "0.0.0.0:3505")]
        bind: String,
    },
    /// Run a web server.
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
    /// Start an interactive login shell.
    Shell {
        /// Provider factory.
        #[clap(short, long)]
        provider: Option<ProviderFactory>,

        /// Account name or address.
        account: AccountRef,
    },
}

async fn run() -> Result<()> {
    let args = Sos::parse();
    match args.cmd {
        Command::Account { cmd } => account::run(cmd).await?,
        Command::Audit { cmd } => audit::run(cmd)?,
        Command::Changes {
            server,
            account,
        } => changes::run(server, account).await?,
        Command::Check { cmd } => check::run(cmd)?,
        Command::Shell {
            provider,
            account,
        } => shell::run(provider, account).await?,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "sos=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run().await {
        tracing::error!("{}", e);
    }

    Ok(())
}
