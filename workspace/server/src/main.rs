use clap::Parser;

use sos_core::{AuditLogFile, FileLocks};
use sos_node::{
    server::{
        BackendHandler, Result, Server, ServerConfig, ServerInfo, State,
    },
    session::SessionManager,
};

use axum_server::Handle;
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Secret storage server.
#[derive(Parser, Debug)]
#[clap(name = "sos-server", author, version, about, long_about = None)]
struct Cli {
    /// Serve the built in GUI.
    #[clap(short, long)]
    gui: Option<bool>,

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
}

async fn run() -> Result<()> {
    let args = Cli::parse();

    let name = env!("CARGO_PKG_NAME").to_string();
    let version = env!("CARGO_PKG_VERSION").to_string();

    let mut config = ServerConfig::load(&args.config)?;
    if let Some(gui) = args.gui {
        config.gui = gui;
    }

    if let Some(reap_interval) = args.reap_interval {
        config.session.reap_interval = reap_interval;
    }

    if let Some(session_duration) = args.session_duration {
        config.session.duration = session_duration;
    }

    let sessions = SessionManager::new(config.session.duration);

    //println!("Config {:#?}", config);

    let mut backend = config.backend().await?;

    let audit_log_file =
        args.audit_log.unwrap_or_else(|| config.audit_file());

    let mut locks = FileLocks::new();
    locks.add(&audit_log_file)?;
    // Move into the backend so it can manage lock files too
    backend.handler_mut().set_file_locks(locks)?;

    tracing::debug!(
        "lock files {:#?}",
        backend.handler().file_locks().paths()
    );

    // Set up the audit log
    let audit_log = AuditLogFile::new(&audit_log_file)?;

    let state = Arc::new(RwLock::new(State {
        info: ServerInfo { name, version },
        config,
        backend,
        audit_log,
        sockets: Default::default(),
        sessions,
    }));

    let handle = Handle::new();

    let addr = SocketAddr::from_str(&args.bind)?;
    let server = Server::new();
    server.start(addr, state, handle).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| {
                "sos_node::server=info,sos_server=info".into()
            }),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match run().await {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("{}", e);
        }
    }
    Ok(())
}
