use clap::Parser;
use sos_server::{
    Authentication, FileLocks, Result, Server, ServerConfig, State,
};

use sos_audit::AuditLogFile;

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

    /// Bind to host:port.
    #[clap(short, long, default_value = "127.0.0.1:5053")]
    bind: String,

    /// Config file to load.
    #[clap(short, long, parse(from_os_str))]
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

    //println!("Config {:#?}", config);

    let authentication: Authentication = Default::default();
    let mut backend = config.backend().await?;

    let audit_log_file =
        args.audit_log.unwrap_or_else(|| config.audit_file());

    let mut locks = FileLocks::new();
    let _ = locks.add(&audit_log_file)?;
    // Move into the backend so it can manage lock files too
    backend.set_file_locks(locks)?;

    tracing::debug!("lock files {:#?}", backend.file_locks().paths());

    // Set up the audit log
    let audit_log = AuditLogFile::new(&audit_log_file)?;

    let state = Arc::new(RwLock::new(State {
        name,
        version,
        config,
        backend,
        authentication,
        audit_log,
        sse: Default::default(),
    }));

    let addr = SocketAddr::from_str(&args.bind)?;
    Server::start(addr, state).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sos_server=info".into()),
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
