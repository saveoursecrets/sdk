use clap::Parser;
use sos_server::{
    AuditLogFile, Authentication, Error, Result, Server, ServerConfig, State,
};
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

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
    let backend = config.backend().await?;

    let audit_log_file =
        args.audit_log.unwrap_or_else(|| config.audit_file());

    if AuditLogFile::would_block(&audit_log_file)? {
        return Err(Error::AuditWouldBlock(audit_log_file));
    }

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
    match run().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    }
    Ok(())
}
