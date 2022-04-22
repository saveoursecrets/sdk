use clap::Parser;
use sos_server::{Authentication, Error, Result, Server, ServerConfig, State, AuditLogFile};
use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
use tokio::sync::RwLock;

/// Secret storage server.
#[derive(Parser, Debug)]
#[clap(name = "sos3", author, version, about, long_about = None)]
struct Cli {
    /// Serve the built in GUI.
    #[structopt(short, long)]
    gui: Option<bool>,

    /// Bind to host:port.
    #[structopt(short, long, default_value = "127.0.0.1:5053")]
    bind: String,

    /// Config file to load.
    #[structopt(short, long, parse(from_os_str))]
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
    let backend = config.backend()?;

    let audit_log_file = PathBuf::from("./audit.log");

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
