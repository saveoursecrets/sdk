use crate::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct SosServer {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a configuration file.
    Init {
        /// Config file to write.
        config: PathBuf,
    },
    /// Start a server.
    Start {
        /// Bind to host:port.
        #[clap(short, long, default_value = "0.0.0.0:5053")]
        bind: String,

        /// Config file to load.
        config: PathBuf,
    },
}

pub async fn run() -> Result<()> {
    let args = SosServer::parse();

    match args.cmd {
        Command::Init { config } => {
            service::init(config).await?;
        }
        Command::Start { bind, config } => {
            service::start(bind, config).await?;
        }
    }

    Ok(())
}

mod service {
    use axum_server::Handle;
    use sos_net::{
        sdk::vfs,
        server::{Error, Result, Server, ServerConfig, State},
    };
    use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
    use tokio::sync::RwLock;

    /// Initialize default server configuration.
    pub async fn init(path: PathBuf) -> Result<()> {
        if vfs::try_exists(&path).await? {
            return Err(Error::FileExists(path));
        }

        let config: ServerConfig = Default::default();
        let content = toml::to_string_pretty(&config)?;
        vfs::write(path, content.as_bytes()).await?;
        Ok(())
    }

    /// Start a web server.
    pub async fn start(bind: String, config: PathBuf) -> Result<()> {
        let config = ServerConfig::load(&config).await?;
        let backend = config.backend().await?;

        let state = Arc::new(RwLock::new(State {
            config,
            sockets: Default::default(),
        }));

        let handle = Handle::new();

        let addr = SocketAddr::from_str(&bind)?;
        let server = Server::new();
        server
            .start(addr, state, Arc::new(RwLock::new(backend)), handle)
            .await?;
        Ok(())
    }
}
