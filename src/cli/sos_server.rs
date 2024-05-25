use crate::{CommandTree, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(name = "sos-server", author, version, about, long_about = None)]
pub struct SosServer {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a configuration file.
    Init {
        /// Path to the storage folder.
        #[clap(short, long)]
        path: Option<PathBuf>,

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
    // Support JSON output of command tree
    if std::env::var("SOS_CLI_JSON").ok().is_some() {
        let cmd = SosServer::command();
        let tree: CommandTree = (&cmd).into();
        serde_json::to_writer_pretty(std::io::stdout(), &tree)?;
        std::process::exit(0);
    }

    let args = SosServer::parse();

    match args.cmd {
        Command::Init { config, path } => {
            service::init(config, path).await?;
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
        server::{Error, Result, Server, ServerConfig, State, StorageConfig},
    };
    use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};
    use tokio::sync::RwLock;

    /// Initialize default server configuration.
    pub async fn init(
        output: PathBuf,
        mut path: Option<PathBuf>,
    ) -> Result<()> {
        if vfs::try_exists(&output).await? {
            return Err(Error::FileExists(output));
        }

        let mut config: ServerConfig = Default::default();
        if let Some(path) = path.take() {
            config.storage = StorageConfig { path };
        }

        let content = toml::to_string_pretty(&config)?;
        vfs::write(output, content.as_bytes()).await?;
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
        let server = Server::new(backend.directory()).await?;
        server
            .start(addr, state, Arc::new(RwLock::new(backend)), handle)
            .await?;
        Ok(())
    }
}
