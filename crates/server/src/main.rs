use sos_server::Result;

#[tokio::main]
async fn main() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "sos=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = cli::run().await {
        sos_cli_helpers::messages::fail(e.to_string());
    }

    Ok(())
}

mod cli {
    use crate::Result;
    use clap::{CommandFactory, Parser, Subcommand};
    use sos_cli_helpers::CommandTree;
    use std::{net::SocketAddr, path::PathBuf};

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

            /// Bind to host:port.
            #[clap(short, long)]
            bind: Option<SocketAddr>,

            /// Cache directory for ACME SSL configration.
            #[clap(short, long)]
            cache: Option<PathBuf>,

            /// Domains for ACME SSL configration.
            #[clap(short, long)]
            domains: Vec<String>,

            /// Email addresses for ACME SSL configration.
            #[clap(short, long)]
            email: Vec<String>,

            /// Production flag for ACME SSL configration.
            #[clap(long)]
            production: bool,

            /// Config file to write.
            config: PathBuf,
        },
        /// Start a server.
        Start {
            /// Bind to host:port.
            #[clap(short, long)]
            bind: Option<SocketAddr>,

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
            Command::Init {
                config,
                path,
                bind,
                cache,
                domains,
                email,
                production,
            } => {
                service::init(
                    config, path, bind, cache, domains, email, production,
                )
                .await?;
            }
            Command::Start { bind, config } => {
                service::start(config, bind).await?;
            }
        }

        Ok(())
    }

    mod service {
        use axum_server::Handle;
        use sos_protocol::sdk::vfs;
        use sos_server::{
            AcmeConfig, Error, Result, Server, ServerConfig, SslConfig,
            State, StorageConfig,
        };
        use std::{net::SocketAddr, path::PathBuf, sync::Arc};
        use tokio::sync::RwLock;

        /// Initialize default server configuration.
        pub async fn init(
            output: PathBuf,
            mut path: Option<PathBuf>,
            bind: Option<SocketAddr>,
            cache: Option<PathBuf>,
            domains: Vec<String>,
            email: Vec<String>,
            production: bool,
        ) -> Result<()> {
            if vfs::try_exists(&output).await? {
                return Err(Error::FileExists(output));
            }

            let mut config: ServerConfig = Default::default();
            if let Some(path) = path.take() {
                config.storage = StorageConfig { path };
            }
            if let Some(addr) = bind {
                config.set_bind_address(addr);
            }

            if let (Some(cache), false) = (cache, domains.is_empty()) {
                config.net.ssl = SslConfig::Acme(AcmeConfig {
                    cache,
                    domains,
                    email,
                    production,
                })
            }

            let content = toml::to_string_pretty(&config)?;
            vfs::write(output, content.as_bytes()).await?;
            Ok(())
        }

        /// Start a web server.
        pub async fn start(
            config: PathBuf,
            bind: Option<SocketAddr>,
        ) -> Result<()> {
            let mut config = ServerConfig::load(&config).await?;

            if let Some(addr) = bind {
                config.set_bind_address(addr);
            }

            let backend = config.backend().await?;

            let state = Arc::new(RwLock::new(State::new(config)));

            let handle = Handle::new();
            let server = Server::new(backend.directory()).await?;
            server
                .start(state, Arc::new(RwLock::new(backend)), handle)
                .await?;
            Ok(())
        }
    }
}
