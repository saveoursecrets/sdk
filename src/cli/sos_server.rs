use crate::{commands::server, Result};
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
    Init{
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
        Command::Init{ config } => {
            server::init(config).await?;
        }
        Command::Start { bind, config } => {
            server::run(bind, config).await?;
        }
    }

    Ok(())
}
