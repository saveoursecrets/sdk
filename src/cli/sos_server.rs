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
    /// Start a server.
    Start {
        /// Bind to host:port.
        #[clap(short, long, default_value = "0.0.0.0:5053")]
        bind: String,

        /// Config file to load.
        #[clap(short, long)]
        config: PathBuf,
    },
}

pub async fn run() -> Result<()> {
    let args = SosServer::parse();

    match args.cmd {
        Command::Start { bind, config } => {
            server::run(bind, config).await?;
        }
    }

    Ok(())
}
