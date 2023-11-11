use crate::{commands::{server, generate_keypair}, Result};
use clap::{Subcommand, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct SosServer {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate PEM-encoded keypair and write to file.
    GenerateKeypair {
        /// Force overwrite if the file exists.
        #[clap(short, long)]
        force: bool,

        /// Write hex-encoded public key to a file.
        #[clap(long)]
        public_key: Option<PathBuf>,

        /// Write keypair to this file.
        file: PathBuf,
    },

    /// Start a server.
    Start {
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
}

pub async fn run() -> Result<()> {
    let args = SosServer::parse();
    
    match args.cmd {
        Command::GenerateKeypair {
            file,
            force,
            public_key,
        }  => generate_keypair::run(file, force, public_key).await?,
        Command::Start { audit_log, reap_interval, session_duration, bind, config } => {
            server::run(
                audit_log,
                reap_interval,
                session_duration,
                bind,
                config,
            )
            .await?;
        }
    }

    Ok(())
}
