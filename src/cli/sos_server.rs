use clap::Parser;
use std::path::PathBuf;
use crate::{commands::server, Result};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct SosServer {
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

pub async fn run() -> Result<()> {
    let args = SosServer::parse();
    server::run(
        args.audit_log,
        args.reap_interval,
        args.session_duration,
        args.bind,
        args.config,
    )
    .await?;
    Ok(())
}
