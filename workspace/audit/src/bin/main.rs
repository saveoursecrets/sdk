use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sos_audit::Result;

/// Print and monitor audit logs.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the log records in an audit log file
    #[clap(alias = "log")]
    Logs {
        /// Print each log record as a line of JSON
        #[clap(short, long)]
        json: bool,

        /// Audit log file
        #[clap(parse(from_os_str))]
        audit_log: PathBuf,
    },
}

fn run() -> Result<()> {
    let args = Cli::parse();
    match args.cmd {
        Command::Logs { audit_log, json } => {
            sos_audit::logs(audit_log, json)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sos_audit=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    if let Err(e) = run() {
        tracing::error!("{}", e);
    }

    Ok(())
}
