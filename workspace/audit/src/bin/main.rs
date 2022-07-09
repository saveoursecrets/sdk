use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sos_audit::Result;
use sos_core::address::AddressStr;

/// Print and monitor audit log events.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the events in an audit log file
    Logs {
        /// Print each event as a line of JSON
        #[clap(short, long)]
        json: bool,

        /// Iterate from the end of the file
        #[clap(short, long)]
        reverse: bool,

        /// Limit events to displayed to this count
        #[clap(short, long)]
        count: Option<usize>,

        /// Filter to events that match the given address.
        #[clap(short, long)]
        address: Vec<AddressStr>,

        /// Audit log file
        #[clap(parse(from_os_str))]
        audit_log: PathBuf,
    },
    /// Monitor changes to an audit log file
    Monitor {
        /// Print each event as a line of JSON
        #[clap(short, long)]
        json: bool,

        /// Filter to events that match the given address.
        #[clap(short, long)]
        address: Vec<AddressStr>,

        /// Audit log file
        #[clap(parse(from_os_str))]
        audit_log: PathBuf,
    },
}

fn run() -> Result<()> {
    let args = Cli::parse();
    match args.cmd {
        Command::Logs {
            audit_log,
            json,
            address,
            reverse,
            count,
        } => {
            sos_audit::logs(audit_log, json, address, reverse, count)?;
        }
        Command::Monitor {
            audit_log,
            json,
            address,
        } => {
            sos_audit::monitor(audit_log, json, address)?;
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
