use clap::Subcommand;
use std::path::PathBuf;
use web3_address::ethereum::Address;

use super::{logs, monitor};

use crate::Result;

#[derive(Subcommand, Debug)]
pub enum Command {
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
        address: Vec<Address>,

        /// Audit log file
        audit_log: PathBuf,
    },
    /// Monitor changes to an audit log file
    Monitor {
        /// Print each event as a line of JSON
        #[clap(short, long)]
        json: bool,

        /// Filter to events that match the given address.
        #[clap(short, long)]
        address: Vec<Address>,

        /// Audit log file
        audit_log: PathBuf,
    },
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Logs {
            audit_log,
            json,
            address,
            reverse,
            count,
        } => {
            logs(audit_log, json, address, reverse, count)?;
        }
        Command::Monitor {
            audit_log,
            json,
            address,
        } => {
            monitor(audit_log, json, address)?;
        }
    }
    Ok(())
}
