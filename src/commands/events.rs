use clap::Subcommand;
use std::path::PathBuf;

use binary_stream::futures::{Decodable, Encodable};
use sos_net::sdk::{
    events::{
        AccountEvent, AccountEventLog, EventLogFile, FileEvent, FileEventLog,
        FileLog, FolderEventLog, LogEvent, WriteEvent,
    },
    vfs,
};

use futures::{pin_mut, stream::StreamExt};

use crate::{Error, Result};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print account event log records.
    Account {
        /// Reverse the iteration direction.
        #[clap(short, long)]
        reverse: bool,

        /// Log file path.
        file: PathBuf,
    },
    /// Print folder event log records.
    Folder {
        /// Reverse the iteration direction.
        #[clap(short, long)]
        reverse: bool,

        /// Log file path.
        file: PathBuf,
    },
    /// Print file event log records.
    File {
        /// Reverse the iteration direction.
        #[clap(short, long)]
        reverse: bool,

        /// Log file path.
        file: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Account { file, reverse } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = AccountEventLog::new_account(&file).await?;
            print_events::<AccountEvent>(event_log, reverse).await?;
        }
        Command::Folder { file, reverse } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = FolderEventLog::new_folder(&file).await?;
            print_events::<WriteEvent>(event_log, reverse).await?;
        }
        Command::File { file, reverse } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = FileEventLog::new_file(&file).await?;
            print_events::<FileEvent>(event_log, reverse).await?;
        }
    }

    Ok(())
}

/// Print the events of a log file.
async fn print_events<T: Default + Encodable + Decodable + LogEvent>(
    event_log: EventLogFile<T, FileLog, FileLog>,
    reverse: bool,
) -> Result<()> {
    let version = event_log.read_file_version().await?;
    let mut count = 0;
    let divider = "-".repeat(72);

    let stream = event_log.stream(reverse).await;
    pin_mut!(stream);

    while let Some(event) = stream.next().await {
        let (record, event) = event?;
        println!("{}", divider);
        println!("  time: {}", record.time());
        println!("before: {}", record.last_commit());
        println!("commit: {}", record.commit());
        println!(" event: {}", event.event_kind());
        count += 1;
    }

    if count > 0 {
        println!("{}", divider);
        println!("  total: {}", count);
        println!("version: {}", version);
        println!("{}", divider);
    } else {
        println!("no events yet");
    }

    Ok(())
}
