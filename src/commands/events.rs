use clap::Subcommand;
use std::path::PathBuf;

use binary_stream::futures::{Decodable, Encodable};
use sos_net::sdk::{
    commit::CommitHash,
    events::{
        AccountEvent, AccountEventLog, EventLogFile, EventRecord, FileEvent,
        FileEventLog, FolderEventLog, LogEvent, WriteEvent,
    },
    vfs,
};

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
    event_log: EventLogFile<T>,
    reverse: bool,
) -> Result<()> {
    let mut it = if reverse {
        event_log.iter().await?.rev()
    } else {
        event_log.iter().await?
    };

    let version = event_log.read_file_version().await?;
    let mut count = 0;
    let divider = "-".repeat(80);
    while let Some(record) = it.next_entry().await? {
        println!("{}", divider);
        println!("  time: {}", record.time());
        println!("before: {}", CommitHash(record.last_commit()));
        println!("commit: {}", CommitHash(record.commit()));
        let event_buffer = event_log.read_event_buffer(&record).await?;
        let event_record: EventRecord = (record, event_buffer).into();
        let event = event_record.decode_event::<T>().await?;
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
