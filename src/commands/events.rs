use clap::Subcommand;
use std::path::PathBuf;

use binary_stream::futures::{Decodable, Encodable};
use sos_net::sdk::{
    commit::{CommitHash, CommitTree},
    events::{
        AccountEvent, AccountEventLog, DeviceEvent, DeviceEventLog,
        DiscEventLog, EventLogExt, FileEvent, FileEventLog, FolderEventLog,
        LogEvent, WriteEvent,
    },
    vfs,
};

use futures::{pin_mut, stream::StreamExt};

use crate::{Error, Result};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print account event log records.
    Account {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Log file path.
        file: PathBuf,
    },
    /// Print device event log records.
    Device {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Log file path.
        file: PathBuf,
    },
    /// Print folder event log records.
    Folder {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Log file path.
        file: PathBuf,
    },
    /// Print file event log records.
    File {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Log file path.
        file: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Account { file, until_commit } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = AccountEventLog::new_account(&file).await?;
            print_events::<AccountEvent>(event_log, until_commit).await?;
        }
        Command::Device { file, until_commit } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = DeviceEventLog::new_device(&file).await?;
            print_events::<DeviceEvent>(event_log, until_commit).await?;
        }
        Command::Folder { file, until_commit } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = FolderEventLog::new(&file).await?;
            print_events::<WriteEvent>(event_log, until_commit).await?;
        }
        Command::File { file, until_commit } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = FileEventLog::new_file(&file).await?;
            print_events::<FileEvent>(event_log, until_commit).await?;
        }
    }

    Ok(())
}

/// Print the events of a log file.
async fn print_events<
    T: Default + Encodable + Decodable + LogEvent + Send + Sync + 'static,
>(
    event_log: DiscEventLog<T>,
    until_commit: Option<CommitHash>,
) -> Result<()> {
    let version = event_log.read_file_version().await?;
    let divider = "-".repeat(73);

    let stream = event_log.stream(false).await;
    pin_mut!(stream);

    let mut tree = CommitTree::new();

    while let Some(event) = stream.next().await {
        let (record, event) = event?;

        println!("{}", divider);
        println!("   time: {}", record.time());
        println!(" before: {}", record.last_commit());
        println!(" commit: {}", record.commit());
        println!("  event: {}", event.event_kind());

        tree.append(&mut vec![record.commit().into()]);
        tree.commit();

        if let Some(commit) = &until_commit {
            if commit == record.commit() {
                break;
            }
        }
    }

    if tree.len() > 0 {
        let root = tree.root().unwrap();
        println!("{}", divider);
        println!("   root: {}", root);
        println!("  total: {}", tree.len());
        println!("version: {}", version);
        println!("{}", divider);
    } else {
        println!("No events yet");
    }

    Ok(())
}
