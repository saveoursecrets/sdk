use crate::{Error, Result};
use binary_stream::futures::{Decodable, Encodable};
use clap::Subcommand;
use futures::{pin_mut, stream::StreamExt};
use sos_backend::{
    AccountEventLog, BackendEventLog, DeviceEventLog, FileEventLog,
    FolderEventLog,
};
use sos_core::{
    commit::{CommitHash, CommitTree},
    events::{
        AccountEvent, DeviceEvent, EventLog, FileEvent, LogEvent, WriteEvent,
    },
};
use sos_vfs as vfs;
use std::path::PathBuf;

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
            let event_log = AccountEventLog::new_fs_account(&file).await?;
            print_events::<AccountEvent>(event_log, until_commit).await?;
        }
        Command::Device { file, until_commit } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = DeviceEventLog::new_fs_device(&file).await?;
            print_events::<DeviceEvent>(event_log, until_commit).await?;
        }
        Command::Folder { file, until_commit } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = FolderEventLog::new_fs_folder(&file).await?;
            print_events::<WriteEvent>(event_log, until_commit).await?;
        }
        Command::File { file, until_commit } => {
            if !vfs::metadata(&file).await?.is_file() {
                return Err(Error::NotFile(file));
            }
            let event_log = FileEventLog::new_fs_file(&file).await?;
            print_events::<FileEvent>(event_log, until_commit).await?;
        }
    }

    Ok(())
}

/// Print the events of a log file.
async fn print_events<
    T: Default + Encodable + Decodable + LogEvent + Send + Sync + 'static,
>(
    event_log: BackendEventLog<T>,
    until_commit: Option<CommitHash>,
) -> Result<()> {
    let version = event_log.version();
    let divider = "-".repeat(73);

    let stream = event_log.event_stream(false).await;
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
