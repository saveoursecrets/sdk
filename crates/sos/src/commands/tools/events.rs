use crate::{helpers::account::resolve_account_address, Error, Result};
use binary_stream::futures::{Decodable, Encodable};
use clap::Subcommand;
use futures::{pin_mut, stream::StreamExt};
use serde::Serialize;
use sos_backend::{
    AccountEventLog, BackendEventLog, BackendTarget, DeviceEventLog,
    FileEventLog, FolderEventLog,
};
use sos_core::{
    commit::{CommitHash, CommitTree},
    events::{
        AccountEvent, DeviceEvent, EventKind, EventLog, FileEvent, LogEvent,
        WriteEvent,
    },
    AccountRef, FolderRef, Paths, UtcDateTime,
};

#[derive(Debug, Serialize)]
struct EventLogDump {
    version: u16,
    length: usize,
    root: CommitHash,
    events: Vec<(EventKind, CommitHash, UtcDateTime)>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print account event log records.
    Account {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Print as JSON.
        #[clap(short, long)]
        json: bool,

        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,
    },
    /// Print login folder event log records.
    Login {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Print as JSON.
        #[clap(short, long)]
        json: bool,

        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,
    },
    /// Print device event log records.
    Device {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Print as JSON.
        #[clap(short, long)]
        json: bool,

        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,
    },
    /// Print folder event log records.
    Folder {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Print as JSON.
        #[clap(short, long)]
        json: bool,

        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,

        /// Folder name or identifier.
        #[clap(short, long)]
        folder: FolderRef,
    },
    /// Print file event log records.
    File {
        /// Iterate upto and including a specific commit.
        #[clap(short, long)]
        until_commit: Option<CommitHash>,

        /// Print as JSON.
        #[clap(short, long)]
        json: bool,

        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Account {
            account,
            json,
            until_commit,
        } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?);
            let target = BackendTarget::from_paths(&paths).await?;
            let event_log =
                AccountEventLog::new_account(target, &account_id).await?;
            print_events::<AccountEvent>(event_log, json, until_commit)
                .await?;
        }
        Command::Login {
            account,
            json,
            until_commit,
        } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?);
            let target = BackendTarget::from_paths(&paths).await?;
            let event_log =
                FolderEventLog::new_login_folder(target, &account_id).await?;
            print_events::<WriteEvent>(event_log, json, until_commit).await?;
        }
        Command::Device {
            account,
            json,
            until_commit,
        } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?);
            let target = BackendTarget::from_paths(&paths).await?;
            let event_log =
                DeviceEventLog::new_device(target, &account_id).await?;
            print_events::<DeviceEvent>(event_log, json, until_commit)
                .await?;
        }
        Command::Folder {
            account,
            folder,
            json,
            until_commit,
        } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?);
            let target = BackendTarget::from_paths(&paths).await?;
            let folders = target.list_folders(&account_id).await?;
            let folder = folders
                .iter()
                .find(|f| match &folder {
                    FolderRef::Id(id) => f.id() == id,
                    FolderRef::Name(name) => f.name() == name,
                })
                .ok_or_else(|| Error::FolderNotFound(folder.to_string()))?;
            let event_log =
                FolderEventLog::new_folder(target, &account_id, folder.id())
                    .await?;
            print_events::<WriteEvent>(event_log, json, until_commit).await?;
        }
        Command::File {
            account,
            json,
            until_commit,
        } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?);
            let target = BackendTarget::from_paths(&paths).await?;
            let event_log =
                FileEventLog::new_file(target, &account_id).await?;
            print_events::<FileEvent>(event_log, json, until_commit).await?;
        }
    }

    Ok(())
}

/// Print the events of a log file.
async fn print_events<
    T: Default + Encodable + Decodable + LogEvent + Send + Sync + 'static,
>(
    event_log: BackendEventLog<T>,
    json: bool,
    until_commit: Option<CommitHash>,
) -> Result<()> {
    let version = event_log.version();
    let divider = "-".repeat(73);

    let stream = event_log.event_stream(false).await;
    pin_mut!(stream);

    let mut tree = CommitTree::new();
    let mut events = Vec::new();

    while let Some(event) = stream.next().await {
        let (record, event) = event?;

        if !json {
            println!("{}", divider);
            println!("   time: {}", record.time());
            println!(" commit: {}", record.commit());
            println!("  event: {}", event.event_kind());
        } else {
            events.push((
                event.event_kind(),
                *record.commit(),
                record.time().clone(),
            ));
        }

        tree.append(&mut vec![record.commit().into()]);
        tree.commit();

        if let Some(commit) = &until_commit {
            if commit == record.commit() {
                break;
            }
        }
    }

    if !tree.is_empty() {
        let root = tree.root().unwrap();

        if !json {
            println!("{}", divider);
            println!("   root: {}", root);
            println!("  total: {}", tree.len());
            println!("version: {}", version);
            println!("{}", divider);
        } else {
            let data = EventLogDump {
                version,
                length: events.len(),
                root,
                events,
            };
            serde_json::to_writer_pretty(std::io::stdout(), &data)?;
        }
    } else {
        println!("No events yet");
    }

    Ok(())
}
