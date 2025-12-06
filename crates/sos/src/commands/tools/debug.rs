use crate::{Result, helpers::account::resolve_account_address};
use clap::Subcommand;
use sos_backend::BackendTarget;
use sos_client_storage::ClientStorage;
use sos_core::{AccountRef, Paths};
use sos_debug_snapshot::{DebugSnapshotOptions, export_debug_snapshot};
use sos_sync::SyncStorage;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print the debug tree for an account.
    Tree {
        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,
    },
    /// Create a debug snapshot ZIP bundle.
    Snapshot {
        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,

        /// Include audit trail.
        #[clap(long)]
        include_audit_trail: bool,

        /// Output ZIP file.
        file: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Tree { account } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?)
                .with_account_id(&account_id);
            let target = BackendTarget::from_paths(&paths).await?;

            let storage =
                ClientStorage::new_unauthenticated(target, &account_id)
                    .await?;

            let debug_tree = storage.debug_account_tree(account_id).await?;
            serde_json::to_writer_pretty(std::io::stdout(), &debug_tree)?;
        }
        Command::Snapshot {
            account,
            include_audit_trail,
            file,
        } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?)
                .with_account_id(&account_id);
            let target = BackendTarget::from_paths(&paths).await?;

            let storage =
                ClientStorage::new_unauthenticated(target, &account_id)
                    .await?;

            let options = DebugSnapshotOptions {
                include_audit_trail,
                ..Default::default()
            };
            export_debug_snapshot(&storage, file, options).await?;
        }
    }

    Ok(())
}
