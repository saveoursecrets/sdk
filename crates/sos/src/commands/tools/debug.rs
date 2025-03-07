use crate::{helpers::account::resolve_account_address, Result};
use clap::Subcommand;
use sos_backend::BackendTarget;
use sos_client_storage::ClientStorage;
use sos_core::{AccountRef, Paths};
use sos_sync::SyncStorage;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print the debug tree for an account.
    Tree {
        /// Account name or identifier.
        account: AccountRef,
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
    }

    Ok(())
}
