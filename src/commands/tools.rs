use crate::{
    commands::check::verify_events,
    helpers::{
        account::resolve_account,
        messages::{fail, success},
        readline::read_flag,
    },
    Error, Result,
};
use clap::Subcommand;
use sos_net::sdk::{
    constants::EVENT_LOG_EXT,
    encode,
    events::{EventLogExt, FolderEventLog, FolderReducer},
    identity::AccountRef,
    vault::VaultId,
    vfs, Paths,
};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Repair a vault from a corresponding events file.
    RepairVault {
        /// Account name or address.
        account: AccountRef,

        /// Folder identifier.
        folder: VaultId,
    },
}

/// Handle sync commands.
pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::RepairVault { account, folder } => {
            let account = resolve_account(Some(&account))
                .await
                .ok_or(Error::NoAccount(account.to_string()))?;

            match account {
                AccountRef::Address(address) => {
                    let paths =
                        Paths::new(Paths::data_dir()?, address.to_string());
                    let events_file = paths.event_log_path(&folder);
                    let vault_file = paths.vault_path(&folder);

                    if !vfs::try_exists(&events_file).await? {
                        return Err(Error::NotFile(events_file));
                    }

                    if !vfs::try_exists(&vault_file).await? {
                        return Err(Error::NotFile(vault_file));
                    }

                    let prompt = format!(
                        "Overwrite vault file with events from {}.{} (y/n)? ",
                        folder, EVENT_LOG_EXT,
                    );
                    if read_flag(Some(&prompt))? {
                        verify_events(events_file.clone(), false).await?;

                        let event_log =
                            FolderEventLog::new(&events_file).await?;

                        let vault = FolderReducer::new()
                            .reduce(&event_log)
                            .await?
                            .build(true)
                            .await?;

                        let buffer = encode(&vault).await?;
                        vfs::write(vault_file, buffer).await?;

                        success(format!("Repaired {}", folder));
                    }
                }
                _ => fail("unable to locate account"),
            }
        }
    }
    Ok(())
}
