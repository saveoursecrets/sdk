use anyhow::Result;
use sos_net::{
    client::{RemoteBridge, UserStorage},
    sdk::{
        constants::VAULT_EXT,
        vault::{Summary, VaultId},
        vfs,
    },
};
use std::path::PathBuf;

mod create_remote_data;
mod send_secret_create;
mod send_secret_delete;
mod send_secret_update;

mod send_folder_create;
mod send_folder_delete;
mod send_folder_import;
mod send_folder_rename;

mod change_secret_create;
mod change_secret_update;
mod change_secret_delete;

/// Get the number of events in a log.
pub async fn num_events(owner: &mut UserStorage, folder: &VaultId) -> usize {
    let storage = owner.storage();
    let reader = storage.read().await;
    let events = reader.cache().get(folder).unwrap();
    events.tree().len()
}

/// Assert that local and remote storage are equal.
pub async fn assert_local_remote_vaults_eq(
    expected_summaries: Vec<Summary>,
    server_path: &PathBuf,
    owner: &mut UserStorage,
    provider: &mut RemoteBridge,
) -> Result<()> {
    let storage = owner.storage();
    let reader = storage.read().await;

    // Compare vault buffers
    for summary in expected_summaries {
        let local_folder = reader.vault_path(&summary);
        let remote_folder =
            server_path.join(format!("{}.{}", summary.id(), VAULT_EXT));
        let local_buffer = vfs::read(&local_folder).await?;
        let remote_buffer = vfs::read(&remote_folder).await?;
        assert_eq!(local_buffer, remote_buffer);
    }

    Ok(())
}

pub async fn assert_local_remote_events_eq(
    expected_summaries: Vec<Summary>,
    server_path: &PathBuf,
    owner: &mut UserStorage,
    provider: &mut RemoteBridge,
) -> Result<()> {
    let storage = owner.storage();

    // Compare event log status (commit proofs)
    let local_status = {
        let mut writer = storage.write().await;
        writer.account_status().await?
    };
    let remote_status = provider.account_status().await?;

    //println!("{:#?}", local_status);
    //println!("{:#?}", remote_status);

    assert_eq!(local_status, remote_status);

    Ok(())
}
