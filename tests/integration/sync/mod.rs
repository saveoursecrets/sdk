use anyhow::Result;
use sos_net::{
    client::{
        provider::{RemoteProvider, StorageProvider},
        user::UserStorage,
    },
    sdk::{
        constants::VAULT_EXT,
        vault::Summary,
        vfs,
    },
};
use std::path::PathBuf;

mod create_remote_data;

/// Assert that local and remote storage are equal.
pub async fn assert_local_remote_eq(
    expected_summaries: Vec<Summary>,
    server_path: &PathBuf,
    owner: &mut UserStorage,
    provider: &mut RemoteProvider,
) -> Result<()> {
    // Compare vault buffers
    for summary in expected_summaries {
        let local_folder = owner.storage().vault_path(&summary);
        let remote_folder =
            server_path.join(format!("{}.{}", summary.id(), VAULT_EXT));
        let local_buffer = vfs::read(&local_folder).await?;
        let remote_buffer = vfs::read(&remote_folder).await?;
        assert_eq!(local_buffer, remote_buffer);
    }

    // Compare event log status (commit proofs)
    let local_status = owner.storage_mut().account_status().await?;
    let remote_status = provider.account_status().await?;
    assert_eq!(local_status, remote_status);

    Ok(())
}
