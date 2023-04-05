use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use tempfile::tempdir;

use secrecy::ExposeSecret;
use sos_core::{
    events::SyncEvent,
    secret::Secret,
    signer::{ecdsa::SingleParty, Signer},
    wal::WalProvider,
    PatchProvider,
};
use sos_node::client::provider::{
    LocalProvider, StorageDirs, StorageProvider,
};

macro_rules! commit_count {
    ($storage:expr, $summary:expr, $amount:expr) => {{
        let commits = $storage.commit_tree($summary);
        assert!(commits.is_some());
        let commits = commits.unwrap();
        assert_eq!($amount, commits.len());
    }};
}

async fn run_local_storage_tests<W, P>(
    storage: &mut LocalProvider<W, P>,
) -> Result<()>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    // Create an account with default login vault
    let (passphrase, _) = storage.create_account(None, None).await?;

    let mut summaries = storage.vaults().to_vec();
    assert_eq!(1, summaries.len());
    let summary = summaries.remove(0);
    assert_eq!("Documents", summary.name());

    // Single create vault commit
    commit_count!(storage, &summary, 1);

    // Rename a vault
    storage.set_vault_name(&summary, "MockVault").await?;
    let mut summaries = storage.vaults().to_vec();
    let summary = summaries.remove(0);
    assert_eq!("MockVault", summary.name());

    // Extra commit when changing the name
    commit_count!(storage, &summary, 2);

    // Open the vault
    storage.open_vault(&summary, passphrase.expose_secret(), None)?;

    let (meta, secret) = mock_note("Test Note", "Mock note content.");
    let event = storage.create_secret(meta, secret).await?;
    let id = if let SyncEvent::CreateSecret(id, _) = event {
        id
    } else {
        panic!("expecting sync create secret event");
    };

    // Commit for secret creation
    commit_count!(storage, &summary, 3);

    let (meta, secret, _) = storage.read_secret(&id).await?;
    assert_eq!("Test Note", meta.label());

    let value = if let Secret::Note { text, .. } = &secret {
        text
    } else {
        panic!("expecting note secret type");
    };
    assert_eq!("Mock note content.", value.expose_secret());

    let (_, updated_secret) = mock_note("", "New mock note content.");

    let _event = storage.update_secret(&id, meta, updated_secret).await?;

    // Commit for secret edit
    commit_count!(storage, &summary, 4);

    // Create another secret
    let (meta, secret) = mock_note("Alt Note", "Another mock note.");
    let event = storage.create_secret(meta, secret).await?;
    let alt_id = if let SyncEvent::CreateSecret(id, _) = event {
        id
    } else {
        panic!("expecting sync create secret event");
    };

    // Commit for secret creation
    commit_count!(storage, &summary, 5);

    let _event = storage.delete_secret(&alt_id).await?;

    // Commit for secret deletion
    commit_count!(storage, &summary, 6);

    // Close the vault
    storage.close_vault();

    // Compact the vault
    storage.compact(&summary).await?;

    // After compaction only two commits are left
    // one for vault creation and one for the
    // remaining secret
    commit_count!(storage, &summary, 2);
    let history = storage.history(&summary)?;
    assert_eq!(2, history.len());

    Ok(())
}

#[tokio::test]
#[serial]
async fn integration_local_provider_memory() -> Result<()> {
    let mut storage = LocalProvider::new_memory_storage();
    run_local_storage_tests(&mut storage).await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn integration_local_provider_file() -> Result<()> {
    let dir = tempdir()?;
    let signer = Box::new(SingleParty::new_random());
    let user_id = signer.address()?.to_string();
    let dirs = StorageDirs::new(dir.path(), &user_id);
    let mut storage = LocalProvider::new_file_storage(dirs)?;
    run_local_storage_tests(&mut storage).await?;
    Ok(())
}
