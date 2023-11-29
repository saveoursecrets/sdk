use crate::test_utils::mock_note;
use anyhow::Result;
use secrecy::ExposeSecret;
use sos_net::sdk::{
    account::FolderStorage,
    events::WriteEvent,
    signer::{ecdsa::SingleParty, Signer},
    vault::secret::{Secret, SecretRow},
};
use tempfile::tempdir;

macro_rules! commit_count {
    ($storage:expr, $summary:expr, $amount:expr) => {{
        let commits = $storage.commit_tree($summary);
        assert!(commits.is_some());
        let commits = commits.unwrap();
        assert_eq!($amount, commits.len());
    }};
}

/// Tests compacting a folder event log.
#[tokio::test]
async fn integration_compact_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    let dir = tempdir()?;
    let signer = Box::new(SingleParty::new_random());
    let user_id = signer.address()?.to_string();
    let mut storage =
        FolderStorage::new(user_id, Some(dir.path().to_path_buf())).await?;

    // Create an account with default login vault
    let (_, passphrase, _) = storage.create_account(None, None).await?;

    let mut summaries = storage.folders().to_vec();
    assert_eq!(1, summaries.len());
    let summary = summaries.remove(0);
    assert_eq!("Documents", summary.name());

    // Single create vault commit
    commit_count!(storage, &summary, 1);

    // Rename a vault
    storage.set_vault_name(&summary, "MockVault").await?;
    let mut summaries = storage.folders().to_vec();
    let summary = summaries.remove(0);
    assert_eq!("MockVault", summary.name());

    // Extra commit when changing the name
    commit_count!(storage, &summary, 2);

    // Open the vault
    storage
        .open_vault(&summary, passphrase.clone(), None)
        .await?;

    let (meta, secret) = mock_note("Test Note", "Mock note content.");
    let (id, event) = storage.create_secret(meta, secret).await?;

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

    let secret_data = SecretRow::new(id, meta, updated_secret);
    let _event = storage.update_secret(&id, secret_data).await?;

    // Commit for secret edit
    commit_count!(storage, &summary, 4);

    // Create another secret
    let (meta, secret) = mock_note("Alt Note", "Another mock note.");
    let (alt_id, event) = storage.create_secret(meta, secret).await?;

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
    let history = storage.history(&summary).await?;
    assert_eq!(2, history.len());

    Ok(())
}
