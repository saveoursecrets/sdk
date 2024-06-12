use crate::test_utils::{mock, simulate_device, spawn, teardown};
use anyhow::Result;
use sos_net::{client::SyncClient, sdk::prelude::*, CommitScanRequest};

/// Tests scanning commit hashes on remote servers.
#[tokio::test]
async fn automerge_scan_commits() -> Result<()> {
    const TEST_ID: &str = "automerge_scan_commits";
    // crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let default_folder = device.default_folder.clone();

    // Create some commits to a folder so it has 4 total
    // commit hashes.
    //
    // 1. Create vault
    // 2. Create secret
    // 3. Update secret
    // 4. Delete secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let result = device
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_error.is_none());
    let (meta, secret) = mock::note("note_edited", TEST_ID);
    device
        .owner
        .update_secret(
            &result.id,
            meta.clone(),
            Some(secret),
            Default::default(),
            None,
        )
        .await?;
    device
        .owner
        .delete_secret(&result.id, Default::default())
        .await?;

    // Get the remote out of the owner so we can
    // use the HTTP client directly
    let bridge = device.owner.remove_server(&origin).await?.unwrap();
    let client = bridge.client().clone();

    // Get the first commit hash of the identity folder
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Identity;
    req.limit = 1;
    req.ascending = true;
    let mut res = client.scan(&req).await?;
    assert_eq!(1, res.list.len());
    let first_identity_commit = res.list.remove(0);

    // Get the last commit hash of the identity folder
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Identity;
    req.limit = 1;
    let mut res = client.scan(&req).await?;
    assert_eq!(1, res.list.len());
    let last_identity_commit = res.list.remove(0);

    assert_ne!(first_identity_commit, last_identity_commit);

    // Get commit hashes of the account event log
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Account;
    req.limit = 256;
    let res = client.scan(&req).await?;
    assert!(!res.list.is_empty());

    // Get commit hashes of the device event log
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Device;
    req.limit = 256;
    let res = client.scan(&req).await?;
    assert!(!res.list.is_empty());

    // Get commit hashes of the files event log
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Files;
    req.limit = 256;
    let res = client.scan(&req).await?;
    // No files yet!
    assert!(res.list.is_empty());

    // Get the local commits so we can assert
    let folder_log = device.owner.folder_log(default_folder.id()).await?;
    let event_log = folder_log.read().await;
    let commits = event_log
        .tree()
        .leaves()
        .unwrap()
        .into_iter()
        .map(CommitHash)
        .collect::<Vec<_>>();

    // Get the last commit hashes for a folder
    // scanning from the end (descending)
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Folder(*default_folder.id());
    req.limit = 256;
    let folder_desc = client.scan(&req).await?;
    assert_eq!(commits, folder_desc.list);

    // Get the last commit hashes for a folder
    // in ascending order
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Folder(*default_folder.id());
    req.limit = 256;
    req.ascending = true;
    let folder_asc = client.scan(&req).await?;
    assert_eq!(commits, folder_asc.list);

    device.owner.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
