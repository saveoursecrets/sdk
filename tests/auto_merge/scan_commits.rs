use crate::test_utils::{mock, simulate_device, spawn, teardown};
use anyhow::Result;
use sos_net::{client::SyncClient, sdk::prelude::*, CommitScanRequest};

/// Tests scanning commit hashes on remote servers.
#[tokio::test]
async fn auto_merge_scan_commits() -> Result<()> {
    const TEST_ID: &str = "auto_merge_scan_commits";
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

    // Get the last commit proof of the identity folder
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Identity;
    req.limit = 1;
    let mut res = client.scan(&req).await?;
    assert_eq!(1, res.proofs.len());

    // Get commit proofs of the account event log
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Account;
    req.limit = 256;
    let res = client.scan(&req).await?;
    assert!(!res.proofs.is_empty());

    // Get commit proofs of the device event log
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Device;
    req.limit = 256;
    let res = client.scan(&req).await?;
    assert!(!res.proofs.is_empty());

    // Get commit proofs of the files event log
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Files;
    req.limit = 256;
    let res = client.scan(&req).await?;
    // No files yet!
    assert!(res.proofs.is_empty());

    // Get the local commits so we can assert
    let folder_log = device.owner.folder_log(default_folder.id()).await?;
    let event_log = folder_log.read().await;

    // Get the commit proofs for a folder
    // scanning from the end (descending)
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Folder(*default_folder.id());
    req.limit = 256;
    let folder_desc = client.scan(&req).await?;
    assert_eq!(4, folder_desc.proofs.len());
    for proof in &folder_desc.proofs {
        let comparison = event_log.tree().compare(proof)?;
        assert!(matches!(
            comparison,
            Comparison::Equal | Comparison::Contains(_, _),
        ));
    }

    // Get the commit proofs for a folder
    // in ascending order
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Folder(*default_folder.id());
    req.limit = 256;
    let folder_asc = client.scan(&req).await?;
    assert_eq!(4, folder_asc.proofs.len());

    // Scan in chunks of 2 from the end
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Folder(*default_folder.id());
    req.limit = 2;
    let folder_chunk_1 = client.scan(&req).await?;
    assert_eq!(2, folder_chunk_1.offset);
    // Scan next chunk
    let mut req = req.clone();
    req.offset = Some(folder_chunk_1.offset);
    let folder_chunk_2 = client.scan(&req).await?;
    assert_eq!(4, folder_chunk_2.offset);

    // Collect all the server proofs scanned
    let mut all_proofs = Vec::new();
    all_proofs.extend(folder_chunk_1.proofs.into_iter().rev());
    all_proofs.extend(folder_chunk_2.proofs.into_iter().rev());

    // Compare to the tree
    let comparisons = all_proofs
        .into_iter()
        .map(|proof| event_log.tree().compare(&proof))
        .collect::<Vec<_>>();
    assert!(comparisons
        .into_iter()
        .all(|c| matches!(c.unwrap(), Comparison::Equal)));

    // Scan past the length ascending (bad offset)
    // yields empty proofs
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Folder(*default_folder.id());
    req.limit = 256;
    req.offset = Some(64);
    let res = client.scan(&req).await?;
    assert!(res.proofs.is_empty());

    // Scan past the length descending (bad offset)
    // yields empty proofs
    let mut req = CommitScanRequest::default();
    req.log_type = EventLogType::Folder(*default_folder.id());
    req.limit = 256;
    req.offset = Some(64);
    let res = client.scan(&req).await?;
    assert!(res.proofs.is_empty());

    device.owner.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
