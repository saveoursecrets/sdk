use anyhow::Result;
use sos_backend::FolderEventLog;
use sos_core::{commit::Comparison, SecretId};
use sos_sdk::prelude::*;
use sos_test_utils::mock::memory_database;

use super::mock;

#[tokio::test]
async fn fs_event_log_compare() -> Result<()> {
    let (server_log, client_log, secret_id) =
        mock::fs_event_log_server_client().await?;

    // A completely different tree should also be unknown to the server.
    //
    // This can happen if a client compacts its event log which would create
    // a new commit tree.
    let (unknown_log, _) =
        mock::fs_event_log_standalone("target/event_log_compare.events")
            .await?;
    assert_client_server_compare(
        server_log,
        client_log,
        secret_id,
        unknown_log,
    )
    .await
}

#[tokio::test]
async fn db_event_log_compare() -> Result<()> {
    let mut client = memory_database().await?;
    let (server_log, client_log, secret_id) =
        mock::db_event_log_server_client(&mut client).await?;
    let (unknown_log, _) = mock::db_event_log_standalone(&mut client).await?;
    assert_client_server_compare(
        server_log,
        client_log,
        secret_id,
        unknown_log,
    )
    .await
}

async fn assert_client_server_compare(
    mut server: FolderEventLog,
    client: FolderEventLog,
    secret_id: SecretId,
    unknown: FolderEventLog,
) -> Result<()> {
    // Both trees are equal to begin with
    {
        assert_eq!(server.tree().len(), client.tree().len());

        let proof = client.tree().head()?;
        let comparison = server.tree().compare(&proof)?;
        assert_eq!(Comparison::Equal, comparison);

        let proof = server.tree().head()?;
        let comparison = client.tree().compare(&proof)?;
        assert_eq!(Comparison::Equal, comparison);
    }

    // Add another event to the server (perhaps from another client)
    server
        .apply(vec![&WriteEvent::DeleteSecret(secret_id)])
        .await?;

    // Check that the server contains the client proof
    let proof = client.tree().head()?;
    let comparison = server.tree().compare(&proof)?;

    let matched = if let Comparison::Contains(indices) = comparison {
        indices == vec![1]
    } else {
        false
    };
    assert!(matched);

    // Verify that the server root is not contained by the client.
    let proof = server.tree().head()?;
    let comparison = client.tree().compare(&proof)?;
    assert_eq!(Comparison::Unknown, comparison);

    // Ensure that a different unknown tree yields the unknown
    // comparison
    let proof = unknown.tree().head()?;
    let comparison = server.tree().compare(&proof)?;
    assert_eq!(Comparison::Unknown, comparison);

    Ok(())
}
