use super::mock;
use anyhow::Result;
use sos_backend::AccountEventLog;
use sos_core::{
    events::{AccountEvent, EventLog},
    VaultId,
};
use sos_test_utils::mock::memory_database;

#[tokio::test]
async fn fs_event_log_diff_events() -> Result<()> {
    let (temp, event_log) = mock::fs_account_event_log().await?;
    assert_diff_events(event_log).await?;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn db_event_log_diff_events() -> Result<()> {
    let mut client = memory_database().await?;
    let (_, event_log) = mock::db_account_event_log(&mut client).await?;
    assert_diff_events(event_log).await?;
    Ok(())
}

async fn assert_diff_events(mut event_log: AccountEventLog) -> Result<()> {
    let folder = VaultId::new_v4();
    event_log
        .apply(&[
            AccountEvent::CreateFolder(folder, vec![]),
            AccountEvent::DeleteFolder(folder),
        ])
        .await?;

    assert!(event_log.tree().len() > 0);
    assert!(event_log.tree().root().is_some());
    assert!(event_log.tree().last_commit().is_some());

    let patch = event_log.diff_events(None).await?;
    assert_eq!(2, patch.len());

    Ok(())
}
