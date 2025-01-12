use anyhow::Result;
use futures::{pin_mut, StreamExt};
use sos_core::events::EventLog;
use sos_test_utils::mock::memory_database;

use super::mock;

#[tokio::test]
async fn fs_event_stream_forward() -> Result<()> {
    let (temp, event_log) = mock::fs_event_log_file().await?;
    let stream = event_log.event_stream(false).await;
    pin_mut!(stream);
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn fs_event_stream_backward() -> Result<()> {
    let (temp, event_log) = mock::fs_event_log_file().await?;
    let stream = event_log.event_stream(true).await;
    pin_mut!(stream);
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn db_event_stream_forward() -> Result<()> {
    let mut client = memory_database().await?;
    let (_, event_log) = mock::db_event_log_folder(&mut client).await?;
    let stream = event_log.event_stream(false).await;
    pin_mut!(stream);
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
    Ok(())
}

#[tokio::test]
async fn db_event_stream_backward() -> Result<()> {
    let mut client = memory_database().await?;
    let (_, event_log) = mock::db_event_log_folder(&mut client).await?;
    let stream = event_log.event_stream(true).await;
    pin_mut!(stream);
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
    Ok(())
}
