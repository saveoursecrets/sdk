use anyhow::Result;
use futures::{pin_mut, stream::BoxStream, StreamExt};
use sos_backend::Error;
use sos_core::events::{EventLog, EventRecord, WriteEvent};
use sos_test_utils::mock::memory_database;

use super::mock;

async fn assert_records(
    stream: BoxStream<'_, std::result::Result<EventRecord, Error>>,
) {
    pin_mut!(stream);

    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
}

async fn assert_events(
    stream: BoxStream<
        '_,
        std::result::Result<(EventRecord, WriteEvent), Error>,
    >,
) {
    pin_mut!(stream);

    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_some());
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn fs_event_stream_forward() -> Result<()> {
    let (temp, event_log) = mock::fs_event_log_file().await?;
    let stream = event_log.event_stream(false).await;
    assert_events(stream).await;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn fs_event_stream_backward() -> Result<()> {
    let (temp, event_log) = mock::fs_event_log_file().await?;
    let stream = event_log.event_stream(true).await;
    assert_events(stream).await;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn db_event_stream_forward() -> Result<()> {
    let mut client = memory_database().await?;
    let (_, event_log) = mock::db_event_log_folder(&mut client).await?;
    let stream = event_log.event_stream(false).await;
    assert_events(stream).await;
    Ok(())
}

#[tokio::test]
async fn db_event_stream_backward() -> Result<()> {
    let mut client = memory_database().await?;
    let (_, event_log) = mock::db_event_log_folder(&mut client).await?;
    let stream = event_log.event_stream(true).await;
    assert_events(stream).await;
    Ok(())
}

#[tokio::test]
async fn fs_record_stream_forward() -> Result<()> {
    let (temp, event_log) = mock::fs_event_log_file().await?;
    let stream = event_log.record_stream(false).await;
    assert_records(stream).await;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn fs_record_stream_backward() -> Result<()> {
    let (temp, event_log) = mock::fs_event_log_file().await?;
    let stream = event_log.record_stream(true).await;
    assert_records(stream).await;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn db_record_stream_forward() -> Result<()> {
    let mut client = memory_database().await?;
    let (_, event_log) = mock::db_event_log_folder(&mut client).await?;
    let stream = event_log.record_stream(false).await;
    assert_records(stream).await;
    Ok(())
}

#[tokio::test]
async fn db_record_stream_backward() -> Result<()> {
    let mut client = memory_database().await?;
    let (_, event_log) = mock::db_event_log_folder(&mut client).await?;
    let stream = event_log.record_stream(true).await;
    assert_records(stream).await;
    Ok(())
}
