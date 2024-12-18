use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::extras::preferences::*;

/// Tests concurrent writes to the global preferences.
#[tokio::test]
async fn preferences_concurrent_write() -> Result<()> {
    const TEST_ID: &str = "preferences_concurrent_write";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let mut preferences = CachedPreferences::new(Some(data_dir.clone()))?;
    preferences.load_global_preferences().await?;

    let prefs = preferences.global_preferences();

    let mut futures = Vec::new();
    for i in 0..100 {
        let inner = prefs.clone();
        futures.push(tokio::task::spawn(async move {
            let mut prefs = inner.lock().await;
            prefs.insert("mock.int".to_owned(), i.into()).await?;
            Ok::<_, anyhow::Error>(())
        }));
    }

    futures::future::try_join_all(futures).await?;

    let prefs = prefs.lock().await;
    let int = prefs.get_number("mock.int")?;
    assert!(matches!(int, Some(Preference::Number(_))));

    teardown(TEST_ID).await;

    Ok(())
}
